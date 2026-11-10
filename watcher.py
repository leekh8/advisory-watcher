"""
advisory-watcher — KISA 보호나라 + Fortinet PSIRT 보안 권고문 수집기.

표준 라이브러리만 사용(의존성 0). RSS를 정기 fetch해서 새 권고문만
SQLite에 적재하고 알림(메일 또는 콘솔)을 보낸다.

사용:
    python watcher.py            # 스캔 + 신규 알림 (첫 실행은 seed 모드 — 알림 없음)
    python watcher.py --no-mail  # 스캔만 (알림 생략)
    python watcher.py --list 10  # 최근 수집분 조회
    python watcher.py --pending  # 아직 못 보낸 권고문 조회
    python watcher.py --require-mail  # 무인 실행. 메일 미설정을 오류 취급
"""
from __future__ import annotations

import argparse
import re
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

BASE_DIR = Path(__file__).parent
DB_PATH = BASE_DIR / "data" / "advisories.db"

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) advisory-watcher/0.1"
HTTP_TIMEOUT = 20
HTTP_RETRIES = 3
HTTP_BACKOFF = 5  # 초 — 선형 백오프 (5s, 10s)

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
FG_IR_RE = re.compile(r"FG-IR-\d{2}-\d+")


def _fortinet_id(item: dict) -> str:
    # 링크 어디에 있든 FG-IR-YY-NNN 패턴을 앵커링 — 쿼리스트링·경로 변화에 견고
    m = FG_IR_RE.search(item.get("link", ""))
    return m.group(0) if m else ""


# 소스 정의: fetch할 RSS와, 항목에서 고유 ID를 뽑는 방법
SOURCES = {
    "KISA": {
        "name": "KISA 보호나라 보안공지",
        "rss": "https://www.boho.or.kr/kr/rss.do?bbsId=B0000133",
        # 고유 ID = 게시글 링크의 nttId 파라미터
        "entry_id": lambda item: _query_param(item.get("link", ""), "nttId"),
    },
    "FORTINET": {
        "name": "Fortinet PSIRT (IR Advisories)",
        "rss": "https://filestore.fortinet.com/fortiguard/rss/ir.xml",
        # 고유 ID = 링크 내 FG-IR-YY-NNN (정규식 앵커링)
        "entry_id": _fortinet_id,
    },
}


# ---------------------------------------------------------------- HTTP

def fetch(url: str) -> bytes | None:
    """RSS 원본 바이트를 가져온다. 404=None, 4xx=즉시 예외, 5xx/네트워크=재시도.

    디코딩하지 않고 bytes를 반환 — XML 선언의 인코딩(euc-kr/utf-8 등)을
    파서가 직접 처리하도록 위임(관공서 피드 인코딩 변동에 견고)."""
    last: Exception | None = None
    for attempt in range(1, HTTP_RETRIES + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as res:
                return res.read()
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if not (500 <= e.code < 600):
                raise  # 그 외 4xx는 설정 오류 — 즉시 표면화
            last = e
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            last = e  # 네트워크성 → 재시도
        if attempt < HTTP_RETRIES:
            time.sleep(HTTP_BACKOFF * attempt)
    raise last  # type: ignore[misc]


def _query_param(url: str, key: str) -> str:
    qs = urllib.parse.parse_qs(urllib.parse.urlparse(url.strip()).query)
    values = qs.get(key, [])
    return values[0] if values else ""


# ---------------------------------------------------------------- RSS 파싱

def _to_text(data) -> str:
    """bytes를 str로 디코딩. 선언 인코딩 우선 → utf-8 → cp949(euc-kr) 폴백.

    expat는 euc-kr 등 멀티바이트 인코딩 bytes를 직접 못 읽으므로(ValueError),
    우리가 먼저 디코딩해 str로 넘긴다(ET는 str이면 선언 charset을 무시)."""
    if isinstance(data, str):
        return data
    encs = []
    m = re.search(rb'encoding=["\']([\w-]+)["\']', data[:200])
    if m:
        encs.append(m.group(1).decode("ascii", "ignore"))
    encs += ["utf-8-sig", "cp949"]
    for enc in encs:
        try:
            return data.decode(enc)
        except (LookupError, UnicodeDecodeError):
            continue
    return data.decode("utf-8", errors="replace")


def parse_rss(xml_data) -> list[dict]:
    """RSS 2.0 → [{title, link, pubDate, description}] (공백 정돈).

    입력은 bytes(권장, 선언 인코딩 자동 폴백) 또는 str. <channel>이 없으면
    ValueError — Atom 전환·구조 변경을 조용히 삼키지 않고 오류로 표면화한다."""
    root = ET.fromstring(_to_text(xml_data))
    channel = root.find("channel")
    if channel is None:
        raise ValueError(f"RSS <channel> 없음 (Atom 피드/구조 변경? root=<{root.tag}>)")
    entries = []
    for item in channel.findall("item"):
        entries.append({
            "title": (item.findtext("title") or "").strip(),
            "link": (item.findtext("link") or "").strip(),
            "pubDate": (item.findtext("pubDate") or "").strip(),
            "description": (item.findtext("description") or "").strip(),
        })
    return entries


def extract_cves(entry: dict) -> str:
    found = CVE_RE.findall(entry["title"] + " " + entry["description"])
    return ",".join(sorted(set(found)))


# ---------------------------------------------------------------- DB

def get_conn(db_path: Path = DB_PATH) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    # timeout=30: cron 중복 기동 시 'database is locked' 크래시 대신 대기.
    conn = sqlite3.connect(db_path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")  # 동시 read/write 내성
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS advisories (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        source      TEXT NOT NULL,
        entry_id    TEXT NOT NULL,
        title       TEXT NOT NULL,
        url         TEXT NOT NULL,
        published   TEXT,
        cves        TEXT,
        detected_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
        notified    INTEGER NOT NULL DEFAULT 0,
        UNIQUE(source, entry_id)
    );
    CREATE TABLE IF NOT EXISTS scan_log (
        id      INTEGER PRIMARY KEY AUTOINCREMENT,
        ran_at  TEXT NOT NULL DEFAULT (datetime('now','localtime')),
        source  TEXT NOT NULL,
        fetched INTEGER,
        new     INTEGER,
        skipped INTEGER DEFAULT 0,
        error   TEXT
    );
    """)
    # 기존 DB 마이그레이션: scan_log.skipped 컬럼 없으면 추가
    cols = {r[1] for r in conn.execute("PRAGMA table_info(scan_log)")}
    if "skipped" not in cols:
        conn.execute("ALTER TABLE scan_log ADD COLUMN skipped INTEGER DEFAULT 0")
    return conn


# ---------------------------------------------------------------- 스캔

def scan(conn: sqlite3.Connection):
    """모든 소스를 fetch해서 (신규 권고문 행 목록, 오류 메시지 목록)을 반환한다.

    오류 목록이 비어있지 않으면 호출부가 nonzero exit로 모니터링에 알린다.
    entry_id 추출이 전건 실패(링크 포맷 변경 등)하면 조용히 넘기지 않고 오류로 기록."""
    new_ids: list[int] = []
    errors: list[str] = []
    for key, src in SOURCES.items():
        fetched = new = skipped = 0
        error = None
        try:
            raw = fetch(src["rss"])
            if raw is None:
                error = "404 (피드 위치 변경?)"
            else:
                entries = parse_rss(raw)
                for entry in entries:
                    entry_id = src["entry_id"](entry)
                    if not entry_id:
                        skipped += 1  # 고유 ID 추출 실패 — 조용히 버리지 않고 집계
                        continue
                    fetched += 1
                    try:
                        cur = conn.execute(
                            "INSERT INTO advisories (source, entry_id, title, url, published, cves)"
                            " VALUES (?,?,?,?,?,?)",
                            (key, entry_id, entry["title"], entry["link"],
                             entry["pubDate"], extract_cves(entry)))
                        new_ids.append(cur.lastrowid)
                        new += 1
                    except sqlite3.IntegrityError:
                        pass  # 이미 본 항목
                # 항목은 있는데 하나도 ID를 못 뽑았으면 = 추출 로직 붕괴 (무증상 실명 방지)
                if entries and fetched == 0:
                    error = f"entry_id 추출 전건 실패 — {len(entries)}건 전부 스킵 (링크 포맷 변경?)"
        except Exception as e:  # 소스 하나가 죽어도 나머지는 계속
            error = str(e)
        if error:
            errors.append(f"{key}: {error}")
        conn.execute(
            "INSERT INTO scan_log (source, fetched, new, skipped, error) VALUES (?,?,?,?,?)",
            (key, fetched, new, skipped, error))
        status = f"error={error}" if error else "ok"
        print(f"[scan] {key}: fetched={fetched} new={new} skipped={skipped} {status}")
    conn.commit()
    if not new_ids:
        return [], errors
    marks = ",".join("?" * len(new_ids))
    rows = conn.execute(
        f"SELECT * FROM advisories WHERE id IN ({marks}) ORDER BY source, id", new_ids).fetchall()
    return rows, errors


def mark_notified(conn: sqlite3.Connection, rows: list[sqlite3.Row]) -> None:
    conn.executemany("UPDATE advisories SET notified=1 WHERE id=?", [(r["id"],) for r in rows])
    conn.commit()


# 한 번에 알릴 최대 건수. 오래 끊겼다 복구될 때 수백 건짜리 메일 한 통이 되는 것을 막는다.
# 초과분은 notified=0으로 남아 다음 회차에 이어서 나간다.
MAX_PENDING = 200


def pending(conn: sqlite3.Connection, limit: int = MAX_PENDING) -> list[sqlite3.Row]:
    """아직 알리지 못한 권고문. 이번 회차 신규 + 지난 회차에 못 보낸 것.

    이번 실행에서 INSERT된 행만 보내면, 발송이 실패한 회차의 권고문이 영구히 사라진다.
    다음 회차에는 UNIQUE 충돌로 더 이상 '신규'가 아니라서 조회 대상에서 빠지기 때문이다.
    실측(2026-09-17): 메일 Secrets 미설정 상태로 10일 돌면서 18건이 이 경로로 유실됐다.
    DB에 notified=0으로 남아 있었지만 그 값을 읽는 코드가 없었다.

    발송 성공으로 mark_notified 하기 전까지 notified=0으로 남는 것, 그 자체가 큐다.
    별도 큐 테이블을 두지 않는 이유는 두 곳이 어긋날 여지를 만들지 않기 위해서다.
    """
    return conn.execute(
        "SELECT * FROM advisories WHERE notified=0 ORDER BY source, id LIMIT ?",
        (limit,)).fetchall()


def pending_count(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COUNT(*) FROM advisories WHERE notified=0").fetchone()[0]


# ---------------------------------------------------------------- CLI

def print_rows(rows) -> None:
    for r in rows:
        cve = f" [{r['cves']}]" if r["cves"] else ""
        print(f"  - ({r['source']}) {r['title']}{cve}")
        print(f"    {r['url']}")


# 종료 코드 (모니터링/스케줄러가 $? 로 이상 감지)
EXIT_OK = 0
EXIT_SOURCE_ERROR = 3   # 소스 fetch/파싱/추출 오류 (일부 성공했을 수 있음)
EXIT_MAIL_FAILED = 4    # 보낼 것이 있으나 메일 발송 실패(설정됐는데 안 감)
EXIT_MAIL_UNCONFIGURED = 5  # 보낼 것이 있는데 메일 설정 자체가 없음 (--require-mail 일 때만)


def main() -> int:
    ap = argparse.ArgumentParser(description="KISA + Fortinet PSIRT 보안 권고문 수집기")
    ap.add_argument("--no-mail", action="store_true", help="알림 생략 (수집만)")
    ap.add_argument("--require-mail", action="store_true",
                    help="메일 미설정을 오류로 취급. 무인 실행(CI, cron)에서 켠다")
    ap.add_argument("--list", type=int, metavar="N", help="최근 N건 조회 후 종료")
    ap.add_argument("--pending", action="store_true", help="미발송 권고문 조회 후 종료")
    args = ap.parse_args()

    conn = get_conn()
    try:
        if args.list is not None:  # --list 0 도 "0건 조회"로 처리 (스캔 실행 방지)
            rows = conn.execute(
                "SELECT * FROM advisories ORDER BY id DESC LIMIT ?", (args.list,)).fetchall()
            print(f"=== 최근 수집 {len(rows)}건 ===")
            print_rows(rows)
            return EXIT_OK

        if args.pending:
            rows = pending(conn)
            total = pending_count(conn)
            print(f"=== 미발송 {total}건 (표시 {len(rows)}건) ===")
            print_rows(rows)
            return EXIT_OK

        first_run = conn.execute("SELECT COUNT(*) FROM advisories").fetchone()[0] == 0
        new_rows, errors = scan(conn)
        exit_code = EXIT_SOURCE_ERROR if errors else EXIT_OK
        if errors:
            print(f"[warn] 소스 오류 {len(errors)}건: " + " / ".join(errors))

        if first_run:
            # 첫 실행: 기존 공지 전체가 "신규"로 잡히므로 알림 없이 seed만
            mark_notified(conn, new_rows)
            print(f"[done] 첫 실행 seed 완료 — {len(new_rows)}건 적재 (알림 생략)")
            return exit_code

        rows = pending(conn)
        total_pending = pending_count(conn)
        if not rows:
            print("[done] 신규 권고문 없음")
            return exit_code

        backlog = total_pending - len(new_rows)
        head = f"[done] 발송 대상 {len(rows)}건 (이번 신규 {len(new_rows)}, 이월 {backlog})"
        if total_pending > len(rows):
            head += f", {total_pending - len(rows)}건은 다음 회차로"
        print(head + ":")
        print_rows(rows)

        if args.no_mail:
            return exit_code

        from notify import mail_status, send_new_advisories  # 지연 import
        sent = send_new_advisories(rows)
        if sent is True:
            mark_notified(conn, rows)
            print("[mail] 발송 완료")
        elif sent is None:
            # 콘솔 대체는 사람이 보고 있는 터미널에서만 대체다. 무인 실행에서 콘솔은
            # 버리는 곳이라, 여기를 성공으로 처리하면 매일 초록불을 켜면서 권고문을 흘린다.
            print(f"[mail] 미설정: {mail_status()}")
            if args.require_mail:
                print(f"[mail] --require-mail: 보낼 것이 {len(rows)}건인데 설정이 없다")
                if exit_code == EXIT_OK:
                    exit_code = EXIT_MAIL_UNCONFIGURED
            else:
                print("[mail] 콘솔 출력으로 대체 (위 목록)")
        else:  # False = 설정됐으나 실패
            print("[mail] 발송 실패")
        if sent is not True:
            print(f"[mail] {len(rows)}건은 미발송으로 남는다. 다음 회차에 다시 나간다")
            if sent is False and exit_code == EXIT_OK:
                exit_code = EXIT_MAIL_FAILED
        return exit_code
    finally:
        conn.close()


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # Windows cp949 콘솔 대비
    except Exception:
        pass
    sys.exit(main())
