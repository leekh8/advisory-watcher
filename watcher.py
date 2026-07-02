"""
advisory-watcher — KISA 보호나라 + Fortinet PSIRT 보안 권고문 수집기.

표준 라이브러리만 사용(의존성 0). RSS를 정기 fetch해서 새 권고문만
SQLite에 적재하고 알림(메일 또는 콘솔)을 보낸다.

사용:
    python watcher.py            # 스캔 + 신규 알림 (첫 실행은 seed 모드 — 알림 없음)
    python watcher.py --no-mail  # 스캔만 (알림 생략)
    python watcher.py --list 10  # 최근 수집분 조회
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
        # 고유 ID = 링크 끝의 FG-IR-YY-NNN
        "entry_id": lambda item: item.get("link", "").rstrip("/").rsplit("/", 1)[-1],
    },
}


# ---------------------------------------------------------------- HTTP

def fetch(url: str) -> str | None:
    """RSS 텍스트를 가져온다. 404=None, 4xx=즉시 예외, 5xx/네트워크=재시도."""
    last: Exception | None = None
    for attempt in range(1, HTTP_RETRIES + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as res:
                return res.read().decode("utf-8", errors="replace")
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

def parse_rss(xml_text: str) -> list[dict]:
    """RSS 2.0 → [{title, link, pubDate, description}] (공백 정돈)."""
    channel = ET.fromstring(xml_text).find("channel")
    if channel is None:
        return []
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

def get_conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
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
        error   TEXT
    );
    """)
    return conn


# ---------------------------------------------------------------- 스캔

def scan(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    """모든 소스를 fetch해서 신규 권고문 행 목록을 반환한다."""
    new_ids: list[int] = []
    for key, src in SOURCES.items():
        fetched = new = 0
        error = None
        try:
            xml_text = fetch(src["rss"])
            if xml_text is None:
                error = "404 (피드 위치 변경?)"
            else:
                for entry in parse_rss(xml_text):
                    entry_id = src["entry_id"](entry)
                    if not entry_id:
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
        except Exception as e:  # 소스 하나가 죽어도 나머지는 계속
            error = str(e)
        conn.execute("INSERT INTO scan_log (source, fetched, new, error) VALUES (?,?,?,?)",
                     (key, fetched, new, error))
        status = f"error={error}" if error else "ok"
        print(f"[scan] {key}: fetched={fetched} new={new} {status}")
    conn.commit()
    if not new_ids:
        return []
    marks = ",".join("?" * len(new_ids))
    return conn.execute(
        f"SELECT * FROM advisories WHERE id IN ({marks}) ORDER BY source, id", new_ids).fetchall()


def mark_notified(conn: sqlite3.Connection, rows: list[sqlite3.Row]) -> None:
    conn.executemany("UPDATE advisories SET notified=1 WHERE id=?", [(r["id"],) for r in rows])
    conn.commit()


# ---------------------------------------------------------------- CLI

def print_rows(rows) -> None:
    for r in rows:
        cve = f" [{r['cves']}]" if r["cves"] else ""
        print(f"  - ({r['source']}) {r['title']}{cve}")
        print(f"    {r['url']}")


def main() -> int:
    ap = argparse.ArgumentParser(description="KISA + Fortinet PSIRT 보안 권고문 수집기")
    ap.add_argument("--no-mail", action="store_true", help="알림 생략 (수집만)")
    ap.add_argument("--list", type=int, metavar="N", help="최근 N건 조회 후 종료")
    args = ap.parse_args()

    conn = get_conn()
    try:
        if args.list:
            rows = conn.execute(
                "SELECT * FROM advisories ORDER BY id DESC LIMIT ?", (args.list,)).fetchall()
            print(f"=== 최근 수집 {len(rows)}건 ===")
            print_rows(rows)
            return 0

        first_run = conn.execute("SELECT COUNT(*) FROM advisories").fetchone()[0] == 0
        new_rows = scan(conn)

        if not new_rows:
            print("[done] 신규 권고문 없음")
            return 0

        if first_run:
            # 첫 실행: 기존 공지 전체가 "신규"로 잡히므로 알림 없이 seed만
            mark_notified(conn, new_rows)
            print(f"[done] 첫 실행 seed 완료 — {len(new_rows)}건 적재 (알림 생략)")
            return 0

        print(f"[done] 신규 권고문 {len(new_rows)}건:")
        print_rows(new_rows)

        if args.no_mail:
            return 0

        from notify import send_new_advisories  # 지연 import — --list 등에선 불필요
        if send_new_advisories(new_rows):
            mark_notified(conn, new_rows)
            print("[mail] 발송 완료")
        else:
            print("[mail] 미설정/실패 — 콘솔 출력으로 대체 (위 목록)")
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # Windows cp949 콘솔 대비
    except Exception:
        pass
    sys.exit(main())
