"""미발송 큐 회귀 테스트.

이 파일이 지키는 것은 하나다. 발송에 실패한 권고문이 다음 회차에 다시 나오는가.
실패했던 구조는 '이번 실행에서 INSERT된 행만 알린다'였고, 그래서 메일이 안 나간
회차의 권고문이 영구히 사라졌다(2026-09-17 실측 18건).

표준 라이브러리만 쓴다. 이 저장소는 의존성 0을 유지한다.
    python -m unittest discover -s tests -v
"""
import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import watcher  # noqa: E402


def insert(conn, source, entry_id, title="t", url="https://example.com", cves=None):
    cur = conn.execute(
        "INSERT INTO advisories (source, entry_id, title, url, published, cves)"
        " VALUES (?,?,?,?,?,?)",
        (source, entry_id, title, url, "2026-09-17", cves))
    conn.commit()
    return cur.lastrowid


class PendingQueueTest(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.conn = watcher.get_conn(Path(self.tmp.name) / "t.db")

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def test_새로_적재된_행은_미발송으로_잡힌다(self):
        insert(self.conn, "KISA", "1")
        self.assertEqual(len(watcher.pending(self.conn)), 1)
        self.assertEqual(watcher.pending_count(self.conn), 1)

    def test_발송_표시한_행은_빠진다(self):
        insert(self.conn, "KISA", "1")
        watcher.mark_notified(self.conn, watcher.pending(self.conn))
        self.assertEqual(watcher.pending(self.conn), [])
        self.assertEqual(watcher.pending_count(self.conn), 0)

    def test_발송_실패분은_다음_회차에_다시_나온다(self):
        # 1회차: 2건 적재, 메일 실패 -> mark_notified 호출 안 함
        insert(self.conn, "KISA", "1")
        insert(self.conn, "KISA", "2")
        self.assertEqual(len(watcher.pending(self.conn)), 2)

        # 2회차: 신규 1건뿐이지만 큐에는 이월 2건이 함께 있어야 한다.
        # 옛 구조는 여기서 1건만 보고 앞의 2건을 영원히 버렸다.
        insert(self.conn, "FORTINET", "FG-IR-26-001")
        rows = watcher.pending(self.conn)
        self.assertEqual(len(rows), 3)
        self.assertEqual({r["entry_id"] for r in rows}, {"1", "2", "FG-IR-26-001"})

    def test_이미_보낸_건은_이월에_섞이지_않는다(self):
        a = insert(self.conn, "KISA", "1")
        insert(self.conn, "KISA", "2")
        self.conn.execute("UPDATE advisories SET notified=1 WHERE id=?", (a,))
        self.conn.commit()
        rows = watcher.pending(self.conn)
        self.assertEqual([r["entry_id"] for r in rows], ["2"])

    def test_한_번에_보내는_건수에_상한이_있다(self):
        for i in range(5):
            insert(self.conn, "KISA", str(i))
        rows = watcher.pending(self.conn, limit=3)
        self.assertEqual(len(rows), 3)
        # 상한에 걸린 나머지는 큐에 남는다. 총량은 따로 셀 수 있어야 보고가 정확하다.
        self.assertEqual(watcher.pending_count(self.conn), 5)

    def test_상한에_걸려도_순서가_고정이라_누락이_안_생긴다(self):
        for i in range(4):
            insert(self.conn, "KISA", "k%d" % i)
        first = [r["entry_id"] for r in watcher.pending(self.conn, limit=2)]
        watcher.mark_notified(self.conn, watcher.pending(self.conn, limit=2))
        second = [r["entry_id"] for r in watcher.pending(self.conn, limit=2)]
        self.assertEqual(first, ["k0", "k1"])
        self.assertEqual(second, ["k2", "k3"])  # 겹치지도 건너뛰지도 않는다

    def test_UNIQUE_충돌_후에도_큐에_남아있다(self):
        # 유실의 실제 경로 재현: 같은 권고문이 다음 회차에 다시 fetch되면
        # INSERT는 충돌로 무시된다. 그때도 앞서 적재된 행이 큐에 있어야 한다.
        import sqlite3
        insert(self.conn, "KISA", "dup")
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute(
                "INSERT INTO advisories (source, entry_id, title, url) VALUES (?,?,?,?)",
                ("KISA", "dup", "t", "u"))
        self.conn.rollback()
        self.assertEqual(len(watcher.pending(self.conn)), 1)


class ExitCodeTest(unittest.TestCase):

    def test_종료코드가_서로_다르다(self):
        codes = [watcher.EXIT_OK, watcher.EXIT_SOURCE_ERROR,
                 watcher.EXIT_MAIL_FAILED, watcher.EXIT_MAIL_UNCONFIGURED]
        self.assertEqual(len(set(codes)), len(codes))
        self.assertEqual(watcher.EXIT_OK, 0)


class MailStatusTest(unittest.TestCase):
    """미설정의 원인을 구분하는지. 틀린 진단이 로그에 10일간 남았던 자리다."""

    def setUp(self):
        import notify
        self.notify = notify
        self.saved = notify.ENV_PATH
        self.tmp = tempfile.TemporaryDirectory()
        notify.ENV_PATH = Path(self.tmp.name) / ".env"

    def tearDown(self):
        self.notify.ENV_PATH = self.saved
        self.tmp.cleanup()

    def test_파일이_없으면_없다고_말한다(self):
        self.assertIn("파일 없음", self.notify.mail_status())

    def test_파일은_있고_값이_비면_그렇게_말한다(self):
        self.notify.ENV_PATH.write_text(
            "GMAIL_USER=\nGMAIL_APP_PASSWORD=\nMAIL_TO=\n", encoding="utf-8")
        msg = self.notify.mail_status()
        self.assertIn("값이 빔", msg)
        self.assertIn("GMAIL_USER", msg)
        self.assertIn("GMAIL_APP_PASSWORD", msg)

    def test_다_채워지면_설정됨(self):
        self.notify.ENV_PATH.write_text(
            "GMAIL_USER=a@b.com\nGMAIL_APP_PASSWORD=pw\nMAIL_TO=a@b.com\n", encoding="utf-8")
        self.assertEqual(self.notify.mail_status(), "설정됨")


class SeedGateTest(unittest.TestCase):
    """DB가 비었을 때 알림을 생략하는 조건.

    🛑 "비었다"는 "첫 실행이다"가 아니다. 상태를 잃은 것도 비어 보인다.

    2026-11-10 실측. GitHub Actions 캐시는 일정 기간 쓰이지 않으면 지워진다.
    예약이 10-20 에 멈춘 뒤 캐시가 사라졌고, 되살린 첫 실행이
    "Cache not found for input keys: advisory-db-" 로 빈 DB를 받았다.
    그때 seed 분기가 권고문 60건을 "이미 알림"으로 찍어 21일분이 사라졌다.

    예약이 멈춘 것은 눈에 보였지만, 되살아난 실행이 삼킨 것은 안 보였다.
    그래서 seed 는 --seed 를 줄 때만 한다.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "t.db"
        self._argv = sys.argv
        self._scan = watcher.scan
        self._get_conn = watcher.get_conn
        watcher.get_conn = lambda *a, **k: self._get_conn(self.db)

    def tearDown(self):
        sys.argv = self._argv
        watcher.scan = self._scan
        watcher.get_conn = self._get_conn
        self.tmp.cleanup()

    def _run(self, *args):
        def fake_scan(conn):
            rows = []
            for i in range(3):
                rid = insert(conn, "KISA", f"e{i}")
                rows.append(conn.execute(
                    "SELECT * FROM advisories WHERE id=?", (rid,)).fetchone())
            return rows, []

        watcher.scan = fake_scan
        sys.argv = ["watcher.py", "--no-mail", *args]
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = watcher.main()
        return code, buf.getvalue()

    def _pending(self):
        conn = self._get_conn(self.db)
        try:
            return watcher.pending_count(conn)
        finally:
            conn.close()

    def test_seed_를_주면_알림_없이_적재한다(self):
        code, out = self._run("--seed")
        self.assertEqual(code, watcher.EXIT_OK)
        self.assertEqual(self._pending(), 0)
        self.assertIn("seed 완료", out)

    def test_seed_없이_빈_DB면_전부_미발송으로_남는다(self):
        code, out = self._run()
        self.assertEqual(code, watcher.EXIT_OK)
        self.assertEqual(self._pending(), 3, "빈 DB를 첫 실행으로 읽어 삼켰다")

    def test_상태를_잃었을_수_있다고_경고한다(self):
        _, out = self._run()
        self.assertIn("DB가 비어 있었다", out)
        self.assertIn("--seed", out)

    def test_빈_DB가_아니면_seed_를_줘도_삼키지_않는다(self):
        conn = self._get_conn(self.db)
        insert(conn, "KISA", "old")
        watcher.mark_notified(conn, watcher.pending(conn))
        conn.close()
        code, _ = self._run("--seed")
        self.assertEqual(code, watcher.EXIT_OK)
        self.assertEqual(self._pending(), 3, "비지 않은 DB에 seed 가 먹었다")


if __name__ == "__main__":
    unittest.main()
