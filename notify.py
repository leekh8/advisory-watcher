"""
advisory-watcher 메일 알림 — Gmail SMTP (STARTTLS 587), plain+HTML 듀얼.

설정은 프로젝트 루트 .env 파일 (없으면 발송 생략하고 False 반환):
    GMAIL_USER=you@gmail.com
    GMAIL_APP_PASSWORD=xxxxxxxxxxxxxxxx   # Google 계정 > 앱 비밀번호
    MAIL_TO=you@gmail.com                 # 콤마 구분 다중 수신 가능
"""
from __future__ import annotations

import html
import smtplib
import ssl
from email.message import EmailMessage
from pathlib import Path

ENV_PATH = Path(__file__).parent / ".env"


def _load_env() -> dict:
    env = {}
    if ENV_PATH.exists():
        for line in ENV_PATH.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.split("#")[0].strip()
    return env


def _build(rows, user: str, to: str) -> EmailMessage:
    msg = EmailMessage()
    msg["Subject"] = f"[advisory-watcher] 신규 보안 권고문 {len(rows)}건"
    msg["From"] = user
    msg["To"] = to

    plain_lines = []
    html_rows = []
    for r in rows:
        cve = f" [{r['cves']}]" if r["cves"] else ""
        plain_lines.append(f"- ({r['source']}) {r['title']}{cve}\n  {r['url']}")
        html_rows.append(
            "<tr>"
            f"<td style='padding:6px 10px;white-space:nowrap'><b>{html.escape(r['source'])}</b></td>"
            f"<td style='padding:6px 10px'><a href='{html.escape(r['url'], quote=True)}'>"
            f"{html.escape(r['title'])}</a>"
            + (f"<br><small>{html.escape(r['cves'])}</small>" if r["cves"] else "")
            + "</td>"
            f"<td style='padding:6px 10px;white-space:nowrap'>{html.escape(r['published'] or '')}</td>"
            "</tr>")

    msg.set_content("신규 보안 권고문 {}건\n\n{}".format(len(rows), "\n".join(plain_lines)))
    msg.add_alternative(f"""\
<html><body style="font-family:'Segoe UI','Malgun Gothic',sans-serif">
<h3>신규 보안 권고문 {len(rows)}건</h3>
<table style="border-collapse:collapse;font-size:14px" border="1" bordercolor="#ddd">
<tr style="background:#f1f5f9"><th style="padding:6px 10px">출처</th>
<th style="padding:6px 10px">제목</th><th style="padding:6px 10px">게시일</th></tr>
{''.join(html_rows)}
</table>
<p style="color:#888;font-size:12px">advisory-watcher — KISA 보호나라 + Fortinet PSIRT RSS 수집기</p>
</body></html>""", subtype="html")
    return msg


def send_new_advisories(rows) -> bool:
    """신규 권고문 알림 발송. 설정이 없거나 실패하면 False (발송 안 됨)."""
    env = _load_env()
    user = env.get("GMAIL_USER")
    password = env.get("GMAIL_APP_PASSWORD")
    to = env.get("MAIL_TO") or user
    if not user or not password:
        return False
    try:
        msg = _build(rows, user, to)
        ctx = ssl.create_default_context()
        with smtplib.SMTP("smtp.gmail.com", 587, timeout=30) as s:
            s.ehlo()
            s.starttls(context=ctx)
            s.ehlo()
            s.login(user, password)
            s.send_message(msg)
        return True
    except Exception as e:
        print(f"[mail] 발송 실패: {e}")
        return False
