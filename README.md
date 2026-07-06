# advisory-watcher

KISA 보호나라 보안공지 + Fortinet PSIRT(IR Advisories) RSS를 정기 수집해 **새 권고문만** 알려주는 수집기. **표준 라이브러리만 사용 (의존성 0)**.

## 동작

```
RSS fetch (urllib, 재시도) → 파싱 (xml.etree) → SQLite UNIQUE 적재 → 신규만 메일/콘솔 알림
```

- **신규만 알림** — `UNIQUE(source, entry_id)`로 이미 본 항목은 조용히 스킵
- **첫 실행 = seed 모드** — 기존 공지 전체를 알림 없이 적재만 (알림 폭탄 방지)
- **CVE 자동 추출** — 제목/본문에서 `CVE-YYYY-NNNN` 정규식 추출해 함께 저장
- **소스 하나가 죽어도 계속** — 오류는 `scan_log`에 기록하고 나머지 소스 진행
- **메일 미설정 시 콘솔 출력으로 대체** — `.env` 없이도 동작

## 사용

```bash
python watcher.py            # 스캔 + 신규 알림
python watcher.py --no-mail  # 스캔만
python watcher.py --list 10  # 최근 수집분 조회
```

메일 알림(선택): `.env.example`을 `.env`로 복사해 Gmail 앱 비밀번호 설정.

### 종료 코드 (모니터링용)

스케줄러/헬스체크가 `$?`로 이상을 감지할 수 있도록 구분된 종료 코드를 반환한다:

| 코드 | 의미 |
|---|---|
| 0 | 정상 (신규 없음 또는 정상 처리·발송) |
| 3 | 소스 오류 — fetch/파싱 실패, 또는 **entry_id 추출 전건 실패**(링크 포맷 변경 등 무증상 실명 방지). 일부 소스는 성공했을 수 있음 |
| 4 | 신규 권고문은 있으나 메일 발송 실패(설정됐는데 안 감). `.env` 미설정(콘솔 대체)은 오류 아님(0) |

## 정기 실행

```bash
# Linux cron — 매일 09:00
0 9 * * * cd /path/to/advisory-watcher && python watcher.py >> data/cron.log 2>&1
```

```powershell
# Windows 작업 스케줄러
schtasks /Create /TN advisory-watcher /SC DAILY /ST 09:00 `
  /TR "python C:\path\to\advisory-watcher\watcher.py"
```

## 구조

```
watcher.py      # fetch → parse → 적재 → 알림 오케스트레이션 + CLI
notify.py       # Gmail SMTP (STARTTLS 587), plain+HTML 듀얼
data/           # advisories.db (자동 생성, 커밋 제외)
.env.example    # 메일 설정 템플릿
```

| 테이블 | 역할 |
|---|---|
| `advisories` | 권고문 (source, entry_id UNIQUE, title, url, published, cves, notified) |
| `scan_log` | 실행 이력 (소스별 fetched/new/**skipped**/error) — skipped>0이면 고유 ID를 못 뽑은 항목 수(추출 로직 점검 신호) |

## 소스 추가

`watcher.py`의 `SOURCES`에 항목 추가 — RSS URL과 "항목에서 고유 ID를 뽑는 방법"만 정의하면 된다:

```python
"NEWSRC": {
    "name": "표시 이름",
    "rss": "https://example.com/feed.xml",
    "entry_id": lambda item: item.get("link", ""),  # 고유 ID 추출 규칙
},
```

## 소스 메모

- KISA 보호나라 보안공지: `https://www.boho.or.kr/kr/rss.do?bbsId=B0000133` (항목 10건 노출, 고유 ID = `nttId`)
- Fortinet PSIRT: `https://filestore.fortinet.com/fortiguard/rss/ir.xml` (항목 50건 노출, 고유 ID = `FG-IR-YY-NNN`)
- RSS 노출 개수가 제한적이므로 **하루 1회 이상** 돌려야 누락이 없다 (KISA는 하루 수 건 게시).
