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
- **발송 실패분은 큐에 남아 다음 회차에 재시도**. 놓친 권고문이 사라지지 않는다
- **무인 실행에서는 메일 미설정이 오류**(`--require-mail`). 콘솔 대체는 사람이 볼 때만 대체다

## 사용

```bash
python watcher.py                # 스캔 + 알림 (첫 실행은 seed, 알림 없음)
python watcher.py --no-mail      # 스캔만
python watcher.py --list 10      # 최근 수집분 조회
python watcher.py --pending      # 아직 못 보낸 권고문 조회
python watcher.py --require-mail # 무인 실행. 메일 미설정을 오류 취급
```

메일 알림: `.env.example`을 `.env`로 복사해 Gmail 앱 비밀번호 설정.

### 미발송 큐

알림 대상은 "이번에 새로 수집한 것"이 아니라 **아직 못 보낸 것 전부**다
(`advisories.notified = 0`). 발송에 성공해야만 큐에서 빠진다.

이렇게 두는 이유는 실측된 사고 때문이다. 예전에는 이번 실행에서 INSERT된 행만
알렸는데, 발송이 안 된 회차의 권고문은 다음 회차에 UNIQUE 충돌로 "신규"가 아니게
되어 조회 대상에서 빠졌다. 2026-09-17 기준으로 메일 설정이 없는 CI가 10일간
초록불을 켜는 동안 권고문 18건이 그 경로로 사라졌다.

한 번에 보내는 상한은 200건(`MAX_PENDING`)이고, 초과분은 다음 회차로 이월한다.
오래 끊겼다 복구될 때 수백 건짜리 메일 한 통이 되는 것을 막기 위해서다.

테스트:

```bash
python -m unittest discover -s tests -v
```

### 종료 코드 (모니터링용)

스케줄러/헬스체크가 `$?`로 이상을 감지할 수 있도록 구분된 종료 코드를 반환한다:

| 코드 | 의미 |
|---|---|
| 0 | 정상 (신규 없음 또는 정상 처리·발송) |
| 3 | 소스 오류 — fetch/파싱 실패, 또는 **entry_id 추출 전건 실패**(링크 포맷 변경 등 무증상 실명 방지). 일부 소스는 성공했을 수 있음 |
| 4 | 보낼 권고문이 있으나 메일 발송 실패(설정은 됐는데 안 감). 해당 건은 큐에 남아 다음 회차에 재시도 |
| 5 | 보낼 권고문이 있는데 **메일 설정 자체가 없음**. `--require-mail`일 때만 나온다. 손으로 돌릴 때는 콘솔 출력으로 충분하므로 0 |

무인 실행(CI, cron)에서는 `--require-mail`을 켠다. 콘솔 출력은 사람이 보고 있을 때만
알림이고, 아무도 안 보는 로그로 흘리면서 초록불을 켜는 것이 가장 나쁜 실패 모양이다.

## 정기 실행

```bash
# Linux cron — 매일 09:00
0 9 * * * cd /path/to/advisory-watcher && python watcher.py --require-mail >> data/cron.log 2>&1
```

```powershell
# Windows 작업 스케줄러
schtasks /Create /TN advisory-watcher /SC DAILY /ST 09:00 `
  /TR "python C:\path\to\advisory-watcher\watcher.py --require-mail"
```

### GitHub Actions (사실상 주 실행기)

`.github/workflows/watch.yml` 가 매일 00:23 UTC(09:23 KST)에 돌린다. 정각을 피한 이유는
공식 문서가 "High load times include the start of every hour", "some queued jobs
may be dropped" 라고 적어 둔 기 낮추기 끔이다. DB 는 Actions 추어(cache)에 든다.

새로 포후하는 것은 이것이 아니라 아래 함정이다.

> 🛑 **공개 저장소의 예약 워크흐로는 60일 무활동으로 자동 중단된다.**
> 공식 문서: "In a public repository, scheduled workflows are automatically
> disabled when no repository activity has occurred in 60 days."
>
> 실제로 이 저장소가 걸렸다. 마지리 커밋이 2026-08-20 이었고, 마지리 실행이
> 10-20 이고, 11-10 에 보니 `disabled_inactivity` 였다. **21일간 수집이 0 이었다.**
> 이번엔 에러도 빨간불도 없었다. 생기는 일 자신이 없었기 때문이다.
>
> 다시 컰는 법은 둘이다. 그낥 커밋은 재활성화 조건이 아니다.
> - **cron 값을 바꾸는 커밋** -- "if a user with write permissions to the
>   repository makes a commit that changes the `cron` schedule on the workflow,
>   the workflow will be reactivated"
> - Actions 화면에서 Enable workflow, 또는 `gh workflow enable "Advisory watch"`
>
> 점검은 `gh workflow list --all` 에 `active` 가 찍힐는가로 한다.

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
