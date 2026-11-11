# advisory-watcher

KISA 보호나라 보안공지 + Fortinet PSIRT(IR Advisories) RSS를 정기 수집해 **새 권고문만** 알려주는 수집기. **표준 라이브러리만 사용 (의존성 0)**.

## 동작

```
RSS fetch (urllib, 재시도) → 파싱 (xml.etree) → SQLite UNIQUE 적재 → 신규만 메일/콘솔 알림
```

- **신규만 알림** — `UNIQUE(source, entry_id)`로 이미 본 항목은 조용히 스킵
- **seed 는 `--seed` 를 줄 때만** (첫 설치용). 빈 DB를 첫 실행으로 단정하지 않는다
- **CVE 자동 추출** — 제목/본문에서 `CVE-YYYY-NNNN` 정규식 추출해 함께 저장
- **소스 하나가 죽어도 계속** — 오류는 `scan_log`에 기록하고 나머지 소스 진행
- **발송 실패분은 큐에 남아 다음 회차에 재시도**. 놓친 권고문이 사라지지 않는다
- **무인 실행에서는 메일 미설정이 오류**(`--require-mail`). 콘솔 대체는 사람이 볼 때만 대체다

## 사용

```bash
python watcher.py                # 스캔 + 미발송 전부 알림
python watcher.py --no-mail      # 스캔만
python watcher.py --list 10      # 최근 수집분 조회
python watcher.py --pending      # 아직 못 보낸 권고문 조회
python watcher.py --require-mail # 무인 실행. 메일 미설정을 오류 취급
python watcher.py --seed         # 첫 설치. 수집분을 알림 없이 적재만
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

`.github/workflows/watch.yml` 가 매일 00:47 UTC(09:47 KST)에 돈다. 정각을 피한 이유는
공식 문서가 "High load times include the start of every hour", "some queued jobs
may be dropped" 라고 적어 둔 것이다. 늦어지는 데 그치지 않고 그날 회차가 아예 빠질 수
있다. 수집 DB 는 Actions 캐시에 둔다.

이 저장소를 두 번 조용히 죽인 함정이 둘 있다. 둘 다 아래에 적어 둔다.

> 🛑 **함정 1. 공개 저장소의 예약 워크플로는 60일 무활동으로 자동 중단된다.**
> 공식 문서: "In a public repository, scheduled workflows are automatically
> disabled when no repository activity has occurred in 60 days."
>
> 실제로 걸렸다. 마지막 커밋이 2026-08-20, 마지막 실행이 10-20 이었고 11-10 에 보니
> `disabled_inactivity` 였다. **21일간 수집이 0 이었다.** 에러도 빨간불도 없었다.
> 생기는 일 자체가 없었기 때문이다.
>
> 다시 켜는 법은 둘이다. 그냥 커밋은 재활성화 조건이 아니다.
> - **cron 값을 바꾸는 커밋**: "if a user with write permissions to the
>   repository makes a commit that changes the `cron` schedule on the workflow,
>   the workflow will be reactivated"
> - Actions 화면에서 Enable workflow, 또는 `gh workflow enable "Advisory watch"`
>
> 점검은 `gh workflow list --all` 에 `active` 가 찍히는가로 한다.

> 🛑 **함정 2. 캐시는 영구 저장소가 아니다. 상태를 잃으면 빈 DB로 시작한다.**
>
> 함정 1 로 예약이 멈춘 뒤 캐시도 쓰이지 않아 사라졌다. 11-10 에 되살린 첫 실행이
> `Cache not found for input keys: advisory-db-` 로 빈 DB를 받았다.
>
> 그때까지 코드는 "DB가 비었다"를 "첫 실행이다"로 읽어 seed 모드로 들어갔고,
> 수집한 60건을 알림 없이 `notified=1` 로 찍었다. **21일분이 메일 한 통 없이
> 사라졌다.** 예약이 멈춘 것은 눈에 보였지만 되살아난 실행이 삼킨 것은 안 보였다.
>
> 지금은 seed 를 `--seed` 로만 한다. 빈 DB를 만나면 전부 미발송으로 두고 경고를
> 찍는다. 알림 폭탄은 `MAX_PENDING`(200건)이 막으므로 seed 가 그 일을 겸할 이유가
> 없다. 진짜 첫 설치일 때만 수동 실행에서 `seed` 를 켠다.
>
> 상태를 캐시 밖(저장소 커밋 등)으로 옮기는 것이 다음 걸음이다. 지금은 캐시가
> 사라져도 **유실 대신 중복 알림**으로 끝난다는 선까지만 맞춰 뒀다.

> 🛑 **함정 3. `state=active` 는 「예약이 실제로 돈다」는 뜻이 아니다.**
>
> 11-10 에 cron 을 바꿔 `disabled_inactivity` 에서 `active` 로 되살렸는데,
> 11-11 의 예약이 **다섯 시간이 지나도 발화하지 않았다.** API 로 봐도
> workflow `state=active`, repo `archived=false`, `disabled=false` 였고 같은
> 커밋으로 돌린 수동 실행 2건은 둘 다 성공이었다. GitHub 이 그 회차를 그냥
> 돌리지 않았다. 공식 문서의 "some queued jobs may be dropped" 가 그 자리다.
>
> **점검은 `active` 가 아니라 「오늘 schedule 런이 있나」로 한다.**
>
> ```bash
> gh run list --limit 5 --json event,createdAt,conclusion
> ```
>
> `event` 에 `schedule` 이 보이는지 센다. `active` 만 보면 멈춘 것을 모른다.
> 함정 1 과 같은 실수를 한 겹 위에서 또 하는 꼴이다.

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
