# DKISchool Axum API

Unofficial API for the public static reconstruction at `https://dogebi.github.io/dkischool-remake/`. This service is not operated or endorsed by the school and uses no real school account or records.

## Deploy on Vercel

Import this repository into Vercel with the project root set to `api`. Install a Neon Postgres integration from the Vercel Marketplace and connect it to the project. The free plan is sufficient to start. The service initializes its tables and generic sample notices on first request.

Set these Vercel environment variables for Production:

| Variable | Value |
| --- | --- |
| `FRONTEND_ORIGIN` | `https://dogebi.github.io` |
| `COOKIE_SECURE` | `true` |
| `COOKIE_SAME_SITE` | `None` |
| `ADMIN_USERNAME` | Chosen administrator username |
| `ADMIN_PASSWORD` | A unique password of at least 12 characters |
| `DATABASE_URL` | Injected by the Neon integration |

Do not add passwords or database credentials to Git. Deploy, then verify `/api/health` returns `{"status":"ok","service":"dkischool-api"}`.

The GitHub Pages project must set the repository Actions variable `VITE_API_BASE_URL` to the Vercel HTTPS origin, then run its Pages workflow again.

## Local build

```sh
cargo check --manifest-path Cargo.toml
```

## 배포 검증

- GET /api/health는 서비스 응답을, GET /api/ready는 DB 연결 상태를 확인합니다.
- 관리자 변경 요청의 Origin은 FRONTEND_ORIGIN과 일치해야 합니다. 운영 환경의 자동 자료 이관에도 같은 값을 사용하세요.
- PostgreSQL 통합 테스트는 빈 테스트 DB의 DATABASE_URL, FRONTEND_ORIGIN, ADMIN_USERNAME, ADMIN_PASSWORD, COOKIE_SAME_SITE=Lax를 설정한 뒤 cargo test --locked postgres_http_regressions -- --ignored로 실행합니다. 기존 스키마 업그레이드를 재현하려면 별도 빈 DB에서 DKIS_TEST_UPGRADE=1로 실행하세요.
