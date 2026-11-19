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

## 백엔드 모듈과 배포 확인

- api/axum.rs는 Vercel 진입점과 공개·관리자 라우터 조합을 담당합니다. src/auth.rs, src/notices.rs, src/school.rs, src/search.rs에서 각 기능의 경로와 구현을 관리합니다.
- 관리자 기능 라우터에는 세션 미들웨어가 일괄 적용됩니다. 로그인·로그아웃은 같은 Origin 검사 범위에서 세션 없이 접근할 수 있습니다.
- 운영 배포 후 GitHub의 소스 커밋과 Vercel 배포를 대조하고 /api/health, /api/ready 및 비로그인 관리자 API 응답을 확인합니다. 초기화 로그에는 적용한 최신 마이그레이션 버전과 DB 연결·초기화 시간이 기록됩니다.
