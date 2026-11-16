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
