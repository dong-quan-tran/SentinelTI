# SentinelTI frontend

This Vite/React application is deployed from this directory. In Vercel, set
the project **Root Directory** to `sentinelti/frontend`; the build command is
`npm run build` and the output directory is `dist`.

## Local development

From this directory:

```bash
npm ci
npm run dev
```

The development server proxies `/api` requests to the local FastAPI service at
`http://127.0.0.1:8000`. Set `SENTINELTI_API_KEY` in the Vite server process
when the API requires a key; never expose it through a `VITE_` variable.

Run frontend checks with:

```bash
npm run lint
npm run test -- --run
npm run build
```

See the root [README](../../README.md) for project usage and the
[deployment guide](../../docs/VERCEL_RENDER_DEPLOYMENT.md) for Vercel and
Render configuration.
