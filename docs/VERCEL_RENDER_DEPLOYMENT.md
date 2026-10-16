# Vercel + Render deployment

SentinelTI can be hosted as a Vercel frontend with a Render FastAPI service.
The browser calls a same-origin Vercel function, which forwards approved API
routes to Render using a server-only API key. The key must never be placed in a
`VITE_` variable or shipped in frontend assets.

## Configure the services

1. Create the Render service from the repository's `render.yaml` blueprint.
   Confirm its health check is `https://<render-service>/health/ready` and wait
   for it to report healthy.
2. Copy the generated `SENTINELTI_API_KEY` from the Render service environment.
3. Create the Vercel project with `sentinelti/frontend` as its **Root
   Directory**. Keep the configured build command (`npm run build`) and output
   directory (`dist`).
4. Configure these Vercel **server-side** environment variables for Preview and
   Production:
   - `SENTINELTI_RENDER_API_URL`: the Render service origin, e.g.
     `https://sentinelti-api.onrender.com` (no path or trailing endpoint).
   - `SENTINELTI_RENDER_API_KEY`: the exact generated Render
     `SENTINELTI_API_KEY` value.
5. Redeploy Vercel after changing either variable. Never expose these values as
   frontend build variables, and do not enable a public Render endpoint without
   its API key.

The gateway deliberately allows only the API routes it needs and forwards no
browser-supplied API key. Its HTTPS-only upstream check prevents accidentally
sending the Render credential over cleartext HTTP. The local Vite proxy is a
development convenience only; set `SENTINELTI_API_KEY` in the Vite server
process when using it.

## Abuse controls: public launch gate

The FastAPI rate limiter is process-local and is only a fallback. Render's
blueprint value of 600 requests per 60 seconds is not a per-user public abuse
limit, and it does not coordinate across service instances. The Vercel gateway
also has no application-level per-user limiter.

**Keep production behind Vercel Deployment Protection until an edge
rate-limit rule is configured and verified.** In the Vercel project:

1. For restricted Preview testing, enable Deployment Protection and allow only
   approved testers. Do not turn on unrestricted production access as a
   substitute for rate limiting.
2. Open **Firewall → Configure → New Rule** and create a **Rate Limit** rule
   matching the `/api/` path prefix. Use the **Fixed Window** strategy, **10
   requests per 60 seconds per IP**, and the default **429** action as an
   initial conservative limit. This covers all gateway routes, including
   scoring, explanations, model metadata, and AI explanations.
3. Review and publish the rule. Check the Firewall traffic view to confirm the
   rule is matching the expected `/api/` requests.
4. Exercise the public Preview endpoint: requests within the limit should
   succeed; requests beyond it should be blocked with 429. Repeat from a
   second IP/network to confirm counters are per source rather than global.
5. Keep Deployment Protection enabled until this test succeeds. Only then may
   production be made public. If the rule cannot be configured or the block
   behavior cannot be verified, keep access restricted.

Vercel WAF rate-limit counters are regional, so clients reaching multiple
regions may exceed the configured limit. Treat 10 requests per minute as a
starter ceiling, not a guaranteed global cap; watch Firewall traffic and
service load before relaxing it. Batch requests can score up to 25 URLs each.
If abuse or cost requires tighter controls, lower the limit or add narrower
route rules where the Vercel plan permits. Do not rely on CORS, the hidden API
key, or Render's process-local limiter as a substitute.

Vercel currently documents rate-limit configuration through the project
Firewall controls. The `vercel.json` WAF `routes` configuration supports
challenge and deny actions, but not rate-limit actions; adding a rule there
does not satisfy this launch gate.

Use an always-on Render instance for a public service. A sleeping instance may
take longer to wake than the gateway's 10-second upstream timeout.

## Pre-launch verification

Run the repository checks before deployment:

```powershell
.venv\Scripts\python.exe -m pytest
Set-Location sentinelti\frontend
npm run lint
npm run test -- --run
npm run build
```

After deploying a restricted Preview, verify all of the following:

- `GET https://<render-service>/health/ready` returns 200 and
  `{"status":"ready","checks":{"model":"available"}}`.
- The Preview can score a benign test URL and a known phishing test fixture;
  the UI labels remain experimental signals, not a safety guarantee.
- An unsupported `/api/...` path returns 404, an unsupported method returns
  405, and an oversized or invalid request is rejected before forwarding.
- Browser developer tools and built assets contain neither API key nor direct
  Render API URL. The browser should call only the same-origin `/api` path.
- Requests without configured Vercel environment variables fail closed with
  503; an unreachable Render service yields a generic gateway error.
- The Vercel edge rate-limit rule has been exercised and its behavior recorded
  before removing Preview access protection.

Do not treat Render `/health/ready` alone as proof that scoring works; it checks
that model metadata and the artifact can load, not complete end-to-end scoring.

## Data and rollback

SentinelTI processes submitted URLs to score them and does not need to persist
them for scoring. Users should not submit URLs containing credentials,
session tokens, or other private data. Review Vercel and Render logging,
retention, privacy, and access settings before launch; this application-level
statement does not describe or override provider retention.

Keep the previous Vercel deployment available for rollback. If the new
deployment fails readiness, scoring, or rate-limit verification, restore the
previous frontend deployment and disable public access to the new endpoint
until the issue is resolved. Rotate the Render API key in both services if it
is exposed, and redeploy both services after rotation.
