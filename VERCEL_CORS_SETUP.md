# PromptShield Vercel CORS Setup

The production backend must allow the published Chrome extension origin exactly.

Published extension origin:

- chrome-extension://ppoigpencblphlaijhlfiaajmoaleinl

Set these Vercel environment variables for the backend project:

```text
GROQ_API_KEY=<your real key>
APP_ENV=production
CORS_ORIGINS=["http://localhost:5173","chrome-extension://ppoigpencblphlaijhlfiaajmoaleinl"]
PROMPTSHIELD_EXTENSION_ID=ppoigpencblphlaijhlfiaajmoaleinl
RATE_LIMIT=10/minute
MAX_CODE_SIZE_KB=500
```

Why this matters:

- The API is live and can process requests.
- Chrome blocks the extension request unless the response includes Access-Control-Allow-Origin for the extension origin.
- FastAPI CORSMiddleware only matches exact origins when credentials are enabled.
- `chrome-extension://*` does not work as an exact origin allowlist entry.

After updating Vercel:

1. Redeploy the backend.
2. Verify preflight/POST responses include `Access-Control-Allow-Origin: chrome-extension://ppoigpencblphlaijhlfiaajmoaleinl`.
3. Reload the Chrome extension and test again.
