# 🚀 PromptShield Backend - Vercel Deployment Guide

## 📋 Table of Contents

1. [Pre-Deployment Security Review](#security-review)
2. [Environment Setup](#environment-setup)
3. [Vercel Deployment Steps](#deployment-steps)
4. [Post-Deployment Verification](#verification)
5. [Troubleshooting](#troubleshooting)
6. [Production Optimization](#optimization)

---

## 🔒 Pre-Deployment Security Review

### ✅ Security Fixes Applied

**CRITICAL FIXES:**

1. ✅ **CORS Wildcard Removed** - No longer accepts any Chrome extension
   - Before: `allow_origin_regex=r"chrome-extension://[a-z]+"`
   - After: Only specific origins in `CORS_ORIGINS` environment variable
2. ✅ **Input Sanitization Added** - Scanner's own API now validates input
   - Path traversal prevention in filenames
   - Null byte and control character removal
   - Filename validation (alphanumeric + safe characters only)
3. ✅ **Request Validation Enhanced** - Pydantic models validate all inputs
   - Code size limit: 500KB
   - Filename length limit: 255 characters
   - Language allowlist: Python, JavaScript, TypeScript, JSX, TSX only

**SERVERLESS OPTIMIZATIONS:** 4. ✅ **In-Memory Cache Documented** - Added warnings about serverless limitations 5. ✅ **Logging Optimized** - Removed excessive `print()` statements 6. ✅ **Environment-Aware Logging** - Debug mode only in development 7. ✅ **Cold Start Optimization** - Lazy initialization of scanner

---

## ⚙️ Environment Setup

### Required Environment Variables

Create these in Vercel Dashboard → Project Settings → Environment Variables:

```bash
# REQUIRED - Get from https://console.groq.com/keys
GROQ_API_KEY=gsk_xxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# REQUIRED - Set to production
APP_ENV=production

# REQUIRED - Add your Chrome extension ID
# Format: ["http://localhost:5173","chrome-extension://YOUR-EXTENSION-ID-HERE"]
CORS_ORIGINS=["https://yourdomain.com","chrome-extension://abcdefghijklmnop"]

# OPTIONAL - Default values shown
RATE_LIMIT=10/minute
MAX_CODE_SIZE_KB=500
REQUEST_TIMEOUT=30

# Cache settings (NOTE: In-memory cache has limited effect in serverless)
CACHE_ENABLED=false
CACHE_TTL_SECONDS=300
```

### 🔑 How to Get Your Chrome Extension ID

1. Build your extension: `cd chrome-extension && npm run build`
2. Open Chrome → `chrome://extensions/`
3. Enable "Developer mode" (top right)
4. Click "Load unpacked" → Select `chrome-extension/dist` folder
5. Copy the Extension ID (looks like: `abcdefghijklmnopqrst`)
6. Update `CORS_ORIGINS` in Vercel with your extension ID

---

## 🚀 Deployment Steps

### Method 1: Deploy via Vercel CLI (Recommended)

```bash
# 1. Install Vercel CLI
npm install -g vercel

# 2. Navigate to backend folder
cd backend

# 3. Login to Vercel
vercel login

# 4. Deploy to production
vercel --prod

# 5. Set environment variables (do this ONCE)
vercel env add GROQ_API_KEY
# Paste your API key when prompted

vercel env add CORS_ORIGINS
# Paste: ["chrome-extension://YOUR-EXTENSION-ID"]

vercel env add APP_ENV
# Enter: production
```

### Method 2: Deploy via GitHub Integration

```bash
# 1. Push code to GitHub
git add backend/
git commit -m "Prepare backend for Vercel deployment"
git push origin main

# 2. Go to https://vercel.com/new
#    - Import your GitHub repository
#    - Root Directory: backend
#    - Framework Preset: Other
#    - Click "Deploy"

# 3. After deployment, add environment variables:
#    Project Settings → Environment Variables → Add
#    Add all variables listed in "Environment Setup" section
```

### Method 3: Deploy via Vercel Dashboard

```bash
# 1. Zip your backend folder
# 2. Go to https://vercel.com/new
# 3. Click "Upload" and select your zip file
# 4. Configure environment variables
# 5. Click "Deploy"
```

---

## ✅ Post-Deployment Verification

### 1. Health Check

```bash
# Test health endpoint
curl https://your-app.vercel.app/health

# Expected response:
{
  "status": "healthy",
  "groq_available": true,
  "version": "1.0.0"
}
```

### 2. API Scan Test

```bash
# Test scan endpoint
curl -X POST https://your-app.vercel.app/api/scan \
  -H "Content-Type: application/json" \
  -H "Origin: chrome-extension://YOUR-EXTENSION-ID" \
  -d '{
    "code": "def process(user_input):\n    prompt = f\"System: Be helpful\\nUser: {user_input}\"\n    return ai.generate(prompt)",
    "filename": "test.py",
    "language": "python"
  }'

# Expected: JSON response with vulnerabilities found
```

### 3. CORS Verification

```bash
# Test CORS headers
curl -X OPTIONS https://your-app.vercel.app/api/scan \
  -H "Origin: chrome-extension://YOUR-EXTENSION-ID" \
  -H "Access-Control-Request-Method: POST" \
  -v

# Expected: Access-Control-Allow-Origin header in response
```

### 4. Rate Limiting Test

```bash
# Send 12 requests rapidly (limit is 10/minute)
for i in {1..12}; do
  curl -X POST https://your-app.vercel.app/api/scan \
    -H "Content-Type: application/json" \
    -d '{"code":"test","filename":"test.py","language":"python"}' &
done

# Expected: 11th and 12th requests get 429 Too Many Requests
```

---

## 🎯 Update Chrome Extension

After deployment, update extension to use production API:

### File: `chrome-extension/src/utils/api.ts`

```typescript
const API_BASE_URL = "https://your-app.vercel.app"; //Change this to your Vercel URL

class APIClient {
  private baseURL = API_BASE_URL;
  // ... rest of code
}
```

### Rebuild Extension

```bash
cd chrome-extension
npm run build

# Reload extension in Chrome
# chrome://extensions/ → Click reload icon
```

---

## 🐛 Troubleshooting

### Issue: "GROQ_API_KEY environment variable not set"

**Solution:**

```bash
# Verify environment variable in Vercel
vercel env ls

# If missing, add it:
vercel env add GROQ_API_KEY

# Redeploy
vercel --prod
```

### Issue: CORS errors in Chrome extension

**Solution:**

1. Check your extension ID is correct
2. Update `CORS_ORIGINS` in Vercel environment variables
3. Format must be: `["chrome-extension://YOUR-ID"]` (with quotes and brackets)
4. Redeploy after changing environment variables

### Issue: "Function execution timeout" (30 seconds)

**Cause:** Groq API taking too long OR network issues

**Solution:**

- Check Groq API status: https://status.groq.com
- Reduce code size sent to API (current limit: 500KB)
- Check `REQUEST_TIMEOUT` environment variable

### Issue: Cache not working

**Expected:** In-memory cache has LIMITED effect in serverless environments

**Solution for Production:**
Use external cache like Vercel KV (Redis):

```bash
# Install Vercel KV
npm install @vercel/kv

# Update cache_service.py to use Vercel KV
# See: https://vercel.com/docs/storage/vercel-kv/quickstart
```

### Issue: "Module not found" errors

**Solution:**

```bash
# Verify requirements.txt is complete
cat requirements.txt

# Ensure all dependencies listed:
# fastapi, uvicorn, groq, pydantic, etc.

# Redeploy
vercel --prod
```

---

## ⚡ Production Optimization

### 1. Monitoring Setup

Add Vercel Analytics:

```bash
# In Vercel Dashboard
Project Settings → Analytics → Enable
```

Add Sentry Error Tracking:

```bash
# Install Sentry
pip install sentry-sdk

# In app/main.py
import sentry_sdk
sentry_sdk.init(dsn="YOUR-SENTRY-DSN")
```

### 2. Performance Optimization

**Current Cold Start Time:** ~2-3 seconds
**Optimizations Applied:**

- ✅ Lazy initialization of Groq client
- ✅ Minimal imports in main.py
- ✅ Removed excessive logging

**Further Optimizations:**

```python
# Use connection pooling (already implemented in groq_client.py)
# Reduce model token limits if faster response needed
# Cache pattern matching results
```

### 3. Cost Optimization

**Groq API Costs:**

- Free tier: 30 requests/minute
- Paid tier: $0.27 per 1M tokens

**Optimization:**

- Enable caching (client-side recommended for serverless)
- Limit code size (current: 500KB max)
- Use pattern matching first, LLM only when needed

### 4. Security Hardening

**Recommended Additional Measures:**

1. **API Key Rotation:**

```bash
# Rotate Groq API key monthly
# Update in Vercel: vercel env add GROQ_API_KEY
```

2. **IP Allowlist (Optional):**

```python
# In app/main.py, add IP middleware
from fastapi import Request, HTTPException

ALLOWED_IPS = ["1.2.3.4", "5.6.7.8"]  # Your IPs

@app.middleware("http")
async def ip_allowlist(request: Request, call_next):
    client_ip = request.client.host
    if client_ip not in ALLOWED_IPS:
        raise HTTPException(status_code=403, detail="Forbidden")
    return await call_next(request)
```

3. **Request Signing:**

```python
# Add HMAC signature validation
# Extension signs requests, backend verifies
```

---

## 📊 Production Checklist

### Pre-Deployment

- [ ] Environment variables set in Vercel
- [ ] CORS_ORIGINS includes actual extension ID
- [ ] GROQ_API_KEY is valid and has quota
- [ ] APP_ENV=production
- [ ] Code reviewed for security issues
- [ ] vercel.json configured correctly

### Post-Deployment

- [ ] Health check returns 200 OK
- [ ] Scan endpoint works with test code
- [ ] CORS headers correct for extension
- [ ] Rate limiting works (test 11+ requests)
- [ ] Extension updated with production URL
- [ ] Extension rebuilt and reloaded
- [ ] End-to-end test: Scan GitHub file
- [ ] Monitor Vercel logs for errors
- [ ] Check Groq API usage/quota

### Monitoring

- [ ] Vercel Analytics enabled
- [ ] Error tracking configured (Sentry)
- [ ] Set up alerts for 5xx errors
- [ ] Monitor Groq API rate limits
- [ ] Track cold start times
- [ ] Monitor function execution duration

---

## 🔗 Useful Links

- **Vercel Dashboard:** https://vercel.com/dashboard
- **Vercel CLI Docs:** https://vercel.com/docs/cli
- **Groq Console:** https://console.groq.com
- **Groq API Docs:** https://console.groq.com/docs
- **Vercel KV (Redis):** https://vercel.com/docs/storage/vercel-kv
- **FastAPI Docs:** https://fastapi.tiangolo.com

---

## 🆘 Support

**Issues with deployment?**

1. Check Vercel Function Logs:
   - Vercel Dashboard → Project → Functions → Click function → View Logs

2. Check Groq API Status:
   - https://status.groq.com

3. Test locally first:

   ```bash
   cd backend
   python -m uvicorn app.main:app --reload
   # Test at http://localhost:8000
   ```

4. Common errors:
   - `ModuleNotFoundError`: Check requirements.txt
   - `CORS error`: Check CORS_ORIGINS format
   - `Timeout`: Check Groq API status
   - `401 Unauthorized`: Check GROQ_API_KEY

---

**Deployment Date:** March 8, 2026  
**Backend Version:** 1.0.0  
**Deployment Platform:** Vercel Serverless Functions  
**Runtime:** Python 3.11

**🎉 Your PromptShield backend is now production-ready for Vercel!**
