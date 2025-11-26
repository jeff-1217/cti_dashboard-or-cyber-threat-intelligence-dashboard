# Quick Fix: Add API Keys

## 🚀 Quick Setup (3 Steps)

### Step 1: Get Your API Keys

#### VirusTotal (Free)
1. Visit: https://www.virustotal.com/gui/join-us
2. Sign up or log in
3. Go to: **Settings → API Key**
4. Copy your API key (64 characters)

#### AbuseIPDB (Free)
1. Visit: https://www.abuseipdb.com/pricing
2. Sign up for free account
3. Go to: **Account → API Key**
4. Generate and copy your API key (32-40 characters)

### Step 2: Add Keys to .env File

**Option A: Use the Setup Script (Easiest)**
```bash
./setup_api_keys.sh
```

**Option B: Edit Manually**
```bash
# Open .env file in your editor
nano .env
# or
code .env
# or
vim .env
```

Then update these lines:
```
VT_API_KEY=your-virustotal-key-here
ABUSEIPDB_KEY=your-abuseipdb-key-here
```

**Important:** 
- No spaces around `=`
- No quotes around the key
- Save the file

### Step 3: Restart the Application

```bash
# Stop the app (Ctrl+C in terminal where it's running)
# Then start again:
python3 app.py

# OR use the startup script:
./start.sh
```

### Step 4: Test It!

1. Go to: http://localhost:5001/lookup
2. Enter an IP: `8.8.8.8`
3. Click "Check Threat Status"
4. You should see real threat data! ✅

## 🔍 Verify Keys Are Set

```bash
# Check if keys are in .env
cat .env | grep API_KEY
```

You should see:
```
VT_API_KEY=your-actual-key-here
ABUSEIPDB_KEY=your-actual-key-here
```

## ⚠️ Troubleshooting

### Keys not working?
1. Make sure no extra spaces: `VT_API_KEY=key` (not `VT_API_KEY = key`)
2. Make sure no quotes: `VT_API_KEY=key` (not `VT_API_KEY="key"`)
3. Restart the app after adding keys
4. Check API key is valid (not expired/revoked)

### Test API keys manually:
```bash
# Test VirusTotal (replace YOUR_KEY)
curl "https://www.virustotal.com/vtapi/v2/ip-address/report?apikey=YOUR_KEY&ip=8.8.8.8"

# Test AbuseIPDB (replace YOUR_KEY)
curl -G https://api.abuseipdb.com/api/v2/check \
  --data-urlencode "ipAddress=8.8.8.8" \
  -H "Key: YOUR_KEY" \
  -H "Accept: application/json"
```

## 📝 Notes

- **Free tier limits:**
  - VirusTotal: 4 requests/minute
  - AbuseIPDB: 1,000 requests/day
- You can use the dashboard without API keys, but lookup will show "API key not configured"
- API keys are stored in `.env` file (never commit this to git!)

---

**Need more help?** See `API_SETUP.md` for detailed instructions.

