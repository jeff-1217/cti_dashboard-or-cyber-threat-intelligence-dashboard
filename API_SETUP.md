# API Keys Setup Guide

## Why You Need API Keys

The dashboard needs API keys to:
- ✅ Check IP addresses and domains against threat intelligence databases
- ✅ Fetch real-time threat data
- ✅ Populate the dashboard with actual threat information

Without API keys, the dashboard will show zeros and "Loading..." states.

## Step 1: Get Your API Keys

### VirusTotal API Key (Free Tier Available)

1. **Sign up / Log in:**
   - Go to: https://www.virustotal.com/gui/join-us
   - Create a free account or log in if you already have one

2. **Get Your API Key:**
   - After logging in, go to: https://www.virustotal.com/gui/user/YOUR_USERNAME/apikey
   - Or navigate to: Settings → API Key
   - Copy your API key (it's a long string of characters)

3. **Rate Limits:**
   - Free tier: 4 requests per minute
   - Upgrade options available for higher limits

### AbuseIPDB API Key (Free Tier Available)

1. **Sign up / Log in:**
   - Go to: https://www.abuseipdb.com/pricing
   - Click "Sign Up" for a free account

2. **Get Your API Key:**
   - After logging in, go to your dashboard
   - Navigate to: Account → API Key
   - Generate a new API key or copy your existing one

3. **Rate Limits:**
   - Free tier: 1,000 requests per day
   - Upgrade options available for higher limits

## Step 2: Add Keys to .env File

### Option A: Using Terminal (Recommended)

```bash
# Open the .env file in nano editor
nano .env

# Or use vim
vim .env

# Or use VS Code (if installed)
code .env
```

Then edit the lines:
```
VT_API_KEY=your-virustotal-key-here
ABUSEIPDB_KEY=your-abuseipdb-key-here
```

**Important:** 
- No spaces around the `=` sign
- No quotes around the key
- Save the file (Ctrl+O in nano, then Ctrl+X)

### Option B: Using Text Editor

1. Open the `.env` file in any text editor
2. Find these lines:
   ```
   VT_API_KEY=
   ABUSEIPDB_KEY=
   ```
3. Add your keys after the `=` sign:
   ```
   VT_API_KEY=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2
   ABUSEIPDB_KEY=xyz123abc456def789ghi012jkl345mno678pqr901stu234vwx567yza890bcd
   ```
4. Save the file

## Step 3: Restart the Application

After adding your API keys:

1. **Stop the current app** (if running):
   - Press `Ctrl+C` in the terminal where the app is running

2. **Start it again:**
   ```bash
   python3 app.py
   ```

3. **Wait a few minutes:**
   - The scheduler runs every 30 minutes
   - Or use the Lookup page to test immediately!

## Step 4: Test Your Setup

### Quick Test - Use the Lookup Page

1. Go to: http://localhost:5001/lookup
2. Enter a test IP: `8.8.8.8` (Google DNS - safe to test)
3. Click "Check Threat Status"
4. If you see results, your API keys are working! ✅

### What You Should See

- **With API keys:** Real threat scores, country info, detection counts
- **Without API keys:** Error messages like "API key not configured"

## Troubleshooting

### Keys Not Working?

1. **Check for typos:**
   ```bash
   cat .env | grep API_KEY
   ```

2. **Verify no extra spaces:**
   - Should be: `VT_API_KEY=yourkey`
   - NOT: `VT_API_KEY = yourkey` or `VT_API_KEY="yourkey"`

3. **Check API key format:**
   - VirusTotal: Usually 64 characters long
   - AbuseIPDB: Usually 32-40 characters long

4. **Test API keys manually:**
   ```bash
   # Test VirusTotal (replace YOUR_KEY)
   curl "https://www.virustotal.com/vtapi/v2/ip-address/report?apikey=YOUR_KEY&ip=8.8.8.8"
   
   # Test AbuseIPDB (replace YOUR_KEY)
   curl -G https://api.abuseipdb.com/api/v2/check \
     --data-urlencode "ipAddress=8.8.8.8" \
     -H "Key: YOUR_KEY" \
     -H "Accept: application/json"
   ```

### Still Having Issues?

- Make sure you saved the `.env` file
- Restart the Flask app after adding keys
- Check that your API keys are active (not expired/revoked)
- Verify you're within rate limits

---

**Need Help?** Check the main README.md for more details!

