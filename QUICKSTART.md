# Quick Start Guide

## ✅ Setup Complete!

Your CTI Dashboard is ready to run. Here's what's been set up:

- ✅ All Python dependencies installed
- ✅ MongoDB is running
- ✅ .env file created
- ✅ Startup script ready

## 🚀 How to Run

### Option 1: Using the startup script (Recommended)
```bash
./start.sh
```

### Option 2: Direct Python command
```bash
python3 app.py
```

## 🔑 Add Your API Keys (Optional but Recommended)

Edit the `.env` file and add your API keys:

1. **VirusTotal API Key:**
   - Sign up at: https://www.virustotal.com/gui/join-us
   - Get your API key from account settings
   - Add to `.env`: `VT_API_KEY=your-key-here`

2. **AbuseIPDB API Key:**
   - Sign up at: https://www.abuseipdb.com/pricing
   - Generate API key from dashboard
   - Add to `.env`: `ABUSEIPDB_KEY=your-key-here`

**Note:** The app will work without API keys, but lookup functionality will be limited.

## 📍 Access the Dashboard

Once running, open your browser and go to:
```
http://localhost:5000
```

## 🎯 What You Can Do

1. **Dashboard** (`/`) - View threat statistics and charts
2. **Lookup** (`/lookup`) - Check IP addresses or domains
3. **Export** (`/export`) - Export threat data as CSV or PDF
4. **API** (`/api/feeds`) - Access threat data via JSON

## 🛑 Stop the Application

Press `Ctrl+C` in the terminal where the app is running.

## ⚠️ Troubleshooting

### MongoDB Not Running
```bash
brew services start mongodb-community
```

### Port 5000 Already in Use
Edit `app.py` and change the port:
```python
app.run(debug=True, host='0.0.0.0', port=5001)  # Change 5000 to 5001
```

### Import Errors
Make sure all dependencies are installed:
```bash
pip3 install -r requirements.txt
```

---

**Happy Threat Hunting! 🛡️**

