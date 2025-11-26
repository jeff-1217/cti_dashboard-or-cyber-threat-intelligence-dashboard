# Cyber Threat Intelligence Dashboard

A real-time Flask-based dashboard that aggregates threat intelligence data from multiple APIs (VirusTotal, AbuseIPDB) and provides visualization, lookup, and export capabilities.

## 🎯 Features

- **Real-time Threat Intelligence**: Aggregates data from VirusTotal and AbuseIPDB APIs
- **Interactive Dashboard**: Visual charts showing threat categories, trends, and top malicious IPs
- **IP/Domain Lookup**: Check any IP address or domain against threat intelligence databases
- **Automated Data Fetching**: Background scheduler updates threat data every 30 minutes
- **Data Export**: Export threat data as CSV or PDF
- **Manual Tagging**: Add custom tags to IOCs (e.g., "phishing", "brute-force")
- **JSON API**: Access threat feeds programmatically via `/api/feeds`
- **Dark Theme UI**: Modern, clean interface built with Bootstrap 5

## 📁 Project Structure

```
cti_dashboard/
├── app.py                 # Main Flask application
├── config.py              # Configuration settings
├── requirements.txt       # Python dependencies
├── static/
│   ├── css/
│   │   └── style.css      # Custom dark theme styles
│   └── js/
│       ├── dashboard.js    # Dashboard interactivity
│       ├── lookup.js       # Lookup page logic
│       └── export.js       # Export functionality
├── templates/
│   ├── index.html         # Main dashboard page
│   ├── lookup.html        # IP/Domain lookup page
│   └── export.html        # Export page
├── services/
│   ├── virustotal.py      # VirusTotal API integration
│   └── abuseipdb.py       # AbuseIPDB API integration
├── db/
│   └── mongo_connection.py # MongoDB connection and operations
├── utils/
│   ├── scheduler.py       # APScheduler configuration
│   └── exporter.py        # CSV/PDF export utilities
└── exports/               # Generated export files (created automatically)
```

## 🚀 Setup Instructions

### Prerequisites

- Python 3.8 or higher
- MongoDB (local installation or MongoDB Atlas account)
- VirusTotal API key (free tier available)
- AbuseIPDB API key (free tier available)

### Installation

1. **Clone or navigate to the project directory:**
   ```bash
   cd cti_dashboard
   ```

2. **Create a virtual environment (recommended):**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Create a `.env` file in the project root:**
   ```bash
   # Flask Configuration
   SECRET_KEY=your-secret-key-here-change-in-production
   
   # MongoDB Configuration
   # For local MongoDB: mongodb://localhost:27017/
   # For MongoDB Atlas: mongodb+srv://username:password@cluster.mongodb.net/
   MONGO_URI=mongodb://localhost:27017/
   MONGO_DB_NAME=cti_dashboard
   
   # API Keys
   # Get your VirusTotal API key from: https://www.virustotal.com/gui/join-us
   VT_API_KEY=your-virustotal-api-key-here
   
   # Get your AbuseIPDB API key from: https://www.abuseipdb.com/pricing
   ABUSEIPDB_KEY=your-abuseipdb-api-key-here
   ```

5. **Start MongoDB (if using local installation):**
   ```bash
   # macOS (using Homebrew)
   brew services start mongodb-community
   
   # Linux
   sudo systemctl start mongod
   
   # Windows
   net start MongoDB
   ```

6. **Run the application:**
   ```bash
   python app.py
   ```

7. **Access the dashboard:**
   Open your browser and navigate to `http://localhost:5000`

## 🔑 API Keys Setup

### VirusTotal API Key

1. Sign up for a free account at [VirusTotal](https://www.virustotal.com/gui/join-us)
2. Navigate to your account settings
3. Copy your API key
4. Add it to your `.env` file as `VT_API_KEY`

**Note:** Free tier has rate limits (4 requests per minute)

### AbuseIPDB API Key

1. Sign up for a free account at [AbuseIPDB](https://www.abuseipdb.com/pricing)
2. Navigate to your account dashboard
3. Generate an API key
4. Add it to your `.env` file as `ABUSEIPDB_KEY`

**Note:** Free tier allows 1,000 requests per day

## 📊 Usage

### Dashboard

The main dashboard displays:
- **Total Threats**: Total number of threats stored in the database
- **Risk Levels**: Breakdown of high, medium, and low risk threats
- **Threat Categories**: Pie chart showing distribution of threat types
- **Threats Over Time**: Line chart showing threat trends (last 7 days)
- **Top 10 Malicious IPs**: Table of most dangerous IPs by threat score

### IP/Domain Lookup

1. Navigate to the "Lookup" page
2. Enter an IP address (e.g., `8.8.8.8`) or domain (e.g., `example.com`)
3. Click "Check Threat Status"
4. View results from both VirusTotal and AbuseIPDB
5. Optionally add manual tags to categorize the IOC

### Export Data

1. Navigate to the "Export" page
2. Set the number of records to export (default: 1000)
3. Click "Export as CSV" or "Export as PDF"
4. Files will be downloaded automatically

### JSON API

Access threat data programmatically:

```bash
# Get all threats (default: 100 records)
curl http://localhost:5000/api/feeds

# With pagination
curl http://localhost:5000/api/feeds?limit=50&skip=0
```

## 🔧 Configuration

### Scheduler Interval

The default interval for automatic threat data fetching is 30 minutes. To change this, modify `SCHEDULER_INTERVAL_MINUTES` in `config.py`.

### MongoDB Connection

For **local MongoDB**:
```
MONGO_URI=mongodb://localhost:27017/
```

For **MongoDB Atlas** (cloud):
```
MONGO_URI=mongodb+srv://username:password@cluster.mongodb.net/
```

## 🛠️ API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Main dashboard page |
| `/lookup` | GET | IP/Domain lookup page |
| `/export` | GET | Export page |
| `/api/lookup` | POST | Perform IP/domain lookup |
| `/api/dashboard/stats` | GET | Get dashboard statistics |
| `/api/feeds` | GET | Get threat feed (JSON) |
| `/api/tag` | POST | Add manual tag to IOC |
| `/api/export/csv` | POST | Export threats as CSV |
| `/api/export/pdf` | POST | Export threats as PDF |

## 📝 Example API Usage

### Lookup IP Address

```bash
curl -X POST http://localhost:5000/api/lookup \
  -H "Content-Type: application/json" \
  -d '{"query": "8.8.8.8"}'
```

### Add Manual Tag

```bash
curl -X POST http://localhost:5000/api/tag \
  -H "Content-Type: application/json" \
  -d '{"query": "8.8.8.8", "tag": "phishing"}'
```

### Export CSV

```bash
curl -X POST http://localhost:5000/api/export/csv \
  -H "Content-Type: application/json" \
  -d '{"limit": 100}' \
  -o threats_export.csv
```

## 🐛 Troubleshooting

### MongoDB Connection Issues

- Ensure MongoDB is running: `mongosh` or check service status
- Verify `MONGO_URI` in `.env` is correct
- For Atlas, check network access and credentials

### API Rate Limits

- VirusTotal free tier: 4 requests/minute
- AbuseIPDB free tier: 1,000 requests/day
- Consider implementing rate limiting or upgrading API tiers

### Import Errors

- Ensure all dependencies are installed: `pip install -r requirements.txt`
- Check Python version: `python --version` (requires 3.8+)

## 🔒 Security Notes

- **Never commit your `.env` file** to version control
- Change `SECRET_KEY` in production
- Use strong MongoDB credentials
- Consider implementing authentication for production use
- Rate limit API endpoints to prevent abuse

## 📦 Dependencies

- **Flask**: Web framework
- **pymongo**: MongoDB driver
- **requests**: HTTP library for API calls
- **APScheduler**: Background task scheduling
- **pandas**: Data manipulation for CSV export
- **reportlab**: PDF generation
- **python-dotenv**: Environment variable management

## 🎨 Technologies Used

- **Backend**: Python, Flask
- **Database**: MongoDB
- **Frontend**: HTML, Bootstrap 5, Chart.js
- **APIs**: VirusTotal, AbuseIPDB
- **Scheduling**: APScheduler
- **Export**: Pandas, ReportLab

## 📄 License

This project is provided as-is for educational and research purposes.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## 📧 Support

For issues or questions, please open an issue on the repository.

---

**Note:** This tool is for authorized security testing and threat intelligence purposes only. Always ensure you have permission to scan or analyze systems and follow applicable laws and regulations.

# cti_dashboard-or-cyber-threat-intelligence-dashboard
