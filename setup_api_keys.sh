#!/bin/bash
# Interactive API Key Setup Script for CTI Dashboard

echo "🛡️  CTI Dashboard - API Keys Setup"
echo "=================================="
echo ""

# Check if .env exists
if [ ! -f .env ]; then
    echo "⚠️  .env file not found. Creating one..."
    cat > .env << 'EOF'
# Flask Configuration
SECRET_KEY=dev-secret-key-change-in-production

# MongoDB Configuration
MONGO_URI=mongodb://localhost:27017/
MONGO_DB_NAME=cti_dashboard

# API Keys (add your keys here)
VT_API_KEY=
ABUSEIPDB_KEY=
EOF
    echo "✓ Created .env file"
    echo ""
fi

echo "This script will help you add your API keys to the .env file."
echo ""
echo "📋 Steps to get API keys:"
echo ""
echo "1. VirusTotal API Key (Free):"
echo "   → Go to: https://www.virustotal.com/gui/join-us"
echo "   → Sign up or log in"
echo "   → Go to: Settings → API Key"
echo "   → Copy your API key"
echo ""
echo "2. AbuseIPDB API Key (Free):"
echo "   → Go to: https://www.abuseipdb.com/pricing"
echo "   → Sign up for a free account"
echo "   → Go to: Account → API Key"
echo "   → Generate or copy your API key"
echo ""
echo ""

# Ask for VirusTotal key
read -p "Enter your VirusTotal API key (or press Enter to skip): " vt_key
if [ ! -z "$vt_key" ]; then
    # Use sed to update the .env file (works on macOS and Linux)
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        sed -i '' "s|^VT_API_KEY=.*|VT_API_KEY=$vt_key|" .env
    else
        # Linux
        sed -i "s|^VT_API_KEY=.*|VT_API_KEY=$vt_key|" .env
    fi
    echo "✓ VirusTotal API key added"
else
    echo "⊘ VirusTotal API key skipped"
fi

echo ""

# Ask for AbuseIPDB key
read -p "Enter your AbuseIPDB API key (or press Enter to skip): " abuse_key
if [ ! -z "$abuse_key" ]; then
    # Use sed to update the .env file
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        sed -i '' "s|^ABUSEIPDB_KEY=.*|ABUSEIPDB_KEY=$abuse_key|" .env
    else
        # Linux
        sed -i "s|^ABUSEIPDB_KEY=.*|ABUSEIPDB_KEY=$abuse_key|" .env
    fi
    echo "✓ AbuseIPDB API key added"
else
    echo "⊘ AbuseIPDB API key skipped"
fi

echo ""
echo "✅ API keys have been updated in .env file"
echo ""
echo "⚠️  IMPORTANT: You need to restart the application for changes to take effect!"
echo ""
echo "To restart:"
echo "  1. Stop the current app (Ctrl+C in the terminal where it's running)"
echo "  2. Start it again: python3 app.py"
echo ""
echo "Or run: ./start.sh"
echo ""

