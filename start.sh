#!/bin/bash
# Startup script for CTI Dashboard

echo "🛡️  Starting Cyber Threat Intelligence Dashboard..."
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
    echo "✓ Created .env file. Please add your API keys!"
    echo ""
fi

# Check MongoDB
if ! pgrep -x mongod > /dev/null; then
    echo "⚠️  MongoDB doesn't appear to be running."
    echo "   Start it with: brew services start mongodb-community"
    echo ""
fi

# Start the app
echo "🚀 Starting Flask application..."
echo "   Dashboard will be available at: http://localhost:5001"
echo "   (Using port 5001 to avoid macOS AirPlay Receiver on port 5000)"
echo "   Press Ctrl+C to stop"
echo ""
python3 app.py

