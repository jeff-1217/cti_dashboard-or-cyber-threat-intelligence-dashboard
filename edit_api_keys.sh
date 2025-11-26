#!/bin/bash
# Helper script to edit API keys

echo "🔑 Opening .env file for editing..."
echo ""
echo "After you add your API keys, save the file and restart the app."
echo ""

# Try to open with the default editor
if command -v code &> /dev/null; then
    echo "Opening with VS Code..."
    code .env
elif command -v nano &> /dev/null; then
    echo "Opening with nano..."
    echo "Press Ctrl+O to save, then Ctrl+X to exit"
    sleep 2
    nano .env
else
    echo "Opening with default text editor..."
    open -a TextEdit .env 2>/dev/null || open .env
fi

echo ""
echo "✅ Done! Don't forget to restart your Flask app after adding keys."

