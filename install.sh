#!/data/data/com.termux/files/usr/bin/bash

echo "⚡ Installing HostScanX ⚡"
echo "-------------------------"

# Update system
pkg update -y && pkg upgrade -y

# Install required packages
pkg install python git -y

# Upgrade pip
pip install --upgrade pip

# Install python requirements
pip install -r requirements.txt

# Permission
chmod +x HostScanX.py

echo ""
echo "✅ Installation Complete!"
echo "🔐 Now authorize the tool:"
echo ""
echo "   python3 HostScanX.py --authorize"
echo ""