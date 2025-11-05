#!/bin/bash
echo "Updating RX-Wifi Pro..."
git pull
sudo python3 -m pip install -r requirements.txt
echo "Update completed!"