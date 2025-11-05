bash
#!/bin/bash
echo "Installing RX-Wifi Pro..."
sudo apt-get update
sudo apt-get install -y aircrack-ng tshark hashcat hcxdumptool hcxpcapngtool
chmod +x rxwifi.py
echo "Installation complete! Run: sudo python3 rxwifi.py"