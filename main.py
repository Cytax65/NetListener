#!/usr/bin/env python3

import argparse
import signal
import sys
import time
import threading
from scapy.all import sniff, get_if_list
from scapy.layers.inet import IP

from modules import arp, scan, dns
from utils.logger import log_alert, setup_logging


class NetListener:
    def __init__(self, interface, window=10, scan_threshold=12, suspicious_tlds=None, 
                 pcap_out=None, quiet=False, log_file="alerts.log"):
        self.interface = interface
        self.window = window
        self.scan_threshold = scan_threshold
        self.suspicious_tlds = set(suspicious_tlds or [])
        self.pcap_out = pcap_out
        self.quiet = quiet
        self.log_file = log_file
        
        self.arp_state = {"ip_to_mac": {}, "mac_to_ips": {}}
        self.scan_state = {"by_src": {}}
        self.dns_state = {"queries": [], "by_domain": {}}
        
        self.stats = {
            "packets_processed": 0,
            "alerts_raised": 0,
            "start_time": time.time(),
            "last_cleanup": time.time()
        }
        
        self.running = True
        
        setup_logging(log_file, quiet)
        
    def packet_callback(self, pkt):
        if not self.running:
            return
            
        if not pkt.haslayer(IP):
            return
            
        self.stats["packets_processed"] += 1
        now = time.time()
        
        try:
            arp.check(pkt, self.arp_state, self._log_wrapper)
            scan.check(pkt, self.scan_state, self._log_wrapper, 
                      window=self.window, threshold=self.scan_threshold)
            dns.check(pkt, self.dns_state, self._log_wrapper, 
                     window=max(self.window, 60), tlds=self.suspicious_tlds)
            
            if now - self.stats["last_cleanup"] > 30:
                self._cleanup_old_state(now)
                self.stats["last_cleanup"] = now
                
        except Exception as e:
            log_alert("INTERNAL_ERROR", f"Packet processing error: {e}", 
                     {"exception": str(e), "packet_summary": str(pkt.summary())})
    
    def _log_wrapper(self, kind, msg, meta=None):
        self.stats["alerts_raised"] += 1
        log_alert(kind, msg, meta)
        
        if self.pcap_out:
            pass
    
    def _cleanup_old_state(self, now):
        cleanup_window = self.window * 3
        
        for src_ip in list(self.scan_state["by_src"].keys()):
            src_data = self.scan_state["by_src"][src_ip]
            if "ts" in src_data:
                src_data["ts"] = [(port, dst, ts) for port, dst, ts in src_data["ts"] 
                                 if now - ts < cleanup_window]
                
                if not src_data["ts"]:
                    del self.scan_state["by_src"][src_ip]
        
        self.dns_state["queries"] = [q for q in self.dns_state["queries"] 
                                   if now - q["t"] < cleanup_window]
        
        for domain in list(self.dns_state["by_domain"].keys()):
            domain_data = self.dns_state["by_domain"][domain]
            if "queries" in domain_data:
                domain_data["queries"] = [q for q in domain_data["queries"] 
                                        if now - q["t"] < cleanup_window]
                if not domain_data["queries"]:
                    del self.dns_state["by_domain"][domain]
    
    def start_monitoring(self):
        if not self.quiet:
            print(f"[NetListener] Starting monitoring on interface: {self.interface}")
            print(f"[NetListener] Window: {self.window}s, Scan threshold: {self.scan_threshold}")
            print(f"[NetListener] Suspicious TLDs: {', '.join(self.suspicious_tlds) if self.suspicious_tlds else 'None'}")
            print(f"[NetListener] Press Ctrl+C to stop")
        
        log_alert("SYSTEM", "NetListener monitoring started", {
            "interface": self.interface,
            "window": self.window,
            "scan_threshold": self.scan_threshold,
            "suspicious_tlds": list(self.suspicious_tlds)
        })
        
        try:
            sniff(prn=self.packet_callback, store=False, iface=self.interface)
        except KeyboardInterrupt:
            self.stop_monitoring()
        except Exception as e:
            log_alert("SYSTEM_ERROR", f"Sniffing error: {e}", {"exception": str(e)})
            sys.exit(1)
    
    def stop_monitoring(self):
        self.running = False
        runtime = time.time() - self.stats["start_time"]
        
        print(f"\n[NetListener] Shutting down...")
        print(f"[NetListener] Runtime: {runtime:.1f}s")
        print(f"[NetListener] Packets processed: {self.stats['packets_processed']}")
        print(f"[NetListener] Alerts raised: {self.stats['alerts_raised']}")
        print(f"[NetListener] Processing rate: {self.stats['packets_processed']/runtime:.1f} pkt/s")
        
        log_alert("SYSTEM", "NetListener monitoring stopped", {
            "runtime_seconds": round(runtime, 1),
            "packets_processed": self.stats["packets_processed"],
            "alerts_raised": self.stats["alerts_raised"]
        })


def validate_interface(interface):
    available_ifaces = get_if_list()
    if interface not in available_ifaces:
        print(f"Error: Interface '{interface}' not found.")
        print(f"Available interfaces: {', '.join(available_ifaces)}")
        return False
    return True


def parse_args():
    parser = argparse.ArgumentParser(
        description="NetListener - Network Intrusion Detection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --iface eth0
  python main.py --iface wlan0 --window 15 --scan-threshold 20
  python main.py --iface eth0 --suspicious-tlds .tk,.ml,.ga --quiet
        """
    )
    
    parser.add_argument("--iface", required=True, 
                       help="Network interface to monitor (required)")
    parser.add_argument("--window", type=int, default=10,
                       help="Time window in seconds for detection (default: 10)")
    parser.add_argument("--scan-threshold", type=int, default=12,
                       help="Unique ports/hosts threshold for scan detection (default: 12)")
    parser.add_argument("--suspicious-tlds", type=str, default="",
                       help="Comma-separated list of suspicious TLDs (e.g., .tk,.ml,.ga)")
    parser.add_argument("--pcap-out", type=str,
                       help="Optional: write alert-correlated packets to pcap file")
    parser.add_argument("--log", type=str, default="alerts.log",
                       help="Log file path (default: alerts.log)")
    parser.add_argument("--quiet", action="store_true",
                       help="Reduce console output")
    
    return parser.parse_args()


def main():
    args = parse_args()
    
    if not validate_interface(args.iface):
        sys.exit(1)
    
    suspicious_tlds = []
    if args.suspicious_tlds:
        suspicious_tlds = [tld.strip() for tld in args.suspicious_tlds.split(",") if tld.strip()]
    
    ids = NetListener(
        interface=args.iface,
        window=args.window,
        scan_threshold=args.scan_threshold,
        suspicious_tlds=suspicious_tlds,
        pcap_out=args.pcap_out,
        quiet=args.quiet,
        log_file=args.log
    )
    
    def signal_handler(signum, frame):
        print(f"\n[NetListener] Received signal {signum}")
        ids.stop_monitoring()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    ids.start_monitoring()


if __name__ == "__main__":
    main()