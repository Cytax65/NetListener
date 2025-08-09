#!/usr/bin/env python3

import time
from scapy.layers.inet import IP, TCP

def check(pkt, state, log, window=10, threshold=12):
    if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
        return
    
    tcp_pkt = pkt[TCP]
    ip_pkt = pkt[IP]
    if tcp_pkt.flags != 2:
        return
    
    src_ip = ip_pkt.src
    dst_ip = ip_pkt.dst
    dst_port = tcp_pkt.dport
    timestamp = time.time()
    
    if "by_src" not in state:
        state["by_src"] = {}
    if src_ip not in state["by_src"]:
        state["by_src"][src_ip] = {
            "ports": set(),
            "targets": set(), 
            "ts": [],
            "last_alert_vertical": 0,
            "last_alert_horizontal": 0
        }
    
    src_data = state["by_src"][src_ip]
    
    cutoff_time = timestamp - window
    src_data["ts"] = [(p, t, ts) for p, t, ts in src_data["ts"] if ts > cutoff_time]
    
    current_ports = set()
    current_targets = set()
    target_port_map = {}
    
    for port, target, ts in src_data["ts"]:
        current_ports.add(port)
        current_targets.add(target)
        if target not in target_port_map:
            target_port_map[target] = set()
        target_port_map[target].add(port)
    
    src_data["ts"].append((dst_port, dst_ip, timestamp))
    current_ports.add(dst_port)
    current_targets.add(dst_ip)
    if dst_ip not in target_port_map:
        target_port_map[dst_ip] = set()
    target_port_map[dst_ip].add(dst_port)
    
    src_data["ports"] = current_ports
    src_data["targets"] = current_targets
    
    # Vertical scan detection
    for target, ports_to_target in target_port_map.items():
        if (len(ports_to_target) >= threshold and 
            timestamp - src_data["last_alert_vertical"] > window):
            
            log("SCAN_VERTICAL",
                f"Vertical scan detected: {src_ip} -> {target} ({len(ports_to_target)} ports)",
                {
                    "src": src_ip,
                    "dst": target,
                    "port_count": len(ports_to_target),
                    "sample_ports": list(sorted(ports_to_target))[:10],
                    "time_window": window,
                    "threshold": threshold
                })
            src_data["last_alert_vertical"] = timestamp
    
    port_target_map = {}
    for port, target, ts in src_data["ts"]:
        if port not in port_target_map:
            port_target_map[port] = set()
        port_target_map[port].add(target)
    
    for port, targets_for_port in port_target_map.items():
        if (len(targets_for_port) >= threshold and 
            timestamp - src_data["last_alert_horizontal"] > window):
            
            log("SCAN_HORIZONTAL",
                f"Horizontal scan detected: {src_ip} port {port} -> {len(targets_for_port)} hosts",
                {
                    "src": src_ip,
                    "port": port,
                    "target_count": len(targets_for_port),
                    "sample_hosts": list(sorted(targets_for_port))[:10],
                    "time_window": window,
                    "threshold": threshold
                })
            src_data["last_alert_horizontal"] = timestamp
    
    total_connections = len(src_data["ts"])
    if (total_connections >= threshold * 2 and 
        timestamp - max(src_data["last_alert_vertical"], src_data["last_alert_horizontal"]) > window):
        
        log("SCAN_GENERAL",
            f"High scan activity: {src_ip} made {total_connections} connection attempts",
            {
                "src": src_ip,
                "connection_attempts": total_connections,
                "unique_ports": len(current_ports),
                "unique_targets": len(current_targets),
                "time_window": window,
                "rate_per_second": round(total_connections / window, 2)
            })
