from scapy.layers.l2 import ARP

def check(pkt, state, log):
    if not pkt.haslayer(ARP):
        return
    
    arp_pkt = pkt[ARP]

    if arp_pkt.op != 2:
        return
    
    src_ip = arp_pkt.psrc
    src_mac = arp_pkt.hwsrc.lower()

    if not src_ip or not src_mac or src_mac == "00:00:00:00:00:00":
        return 
    
    if "ip_to_mac" not in state:
        state["ip_to_mac"] = {}
    if "mac_to_ips" not in state:
        state["mac_to_ips"] = {}

    if src_ip in state["ip_to_mac"]:
        known_mac = state["ip_to_mac"][src_ip]
        if known_mac != src_mac:
            log("ARP_SPOOF_IP_CHANGED",
                f"IP {src_ip} changed from MAC {known_mac} to {src_mac}",
                {
                    "ip": src_ip,
                    "old_mac": known_mac,
                    "new_mac": src_mac,
                    "packet_src": pkt.src if hasattr(pkt, 'src') else None
                })
            
    if src_mac in state["mac_to_ips"]:
        known_ips = state["mac_to_ips"][src_mac]
        if src_ip not in known_ips:
            known_ips.add(src_ip)
            if len(known_ips) > 3:
                log("ARP_SPOOF_MAC_MULTIIP",
                    f"MAC {src_mac} claiming {len(known_ips)} different IPs",
                    {
                        "mac": src_mac,
                        "ip_count": len(known_ips),
                        "ips": list(known_ips),
                        "latest_ip": src_ip
                    })
                
    else:
        state["mac_to_ips"][src_mac] = {src_ip}

    state["ip_to_mac"][src_ip] = src_mac

    gateway_patterns = [".1", ".245", ".255"]
    if any(src_ip.endswith(pattern) for pattern in gateway_patterns):
        gateway_macs = set()
        for ip, mac in state["ip_to_mac"].items():
            if any(ip.endswith(pattern) for pattern in gateway_patterns):
                gateway_macs.add(mac)

        if len(gateway_macs) > 2:
            log("ARP_SPOOF_GATEWAY_CONFLICT",
                f"Multiple MACs claiming gateway IPs: {len(gateway_macs)} different MACs",
                {
                    "gateway_mac_count": len(gateway_macs),
                    "current_ip": src_ip,
                    "current_mac": src_mac,
                    "all_gateway_macs": list(gateway_macs)
                })