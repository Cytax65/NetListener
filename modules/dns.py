#!/usr/bin/env python3

import time 
import statistics
import math
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSQR

def check(pkt, state, log, window=60, tlds=None):
    if tlds is None:
        tlds = set()

    if not (pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt.haslayer(DNS)):
        return
    
    dns_pkt = pkt[DNS]
    ip_pkt = pkt[IP]

    if dns_pkt.qr != 0:
        return
    
    if not dns_pkt.qd:
        return
    
    query = dns_pkt.qd
    if not hasattr(query, 'qname') or not query.qname:
        return
    
    src_ip = ip_pkt.src
    qname = query.qname.decode('utf-8', errors='ignore').rstrip('.')
    timestamp = time.time()

    if "queries" not in state:
        state["queries"] = []
    if "by_domain" not in state:
        state["by_domain"] = {}

    query_record = {
        "src": src_ip,
        "qname": qname,
        "t": timestamp
    }
    state["queries"].append(query_record)

    cutoff_time = timestamp - window
    state["queries"] = [q for q in state["queries"] if q["t"] > cutoff_time]

    if tlds:
        qname_lower = qname.lower()
        for suspicious_tld in tlds:
            if qname_lower.endswith(suspicious_tld.lower()):
                log("DNS_SUSPICIOUS_TLD",
                    f"Query to suspicious TLD: {qname} (TLD: {suspicious_tld})",
                    {
                        "src": src_ip,
                        "domain": qname,
                        "suspicious_tld": suspicious_tld,
                        "query_type": query.qtype if hasattr(query, 'qtype') else 'unknown'
                    })
                break

    if qname not in state["by_domain"]:
        state["by_domain"][qname] = {
            "queries": [],
            "last_alert": 0,
            "src_ips": set()
        }
    
    domain_data = state["by_domain"][qname]
    domain_data["src_ips"].add(src_ip)
    
    domain_data["queries"] = [q for q in domain_data["queries"] if q["t"] > cutoff_time]
    domain_data["queries"].append({"src": src_ip, "t": timestamp})
    
    queries_in_window = len(domain_data["queries"])
    if queries_in_window > 50:
        rate = queries_in_window / window
        if timestamp - domain_data["last_alert"] > window:
            log("DNS_FLOOD",
                f"High query rate to {qname}: {queries_in_window} queries in {window}s ({rate:.1f}/s)",
                {
                    "domain": qname,
                    "query_count": queries_in_window,
                    "time_window": window,
                    "queries_per_second": round(rate, 2),
                    "source_ips": list(domain_data["src_ips"])
                })
            domain_data["last_alert"] = timestamp
    
    src_queries = [q for q in domain_data["queries"] if q["src"] == src_ip]
    if len(src_queries) >= 5:
        timestamps = sorted([q["t"] for q in src_queries])
        intervals = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
        
        if len(intervals) >= 3:
            try:
                mean_interval = statistics.mean(intervals)
                
                if 5 <= mean_interval <= 300:
                    stdev = statistics.stdev(intervals) if len(intervals) > 1 else 0
                    coefficient_of_variation = stdev / mean_interval if mean_interval > 0 else 1
                    
                    if coefficient_of_variation < 0.3 and timestamp - domain_data["last_alert"] > window:
                        log("DNS_BEACONING",
                            f"Regular DNS beaconing detected: {src_ip} -> {qname} "
                            f"(avg interval: {mean_interval:.1f}s, CV: {coefficient_of_variation:.3f})",
                            {
                                "src": src_ip,
                                "domain": qname,
                                "query_count": len(src_queries),
                                "avg_interval_seconds": round(mean_interval, 1),
                                "coefficient_of_variation": round(coefficient_of_variation, 3),
                                "time_span_minutes": round((timestamps[-1] - timestamps[0]) / 60, 1)
                            })
                        domain_data["last_alert"] = timestamp
            except (statistics.StatisticsError, ZeroDivisionError):
                pass
    
    if _is_potential_dga(qname):
        log("DNS_POTENTIAL_DGA",
            f"Potential DGA domain detected: {qname}",
            {
                "src": src_ip,
                "domain": qname,
                "domain_length": len(qname),
                "entropy_score": _calculate_entropy(qname)
            })


def _is_potential_dga(domain):
    domain_parts = domain.lower().split('.')
    if len(domain_parts) < 2:
        return False
    
    domain_name = domain_parts[0]
    
    if len(domain_name) < 6:
        return False
    
    legit_words = [
        'google', 'github', 'python', 'stackoverflow', 'amazon', 'microsoft',
        'apple', 'facebook', 'twitter', 'linkedin', 'youtube', 'netflix',
        'reddit', 'wikipedia', 'ubuntu', 'crypto', 'currency'
    ]

    if any(word in domain_name for word in legit_words):
        return False

    suspicious_score = 0
    
    if len(domain_name) > 15:
        suspicious_score += 1
    
    vowels = sum(1 for c in domain_name if c in 'aeiou')
    consonants = sum(1 for c in domain_name if c.isalpha() and c not in 'aeiou')
    if consonants > 0 and vowels / consonants < 0.3:
        suspicious_score += 1
    
    max_consecutive_consonants = 0
    current_consecutive = 0
    for c in domain_name:
        if c.isalpha() and c not in 'aeiou':
            current_consecutive += 1
            max_consecutive_consonants = max(max_consecutive_consonants, current_consecutive)
        else:
            current_consecutive = 0
    
    if max_consecutive_consonants >= 4:
        suspicious_score += 1
    
    entropy = _calculate_entropy(domain_name)
    if entropy > 4.2:
        suspicious_score += 1
    
    return suspicious_score >= 3


def _calculate_entropy(string):
    if not string:
        return 0
    
    char_counts = {}
    for char in string.lower():
        char_counts[char] = char_counts.get(char, 0) + 1
    
    length = len(string)
    entropy = 0
    for count in char_counts.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    
    return entropy
