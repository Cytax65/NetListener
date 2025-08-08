import json
import os
import time
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
import logging

_logger = None
_console_output = True

def setup_logging(log_file="alerts.log", quiet=False):
    global _logger, _console_output
    
    _console_output = not quiet
    
    _logger = logging.getLogger('NetListener')
    _logger.setLevel(logging.INFO)
    
    _logger.handlers = []
    
    formatter = logging.Formatter('%(message)s')
    
    file_handler = RotatingFileHandler(
        log_file, 
        maxBytes=5*1024*1024,
        backupCount=3
    )
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)
    _logger.addHandler(file_handler)
    
    if not quiet:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        _logger.addHandler(console_handler)

def log_alert(kind, msg, meta=None):
    global _logger
    
    if _logger is None:
        setup_logging()
    
    timestamp = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    
    meta_json = json.dumps(meta or {}, separators=(',', ':'))
    
    log_line = f"{timestamp} | {kind} | {msg} | {meta_json}"
    
    _logger.info(log_line)

def log_system(msg, meta=None):
    log_alert("SYSTEM", msg, meta)

def log_error(msg, meta=None):
    log_alert("ERROR", msg, meta)

def get_log_stats(log_file="alerts.log"):
    if not os.path.exists(log_file):
        return {"total_alerts": 0, "file_size": 0}
    
    stats = {
        "file_size": os.path.getsize(log_file),
        "total_alerts": 0,
        "alert_types": {},
        "last_modified": os.path.getmtime(log_file)
    }
    
    try:
        with open(log_file, 'r') as f:
            for line in f:
                if ' | ' in line:
                    stats["total_alerts"] += 1
                    
                    parts = line.split(' | ')
                    if len(parts) >= 2:
                        alert_type = parts[1]
                        stats["alert_types"][alert_type] = stats["alert_types"].get(alert_type, 0) + 1
    
    except (IOError, UnicodeDecodeError):
        pass
    
    return stats

def tail_log(log_file="alerts.log", lines=10):
    if not os.path.exists(log_file):
        return []
    
    try:
        with open(log_file, 'r') as f:
            all_lines = f.readlines()
            return [line.strip() for line in all_lines[-lines:]]
    except (IOError, UnicodeDecodeError):
        return []

def filter_alerts_by_type(log_file="alerts.log", alert_type=None, since_minutes=None):
    if not os.path.exists(log_file):
        return []
    
    results = []
    now = time.time()
    cutoff_time = now - (since_minutes * 60) if since_minutes else 0
    
    try:
        with open(log_file, 'r') as f:
            for line in f:
                line = line.strip()
                if ' | ' not in line:
                    continue
                
                parts = line.split(' | ')
                if len(parts) < 4:
                    continue
                
                timestamp_str, kind, msg, meta_json = parts[0], parts[1], parts[2], parts[3]
                
                if alert_type and kind != alert_type:
                    continue
                
                if since_minutes:
                    try:
                        if timestamp_str.count(':') >= 2:
                            continue
                    except:
                        continue
                
                try:
                    meta = json.loads(meta_json)
                except json.JSONDecodeError:
                    meta = {}
                
                results.append({
                    "timestamp": timestamp_str,
                    "kind": kind,
                    "message": msg,
                    "metadata": meta,
                    "raw_line": line
                })
    
    except (IOError, UnicodeDecodeError):
        pass
    
    return results