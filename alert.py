import requests
import json
from datetime import datetime, timedelta

ES_HOST = "http://localhost:9200"
INDEX = "zeek-*"

def check_port_scan():
    """Detect if any IP connected to 20+ unique ports in last 5 minutes"""
    query = {
        "query": {
            "range": {
                "@timestamp": {
                    "gte": "now-72h"
                }
            }
        },
        "aggs": {
            "source_ips": {
                "terms": {"field": "id.orig_h", "size": 100},
                "aggs": {
                    "unique_ports": {
                        "cardinality": {"field": "id.resp_p"}
                    }
                }
            }
        },
        "size": 0
    }
    
    r = requests.post(f"{ES_HOST}/{INDEX}/_search", json=query)
    data = r.json()
    
    alerts = []
    for bucket in data["aggregations"]["source_ips"]["buckets"]:
        ip = bucket["key"]
        port_count = bucket["unique_ports"]["value"]
        if port_count >= 3:
            alerts.append(f"[ALERT] Possible port scan from {ip} — {port_count} unique ports")
    
    return alerts

def check_dns_tunneling():
    """Detect unusually long DNS queries (possible data exfiltration)"""
    query = {
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": "now-10m"}}},
                    {"exists": {"field": "query"}}
                ]
            }
        },
        "_source": ["id.orig_h", "query"],
        "size": 1000
    }
    
    r = requests.post(f"{ES_HOST}/{INDEX}/_search", json=query)
    data = r.json()
    
    alerts = []
    for hit in data["hits"]["hits"]:
        src = hit["_source"]
        query_val = src.get("query", "")
        if len(query_val) > 50:
            alerts.append(f"[ALERT] Long DNS query from {src.get('id.orig_h')} — {query_val[:60]}...")
    
    return alerts

if __name__ == "__main__":
    print(f"\n=== Security Check @ {datetime.now().strftime('%H:%M:%S')} ===")
    
    scan_alerts = check_port_scan()
    dns_alerts = check_dns_tunneling()
    
    all_alerts = scan_alerts + dns_alerts
    
    if all_alerts:
        for alert in all_alerts:
            print(alert)
    else:
        print("No threats detected.")
