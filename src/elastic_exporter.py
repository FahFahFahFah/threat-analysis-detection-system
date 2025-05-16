import requests
import math

def sanitize_json(obj):
    if isinstance(obj, dict):
        return {k: sanitize_json(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [sanitize_json(v) for v in obj]
    elif isinstance(obj, float):
        if math.isnan(obj) or math.isinf(obj):
            return None
        return obj
    else:
        return obj

def create_index_template(config):
    url = f"http://{config['elastic']['host']}:{config['elastic']['port']}/_index_template/threat-alerts-template"
    template = {
        "index_patterns": [f"{config['elastic']['index']}*"],
        "template": {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0,
                "lifecycle": {
                    "name": "threat-alerts-policy"
                }
            },
            "mappings": {
                "properties": {
                    "@timestamp": {"type": "date"},
                    "type": {"type": "keyword"},
                    "event": {"type": "object"},
                    "severity": {"type": "integer"}
                }
            }
        }
    }
    response = requests.put(url, json=template)
    response.raise_for_status()
    print("[+] Index template created successfully.")

def export_alerts(alerts, config):
    url = f"http://{config['elastic']['host']}:{config['elastic']['port']}/{config['elastic']['index']}/_doc"
    for alert in alerts:
        sanitized_alert = sanitize_json(alert)
        response = requests.post(url, json=sanitized_alert)
        response.raise_for_status()
    print(f"[+] Exported {len(alerts)} alerts to Elasticsearch.")