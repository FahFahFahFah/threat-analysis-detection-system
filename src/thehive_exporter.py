import requests

def send_case_to_thehive(alert, config):
    url = f"{config['thehive']['url'].rstrip('/')}/api/case"
    headers = {
        "Authorization": f"Bearer {config['thehive']['api_key']}",
        "Content-Type": "application/json"
    }
    case = {
        "title": f"Incident: {alert['type']}",
        "description": str(alert),
        "severity": alert.get("severity", 2),
        "tlp": 2,
        "tags": [alert['type']],
    }
    response = requests.post(url, json=case, headers=headers)
    response.raise_for_status()
    print(f"[+] Sent alert to TheHive as a case: {case['title']}")