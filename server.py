from src.log_ingestor import load_logs
from src.rules.failed_login_rules import detect_failed_logins
from src.rules.privilege_escalation_rules import detect_privilege_escalation
from src.elastic_exporter import export_alerts, create_index_template
from src.utils.config_loader import get_config
from src.thehive_exporter import send_case_to_thehive  # <-- Add this import

def main(file_path=None):
    # Load configuration
    config = get_config()
    if file_path:
        config['log']['file_path'] = file_path
    log_file = config['log']['file_path']

    # Ensure Elasticsearch index template exists
    create_index_template(config)

    # Load logs from the dataset
    logs = load_logs(log_file)

    # Run detection rules
    failed_login_alerts = detect_failed_logins(logs, config)
    privilege_escalation_alerts = detect_privilege_escalation(logs, config)

    # Combine all alerts
    all_alerts = failed_login_alerts + privilege_escalation_alerts

    # Export to Elasticsearch
    export_alerts(all_alerts, config)

    # Escalate critical alerts to TheHive (example: privilege escalation)

    # Escalate critical alerts to TheHive
    if privilege_escalation_alerts:
        # Send a summary case first
        summary = {
            "type": "privilege_escalation_summary",
            "event": {
                "summary": True,
                "count": len(privilege_escalation_alerts),
                "description": f"Detected {len(privilege_escalation_alerts)} privilege escalation attempts",
                "session_ids": [alert["event"].get("session_id", "unknown") for alert in privilege_escalation_alerts[:10]],
                "sample": privilege_escalation_alerts[0]["event"] if privilege_escalation_alerts else {}
            },
            "severity": 3  # Higher severity for the summary
        }
        send_case_to_thehive(summary, config)
        print(f"[+] Sent summary case to TheHive: {len(privilege_escalation_alerts)} privilege escalation alerts")
        
        # Then send individual cases (limit to first 5 to avoid flooding)
        for i, alert in enumerate(privilege_escalation_alerts[:5]):
            send_case_to_thehive(alert, config)
            print(f"[+] Sent individual case {i+1}/5 to TheHive: {alert['event'].get('session_id', 'unknown')}")