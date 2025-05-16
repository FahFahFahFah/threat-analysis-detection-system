def detect_privilege_escalation(logs, config):
    alerts = []
    for event in logs:
        try:
            failed_logins = int(event.get('failed_logins', 0))
            unusual_time_access = int(event.get('unusual_time_access', 0))
            attack_detected = int(event.get('attack_detected', 0))

            # Check if this satisfies privilege escalation criteria
            is_privilege_escalation = unusual_time_access == 1 or (attack_detected == 1 and failed_logins == 0)
            
            if is_privilege_escalation:
                # This is a privilege escalation event
                alerts.append({"type": "privilege_escalation", "event": event})
        except (ValueError, TypeError):
            continue
    
    return alerts
