def detect_failed_logins(logs, config):
    alerts = []
    threshold = config['thresholds']['failed_login_attempts']
    
    for event in logs:
        try:
            failed_logins = int(event.get('failed_logins', 0))
            unusual_time_access = int(event.get('unusual_time_access', 0))
            attack_detected = int(event.get('attack_detected', 0))
            
            # Check if this meets failed login criteria but NOT privilege escalation criteria
            is_failed_login = failed_logins >= threshold
            is_privilege_escalation = unusual_time_access == 1 or (attack_detected == 1 and failed_logins == 0)
            
            if is_failed_login and not is_privilege_escalation:
                alerts.append({"type": "failed_login", "event": event})
        except (ValueError, TypeError):
            continue
    
    return alerts
