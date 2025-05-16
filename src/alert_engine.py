import re

def detect_failed_logins(logs, config):
    alerts = []
    threshold = config['thresholds']['failed_login_attempts']
    failed_login_pattern = re.compile(
        r'(failed password|authentication error|pam: authentication failure|illegal user|invalid user)',
        re.IGNORECASE
    )

    for event in logs:
        message = event.get('message', '')
        if failed_login_pattern.search(message):
            alerts.append({"type": "failed_login", "event": event})
        try:
            if int(event.get('failed_logins', 0)) >= threshold:
                alerts.append({"type": "failed_login", "event": event})
        except (ValueError, TypeError):
            continue
    return alerts

def detect_privilege_escalation(logs, config):
    alerts = []
    privilege_pattern = re.compile(
        r'(sudo|su|setuid|chmod 777|root access|session opened for user root|not in sudoers)',
        re.IGNORECASE
    )

    for event in logs:
        message = event.get('message', '')
        if privilege_pattern.search(message):
            alerts.append({"type": "privilege_escalation", "event": event})
    return alerts