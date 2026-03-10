User Upload
     ↓
Detection Engine
     ↓
Elasticsearch
     ↓
Alert Trigger
     ↓
TheHive Case Creation


[1] Failed Login Detection
- analysing authentication failure events
    - SSH login failures using rule IDs
    - Rule ID 5710: Detects attempts to log in using a non-existent user via SSH.
    - Rule ID 5712: Triggers when multiple failed login attempts are detected, indicating a potential brute-force attack.

[2] Privilege Escalation Detection
- audit rules to monitor system calls that could indicate unauthorized access or privilege abuse
    - Audit Rule: Monitors access to sensitive directories with specific permissions, ensuring that only authorized users can perform certain actions.

- integrated with Elastic Stack (search engine & visualisation)
- Log data analysis:
    - read OS and application logs, forward them to a central manager for rule-based analysis and storage
    - (no agent) the server can also receive data via syslog from network devices or applications
    - rules help make you aware of application or system errors,misconfigurations, attempted and/or successful malicious activities, policy violations
- UI
- threat intelligence
- Improvement: ML

Project purpose
Setup instructions
Usage examples
Directory structure
