import re

def decode_pam_line(line: str) -> dict:
    """
    Extract fields from PAM log lines.
    """
    fields = {}
    pam_regexes = {
        'user': r'user=(\S+)',
        'srcuser': r'ruser=(\S+)',
        'srcip': r'rhost=(\S+)',
        'logname': r'logname=(\S+)',
        'uid': r'uid=(\S+)',
        'euid': r'euid=(\S+)',
        'tty': r'tty=(\S+)',
    }
    for field, pattern in pam_regexes.items():
        match = re.search(pattern, line)
        if match:
            fields[field] = match.group(1)
    fields['message'] = line
    return fields
