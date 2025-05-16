import re

def decode_sudo_line(line: str) -> dict:
    """
    Extract sudo usage data including srcuser, dstuser, command.
    """
    fields = {}
    # Match username before colon
    user_match = re.search(r'^\s*(\S+)\s*:', line)
    if user_match:
        fields['srcuser'] = user_match.group(1)
    # Extract standard sudo fields
    for field, pattern in {
        'tty': r'TTY=(\S+)',
        'pwd': r'PWD=(\S+)',
        'dstuser': r'USER=(\S+)',
        'command': r'COMMAND=(.+)',
    }.items():
        match = re.search(pattern, line)
        if match:
            fields[field] = match.group(1)
    fields['message'] = line
    return fields
