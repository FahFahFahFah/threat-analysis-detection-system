import re

def decode_ssh_line(line: str) -> dict:
    """
    Extract fields from SSH log lines.
    """
    patterns = [
        (r'Failed password for (invalid user )?(\S+) from (\S+)', ['user', 'srcip']),
        (r'Invalid user (\S+) from (\S+)', ['user', 'srcip']),
        (r'Accepted password for (\S+) from (\S+)', ['user', 'srcip']),
        (r'User (\S+) from (\S+)', ['user', 'srcip']),
    ]
    for pattern, fields in patterns:
        match = re.search(pattern, line)
        if match:
            values = match.groups()
            return {k: v for k, v in zip(fields, values) if v}
    return {'message': line}
