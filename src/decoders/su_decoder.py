import re

def decode_su_line(line: str) -> dict:
    """
    Extract SU user transitions or failures.
    """
    patterns = [
        (r"FAILED su for (\S+) by (\S+)", ['dstuser', 'srcuser']),
        (r"BAD SU (\S+) to (\S+)", ['srcuser', 'dstuser']),
        (r"^'su (\S+)' .* for (\S+) on", ['dstuser', 'srcuser']),
    ]
    for pattern, fields in patterns:
        match = re.search(pattern, line)
        if match:
            values = match.groups()
            return {k: v for k, v in zip(fields, values)}
    return {'message': line}
