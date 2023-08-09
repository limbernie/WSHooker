"""patterns.py

Django's URLValidator regex patterns.
"""
import re

# Copied from Django's URLValidator class
UNICODE = "\u00a1-\uffff"

# IP regex pattern
IPV4_PATTERN = (
    r"(?:0|25[0-5]|2[0-4][0-9]|1[0-9]?[0-9]?|[1-9][0-9]?)"
    r"(?:\.(?:0|25[0-5]|2[0-4][0-9]|1[0-9]?[0-9]?|[1-9][0-9]?)){3}"
)
IPV6_PATTERN = r"\[[0-9a-f:.]+\]"

# Host regex pattern
HOSTNAME_PATTERN = "".join(
    [
        r"[a-z",
        UNICODE,
        r"0-9](?:[a-z",
        UNICODE,
        r"0-9-]{0,61}[a-z",
        UNICODE,
        r"0-9])?",
    ]
)

# Max length for domain name labels is 63 characters
# per RFC 1034 sec. 3.1
DOMAIN_PATTERN = "".join([r"(?:\.(?!-)[a-z", UNICODE, r"0-9-]{1,63}(?<!-))*"])
TLD_PATTERN = (
    r"\."
    r"(?!-)"
    r"(?:[a-z" + UNICODE + "-]{2,63}"
    r"|xn--[a-z0-9]{1,59})"
    r"(?<!-)"
    r"\.?"
)
HOST_PATTERN = "".join(
    ["(", HOSTNAME_PATTERN, DOMAIN_PATTERN, TLD_PATTERN, "|localhost)"]
)

URL_RE = re.compile(
    r"(?:['\"]?)"
    r"(?:https?|ftps?)://"
    r"(?:[^\s:@/]+(?::[^\s:@/]*)?@)?"
    r"(?:" + IPV4_PATTERN + "|" + IPV6_PATTERN + "|" + HOST_PATTERN + ")"
    r"(?::[0-9]{1,5})?"
    r"(?:[/?#][^,\s]*)?"
    r"(?:['\"]?)",
    re.IGNORECASE,
)

DOMAIN_RE = re.compile(r"(?:['\"]?)" r"(?:" + HOST_PATTERN + ")")

IP_RE = re.compile("".join([r"(?:", IPV4_PATTERN, ")"]))
