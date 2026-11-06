"""NSL-KDD network-traffic schema and attack-category mapping.

Shared by the training script (ml/train.py) and the API so both use
exactly the same feature order and labels.
"""

FEATURE_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
]
RAW_COLUMNS = FEATURE_COLUMNS + ["attack", "difficulty"]

CATEGORICAL_COLUMNS = ["protocol_type", "service", "flag"]
NUMERIC_COLUMNS = [c for c in FEATURE_COLUMNS if c not in CATEGORICAL_COLUMNS]

_ATTACK_GROUPS = {
    "DoS": [
        "back", "land", "neptune", "pod", "smurf", "teardrop", "apache2",
        "udpstorm", "processtable", "mailbomb", "worm",
    ],
    "Probe": ["satan", "ipsweep", "nmap", "portsweep", "mscan", "saint"],
    "R2L": [
        "guess_passwd", "ftp_write", "imap", "phf", "multihop", "warezmaster",
        "warezclient", "spy", "xlock", "xsnoop", "snmpguess", "snmpgetattack",
        "httptunnel", "sendmail", "named",
    ],
    "U2R": [
        "buffer_overflow", "loadmodule", "rootkit", "perl", "sqlattack",
        "xterm", "ps",
    ],
}
ATTACK_TO_CATEGORY = {
    attack: category
    for category, attacks in _ATTACK_GROUPS.items()
    for attack in attacks
}

CATEGORY_DESCRIPTIONS = {
    "Normal": "Benign network traffic",
    "DoS": "Denial-of-Service flood attempt",
    "Probe": "Port scan / network reconnaissance",
    "R2L": "Remote-to-local intrusion (unauthorised remote access)",
    "U2R": "User-to-root privilege escalation",
}


def to_category(attack_name: str) -> str:
    """Map a raw NSL-KDD attack label to one of the five categories."""
    name = attack_name.strip().lower()
    if name == "normal":
        return "Normal"
    return ATTACK_TO_CATEGORY.get(name, "R2L")
