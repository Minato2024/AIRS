ENTERPRISE_TACTICS = [
    {"id": "TA0043", "name": "Reconnaissance", "url": "https://attack.mitre.org/tactics/TA0043/", "technique_count": 10},
    {"id": "TA0042", "name": "Resource Development", "url": "https://attack.mitre.org/tactics/TA0042/", "technique_count": 8},
    {"id": "TA0001", "name": "Initial Access", "url": "https://attack.mitre.org/tactics/TA0001/", "technique_count": 11},
    {"id": "TA0002", "name": "Execution", "url": "https://attack.mitre.org/tactics/TA0002/", "technique_count": 16},
    {"id": "TA0003", "name": "Persistence", "url": "https://attack.mitre.org/tactics/TA0003/", "technique_count": 23},
    {"id": "TA0004", "name": "Privilege Escalation", "url": "https://attack.mitre.org/tactics/TA0004/", "technique_count": 14},
    {"id": "TA0005", "name": "Defense Evasion", "url": "https://attack.mitre.org/tactics/TA0005/", "technique_count": 45},
    {"id": "TA0006", "name": "Credential Access", "url": "https://attack.mitre.org/tactics/TA0006/", "technique_count": 17},
    {"id": "TA0007", "name": "Discovery", "url": "https://attack.mitre.org/tactics/TA0007/", "technique_count": 33},
    {"id": "TA0008", "name": "Lateral Movement", "url": "https://attack.mitre.org/tactics/TA0008/", "technique_count": 9},
    {"id": "TA0009", "name": "Collection", "url": "https://attack.mitre.org/tactics/TA0009/", "technique_count": 17},
    {"id": "TA0011", "name": "Command and Control", "url": "https://attack.mitre.org/tactics/TA0011/", "technique_count": 18},
    {"id": "TA0010", "name": "Exfiltration", "url": "https://attack.mitre.org/tactics/TA0010/", "technique_count": 9},
    {"id": "TA0040", "name": "Impact", "url": "https://attack.mitre.org/tactics/TA0040/", "technique_count": 15},
]

TACTIC_BY_ID = {item["id"]: item for item in ENTERPRISE_TACTICS}
TACTIC_BY_NAME = {item["name"]: item for item in ENTERPRISE_TACTICS}
TOTAL_ENTERPRISE_TACTICS = len(ENTERPRISE_TACTICS)
TOTAL_ENTERPRISE_TECHNIQUES = sum(item["technique_count"] for item in ENTERPRISE_TACTICS)

BASE_ATTACK_TYPE_MAPPINGS = {
    "reconnaissance": ("TA0043", "T1595", "Active Scanning"),
    "exploitation": ("TA0001", "T1190", "Exploit Public-Facing Application"),
    "privilege_escalation": ("TA0004", "T1068", "Exploitation for Privilege Escalation"),
    "lateral_movement": ("TA0008", "T1021", "Remote Services"),
    "exfiltration": ("TA0010", "T1041", "Exfiltration Over C2 Channel"),
    "denial_of_service": ("TA0040", "T1498", "Network Denial of Service"),
    "malware": ("TA0002", "T1204", "User Execution"),
    "brute_force": ("TA0006", "T1110", "Brute Force"),
}


def _mapping(tactic_id: str, technique_id: str, technique_name: str):
    tactic = TACTIC_BY_ID[tactic_id]
    return {
        "tactic": tactic["name"],
        "tactic_id": tactic_id,
        "tactic_url": tactic["url"],
        "technique": technique_name,
        "technique_id": technique_id,
        "technique_url": f"https://attack.mitre.org/techniques/{technique_id}/",
    }


def get_attack_mapping(attack_type: str):
    base = BASE_ATTACK_TYPE_MAPPINGS.get(attack_type)
    if not base:
        return None
    return _mapping(*base)


def resolve_attack_mapping(attack_type: str, log, features=None, signature_match=None):
    """
    Refine ATT&CK mapping from concrete behavior rather than only attack type.
    """
    features = features or {}
    meta = getattr(log, "meta_data", {}) or {}
    event_type = (getattr(log, "event_type", "") or "").lower()
    command = (getattr(log, "command", "") or "").lower()
    payload = (getattr(log, "payload", "") or "").lower()
    text = f"{command} {payload}"
    dest_port = getattr(log, "dest_port", 0) or 0

    if signature_match == "SIG-001" or event_type == "login_attempt":
        return _mapping("TA0006", "T1110.001", "Password Guessing")

    if any(token in text for token in ("wget", "curl ", "invoke-webrequest", "certutil", "bitsadmin")) or meta.get("dionaea_download_url"):
        return _mapping("TA0011", "T1105", "Ingress Tool Transfer")

    if any(token in text for token in ("powershell", "/bin/sh", "bash -c", "cmd.exe", "python -c", "sh -c")):
        return _mapping("TA0002", "T1059", "Command and Scripting Interpreter")

    if event_type == "file_upload":
        return _mapping("TA0009", "T1114", "Email Collection") if dest_port == 25 else _mapping("TA0011", "T1105", "Ingress Tool Transfer")

    if attack_type == "exploitation" and dest_port in {80, 443, 8080, 8443}:
        return _mapping("TA0001", "T1190", "Exploit Public-Facing Application")

    if attack_type == "lateral_movement" and dest_port in {22, 445, 3389, 139}:
        return _mapping("TA0008", "T1021", "Remote Services")

    if attack_type == "exfiltration" and (features.get("has_ftp_command") or "ftp" in text or "scp " in text or "sftp " in text):
        return _mapping("TA0010", "T1048", "Exfiltration Over Alternative Protocol")

    if attack_type == "exfiltration":
        return _mapping("TA0010", "T1041", "Exfiltration Over C2 Channel")

    if attack_type == "reconnaissance" and (dest_port in {80, 443, 8080} or features.get("protocol_count", 0) > 2):
        return _mapping("TA0043", "T1595", "Active Scanning")

    base = get_attack_mapping(attack_type)
    if base:
        return base

    if any(token in text for token in ("nmap", "masscan", "zmap")):
        return _mapping("TA0043", "T1595", "Active Scanning")

    return None


def resolve_attack_mappings(attack_type: str, log, features=None, signature_match=None):
    """
    Return a list of ATT&CK mappings ordered from strongest contextual fit to
    more general fallback mappings.
    """
    candidates = []
    seen = set()
    features = features or {}
    meta = getattr(log, "meta_data", {}) or {}
    event_type = (getattr(log, "event_type", "") or "").lower()
    command = (getattr(log, "command", "") or "").lower()
    payload = (getattr(log, "payload", "") or "").lower()
    text = f"{command} {payload}"
    dest_port = getattr(log, "dest_port", 0) or 0

    def add(mapping):
        if not mapping:
            return
        key = mapping["technique_id"]
        if key in seen:
            return
        seen.add(key)
        candidates.append(mapping)

    add(resolve_attack_mapping(attack_type, log, features=features, signature_match=signature_match))

    if signature_match == "SIG-001" or event_type == "login_attempt":
        add(_mapping("TA0006", "T1110.001", "Password Guessing"))
        add(_mapping("TA0001", "T1078", "Valid Accounts"))

    if any(token in text for token in ("curl ", "wget", "invoke-webrequest", "certutil", "bitsadmin")) or meta.get("dionaea_download_url"):
        add(_mapping("TA0011", "T1105", "Ingress Tool Transfer"))

    if any(token in text for token in ("powershell", "/bin/sh", "bash -c", "cmd.exe", "python -c", "sh -c")):
        add(_mapping("TA0002", "T1059", "Command and Scripting Interpreter"))

    if "chmod +x" in text or "chmod 777" in text:
        add(_mapping("TA0002", "T1222", "File and Directory Permissions Modification"))

    if any(token in text for token in ("scp ", "sftp ", "ftp ", "nc ", "netcat ")) or features.get("has_ftp_command"):
        add(_mapping("TA0010", "T1048", "Exfiltration Over Alternative Protocol"))

    if dest_port in {445, 139, 3389, 22} and attack_type in {"lateral_movement", "exploitation"}:
        add(_mapping("TA0008", "T1021", "Remote Services"))

    if dest_port in {80, 443, 8080, 8443} and attack_type == "exploitation":
        add(_mapping("TA0001", "T1190", "Exploit Public-Facing Application"))

    if attack_type == "reconnaissance":
        add(_mapping("TA0043", "T1595", "Active Scanning"))

    if attack_type == "malware":
        add(_mapping("TA0005", "T1204", "User Execution"))

    add(get_attack_mapping(attack_type))
    return candidates
