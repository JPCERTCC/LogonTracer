#!/usr/bin/env python3
"""
Rule-based detections for LogonTracer.

Every detection works on one event at a time: ``DetectionEngine.process``
receives the EventID, the event time and a flat ``{field_name: value}`` dict
built from <EventData>. This keeps the logic independent of the log source
(EVTX/XML or Elasticsearch/winlogbeat) and unit-testable without Neo4j.

Results are kept as:
  * ``user_flags``: {"user@": {label: first_seen_str}}
  * ``host_flags``: {"ip_or_host": {label: first_seen_str}}

Window-based detections (Kerberoasting, password spraying, brute force,
explicit credentials) assume events arrive roughly in chronological order,
which is how EVTX files and the ES scan are read. Out-of-order input can only
make them miss a burst, never invent one.
"""

import re
from collections import defaultdict, deque

# --- Reference values ---------------------------------------------------------

# Extended rights used by DRSUAPI replication (DCSync).
# https://learn.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-get-changes
DCSYNC_GUIDS = (
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",  # DS-Replication-Get-Changes
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",  # DS-Replication-Get-Changes-All
    "89e95b76-444d-4c62-991a-0facbeda640c",  # DS-Replication-Get-Changes-In-Filtered-Set
)
# Control Access right
DCSYNC_ACCESS_MASK = 0x100

# SPN prefix registered by a rogue DC (DCShadow): DRS RPC interface GUID / Global Catalog
DCSHADOW_SPN_MARKERS = ("e3514235-4b06-11d1-ab04-00c04fc2dcd2", "gc/")
DCSHADOW_OBJECT_CLASSES = ("ntdsdsa", "server")

# Ticket encryption types considered weak (RC4)
WEAK_KERBEROS_ETYPES = ("0x17", "0x18", "23", "24")

# 4625 Status/SubStatus and 4771 FailureCode values that mean "wrong password"
# or "unknown user" (spraying/brute force), not lockouts or disabled accounts.
BAD_CREDENTIAL_CODES = ("0xc000006a", "0xc0000064", "0x18", "0x6")

# 5136 attributes whose modification is a known persistence / privilege path
SENSITIVE_LDAP_ATTRIBUTES = {
    "msds-keycredentiallink": "ShadowCredentials",
    "msds-allowedtoactonbehalfofotheridentity": "RBCD",
    "msds-allowedtodelegateto": "ConstrainedDelegation",
    "serviceprincipalname": "SPNChange",
    "gpcfilesyspath": "GPOChange",
    "scriptpath": "LogonScript",
    "sidhistory": "SIDHistory",
}
ADMINSDHOLDER_MARKER = "cn=adminsdholder,cn=system"

# Service image paths that are typical of remote execution tools
SUSPICIOUS_SERVICE_PATTERN = re.compile(
    r"(%comspec%|cmd(\.exe)?\s*/[ckr]|powershell|pwsh|\\\\127\.0\.0\.1\\|\\admin\$\\|"
    r"\\c\$\\|rundll32|regsvr32|mshta|-enc(odedcommand)?\s)",
    re.IGNORECASE,
)

DEFAULT_CONFIG = {
    # Accounts allowed to replicate besides DC machine accounts (regex, case-insensitive),
    # e.g. Entra Connect "MSOL_*" sync accounts.
    "dcsync_allowlist": r"\A(msol_[0-9a-f]+|aad_[0-9a-f]+|sync_.*)\Z",
    "kerberoast_threshold": 3,      # distinct RC4 service tickets per account ...
    "kerberoast_window": 300,       # ... within N seconds
    "spray_threshold": 10,          # distinct target accounts per source ...
    "spray_window": 600,            # ... within N seconds
    "bruteforce_threshold": 20,     # failures for one account ...
    "bruteforce_window": 600,       # ... within N seconds
    "explicit_creds_threshold": 3,  # distinct remote targets with 4648 ...
    "explicit_creds_window": 3600,  # ... within N seconds
    "reset_after_create_grace": 300,  # 4724 right after 4720 is the normal account creation flow
}

# Labels that lower the PageRank damping factor (more suspicious = rank higher)
HIGH_SEVERITY_LABELS = (
    "DCSync", "DCShadow", "Kerberoasting", "ASREPRoast", "PassTheHash",
    "PasswordSpray", "BruteForce", "ShadowCredentials", "RBCD",
    "ConstrainedDelegation", "AdminSDHolder", "SIDHistory", "SuspiciousService",
)


def _lower(value):
    return str(value).strip().lower() if value is not None else ""


def _parse_int(value):
    """Parse '0x100', '256' or '%%7688'-free numeric strings. Returns None on failure."""
    text = _lower(value)
    if not text:
        return None
    try:
        return int(text, 16) if text.startswith("0x") else int(text)
    except ValueError:
        return None


class DetectionEngine:
    def __init__(self, normalize_user, config=None, logger=None):
        """
        normalize_user: callable(raw_name) -> "user@" | "-" (same rules as the graph,
                        so flags match Username nodes).
        """
        self.normalize_user = normalize_user
        self.logger = logger
        self.config = dict(DEFAULT_CONFIG)
        if config:
            self.config.update({k: v for k, v in config.items() if v is not None})
        self._dcsync_allow = re.compile(self.config["dcsync_allowlist"], re.IGNORECASE)

        self.user_flags = defaultdict(dict)
        self.host_flags = defaultdict(dict)

        # sliding-window state
        self._kerb = defaultdict(deque)     # user -> deque[(ts, service)]
        self._spray = defaultdict(deque)    # source -> deque[(ts, user)]
        self._brute = defaultdict(deque)    # user -> deque[ts]
        self._explicit = defaultdict(deque)  # user -> deque[(ts, target)]
        self._created = {}                   # user -> creation timestamp (4720)

    # -- state helpers ---------------------------------------------------------

    def _flag_user(self, user, label, when):
        if user and user != "-" and label not in self.user_flags[user]:
            self.user_flags[user][label] = when

    def _flag_host(self, host, label, when):
        if host and host not in ("-", "::1", "127.0.0.1") and label not in self.host_flags[host]:
            self.host_flags[host][label] = when

    @staticmethod
    def _window_push(dq, ts, item, window):
        dq.append((ts, item))
        while dq and ts - dq[0][0] > window:
            dq.popleft()
        return len({entry[1] for entry in dq})

    @staticmethod
    def _source(fields):
        ip = _lower(fields.get("IpAddress")).replace("::ffff:", "")
        if ip and ip != "-":
            return ip
        ws = _lower(fields.get("WorkstationName") or fields.get("Workstation")).replace("\\", "")
        return ws or "-"

    # -- state persistence (for --add) ----------------------------------------

    def export_state(self):
        return {"user_flags": dict(self.user_flags), "host_flags": dict(self.host_flags)}

    def import_state(self, state):
        if not state:
            return
        for user, labels in state.get("user_flags", {}).items():
            self.user_flags[user].update(labels)
        for host, labels in state.get("host_flags", {}).items():
            self.host_flags[host].update(labels)

    # -- output helpers --------------------------------------------------------

    def user_status(self, user):
        return "".join("{0}({1}) ".format(label, when) for label, when in self.user_flags.get(user, {}).items())

    def host_status(self, host):
        return "".join("{0}({1}) ".format(label, when) for label, when in self.host_flags.get(host, {}).items())

    def high_severity_users(self):
        return {u for u, labels in self.user_flags.items() if any(l in HIGH_SEVERITY_LABELS for l in labels)}

    def high_severity_hosts(self):
        return {h for h, labels in self.host_flags.items() if any(l in HIGH_SEVERITY_LABELS for l in labels)}

    # -- main entry point --------------------------------------------------------

    def process(self, eventid, etime, fields):
        """Evaluate every rule for one event. ``etime`` is a datetime."""
        handler = self._handlers.get(eventid)
        if handler is None:
            return
        try:
            handler(self, etime, fields)
        except Exception as e:  # one malformed event must not stop the parse
            if self.logger:
                self.logger.debug("[!] Detection error on EventID {0}: {1}".format(eventid, e))

    # -- rules -----------------------------------------------------------------

    def _r4662_dcsync(self, etime, f):
        # T1003.006 - OS Credential Dumping: DCSync
        mask = _parse_int(f.get("AccessMask"))
        if mask is None or not (mask & DCSYNC_ACCESS_MASK):
            return
        props = _lower(f.get("Properties"))
        if not any(guid in props for guid in DCSYNC_GUIDS):
            return
        raw = (f.get("SubjectUserName") or "").split("@")[0]
        if not raw or raw.endswith("$") or self._dcsync_allow.search(raw):
            return  # DC machine accounts and allow-listed sync accounts replicate legitimately
        self._flag_user(self.normalize_user(raw), "DCSync", etime.strftime("%Y-%m-%d %H:%M:%S"))

    def _r5137_dcshadow(self, etime, f):
        # T1207 - Rogue Domain Controller (object creation/removal under Sites)
        oclass = _lower(f.get("ObjectClass"))
        odn = _lower(f.get("ObjectDN"))
        if oclass in DCSHADOW_OBJECT_CLASSES and "cn=sites,cn=configuration" in odn:
            user = self.normalize_user(f.get("SubjectUserName") or "")
            when = etime.strftime("%Y-%m-%d %H:%M:%S")
            self._flag_user(user, "DCShadow", when)
            if user == "-" and self.logger:
                self.logger.warning("[!] DCShadow indicator by machine account {0} at {1} ({2}).".format(
                    f.get("SubjectUserName"), when, f.get("ObjectDN")))

    def _r4742_dcshadow_spn(self, etime, f):
        # T1207 - SPN of a DC (DRS / GC) added to a computer account
        spns = _lower(f.get("ServicePrincipalNames"))
        if spns and spns != "-" and any(m in spns for m in DCSHADOW_SPN_MARKERS):
            # Legit for real DCs; only flag when changed by a user account (not SYSTEM/DC$).
            user = self.normalize_user(f.get("SubjectUserName") or "")
            self._flag_user(user, "DCShadow", etime.strftime("%Y-%m-%d %H:%M:%S"))

    def _r4769_kerberoast(self, etime, f):
        # T1558.003 - Kerberoasting
        etype = _lower(f.get("TicketEncryptionType"))
        service = _lower(f.get("ServiceName"))
        status = _lower(f.get("Status")) or "0x0"
        if etype not in WEAK_KERBEROS_ETYPES or status != "0x0":
            return
        if not service or service.endswith("$") or service.startswith("krbtgt"):
            return
        user = self.normalize_user(f.get("TargetUserName") or "")
        if user == "-":
            return
        distinct = self._window_push(self._kerb[user], etime.timestamp(), service, self.config["kerberoast_window"])
        if distinct >= int(self.config["kerberoast_threshold"]):
            when = etime.strftime("%Y-%m-%d %H:%M:%S")
            self._flag_user(user, "Kerberoasting", when)
            self._flag_host(self._source(f), "Kerberoasting", when)

    def _r4768_asrep(self, etime, f):
        # T1558.004 - AS-REP Roasting (TGT issued without pre-authentication)
        if _lower(f.get("PreAuthType")) != "0" or (_lower(f.get("Status")) or "0x0") != "0x0":
            return
        when = etime.strftime("%Y-%m-%d %H:%M:%S")
        self._flag_user(self.normalize_user(f.get("TargetUserName") or ""), "ASREPRoast", when)
        self._flag_host(self._source(f), "ASREPRoast", when)

    def _failed_logon(self, etime, f, codes):
        # T1110.003 Password Spraying / T1110.001 Password Guessing
        if not any(c in BAD_CREDENTIAL_CODES for c in codes):
            return
        user = self.normalize_user(f.get("TargetUserName") or "")
        if user == "-":
            return
        ts = etime.timestamp()
        when = etime.strftime("%Y-%m-%d %H:%M:%S")
        source = self._source(f)
        if source != "-":
            distinct = self._window_push(self._spray[source], ts, user, self.config["spray_window"])
            if distinct >= int(self.config["spray_threshold"]):
                self._flag_host(source, "PasswordSpray", when)
        dq = self._brute[user]
        dq.append((ts, ts))
        while dq and ts - dq[0][0] > self.config["bruteforce_window"]:
            dq.popleft()
        if len(dq) >= int(self.config["bruteforce_threshold"]):
            self._flag_user(user, "BruteForce", when)
            self._flag_host(source, "BruteForce", when)

    def _r4625(self, etime, f):
        self._failed_logon(etime, f, (_lower(f.get("Status")), _lower(f.get("SubStatus"))))

    def _r4771(self, etime, f):
        self._failed_logon(etime, f, (_lower(f.get("FailureCode")),))

    def _r4624(self, etime, f):
        user = self.normalize_user(f.get("TargetUserName") or "")
        when = etime.strftime("%Y-%m-%d %H:%M:%S")
        # T1550.002 - Pass the Hash (sekurlsa::pth / runas /netonly pattern)
        if (_lower(f.get("LogonType")) == "9" and _lower(f.get("LogonProcessName")) == "seclogo"
                and _lower(f.get("AuthenticationPackageName")) == "negotiate"):
            self._flag_user(user, "PassTheHash", when)
        # T1557.001 - downgrade / weak protocol
        if _lower(f.get("LmPackageName")) == "ntlm v1":
            self._flag_user(user, "NTLMv1", when)
            self._flag_host(self._source(f), "NTLMv1", when)

    def _r4648(self, etime, f):
        # T1021 / T1078 - explicit credentials towards several remote hosts
        target = _lower(f.get("TargetServerName"))
        if not target or target in ("-", "localhost", "127.0.0.1", "::1"):
            return
        user = self.normalize_user(f.get("SubjectUserName") or "")
        if user == "-":
            return
        distinct = self._window_push(self._explicit[user], etime.timestamp(), target,
                                     self.config["explicit_creds_window"])
        if distinct >= int(self.config["explicit_creds_threshold"]):
            self._flag_user(user, "ExplicitCredsMultiHost", etime.strftime("%Y-%m-%d %H:%M:%S"))

    def _r4697(self, etime, f):
        # T1543.003 / T1569.002 - service installed (PsExec-like lateral movement)
        user = self.normalize_user(f.get("SubjectUserName") or "")
        when = etime.strftime("%Y-%m-%d %H:%M:%S")
        image = f.get("ServiceFileName") or ""
        if SUSPICIOUS_SERVICE_PATTERN.search(image):
            self._flag_user(user, "SuspiciousService", when)
        else:
            self._flag_user(user, "ServiceInstall", when)

    def _r5136(self, etime, f):
        # T1098 / T1556 / T1484.001 - sensitive directory attribute modified
        if _lower(f.get("OperationType")) not in ("%%14674", "value added"):
            return
        user = self.normalize_user(f.get("SubjectUserName") or "")
        when = etime.strftime("%Y-%m-%d %H:%M:%S")
        attr = _lower(f.get("AttributeLDAPDisplayName"))
        if attr in SENSITIVE_LDAP_ATTRIBUTES:
            self._flag_user(user, SENSITIVE_LDAP_ATTRIBUTES[attr], when)
        if ADMINSDHOLDER_MARKER in _lower(f.get("ObjectDN")):
            self._flag_user(user, "AdminSDHolder", when)

    def _r4740(self, etime, f):
        # Context for T1110: account locked out
        self._flag_user(self.normalize_user(f.get("TargetUserName") or ""), "Lockout",
                        etime.strftime("%Y-%m-%d %H:%M:%S"))

    def _r4720(self, etime, f):
        # Not a detection: remembers creations so 4724 on a new account is not flagged
        target = self.normalize_user(f.get("TargetUserName") or "")
        if target != "-":
            self._created[target] = etime.timestamp()

    def _r4724(self, etime, f):
        # T1098 - password reset by another account
        subject = self.normalize_user(f.get("SubjectUserName") or "")
        target = self.normalize_user(f.get("TargetUserName") or "")
        created = self._created.get(target)
        if created is not None and 0 <= etime.timestamp() - created <= self.config["reset_after_create_grace"]:
            return
        if subject != "-" and subject != target:
            self._flag_user(subject, "PasswordReset", etime.strftime("%Y-%m-%d %H:%M:%S"))

    _handlers = {
        4624: _r4624,
        4625: _r4625,
        4648: _r4648,
        4662: _r4662_dcsync,
        4697: _r4697,
        4720: _r4720,
        4724: _r4724,
        4740: _r4740,
        4742: _r4742_dcshadow_spn,
        4768: _r4768_asrep,
        4769: _r4769_kerberoast,
        4771: _r4771,
        5136: _r5136,
        5137: _r5137_dcshadow,
        5141: _r5137_dcshadow,
    }


DETECTION_EVENT_IDS = sorted(DetectionEngine._handlers.keys())
