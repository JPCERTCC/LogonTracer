"""Unit tests for detection.py (synthetic events only, no real data).

Run: python -m pytest tests/
"""
import datetime
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detection import DetectionEngine  # noqa: E402

T0 = datetime.datetime(2026, 1, 1, 10, 0, 0)
GET_CHANGES_ALL = "{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}"


def norm(raw):
    user = str(raw).split("@")[0]
    return "-" if not user or user.endswith("$") else user.lower() + "@"


def engine(**cfg):
    return DetectionEngine(norm, cfg)


def at(seconds):
    return T0 + datetime.timedelta(seconds=seconds)


# --- DCSync -------------------------------------------------------------------

def test_dcsync_requires_replication_guid_and_control_access():
    e = engine()
    # Ordinary 4662 (e.g. reading an object) must not be DCSync, however many times
    for i in range(10):
        e.process(4662, at(i), {"SubjectUserName": "ana", "AccessMask": "0x10",
                                "Properties": "%%7684 {bf967aba-0de6-11d0-a285-00aa003049e2}"})
    assert "DCSync" not in e.user_flags.get("ana@", {})


def test_dcsync_single_event_is_enough():
    e = engine()
    e.process(4662, at(0), {"SubjectUserName": "ana", "AccessMask": "0x100",
                            "Properties": "%%7688 " + GET_CHANGES_ALL})
    assert "DCSync" in e.user_flags["ana@"]


def test_dcsync_ignores_dc_machine_accounts_and_allowlist():
    e = engine()
    for user in ("DC01$", "MSOL_0123abcd"):
        e.process(4662, at(0), {"SubjectUserName": user, "AccessMask": "0x100", "Properties": GET_CHANGES_ALL})
    assert not e.user_flags


# --- DCShadow -----------------------------------------------------------------

def test_dcshadow_ignores_regular_object_creation():
    e = engine()
    for i in range(5):  # several creations in the same second (old heuristic flagged this)
        e.process(5137, at(0), {"SubjectUserName": "ana", "ObjectClass": "user",
                                "ObjectDN": "CN=x,OU=Users,DC=exemplo,DC=pt"})
    assert not e.user_flags


def test_dcshadow_ntdsdsa_under_sites():
    e = engine()
    e.process(5137, at(0), {"SubjectUserName": "ana", "ObjectClass": "nTDSDSA",
                            "ObjectDN": "CN=NTDS Settings,CN=PC01,CN=Servers,CN=Default-First-Site-Name,"
                                        "CN=Sites,CN=Configuration,DC=exemplo,DC=pt"})
    assert "DCShadow" in e.user_flags["ana@"]


def test_dcshadow_spn_on_computer():
    e = engine()
    e.process(4742, at(0), {"SubjectUserName": "ana",
                            "ServicePrincipalNames": "GC/pc01.exemplo.pt/exemplo.pt"})
    assert "DCShadow" in e.user_flags["ana@"]


# --- Kerberos -----------------------------------------------------------------

def test_kerberoasting_threshold_and_window():
    e = engine(kerberoast_threshold=3, kerberoast_window=300)
    base = {"TargetUserName": "ana@EXEMPLO.PT", "TicketEncryptionType": "0x17", "Status": "0x0",
            "IpAddress": "::ffff:192.0.2.10"}
    e.process(4769, at(0), dict(base, ServiceName="svc_sql"))
    e.process(4769, at(1), dict(base, ServiceName="svc_web"))
    assert not e.user_flags
    e.process(4769, at(2), dict(base, ServiceName="svc_bkp"))
    assert "Kerberoasting" in e.user_flags["ana@"]
    assert "Kerberoasting" in e.host_flags["192.0.2.10"]


def test_kerberoasting_ignores_aes_machine_and_krbtgt():
    e = engine(kerberoast_threshold=1)
    e.process(4769, at(0), {"TargetUserName": "ana", "ServiceName": "svc_sql", "TicketEncryptionType": "0x12"})
    e.process(4769, at(1), {"TargetUserName": "ana", "ServiceName": "PC01$", "TicketEncryptionType": "0x17"})
    e.process(4769, at(2), {"TargetUserName": "ana", "ServiceName": "krbtgt", "TicketEncryptionType": "0x17"})
    assert not e.user_flags


def test_kerberoasting_outside_window():
    e = engine(kerberoast_threshold=2, kerberoast_window=60)
    base = {"TargetUserName": "ana", "TicketEncryptionType": "0x17"}
    e.process(4769, at(0), dict(base, ServiceName="a"))
    e.process(4769, at(120), dict(base, ServiceName="b"))
    assert not e.user_flags


def test_asrep_roasting():
    e = engine()
    e.process(4768, at(0), {"TargetUserName": "ana", "PreAuthType": "2", "Status": "0x0"})
    assert not e.user_flags
    e.process(4768, at(1), {"TargetUserName": "rui", "PreAuthType": "0", "Status": "0x0",
                            "IpAddress": "192.0.2.20"})
    assert "ASREPRoast" in e.user_flags["rui@"]


# --- Password spraying / brute force ------------------------------------------

def test_password_spray_from_one_source():
    e = engine(spray_threshold=5, spray_window=600)
    for i in range(5):
        e.process(4625, at(i), {"TargetUserName": "user%d" % i, "Status": "0xc000006d",
                                "SubStatus": "0xc000006a", "IpAddress": "192.0.2.30"})
    assert "PasswordSpray" in e.host_flags["192.0.2.30"]


def test_kerberos_preauth_spray_4771():
    e = engine(spray_threshold=3)
    for i in range(3):
        e.process(4771, at(i), {"TargetUserName": "user%d" % i, "FailureCode": "0x18",
                                "IpAddress": "::ffff:192.0.2.31"})
    assert "PasswordSpray" in e.host_flags["192.0.2.31"]


def test_lockout_codes_do_not_count_as_spray():
    e = engine(spray_threshold=2)
    for i in range(3):  # 0xc0000234 = account locked out
        e.process(4625, at(i), {"TargetUserName": "user%d" % i, "SubStatus": "0xc0000234",
                                "IpAddress": "192.0.2.32"})
    assert not e.host_flags


def test_bruteforce_single_account():
    e = engine(bruteforce_threshold=4)
    for i in range(4):
        e.process(4625, at(i), {"TargetUserName": "ana", "SubStatus": "0xc000006a", "IpAddress": "192.0.2.33"})
    assert "BruteForce" in e.user_flags["ana@"]


# --- Logon anomalies ------------------------------------------------------------

def test_pass_the_hash_seclogo():
    e = engine()
    e.process(4624, at(0), {"TargetUserName": "ana", "LogonType": "9", "LogonProcessName": "seclogo",
                            "AuthenticationPackageName": "Negotiate"})
    assert "PassTheHash" in e.user_flags["ana@"]


def test_ntlmv1():
    e = engine()
    e.process(4624, at(0), {"TargetUserName": "ana", "LogonType": "3", "LmPackageName": "NTLM V1",
                            "IpAddress": "192.0.2.40"})
    assert "NTLMv1" in e.user_flags["ana@"]
    assert "NTLMv1" in e.host_flags["192.0.2.40"]


def test_explicit_credentials_multiple_hosts():
    e = engine(explicit_creds_threshold=3)
    for i, host in enumerate(("srv1.exemplo.pt", "srv2.exemplo.pt", "localhost", "srv3.exemplo.pt")):
        e.process(4648, at(i), {"SubjectUserName": "ana", "TargetServerName": host})
    assert "ExplicitCredsMultiHost" in e.user_flags["ana@"]


# --- Persistence / AD changes -------------------------------------------------

def test_service_install_suspicious_path():
    e = engine()
    e.process(4697, at(0), {"SubjectUserName": "ana", "ServiceName": "abc",
                            "ServiceFileName": "%COMSPEC% /Q /c echo x > \\\\127.0.0.1\\C$\\x"})
    assert "SuspiciousService" in e.user_flags["ana@"]
    e.process(4697, at(1), {"SubjectUserName": "rui", "ServiceFileName": "C:\\Program Files\\Agent\\agent.exe"})
    assert "ServiceInstall" in e.user_flags["rui@"]


def test_5136_shadow_credentials_and_adminsdholder():
    e = engine()
    e.process(5136, at(0), {"SubjectUserName": "ana", "OperationType": "%%14674",
                            "AttributeLDAPDisplayName": "msDS-KeyCredentialLink",
                            "ObjectDN": "CN=PC01,OU=Computers,DC=exemplo,DC=pt"})
    e.process(5136, at(1), {"SubjectUserName": "rui", "OperationType": "%%14674",
                            "AttributeLDAPDisplayName": "nTSecurityDescriptor",
                            "ObjectDN": "CN=AdminSDHolder,CN=System,DC=exemplo,DC=pt"})
    # value deleted (%%14675) is not flagged
    e.process(5136, at(2), {"SubjectUserName": "eva", "OperationType": "%%14675",
                            "AttributeLDAPDisplayName": "msDS-KeyCredentialLink"})
    assert "ShadowCredentials" in e.user_flags["ana@"]
    assert "AdminSDHolder" in e.user_flags["rui@"]
    assert "eva@" not in e.user_flags


# --- Engine behaviour ---------------------------------------------------------

def test_state_roundtrip_and_status_string():
    e = engine()
    e.process(4740, at(0), {"TargetUserName": "ana"})
    state = e.export_state()
    e2 = engine()
    e2.import_state(state)
    assert e2.user_status("ana@") == "Lockout(2026-01-01 10:00:00) "


def test_malformed_event_does_not_raise():
    e = engine()
    e.process(4662, at(0), {"AccessMask": None, "Properties": None})
    e.process(4769, at(0), {})
    e.process(9999, at(0), {"x": "y"})
    assert not e.user_flags


def test_high_severity_sets():
    e = engine()
    e.process(4740, at(0), {"TargetUserName": "ana"})  # context only
    e.process(4624, at(0), {"TargetUserName": "rui", "LogonType": "9", "LogonProcessName": "seclogo",
                            "AuthenticationPackageName": "Negotiate"})
    assert e.high_severity_users() == {"rui@"}


def test_password_reset_after_creation_is_not_flagged():
    e = engine()
    e.process(4720, at(0), {"SubjectUserName": "admin", "TargetUserName": "nova"})
    e.process(4724, at(1), {"SubjectUserName": "admin", "TargetUserName": "nova"})
    assert "admin@" not in e.user_flags
    e.process(4724, at(1000), {"SubjectUserName": "admin", "TargetUserName": "nova"})
    assert "PasswordReset" in e.user_flags["admin@"]
