"""sigma-custom/ rules load and match with LogonTracer's own Sigma evaluator (synthetic events)."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.argv = ["logontracer.py"]

import pytest  # noqa: E402

lt = pytest.importorskip("logontracer")
etree = pytest.importorskip("lxml.etree")

SITES_DN = "CN=NTDS Settings,CN=PC01,CN=Servers,CN=S1,CN=Sites,CN=Configuration,DC=exemplo,DC=pt"
CASES = [
    (5137, dict(SubjectUserName="ana", ObjectClass="nTDSDSA", ObjectDN=SITES_DN), True),
    (5137, dict(SubjectUserName="DC01$", ObjectClass="nTDSDSA", ObjectDN=SITES_DN), False),
    (5137, dict(SubjectUserName="ana", ObjectClass="user", ObjectDN="OU=x,DC=exemplo,DC=pt"), False),
    (4742, dict(SubjectUserName="ana", ServicePrincipalNames="GC/pc01.exemplo.pt/exemplo.pt"), True),
    (4624, dict(TargetUserName="ana", LmPackageName="NTLM V1"), True),
    (4624, dict(TargetUserName="ana", LmPackageName="NTLM V2"), False),
    (5136, dict(SubjectUserName="ana", OperationType="%%14674", AttributeLDAPDisplayName="msDS-KeyCredentialLink",
                ObjectDN="CN=PC01,DC=exemplo,DC=pt"), True),
    (5136, dict(SubjectUserName="ana", OperationType="%%14674", AttributeLDAPDisplayName="description",
                ObjectDN="CN=AdminSDHolder,CN=System,DC=exemplo,DC=pt"), True),
    (5136, dict(SubjectUserName="ana", OperationType="%%14675", AttributeLDAPDisplayName="msDS-KeyCredentialLink",
                ObjectDN="x"), False),
]


@pytest.fixture(scope="module")
def rules():
    loaded, eids = lt.load_sigma(os.path.join(ROOT, "sigma-custom"))
    assert len(loaded) == 4
    return loaded


def _event(eid, fields):
    out = []
    for name, value in list(fields.items()) + [("EventID", str(eid))]:
        e = etree.Element("Data")
        e.set("Name", name)
        e.text = value
        out.append(e)
    return out


@pytest.mark.parametrize("eid,fields,expected", CASES)
def test_custom_rule(rules, eid, fields, expected):
    hits = [t for search, det, t, _, _ in rules if eid in search and lt.evaluate_sigma_condition(det, _event(eid, fields))]
    assert bool(hits) == expected
