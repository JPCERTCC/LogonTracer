"""Regression tests for parser/detection bug fixes (import logontracer.py; no Neo4j needed).

Run: python -m pytest tests/
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.argv = ["logontracer.py"]

import pytest  # noqa: E402

pd = pytest.importorskip("pandas")
lt = pytest.importorskip("logontracer")

GET_CHANGES = "{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}"
GET_CHANGES_ALL = "{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}"


# --- PageRank -----------------------------------------------------------------

def test_pagerank_no_substring_edges():
    events = pd.DataFrame({"ipaddress": ["192.0.2.1", "192.0.2.12"], "username": ["ana@", "joana@"]})
    ranks = lt.pagerank(events, [], {}, {}, [])
    # Two disconnected, symmetric components -> identical ranks per role
    assert ranks["192.0.2.1"] == pytest.approx(ranks["192.0.2.12"])
    assert ranks["ana@"] == pytest.approx(ranks["joana@"])


def test_pagerank_uniform_graph_no_zero_division():
    # Single node -> max == min: the old normalisation divided by zero
    events = pd.DataFrame({"ipaddress": ["192.0.2.1"], "username": ["192.0.2.1"]})
    assert set(lt.pagerank(events, [], {}, {}, []).values()) == {0.0}


def test_pagerank_empty_event_set():
    events = pd.DataFrame({"ipaddress": [], "username": []})
    assert lt.pagerank(events, [], {}, {}, []) == {}


def test_pagerank_ntlm_lowers_damping():
    events = pd.DataFrame({"ipaddress": ["192.0.2.1", "192.0.2.2"], "username": ["ana@", "rui@"]})
    ranks = lt.pagerank(events, [], {}, {}, ["rui@"])
    assert ranks["rui@"] != pytest.approx(ranks["ana@"])


# --- DCSync (4662) ------------------------------------------------------------

def _4662(**kw):
    fields = {"SubjectUserName": "mallory", "AccessMask": "0x100",
              "Properties": "%%7688 " + GET_CHANGES_ALL + " {19195a5b-6da0-11d0-afd3-00c04fd930c9}"}
    fields.update(kw)
    return fields


def test_dcsync_replication_right():
    assert lt.is_dcsync(_4662())
    assert lt.is_dcsync(_4662(Properties=GET_CHANGES.upper()))


def test_dcsync_ignores_ordinary_object_access():
    # A plain read of an object (no replication GUID): the old check flagged this
    assert not lt.is_dcsync(_4662(Properties="{bf967aba-0de6-11d0-a285-00aa003049e2}"))
    # Replication GUID but no Control Access right
    assert not lt.is_dcsync(_4662(AccessMask="0x10"))
    assert not lt.is_dcsync(_4662(AccessMask=None))
    assert not lt.is_dcsync(_4662(AccessMask="garbage"))


def test_dcsync_ignores_dc_machine_accounts():
    assert not lt.is_dcsync(_4662(SubjectUserName="DC01$"))


# --- DCShadow (5137 / 5141) ---------------------------------------------------

def test_dcshadow_ntdsdsa_under_sites():
    assert lt.is_dcshadow({"ObjectClass": "nTDSDSA",
                           "ObjectDN": "CN=NTDS Settings,CN=WS01,CN=Servers,CN=Default-First-Site-Name,"
                                       "CN=Sites,CN=Configuration,DC=exemplo,DC=pt"})
    assert lt.is_dcshadow({"ObjectClass": "server",
                           "ObjectDN": "CN=WS01,CN=Servers,CN=Default-First-Site-Name,"
                                       "CN=Sites,CN=Configuration,DC=exemplo,DC=pt"})


def test_dcshadow_ignores_ordinary_objects():
    assert not lt.is_dcshadow({"ObjectClass": "user", "ObjectDN": "CN=ana,CN=Users,DC=exemplo,DC=pt"})
    assert not lt.is_dcshadow({"ObjectClass": "groupPolicyContainer", "ObjectDN": None})
    assert not lt.is_dcshadow({})


# --- helpers ------------------------------------------------------------------

def test_subject_user_normalisation():
    assert lt.subject_user({"SubjectUserName": "Ana"}) == "ana@"
    assert lt.subject_user({"SubjectUserName": "ana@exemplo.pt"}) == "ana@"
    assert lt.subject_user({"SubjectUserName": "DC01$"}) == "-"
    assert lt.subject_user({"SubjectUserName": None}) == "-"
    assert lt.subject_user({}) == "-"


def test_field_data_shim_matches_lxml_interface():
    d = lt._FieldData("LogonType", 3)
    assert d.get("Name") == "LogonType" and d.text == "3"
    assert lt._FieldData("Status", None).text is None
