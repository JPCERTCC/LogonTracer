"""/upload and /esload: input validation and how the parser subprocess is launched."""
import inspect
import io
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.argv = ["logontracer.py"]

import pytest  # noqa: E402

lt = pytest.importorskip("logontracer")
SECRET = "Synthetic-Test-Pass-123"


@pytest.fixture
def launched(monkeypatch, tmp_path):
    calls = []

    class FakePopen:
        def __init__(self, cmd, **kw):
            calls.append((cmd, kw))

    monkeypatch.setattr(lt.subprocess, "Popen", FakePopen)
    monkeypatch.setattr(lt, "get_neo4j_creds", lambda: ("analyst", SECRET))
    monkeypatch.setattr(lt, "FPATH", str(tmp_path))
    (tmp_path / "static").mkdir()
    return calls


def _call(view, path, data, **kw):
    fn = inspect.unwrap(view)
    with lt.app.test_request_context(path, method="POST", data=data, **kw):
        return fn()


def _es(**over):
    data = {"fromdatetime": "false", "todatetime": "false", "timezone": "0", "es_server": "192.0.2.5:9200",
            "addlog": "false", "casename": "case01", "addes": "false"}
    data.update(over)
    return data


def test_esload_password_not_in_argv(launched):
    assert _call(lt.es_load, "/esload", _es()) == "SUCCESS"
    cmd, kw = launched[0]
    assert SECRET not in cmd and "-p" not in cmd
    assert kw["env"][lt.NEO4J_PASSWORD_ENV] == SECRET
    assert "--delete" in cmd


@pytest.mark.parametrize("server", ["host:9200", "local:9200", ":9200", "192.0.2.5"])
def test_esload_rejects_bad_server(launched, server):
    assert _call(lt.es_load, "/esload", _es(es_server=server)) == "FAIL"
    assert not launched


def test_esload_localhost_ok(launched):
    assert _call(lt.es_load, "/esload", _es(es_server="localhost:9200")) == "SUCCESS"


@pytest.mark.parametrize("value", ["", "t", "rue"])
def test_esload_partial_true_is_not_true(launched, value):
    assert _call(lt.es_load, "/esload", _es(addlog=value, addes=value)) == "SUCCESS"
    cmd, _ = launched[0]
    assert "--delete" in cmd and "--add" not in cmd and "--postes" not in cmd


def test_esload_empty_date_rejected(launched):
    # "" used to be accepted as "false" ('"" not in "false"' is False) -> now it must parse as a date
    assert _call(lt.es_load, "/esload", _es(fromdatetime="")) == "FAIL"


def test_upload_password_not_in_argv(launched):
    data = {"timezone": "0", "logtype": "EVTX", "addlog": "true", "sigmascan": "",
            "casename": "case01", "file0": (io.BytesIO(b"ElfFile\x00"), "x.evtx")}
    assert _call(lt.do_upload, "/upload", data, content_type="multipart/form-data") == "SUCCESS"
    cmd, kw = launched[0]
    assert SECRET not in cmd
    assert kw["env"][lt.NEO4J_PASSWORD_ENV] == SECRET
    assert "--add" in cmd and "--sigma" not in cmd


def test_credentials_endpoint_not_cacheable(monkeypatch):
    monkeypatch.setattr(lt, "get_neo4j_creds", lambda: ("analyst", SECRET))
    with lt.app.test_request_context("/api/neo4j/credentials"):
        resp = inspect.unwrap(lt.neo4j_credentials)()
    assert "no-store" in resp.headers["Cache-Control"]


def test_forwarded_host_ignored_by_default(monkeypatch):
    monkeypatch.delenv("LOGONTRACER_TRUST_PROXY", raising=False)
    monkeypatch.delenv("LOGONTRACER_BROWSER_NEO4J_SERVER", raising=False)
    with lt.app.test_request_context("/", headers={"Host": "lt.exemplo.pt", "X-Forwarded-Host": "evil.example"}):
        assert lt._browser_neo4j_server() == "lt.exemplo.pt"
    monkeypatch.setenv("LOGONTRACER_TRUST_PROXY", "1")
    with lt.app.test_request_context("/", headers={"Host": "lt.exemplo.pt", "X-Forwarded-Host": "proxy.exemplo.pt"}):
        assert lt._browser_neo4j_server() == "proxy.exemplo.pt"
