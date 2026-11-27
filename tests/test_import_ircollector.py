"""tools/import_ircollector.py and tools/ltcase.py with synthetic IR-Collector collections.

No real data: host names and the EVTX body are placeholders. The EVTX is only
the 8-byte magic plus padding; parsing by LogonTracer is not exercised here.
"""
import hashlib
import os
import stat
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

import pytest  # noqa: E402

import import_ircollector as iri  # noqa: E402
import ltcase  # noqa: E402

EVTX = b"ElfFile\x00" + b"\x00" * 4088
REL = "02_eventlogs\\pre_execution\\Security.evtx"


def manifest(host, sha, rel=REL):
    return ("=" * 70 + "\nIR COLLECTOR v4.64.0 -- CHAIN OF CUSTODY\n" + "=" * 70 + "\n"
            "Hostname   : {0}\nUTC Start  : 2026-11-20 10:15:00\n\n{1}  {2}\n"
            "{3}  01_live\\processes.csv\n").format(host, sha, rel, "a" * 64)


def make_folder(base, name, host, body=EVTX, sha=None, with_manifest=True, phase2=False):
    d = os.path.join(base, name)
    sub = os.path.join(d, "02_eventlogs") if phase2 else os.path.join(d, "02_eventlogs", "pre_execution")
    os.makedirs(sub)
    with open(os.path.join(sub, "Security.evtx"), "wb") as f:
        f.write(body)
    if with_manifest:
        rel = "02_eventlogs\\Security.evtx" if phase2 else REL
        with open(os.path.join(d, "MANIFEST.txt"), "w", encoding="utf-8-sig") as f:
            f.write(manifest(host, sha or hashlib.sha256(body).hexdigest(), rel))
    return d


def make_zip(base, name, host, entry_prefix=None, body=EVTX):
    top = entry_prefix if entry_prefix is not None else name + "/"
    path = os.path.join(base, name + ".zip")
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr(top + "02_eventlogs/pre_execution/Security.evtx", body)
        zf.writestr(top + "MANIFEST.txt", manifest(host, hashlib.sha256(body).hexdigest()))
    return path


@pytest.fixture
def store(tmp_path):
    return str(tmp_path / "store")


def test_folder_ok_stored_read_only(tmp_path, store):
    col = make_folder(str(tmp_path), "WS01_20261120_101500", "WS01")
    rows = iri.store_collections([col], store)
    assert rows[0]["Estado"] == "ARMAZENADO" and rows[0]["Manifest"] == "OK"
    dst = os.path.join(store, "evtx", rows[0]["Ficheiro"])
    assert stat.S_IMODE(os.stat(dst).st_mode) == 0o444
    with open(dst, "rb") as f:
        assert f.read() == EVTX


def test_tampered_evidence_refused(tmp_path, store):
    col = make_folder(str(tmp_path), "WS01_20261120_101500", "WS01", sha="b" * 64)
    rows = iri.store_collections([col], store)
    assert rows[0]["Estado"] == "RECUSADO" and "MANIFEST" in rows[0]["Motivo"]
    assert iri.select_latest(store) == ([], [])


def test_without_manifest_needs_flag(tmp_path, store):
    col = make_folder(str(tmp_path), "WS01_20261120_101500", "WS01", with_manifest=False)
    assert iri.store_collections([col], store)[0]["Estado"] == "RECUSADO"
    rows = iri.store_collections([col], store, allow_unverified=True)
    assert rows[0]["Estado"] == "ARMAZENADO" and "SEM_MANIFEST" in rows[0]["Motivo"]


def test_not_evtx_refused(tmp_path, store):
    col = make_folder(str(tmp_path), "WS01_20261120_101500", "WS01", body=b"MZ" + b"\x00" * 100)
    rows = iri.store_collections([col], store)
    assert rows[0]["Estado"] == "RECUSADO" and "EVTX" in rows[0]["Motivo"]


def test_zip_top_folder_and_manifest_hostname(tmp_path, store):
    z = make_zip(str(tmp_path), "renamed", "SRV01", entry_prefix="SRV01_20261121_090000/")
    rows = iri.store_collections([z], store)
    assert rows[0]["Estado"] == "ARMAZENADO"
    assert rows[0]["Host"] == "SRV01" and rows[0]["Carimbo"] == "20261121_090000"


def test_zip_path_traversal_refused(tmp_path, store):
    z = make_zip(str(tmp_path), "evil", "X", entry_prefix="../")
    rows = iri.store_collections([z], store)
    assert rows[0]["Estado"] == "RECUSADO" and "inseguro" in rows[0]["Motivo"]
    assert not os.path.exists(os.path.join(str(tmp_path), "02_eventlogs"))


def test_symlinked_evtx_refused(tmp_path, store):
    outside = tmp_path / "outside.evtx"
    outside.write_bytes(EVTX)
    d = tmp_path / "WS09_20261120_101500" / "02_eventlogs" / "pre_execution"
    d.mkdir(parents=True)
    os.symlink(str(outside), str(d / "Security.evtx"))
    rows = iri.store_collections([str(tmp_path / "WS09_20261120_101500")], store, allow_unverified=True)
    assert rows[0]["Estado"] == "RECUSADO"


def test_same_hash_not_stored_twice(tmp_path, store):
    col = make_folder(str(tmp_path), "WS01_20261120_101500", "WS01")
    iri.store_collections([col], store)
    assert iri.store_collections([col], store)[0]["Estado"] == "JA_EXISTE"
    assert len(os.listdir(os.path.join(store, "evtx"))) == 1


def test_one_collection_per_host_latest_wins(tmp_path, store):
    a = make_folder(str(tmp_path), "WS01_20261120_101500", "WS01", body=EVTX + b"1")
    b = make_folder(str(tmp_path), "WS01_20261122_080000", "WS01", body=EVTX + b"2")
    c = make_folder(str(tmp_path), "DC01_20261121_120000", "DC01", body=EVTX + b"3")
    iri.store_collections([b, a, c], store)
    selected, discarded = iri.select_latest(store)
    assert [(h, s) for h, s, _ in selected] == [("DC01", "20261121_120000"), ("WS01", "20261122_080000")]
    assert [(h, s) for h, s, _ in discarded] == [("WS01", "20261120_101500")]


def test_phase2_only_with_flag(tmp_path, store):
    col = make_folder(str(tmp_path), "WS02_20261120_101500", "WS02", phase2=True)
    assert iri.store_collections([col], store)[0]["Estado"] == "RECUSADO"
    rows = iri.store_collections([col], store, allow_phase2=True)
    assert rows[0]["Estado"] == "ARMAZENADO" and "fase 2" in rows[0]["Motivo"]


def test_formula_host_neutralised_in_ledger(tmp_path, store):
    col = make_folder(str(tmp_path), "x_20261120_101500", "=HYPERLINK(1)")
    iri.store_collections([col], store)
    with open(os.path.join(store, iri.LEDGER), encoding="utf-8") as f:
        text = f.read()
    assert ",=" not in text
    assert iri.select_latest(store)[0][0][0] == "_HYPERLINK_1_"


def test_logontracer_cmd_has_no_password():
    cmd = iri.logontracer_cmd(["/s/a.evtx"], "localhost", "17687", "neo4j")
    assert "-p" not in cmd and "--password" not in cmd
    assert cmd[2:5] == ["--delete", "-e", "/s/a.evtx"] and "17687" in cmd


def test_run_requires_password_env(tmp_path, store, monkeypatch):
    monkeypatch.delenv("LOGONTRACER_NEO4J_PASSWORD", raising=False)
    col = make_folder(str(tmp_path), "WS01_20261120_101500", "WS01")
    assert iri.main([col, "--store", store, "--run"]) == 2


# -- ltcase --------------------------------------------------------------------

def test_ltcase_new_env_private_and_ports_distinct(tmp_path, monkeypatch):
    monkeypatch.setattr(ltcase, "port_free", lambda p: True)
    root = str(tmp_path / "cases")
    assert ltcase.main(["--root", root, "new", "cliente-a"]) == 0
    assert ltcase.main(["--root", root, "new", "cliente-b"]) == 0
    ea, eb = (ltcase.read_env(os.path.join(root, c, ".env")) for c in ("cliente-a", "cliente-b"))
    assert stat.S_IMODE(os.stat(os.path.join(root, "cliente-a", ".env")).st_mode) == 0o600
    assert ea["LT_WEB_PORT"] != eb["LT_WEB_PORT"] and ea["LT_BOLT_PORT"] != eb["LT_BOLT_PORT"]
    assert ea["NEO4J_PASSWORD"] != eb["NEO4J_PASSWORD"] and len(ea["NEO4J_PASSWORD"]) >= 32
    assert ea["LT_PROJECT"] == "lt_cliente_a"


def test_ltcase_rejects_bad_names(tmp_path):
    for bad in ("../x", "A", "Cliente", "x" * 40, "a b"):
        with pytest.raises(SystemExit):
            ltcase.main(["--root", str(tmp_path), "new", bad])


def test_ltcase_import_dry_run(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(ltcase, "port_free", lambda p: True)
    root = str(tmp_path / "cases")
    ltcase.main(["--root", root, "new", "caso1"])
    col = make_folder(str(tmp_path), "WS01_20261120_101500", "WS01")
    assert ltcase.main(["--root", root, "import", "caso1", col, "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "-p lt_caso1" in out and ":/evidencia/evtx:ro" in out and "--delete -e /evidencia/evtx/WS01_" in out
    env = ltcase.read_env(os.path.join(root, "caso1", ".env"))
    assert env["NEO4J_PASSWORD"] not in out
    # nothing new: no rebuild unless asked
    assert ltcase.main(["--root", root, "import", "caso1", col, "--dry-run"]) == 0
    assert "nada de novo" in capsys.readouterr().out


def test_ltcase_rm_is_dry_run_without_confirm(tmp_path, monkeypatch):
    monkeypatch.setattr(ltcase, "port_free", lambda p: True)
    root = str(tmp_path / "cases")
    ltcase.main(["--root", root, "new", "caso1"])
    assert ltcase.main(["--root", root, "rm", "caso1"]) == 0
    assert os.path.isfile(os.path.join(root, "caso1", ".env"))
    assert ltcase.main(["--root", root, "rm", "caso1", "--confirm", "outro"]) == 0
    assert os.path.isfile(os.path.join(root, "caso1", ".env"))


def test_ltcase_new_reuses_evidence_after_rm(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(ltcase, "port_free", lambda p: True)
    monkeypatch.setattr(ltcase, "run", lambda cmd, dry=False: 0)
    root = str(tmp_path / "cases")
    ltcase.main(["--root", root, "new", "caso1"])
    col = make_folder(str(tmp_path), "WS01_20261120_101500", "WS01")
    ltcase.main(["--root", root, "import", "caso1", col])
    old_pw = ltcase.read_env(os.path.join(root, "caso1", ".env"))["NEO4J_PASSWORD"]
    assert ltcase.main(["--root", root, "rm", "caso1", "--confirm", "caso1"]) == 0
    assert not os.path.exists(os.path.join(root, "caso1", ".env"))
    assert ltcase.main(["--root", root, "new", "caso1"]) == 0
    assert "reaproveitada" in capsys.readouterr().out
    assert ltcase.read_env(os.path.join(root, "caso1", ".env"))["NEO4J_PASSWORD"] != old_pw
    assert len(iri.select_latest(os.path.join(root, "caso1", "evidencia"))[0]) == 1
    with pytest.raises(SystemExit):
        ltcase.main(["--root", root, "new", "caso1"])
