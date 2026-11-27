#!/usr/bin/env python3
"""Import IR-Collector collections (folders or ZIPs) into LogonTracer.

Each IR-Collector collection holds 02_eventlogs/pre_execution/Security.evtx, the
Security log exported BEFORE the collector changed the host, with its SHA256 in
MANIFEST.txt. This tool:

  1. finds that EVTX in each collection (folder <HOST>_<YYYYMMDD_HHMMSS> or .zip);
  2. checks the EVTX magic and the SHA256 against MANIFEST.txt (mismatch = refused);
  3. copies it, read-only, into an evidence store: <store>/evtx/<HOST>_<STAMP>.evtx;
  4. records every decision in <store>/IMPORT_IRCOLLECTOR.csv (custody ledger);
  5. selects ONE collection per host, the most recent (same rule as Compare-IRFrota.ps1);
  6. with --run, rebuilds the LogonTracer graph from that selection
     (logontracer.py --delete -e ...): the graph is always a function of the store,
     so a later collection of the same host never double-counts events.

Only the Python standard library is used for steps 1-5. ZIPs are never extracted
as a whole: only the selected entry is streamed, with path and size checks.
The Neo4j password is read from LOGONTRACER_NEO4J_PASSWORD, never from argv.
Tested with Python 3.13 on Linux.
"""
import argparse
import csv
import datetime
import hashlib
import os
import re
import stat
import subprocess
import sys
import tempfile
import zipfile

EVTX_MAGIC = b"ElfFile\x00"
PRE_EXEC = "02_eventlogs/pre_execution/security.evtx"
PHASE2 = "02_eventlogs/security.evtx"
NAME_RX = re.compile(r"^(?P<host>.+)_(?P<stamp>\d{8}_\d{6})$")
MANIFEST_LINE_RX = re.compile(r"^(?P<hash>[0-9a-fA-F]{64}|ERROR_HASH)\s{2}(?P<path>.+?)\s*$")
SAFE_HOST_RX = re.compile(r"[^A-Za-z0-9._-]")
LEDGER = "IMPORT_IRCOLLECTOR.csv"
LEDGER_FIELDS = ["DataUTC", "Recolha", "Host", "Carimbo", "Origem", "Entrada", "SHA256",
                 "Manifest", "Bytes", "Estado", "Motivo", "Ficheiro"]
CHUNK = 1024 * 1024


class Refused(Exception):
    """The collection cannot be used as evidence; the reason goes to the ledger."""


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def csv_cell(value):
    """Neutralise spreadsheet formulas (CWE-1236): host names come from the investigated host."""
    value = "" if value is None else str(value)
    return "'" + value if value[:1] in ("=", "+", "-", "@", "\t", "\r") else value


def norm(path):
    return path.replace("\\", "/").strip("/").lower()


def parse_manifest(text):
    """MANIFEST.txt -> ({normalised relative path: sha256}, header dict)."""
    text = text.lstrip("﻿")
    hashes, header = {}, {}
    for line in text.splitlines():
        m = MANIFEST_LINE_RX.match(line)
        if m:
            hashes[norm(m.group("path"))] = m.group("hash").lower()
            continue
        if ":" in line and not line.startswith(" "):
            key, _, val = line.partition(":")
            header[key.strip()] = val.strip()
    return hashes, header


def identity(name, header):
    """(host, stamp) from the folder name, completed by the MANIFEST header."""
    m = NAME_RX.match(name)
    host = m.group("host") if m else name
    stamp = m.group("stamp") if m else ""
    if header.get("Hostname"):
        host = header["Hostname"]
    if not stamp and header.get("UTC Start"):
        try:
            stamp = datetime.datetime.strptime(header["UTC Start"], "%Y-%m-%d %H:%M:%S").strftime("%Y%m%d_%H%M%S")
        except ValueError:
            stamp = ""
    host = SAFE_HOST_RX.sub("_", host)[:63] or "SEM_NOME"
    return host, stamp


def copy_hash(src, dst, max_bytes):
    """Stream src -> dst, return (sha256, bytes). Checks the EVTX magic and the size cap."""
    h = hashlib.sha256()
    total = 0
    with open(dst, "wb") as out:
        first = True
        while True:
            chunk = src.read(CHUNK)
            if not chunk:
                break
            if first:
                if chunk[:8] != EVTX_MAGIC:
                    raise Refused("cabecalho nao e EVTX")
                first = False
            total += len(chunk)
            if total > max_bytes:
                raise Refused("excede o tecto de {0} MB".format(max_bytes // CHUNK))
            h.update(chunk)
            out.write(chunk)
    if total == 0:
        raise Refused("ficheiro vazio")
    return h.hexdigest(), total


def _tmpfile(staging):
    fd, path = tempfile.mkstemp(dir=staging, suffix=".part")
    os.close(fd)
    return path


def _zip_entry_safe(info):
    name = info.filename.replace("\\", "/")
    if name.startswith("/") or re.match(r"^[A-Za-z]:", name) or ".." in name.split("/"):
        raise Refused("entrada ZIP com caminho inseguro: {0}".format(info.filename))
    if stat.S_ISLNK(info.external_attr >> 16):
        raise Refused("entrada ZIP e um symlink: {0}".format(info.filename))


def _pick(names, allow_phase2):
    """names: {normalised relative path: original}. Returns (origin, key) or None."""
    for origin, suffix in (("pre_execution", PRE_EXEC), ("fase2", PHASE2)):
        if origin == "fase2" and not allow_phase2:
            break
        hits = sorted((k for k in names if k == suffix or k.endswith("/" + suffix)), key=len)
        if hits:
            return origin, hits[0]
    return None


def extract(collection, staging, max_bytes, allow_phase2):
    """Copy the Security.evtx of one collection into staging. Returns a result dict."""
    res = {"Recolha": os.path.basename(collection.rstrip("/\\"))}
    if os.path.isdir(collection):
        if os.path.islink(collection):
            raise Refused("a recolha e um symlink")
        root = os.path.realpath(collection)
        names = {}
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(dirpath, d))]
            for f in filenames:
                rel = os.path.relpath(os.path.join(dirpath, f), root)
                names[norm(rel)] = rel
        pick = _pick(names, allow_phase2)
        if not pick:
            raise Refused("sem 02_eventlogs/pre_execution/Security.evtx")
        origin, key = pick
        path = os.path.join(root, names[key])
        if os.path.islink(path) or not os.path.realpath(path).startswith(root + os.sep):
            raise Refused("Security.evtx fora da recolha (symlink)")
        manifest_path = os.path.join(root, "MANIFEST.txt")
        manifest = None
        if os.path.isfile(manifest_path) and not os.path.islink(manifest_path):
            with open(manifest_path, "r", encoding="utf-8-sig", errors="replace") as fm:
                manifest = fm.read()
        name = os.path.basename(root)
        tmp = _tmpfile(staging)
        with open(path, "rb") as src:
            sha, size = copy_hash(src, tmp, max_bytes)
        rel_in_collection = key
    elif zipfile.is_zipfile(collection):
        with zipfile.ZipFile(collection) as zf:
            infos = {}
            for info in zf.infolist():
                if info.is_dir():
                    continue
                infos[norm(info.filename)] = info
            pick = _pick(infos, allow_phase2)
            if not pick:
                raise Refused("sem 02_eventlogs/pre_execution/Security.evtx")
            origin, key = pick
            info = infos[key]
            _zip_entry_safe(info)
            suffix = PRE_EXEC if origin == "pre_execution" else PHASE2
            prefix = key[:-len(suffix)]  # "" or "<HOST>_<TS>/"
            rel_in_collection = key[len(prefix):]
            name = prefix.strip("/").split("/")[-1] if prefix else os.path.splitext(res["Recolha"])[0]
            manifest = None
            minfo = infos.get(prefix + "manifest.txt")
            if minfo is not None:
                _zip_entry_safe(minfo)
                if minfo.file_size > 64 * CHUNK:
                    raise Refused("MANIFEST.txt excede 64 MB")
                manifest = zf.read(minfo).decode("utf-8-sig", errors="replace")
            if info.file_size > max_bytes:
                raise Refused("excede o tecto de {0} MB".format(max_bytes // CHUNK))
            tmp = _tmpfile(staging)
            with zf.open(info) as src:
                sha, size = copy_hash(src, tmp, max_bytes)
    else:
        raise Refused("nao e pasta nem ZIP")

    hashes, header = parse_manifest(manifest) if manifest is not None else ({}, {})
    host, stamp = identity(name, header)
    if manifest is None:
        mstate = "SEM_MANIFEST"
    elif rel_in_collection not in hashes:
        mstate = "AUSENTE_NO_MANIFEST"
    elif hashes[rel_in_collection] == sha:
        mstate = "OK"
    else:
        mstate = "DIVERGE"
    res.update(Host=host, Carimbo=stamp, Origem=origin, Entrada=rel_in_collection,
               SHA256=sha, Manifest=mstate, Bytes=size, _tmp=tmp)
    return res


def read_ledger(store):
    path = os.path.join(store, LEDGER)
    if not os.path.isfile(path):
        return []
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def append_ledger(store, rows):
    path = os.path.join(store, LEDGER)
    new = not os.path.isfile(path)
    with open(path, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=LEDGER_FIELDS, extrasaction="ignore")
        if new:
            w.writeheader()
        for r in rows:
            w.writerow({k: csv_cell(r.get(k, "")) for k in LEDGER_FIELDS})


def store_collections(collections, store, max_mb=4096, allow_unverified=False, allow_phase2=False):
    """Verify and copy each collection into the store. Returns the ledger rows written."""
    evtx_dir = os.path.join(store, "evtx")
    os.makedirs(evtx_dir, mode=0o755, exist_ok=True)
    known = {r["SHA256"] for r in read_ledger(store) if r.get("Estado") == "ARMAZENADO"}
    rows = []
    with tempfile.TemporaryDirectory(dir=store, prefix=".staging-") as staging:
        for col in collections:
            row = {"DataUTC": utc_now(), "Recolha": os.path.basename(col.rstrip("/\\"))}
            try:
                r = extract(col, staging, max_mb * CHUNK, allow_phase2)
                row.update({k: v for k, v in r.items() if not k.startswith("_")})
                if r["Manifest"] == "DIVERGE":
                    raise Refused("SHA256 nao bate com o MANIFEST.txt -- evidencia alterada depois da recolha")
                if r["Manifest"] != "OK" and not allow_unverified:
                    raise Refused("integridade nao verificavel ({0}); usar --allow-unverified para aceitar".format(r["Manifest"]))
                if r["SHA256"] in known:
                    row.update(Estado="JA_EXISTE", Motivo="mesmo SHA256 ja armazenado")
                else:
                    stamp = r["Carimbo"] or "SEMCARIMBO"
                    fname = "{0}_{1}_{2}.evtx".format(r["Host"], stamp, r["SHA256"][:12])
                    dst = os.path.join(evtx_dir, fname)
                    os.replace(r["_tmp"], dst)
                    os.chmod(dst, 0o444)
                    known.add(r["SHA256"])
                    motivo = []
                    if r["Origem"] == "fase2":
                        motivo.append("Security.evtx da fase 2 (inclui actividade da propria recolha)")
                    if r["Manifest"] != "OK":
                        motivo.append("aceite sem verificacao: " + r["Manifest"])
                    row.update(Estado="ARMAZENADO", Motivo="; ".join(motivo), Ficheiro=fname)
            except Refused as e:
                row.update(Estado="RECUSADO", Motivo=str(e))
            except (OSError, zipfile.BadZipFile) as e:
                row.update(Estado="RECUSADO", Motivo="erro de leitura: {0}".format(e.__class__.__name__))
            rows.append(row)
    append_ledger(store, rows)
    return rows


def select_latest(store):
    """One file per host: the stored collection with the most recent stamp.
    Returns (selected [(host, stamp, path)], discarded [(host, stamp, file)])."""
    best, discarded = {}, []
    for r in read_ledger(store):
        if r.get("Estado") != "ARMAZENADO":
            continue
        path = os.path.join(store, "evtx", r["Ficheiro"].lstrip("'"))
        if not os.path.isfile(path):
            continue
        host, stamp = r["Host"].lstrip("'"), r["Carimbo"]
        cur = best.get(host.lower())
        if cur is None or stamp > cur[1]:
            if cur is not None:
                discarded.append(cur)
            best[host.lower()] = (host, stamp, path)
        else:
            discarded.append((host, stamp, path))
    return sorted(best.values()), sorted(discarded)


def logontracer_cmd(files, server, port, user, case=None, python=sys.executable, script=None):
    script = script or os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logontracer.py")
    cmd = [python, script, "--delete", "-e"] + list(files) + ["-s", server, "--wsport", str(port), "-u", user]
    if case:
        cmd += ["--case", case]
    return cmd


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("recolhas", nargs="*", help="pastas <HOST>_<AAAAMMDD_HHMMSS> e/ou .zip do IR-Collector")
    ap.add_argument("--store", required=True, help="repositorio de evidencia do caso (criado se nao existir)")
    ap.add_argument("--max-mb", type=int, default=4096, help="tecto por Security.evtx (MB, defeito 4096)")
    ap.add_argument("--allow-unverified", action="store_true",
                    help="aceitar recolhas sem MANIFEST.txt ou sem a linha do EVTX (fica no ledger)")
    ap.add_argument("--allow-phase2", action="store_true",
                    help="sem snapshot pre_execution, usar o Security.evtx da fase 2 (tem ruido da recolha)")
    ap.add_argument("--run", action="store_true", help="reconstruir o grafo com o logontracer.py local")
    ap.add_argument("-s", "--server", default="localhost", help="Neo4j (defeito localhost)")
    ap.add_argument("--wsport", default="7687", help="porta Bolt (defeito 7687)")
    ap.add_argument("-u", "--user", default="neo4j")
    ap.add_argument("--case", help="base Neo4j (so Enterprise; em Community fica a 'neo4j')")
    args = ap.parse_args(argv)

    if not re.fullmatch(r"[0-9]{1,5}", str(args.wsport)):
        ap.error("--wsport tem de ser um numero de porta")
    if args.case and not re.fullmatch(r"[0-9a-zA-Z]{2,20}", args.case):
        ap.error("--case: 2-20 caracteres alfanumericos")
    os.makedirs(args.store, mode=0o750, exist_ok=True)

    if args.recolhas:
        rows = store_collections(args.recolhas, args.store, args.max_mb, args.allow_unverified, args.allow_phase2)
        for r in rows:
            print("[{0}] {1} -> {2} {3}".format(r["Estado"], r["Recolha"], r.get("Host", "?"), r.get("Motivo", "")).rstrip())
    selected, discarded = select_latest(args.store)
    for host, stamp, _ in discarded:
        print("[DESCARTADA] {0} {1} (existe recolha mais recente do mesmo host)".format(host, stamp or "-"))
    for host, stamp, path in selected:
        print("[SELECCIONADA] {0} {1} {2}".format(host, stamp or "-", os.path.basename(path)))
    refused = sum(1 for r in (rows if args.recolhas else []) if r["Estado"] == "RECUSADO")

    if args.run:
        if not selected:
            print("[!] nada para importar", file=sys.stderr)
            return 2
        if not os.environ.get("LOGONTRACER_NEO4J_PASSWORD"):
            print("[!] definir LOGONTRACER_NEO4J_PASSWORD (a password nunca vai na linha de comandos)", file=sys.stderr)
            return 2
        env = dict(os.environ, LOGONTRACER_CACHE_DIR=os.path.join(os.path.abspath(args.store), "cache"))
        cmd = logontracer_cmd([p for _, _, p in selected], args.server, args.wsport, args.user, args.case)
        print("[+] reconstruir o grafo com {0} host(s)".format(len(selected)))
        rc = subprocess.call(cmd, env=env)
        if rc != 0:
            return rc
    return 1 if refused else 0


if __name__ == "__main__":
    sys.exit(main())
