#!/usr/bin/env python3
"""ltcase -- one isolated LogonTracer + Neo4j Community instance per case.

Neo4j Community has a single user database, so LogonTracer's own case management
(one database per case) needs Enterprise. ltcase gives each case its own docker
compose project instead: its own Neo4j volume, parse cache, random passwords and
ports, all published on 127.0.0.1. Data of two clients never share a database.

  ltcase.py new <case>                     create the case (no containers yet)
  ltcase.py up <case> | down <case>        start / stop (data is kept)
  ltcase.py import <case> <collections...> verify + store IR-Collector evidence,
                                           rebuild the graph (one collection per host)
  ltcase.py list                           cases, ports, state
  ltcase.py info <case>                    URL and where the credentials are
  ltcase.py rm <case> [--confirm <case>]   DESTRUCTIVE: dry-run unless confirmed

Layout: <root>/<case>/.env (0600: ports + passwords), <root>/<case>/evidencia/
(evidence store + IMPORT_IRCOLLECTOR.csv). Root: --root, $LTCASE_ROOT, or
<LogonTracer>/cases. The graph is always rebuilt from evidencia/, so a removed
instance is recoverable from that folder alone.
Requires Docker with the compose plugin. Tested with Python 3.13 on Linux.
"""
import argparse
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
COMPOSE_FILE = os.path.join(REPO, "docker-compose-case", "docker-compose.yml")
CASE_RX = re.compile(r"\A[a-z0-9][a-z0-9-]{1,30}\Z")
WEB_BASE, BOLT_BASE, MAX_SLOTS = 18080, 17687, 200

sys.path.insert(0, HERE)
import import_ircollector as iri  # noqa: E402


def die(msg, code=2):
    print("[!] " + msg, file=sys.stderr)
    sys.exit(code)


def root_dir(args):
    return os.path.abspath(args.root or os.environ.get("LTCASE_ROOT") or os.path.join(REPO, "cases"))


def check_case(name):
    if not CASE_RX.match(name or ""):
        die("nome de caso invalido: 2-31 caracteres [a-z0-9-], a comecar por letra ou digito")
    return name


def read_env(path):
    env = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                env[k.strip()] = v.strip()
    return env


def case_paths(root, case):
    d = os.path.join(root, case)
    return d, os.path.join(d, ".env"), os.path.join(d, "evidencia")


def existing_cases(root):
    out = []
    if os.path.isdir(root):
        for name in sorted(os.listdir(root)):
            envp = os.path.join(root, name, ".env")
            if CASE_RX.match(name) and os.path.isfile(envp):
                out.append((name, read_env(envp)))
    return out


def port_free(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def allocate_ports(root, is_free=port_free):
    used = set()
    for _, env in existing_cases(root):
        for k in ("LT_WEB_PORT", "LT_BOLT_PORT"):
            if env.get(k, "").isdigit():
                used.add(int(env[k]))
    for slot in range(MAX_SLOTS):
        web, bolt = WEB_BASE + slot, BOLT_BASE + slot
        if web not in used and bolt not in used and is_free(web) and is_free(bolt):
            return web, bolt
    die("sem portas livres em {0}-{1}".format(WEB_BASE, WEB_BASE + MAX_SLOTS))


def write_env(path, case, web, bolt):
    content = (
        "# ltcase -- caso {case}. Contem passwords: nao copiar, nao versionar.\n"
        "LT_PROJECT=lt_{proj}\n"
        "LT_WEB_PORT={web}\n"
        "LT_BOLT_PORT={bolt}\n"
        "NEO4J_PASSWORD={npw}\n"
        "LOGONTRACER_DEFAULT_PASSWORD={lpw}\n"
        "LT_NEO4J_HEAP=1G\n"
        "LT_NEO4J_PAGECACHE=512M\n"
    ).format(case=case, proj=case.replace("-", "_"), web=web, bolt=bolt,
             npw=secrets.token_urlsafe(24), lpw=secrets.token_urlsafe(24))
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(content)


def compose(envp, *extra):
    project = read_env(envp).get("LT_PROJECT", "")
    if not re.fullmatch(r"lt_[a-z0-9_]{2,31}", project):
        die("LT_PROJECT invalido em {0}".format(envp))
    return ["docker", "compose", "-p", project, "--env-file", envp, "-f", COMPOSE_FILE] + list(extra)


def run(cmd, dry=False):
    print("+ " + " ".join(cmd))
    if dry:
        return 0
    if shutil.which(cmd[0]) is None:
        die("{0} nao encontrado".format(cmd[0]))
    return subprocess.call(cmd)


def need_case(root, case):
    d, envp, store = case_paths(root, check_case(case))
    if not os.path.isfile(envp):
        die("caso {0} nao existe em {1} (ltcase.py new {0})".format(case, root))
    return d, envp, store


# -- commands ------------------------------------------------------------------

def cmd_new(args):
    root = root_dir(args)
    d, envp, store = case_paths(root, check_case(args.case))
    reuse = False
    if os.path.exists(envp):
        die("caso {0} ja existe: {1}".format(args.case, d))
    if os.path.exists(d):
        # Left by `rm` without --purge-evidence: new instance, same evidence store.
        if not os.path.isdir(store) or os.path.islink(d):
            die("{0} existe e nao e um caso ltcase".format(d))
        reuse = True
    os.makedirs(root, mode=0o700, exist_ok=True)
    os.makedirs(d, mode=0o700, exist_ok=True)
    os.makedirs(store, mode=0o750, exist_ok=True)
    web, bolt = allocate_ports(root)
    write_env(envp, args.case, web, bolt)
    print("[+] caso {0}: web http://127.0.0.1:{1}  bolt 127.0.0.1:{2}".format(args.case, web, bolt))
    print("[+] credenciais em {0} (0600)".format(envp))
    if reuse:
        print("[+] evidencia existente reaproveitada; reconstruir o grafo: ltcase.py import {0} --rebuild".format(args.case))
    return 0


def cmd_up(args):
    _, envp, _ = need_case(root_dir(args), args.case)
    rc = run(compose(envp, "up", "-d", "--wait"), args.dry_run)
    if rc == 0 and not args.dry_run:
        print("[+] http://127.0.0.1:{0}".format(read_env(envp)["LT_WEB_PORT"]))
    return rc


def cmd_down(args):
    _, envp, _ = need_case(root_dir(args), args.case)
    return run(compose(envp, "stop"), args.dry_run)


def import_command(envp, store, selected):
    """docker compose run of logontracer.py over the store, mounted read-only."""
    files = ["/evidencia/evtx/" + os.path.basename(p) for _, _, p in selected]
    return compose(envp, "run", "--rm", "--no-deps", "-T",
                   "-v", "{0}:/evidencia/evtx:ro".format(os.path.join(store, "evtx")),
                   "logontracer", "python", "logontracer.py", "--delete", "-e", *files,
                   "-s", "neo4j", "-u", "neo4j")


def cmd_import(args):
    _, envp, store = need_case(root_dir(args), args.case)
    rows = iri.store_collections(args.recolhas, store, args.max_mb, args.allow_unverified, args.allow_phase2)
    for r in rows:
        print("[{0}] {1} -> {2} {3}".format(r["Estado"], r["Recolha"], r.get("Host", "?"), r.get("Motivo", "")).rstrip())
    selected, discarded = iri.select_latest(store)
    for host, stamp, _ in discarded:
        print("[DESCARTADA] {0} {1} (ha recolha mais recente do mesmo host)".format(host, stamp or "-"))
    for host, stamp, path in selected:
        print("[SELECCIONADA] {0} {1} {2}".format(host, stamp or "-", os.path.basename(path)))
    if not selected:
        die("nenhuma recolha armazenada para importar")
    if not any(r["Estado"] == "ARMAZENADO" for r in rows) and not args.rebuild:
        print("[=] nada de novo; o grafo nao foi reconstruido (--rebuild para forcar)")
        return 1 if any(r["Estado"] == "RECUSADO" for r in rows) else 0
    rc = run(compose(envp, "up", "-d", "--wait", "neo4j"), args.dry_run)
    if rc != 0:
        return rc
    rc = run(import_command(envp, store, selected), args.dry_run)
    if rc == 0 and any(r["Estado"] == "RECUSADO" for r in rows):
        return 1
    return rc


def cmd_list(args):
    root = root_dir(args)
    cases = existing_cases(root)
    if not cases:
        print("(sem casos em {0})".format(root))
        return 0
    states = {}
    if shutil.which("docker"):
        try:
            out = subprocess.run(["docker", "ps", "--format", "{{.Label \"com.docker.compose.project\"}}"],
                                 capture_output=True, text=True, timeout=20).stdout
            states = {p.strip() for p in out.splitlines() if p.strip()}
        except (OSError, subprocess.SubprocessError):
            states = set()
    print("{0:<32} {1:>6} {2:>6} {3:>6}  {4}".format("CASO", "WEB", "BOLT", "HOSTS", "ESTADO"))
    for name, env in cases:
        sel, _ = iri.select_latest(os.path.join(root, name, "evidencia"))
        st = "a correr" if env.get("LT_PROJECT") in states else "parado"
        print("{0:<32} {1:>6} {2:>6} {3:>6}  {4}".format(name, env.get("LT_WEB_PORT"), env.get("LT_BOLT_PORT"), len(sel), st))
    return 0


def cmd_info(args):
    d, envp, store = need_case(root_dir(args), args.case)
    env = read_env(envp)
    print("caso       : {0}".format(args.case))
    print("web        : http://127.0.0.1:{0}  (login: neo4j / NEO4J_PASSWORD do .env)".format(env["LT_WEB_PORT"]))
    print("bolt       : 127.0.0.1:{0}".format(env["LT_BOLT_PORT"]))
    print("credenciais: {0}".format(envp))
    print("evidencia  : {0}".format(store))
    return 0


def cmd_rm(args):
    root = root_dir(args)
    d, envp, store = need_case(root, args.case)
    destroy = args.confirm == args.case
    print("[!] DESTRUTIVO: remove contentores e volumes (grafo + cache) do caso {0}".format(args.case))
    print("    evidencia/ {0}".format("tambem e APAGADA (--purge-evidence)" if args.purge_evidence else "fica (o grafo reconstroi-se dela)"))
    if not destroy:
        print("[dry-run] nada foi alterado. Para executar: ltcase.py rm {0} --confirm {0}".format(args.case))
        run(compose(envp, "down", "-v", "--remove-orphans"), dry=True)
        return 0
    rc = run(compose(envp, "down", "-v", "--remove-orphans"))
    if rc != 0:
        return rc
    if args.purge_evidence:
        shutil.rmtree(d)
        print("[+] pasta do caso apagada: {0}".format(d))
    else:
        os.remove(envp)
        print("[+] instancia removida; evidencia mantida em {0}".format(store))
    return 0


def build_parser():
    ap = argparse.ArgumentParser(prog="ltcase.py", description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("--root", help="pasta dos casos (defeito: $LTCASE_ROOT ou <LogonTracer>/cases)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("new", "up", "down", "info"):
        p = sub.add_parser(name)
        p.add_argument("case")
        if name in ("up", "down"):
            p.add_argument("--dry-run", action="store_true")
    p = sub.add_parser("import")
    p.add_argument("case")
    p.add_argument("recolhas", nargs="*")
    p.add_argument("--max-mb", type=int, default=4096)
    p.add_argument("--allow-unverified", action="store_true")
    p.add_argument("--allow-phase2", action="store_true")
    p.add_argument("--rebuild", action="store_true", help="reconstruir mesmo sem recolhas novas")
    p.add_argument("--dry-run", action="store_true", help="armazena e selecciona, mas nao corre o docker")
    sub.add_parser("list")
    p = sub.add_parser("rm")
    p.add_argument("case")
    p.add_argument("--confirm", metavar="CASO", help="repetir o nome do caso para executar")
    p.add_argument("--purge-evidence", action="store_true", help="apagar tambem evidencia/")
    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)
    return {"new": cmd_new, "up": cmd_up, "down": cmd_down, "import": cmd_import,
            "list": cmd_list, "info": cmd_info, "rm": cmd_rm}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
