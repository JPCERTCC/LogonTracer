#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# LICENSE
# https://github.com/JPCERTCC/LogonTracer/blob/master/LICENSE.txt
#

import os
import re
import sys
import argparse
import datetime
import secrets
import threading
from functools import wraps
from logging import getLogger
from logging.config import dictConfig

# Lazy import flags - check availability without importing heavy modules
has_lxml = False
has_evtx = False
has_neo4j = False
has_numpy = False
has_changefinder = False
has_flask = False
has_pandas = False
has_hmmlearn = False
has_sklearn = False
has_es = False
has_pyyaml = False
has_flask_login = False
has_flask_sqlalchemy = False
has_flask_wtf = False
has_flask_limiter = False
has_git = False
has_sigma = False


def utc_now():
    """Return a timezone-aware UTC datetime."""
    return datetime.datetime.now(datetime.timezone.utc)


def utc_now_naive():
    """Return a naive UTC datetime for legacy database fields."""
    return utc_now().replace(tzinfo=None)

# Check availability of optional modules
try:
    import importlib.util
    has_lxml = importlib.util.find_spec("lxml") is not None
    has_evtx = importlib.util.find_spec("evtx") is not None
    has_neo4j = importlib.util.find_spec("neo4j") is not None
    has_numpy = importlib.util.find_spec("numpy") is not None
    has_changefinder = importlib.util.find_spec("changefinder") is not None
    has_flask = importlib.util.find_spec("flask") is not None
    has_pandas = importlib.util.find_spec("pandas") is not None
    has_hmmlearn = importlib.util.find_spec("hmmlearn") is not None
    has_sklearn = importlib.util.find_spec("joblib") is not None
    has_es = importlib.util.find_spec("elasticsearch") is not None
    has_pyyaml = importlib.util.find_spec("yaml") is not None
    has_flask_login = importlib.util.find_spec("flask_login") is not None
    has_flask_sqlalchemy = importlib.util.find_spec("flask_sqlalchemy") is not None
    has_flask_wtf = importlib.util.find_spec("flask_wtf") is not None
    has_flask_limiter = importlib.util.find_spec("flask_limiter") is not None
    has_git = importlib.util.find_spec("git") is not None
    has_sigma = importlib.util.find_spec("sigma") is not None
except:
    # Fallback to try/except import if importlib.util is not available
    try:
        from lxml import etree
        has_lxml = True
    except ImportError:
        pass
    
    try:
        from evtx import PyEvtxParser
        has_evtx = True
    except ImportError:
        pass
    
    try:
        from neo4j import GraphDatabase
        has_neo4j = True
    except ImportError:
        pass
    
    try:
        import numpy as np
        has_numpy = True
    except ImportError:
        pass
    
    try:
        import changefinder
        has_changefinder = True
    except ImportError:
        pass
    
    try:
        from flask import Flask
        has_flask = True
    except ImportError:
        pass
    
    try:
        import pandas as pd
        has_pandas = True
    except ImportError:
        pass
    
    try:
        from hmmlearn import hmm
        has_hmmlearn = True
    except ImportError:
        pass
    
    try:
        import joblib
        has_sklearn = True
    except ImportError:
        pass
    
    try:
        from elasticsearch import Elasticsearch
        has_es = True
    except ImportError:
        pass
    
    try:
        import yaml
        has_pyyaml = True
    except ImportError:
        pass
    
    try:
        from flask_login import UserMixin
        has_flask_login = True
    except ImportError:
        pass
    
    try:
        from flask_sqlalchemy import SQLAlchemy
        has_flask_sqlalchemy = True
    except ImportError:
        pass
    
    try:
        from flask_wtf import FlaskForm
        has_flask_wtf = True
    except ImportError:
        pass

    try:
        from flask_limiter import Limiter
        has_flask_limiter = True
    except ImportError:
        pass

    try:
        import git
        has_git = True
    except ImportError:
        pass
    
    try:
        from sigma.rule import SigmaRule
        from sigma.collection import SigmaCollection
        from sigma.conditions import ConditionItem, ConditionAND, ConditionOR, ConditionNOT, ConditionFieldEqualsValueExpression
        has_sigma = True
    except ImportError:
        pass

def ensure_neo4j_imported():
    """Ensure Neo4j modules are imported (lazy loading for web UI)"""
    global GraphDatabase, ClientError, ServiceUnavailable, AuthError, ConfigurationError
    if has_flask and GraphDatabase is None:
        from neo4j import GraphDatabase as _GraphDatabase
        from neo4j.exceptions import ClientError as _ClientError
        from neo4j.exceptions import ServiceUnavailable as _ServiceUnavailable
        from neo4j.exceptions import AuthError as _AuthError
        from neo4j.exceptions import ConfigurationError as _ConfigurationError
        GraphDatabase = _GraphDatabase
        ClientError = _ClientError
        ServiceUnavailable = _ServiceUnavailable
        AuthError = _AuthError
        ConfigurationError = _ConfigurationError

# Decorator to ensure Neo4j is imported before route execution
def with_neo4j(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        ensure_neo4j_imported()
        return f(*args, **kwargs)
    return decorated_function

sys.modules.setdefault('logontracer', sys.modules[__name__])

# Check Event Id
EVENT_ID = [4624, 4625, 4662, 4768, 4769, 4776, 4672, 4720, 4726, 4728, 4729, 4732, 4733, 4756, 4757, 4719, 5137, 5141]

# EVTX Header
EVTX_HEADER = b"\x45\x6C\x66\x46\x69\x6C\x65\x00"

# String Check list
UCHECK = r"[%*+=\[\]\\/|;:\"<>?,&]"
HCHECK = r"[*\\/|:\"<>?&]"

# Username allowed characters: letters, digits, underscore, hyphen only
USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_-]+$')

# Neo4j identifier pattern: only alphanumeric and underscore (for database names, usernames, roles)
NEO4J_IDENTIFIER_PATTERN = re.compile(r'^[a-zA-Z0-9_]+$')

# IPv4 regex
IPv4_PATTERN = re.compile(r"\A\d+\.\d+\.\d+\.\d+\Z", re.DOTALL)

# IPv6 regex
IPv6_PATTERN = re.compile(r"\A(::(([0-9a-f]|[1-9a-f][0-9a-f]{1,3})(:([0-9a-f]|[1-9a-f][0-9a-f]{1,3})){0,5})?|([0-9a-f]|[1-9a-f][0-9a-f]{1,3})(::(([0-9a-f]|[1-9a-f][0-9a-f]{1,3})(:([0-9a-f]|[1-9a-f][0-9a-f]{1,3})){0,4})?|:([0-9a-f]|[1-9a-f][0-9a-f]{1,3})(::(([0-9a-f]|[1-9a-f][0-9a-f]{1,3})(:([0-9a-f]|[1-9a-f][0-9a-f]{1,3})){0,3})?|:([0-9a-f]|[1-9a-f][0-9a-f]{1,3})(::(([0-9a-f]|[1-9a-f][0-9a-f]{1,3})(:([0-9a-f]|[1-9a-f][0-9a-f]{1,3})){0,2})?|:([0-9a-f]|[1-9a-f][0-9a-f]{1,3})(::(([0-9a-f]|[1-9a-f][0-9a-f]{1,3})(:([0-9a-f]|[1-9a-f][0-9a-f]{1,3}))?)?|:([0-9a-f]|[1-9a-f][0-9a-f]{1,3})(::([0-9a-f]|[1-9a-f][0-9a-f]{1,3})?|(:([0-9a-f]|[1-9a-f][0-9a-f]{1,3})){3}))))))\Z", re.DOTALL)

# Allowed character patterns (whitelist approach)
ALLOWED_FILENAME_PATTERN = re.compile(r'^[a-zA-Z0-9_\-. ]+$')  # alphanumeric, underscore, dash, dot, space
ALLOWED_PATH_PATTERN = re.compile(r'^[a-zA-Z0-9_\-./]+$')  # alphanumeric, underscore, dash, dot, slash
ALLOWED_EVTX_FILENAME_PATTERN = re.compile(r'^[a-zA-Z0-9_\-. ]+\.evtx$', re.IGNORECASE)  # EVTX files only

# LogonTracer folder path
FPATH = os.path.dirname(os.path.abspath(__file__))

# CategoryId
CATEGORY_IDs = {
    "%%8280": "Account_Logon",
    "%%8270": "Account_Management",
    "%%8276": "Detailed_Tracking",
    "%%8279": "DS_Access",
    "%%8273": "Logon/Logoff",
    "%%8274": "Object_Access",
    "%%8277": "Policy_Change",
    "%%8275": "Privilege_Use",
    "%%8272": "System"}

# Auditing Constants
AUDITING_CONSTANTS = {
    "{0cce9210-69ae-11d9-bed3-505054503030}": "SecurityStateChange",
    "{0cce9211-69ae-11d9-bed3-505054503030}": "SecuritySubsystemExtension",
    "{0cce9212-69ae-11d9-bed3-505054503030}": "Integrity",
    "{0cce9213-69ae-11d9-bed3-505054503030}": "IPSecDriverEvents",
    "{0cce9214-69ae-11d9-bed3-505054503030}": "Others",
    "{0cce9215-69ae-11d9-bed3-505054503030}": "Logon",
    "{0cce9216-69ae-11d9-bed3-505054503030}": "Logoff",
    "{0cce9217-69ae-11d9-bed3-505054503030}": "AccountLockout",
    "{0cce9218-69ae-11d9-bed3-505054503030}": "IPSecMainMode",
    "{0cce9219-69ae-11d9-bed3-505054503030}": "IPSecQuickMode",
    "{0cce921a-69ae-11d9-bed3-505054503030}": "IPSecUserMode",
    "{0cce921b-69ae-11d9-bed3-505054503030}": "SpecialLogon",
    "{0cce921c-69ae-11d9-bed3-505054503030}": "Others",
    "{0cce921d-69ae-11d9-bed3-505054503030}": "FileSystem",
    "{0cce921e-69ae-11d9-bed3-505054503030}": "Registry",
    "{0cce921f-69ae-11d9-bed3-505054503030}": "Kernel",
    "{0cce9220-69ae-11d9-bed3-505054503030}": "Sam",
    "{0cce9221-69ae-11d9-bed3-505054503030}": "CertificationServices",
    "{0cce9222-69ae-11d9-bed3-505054503030}": "ApplicationGenerated",
    "{0cce9223-69ae-11d9-bed3-505054503030}": "Handle",
    "{0cce9224-69ae-11d9-bed3-505054503030}": "Share",
    "{0cce9225-69ae-11d9-bed3-505054503030}": "FirewallPacketDrops",
    "{0cce9226-69ae-11d9-bed3-505054503030}": "FirewallConnection",
    "{0cce9227-69ae-11d9-bed3-505054503030}": "Other",
    "{0cce9228-69ae-11d9-bed3-505054503030}": "Sensitive",
    "{0cce9229-69ae-11d9-bed3-505054503030}": "NonSensitive",
    "{0cce922a-69ae-11d9-bed3-505054503030}": "Others",
    "{0cce922b-69ae-11d9-bed3-505054503030}": "ProcessCreation",
    "{0cce922c-69ae-11d9-bed3-505054503030}": "ProcessTermination",
    "{0cce922d-69ae-11d9-bed3-505054503030}": "DpapiActivity",
    "{0cce922e-69ae-11d9-bed3-505054503030}": "RpcCall",
    "{0cce922f-69ae-11d9-bed3-505054503030}": "AuditPolicy",
    "{0cce9230-69ae-11d9-bed3-505054503030}": "AuthenticationPolicy",
    "{0cce9231-69ae-11d9-bed3-505054503030}": "AuthorizationPolicy",
    "{0cce9232-69ae-11d9-bed3-505054503030}": "MpsscvRulePolicy",
    "{0cce9233-69ae-11d9-bed3-505054503030}": "WfpIPSecPolicy",
    "{0cce9234-69ae-11d9-bed3-505054503030}": "Others",
    "{0cce9235-69ae-11d9-bed3-505054503030}": "UserAccount",
    "{0cce9236-69ae-11d9-bed3-505054503030}": "ComputerAccount",
    "{0cce9237-69ae-11d9-bed3-505054503030}": "SecurityGroup",
    "{0cce9238-69ae-11d9-bed3-505054503030}": "DistributionGroup",
    "{0cce9239-69ae-11d9-bed3-505054503030}": "ApplicationGroup",
    "{0cce923a-69ae-11d9-bed3-505054503030}": "Others",
    "{0cce923b-69ae-11d9-bed3-505054503030}": "DSAccess",
    "{0cce923c-69ae-11d9-bed3-505054503030}": "AdAuditChanges",
    "{0cce923d-69ae-11d9-bed3-505054503030}": "Replication",
    "{0cce923e-69ae-11d9-bed3-505054503030}": "DetailedReplication",
    "{0cce923f-69ae-11d9-bed3-505054503030}": "CredentialValidation",
    "{0cce9240-69ae-11d9-bed3-505054503030}": "Kerberos",
    "{0cce9241-69ae-11d9-bed3-505054503030}": "Others",
    "{0cce9242-69ae-11d9-bed3-505054503030}": "KerbCredentialValidation",
    "{0cce9243-69ae-11d9-bed3-505054503030}": "NPS"}

# Kerberos Ticket Encryption Types conversion table
# Based on Microsoft documentation: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768
TICKET_ENCRYPTION_TYPES = {
    # Hex formats (lowercase with 0x)
    "0x1": "DES-CBC-CRC",
    "0x3": "DES-CBC-MD5", 
    "0x11": "AES128-CTS-HMAC-SHA1-96",
    "0x12": "AES256-CTS-HMAC-SHA1-96",
    "0x17": "RC4-HMAC",
    "0x18": "RC4-HMAC-EXP",
    "0xffffffff": "-",
}

# Load logging config
import yaml
with open(FPATH + "/config/logging.yml", 'r') as logging_open:
    logging_data = yaml.safe_load(logging_open)

dictConfig(logging_data)
logger = getLogger("agent_logger")

# Flask instance
if not has_flask:
    # Logger already initialized above
    logger.error("[!] Flask must be installed for this script.")
    sys.exit(1)
else:
    # Import Flask modules at startup (Flask itself is lightweight)
    from flask import Flask, render_template, request, redirect, session, jsonify, flash, url_for, abort
    from flask_login import UserMixin, LoginManager, login_user, logout_user, current_user
    from markupsafe import Markup, escape
    from flask_sqlalchemy import SQLAlchemy
    from flask_wtf import FlaskForm
    from wtforms import StringField, PasswordField, BooleanField, TextAreaField, SelectField, IntegerField, FloatField
    from wtforms.validators import DataRequired, Length, EqualTo, Optional, ValidationError, Regexp
    from flask_wtf.csrf import CSRFProtect, generate_csrf
    if has_flask_limiter:
        from flask_limiter import Limiter
        from flask_limiter.util import get_remote_address

    # Import common modules needed by web interface
    import csv
    import json
    import glob
    import pickle
    import shutil
    import subprocess
    import asyncio
    from ssl import create_default_context
    
    # Neo4j will be imported lazily in functions that need it
    # This keeps startup time fast for CLI operations
    GraphDatabase = None
    ClientError = None
    ServiceUnavailable = None
    AuthError = None
    ConfigurationError = None
    
    app = Flask(__name__)

parser = argparse.ArgumentParser(description="Visualizing and analyzing active directory Windows logon event logs.")
parser.add_argument("-r", "--run", action="store_true", default=False,
                    help="Start web application.")
parser.add_argument("-o", "--port", dest="port", action="store", type=int, metavar="PORT",
                    help="Port number to be started web application. (default: 8080).")
parser.add_argument("--host", dest="host", action="store", type=str, metavar="HOST",
                    help="Host address to bind the web application. (default: 0.0.0.0).")
parser.add_argument("-e", "--evtx", dest="evtx", nargs="*", action="store", type=str, metavar="EVTX",
                    help="Import to the AD EVTX file. (multiple files OK)")
parser.add_argument("-x", "--xml", dest="xmls", nargs="*", action="store", type=str, metavar="XML",
                    help="Import to the XML file for event log. (multiple files OK)")
parser.add_argument("-s", "--server", dest="server", action="store", type=str, metavar="SERVER",
                    help="Neo4j server. (default: localhost)")
parser.add_argument("-u", "--user", dest="user", action="store", type=str, metavar="USERNAME",
                    help="Neo4j account name. (default: neo4j)")
parser.add_argument("-p", "--password", dest="password", action="store", type=str, metavar="PASSWORD",
                    help="Neo4j password. (default: password).")
parser.add_argument("--wsport", dest="wsport", action="store", type=str, metavar="PORT",
                    help="Neo4j websocket port number.  (default: 7687).")
parser.add_argument("-l", "--learn", action="store_true", default=False,
                    help="Machine learning event logs using Hidden Markov Model.")
parser.add_argument("--sigma", action="store_true", default=False,
                    help="Scan using Sigma rule. (default: False)")
parser.add_argument("--sigma-only", dest="sigma_only", action="store_true", default=False,
                    help="Sigma scan only mode. Scan EVTX file with Sigma rules without Neo4j processing. (default: False)")
parser.add_argument("--sigma-rules", dest="sigma_rules_path", action="store", type=str, metavar="PATH",
                    help="Path to Sigma rules folder. (default: sigma)")
parser.add_argument("--es-server", dest="esserver", action="store", type=str, metavar="ESSERVER",
                    help="Elastic Search server address. (default: localhost:9200)")
parser.add_argument("--es-index", dest="esindex", action="store", type=str, metavar="ESINDEX",
                    help="Elastic Search index to search. (default: winlogbeat-*)")
parser.add_argument("--es-prefix", dest="esprefix", action="store", type=str, metavar="ESPREFIX",
                    help="Elastic Search event object prefix. (default: winlog)")
parser.add_argument("--es-user", dest="esuser", action="store", type=str, metavar="ESUSER",
                    help="Elastic Search ssl authentication user. (default: elastic)")
parser.add_argument("--es-pass", dest="espassword", action="store", type=str, metavar="ESPASSWORD",
                    help="Elastic Search ssl authentication password.")
parser.add_argument("--es-cafile", dest="escafile", action="store", type=str, metavar="ESCAFILE",
                    help="Elastic Search ssl cert file.")
parser.add_argument("--es", action="store_true", default=False,
                    help="Import data from Elastic Search. (default: False)")
parser.add_argument("--postes", action="store_true", default=False,
                    help="Post data to Elastic Search. (default: False)")
parser.add_argument("-z", "--timezone", dest="timezone", action="store", type=int, metavar="UTC",
                    help="Event log time zone. (for example: +9) (default: GMT)")
parser.add_argument("-f", "--from", dest="fromdate", action="store", type=str, metavar="DATE",
                    help="Parse Security Event log from this time. (for example: 2017-01-01T00:00:00)")
parser.add_argument("-t", "--to", dest="todate", action="store", type=str, metavar="DATE",
                    help="Parse Security Event log to this time. (for example: 2017-02-28T23:59:59)")
parser.add_argument("-c", "--config", dest="config", action="store", type=str, metavar="FILE",
                    help="Configuration file path. (default: config/config.yml)")
parser.add_argument("--case", dest="case", action="store", type=str, metavar="CASE_NAME",
                    help="[for Neo4j Enterprise] Case management option. If you want to manage each EVTX files in case. (default: neo4j)")
parser.add_argument("--create_user", dest="create_user", action="store", type=str, metavar="USER",
                    help="Create a new Neo4j user.")
parser.add_argument("--create_password", dest="create_password", action="store", type=str, metavar="PASSWORD",
                    help="Create a new Neo4j password.")
parser.add_argument("--role", dest="role", action="store", type=str, metavar="ROLE",
                    help="[for Neo4j Enterprise] User role option [admin, architect, reader]. (default: reader)")
parser.add_argument("--delete_user", dest="delete_user", action="store", type=str, metavar="USER",
                    help="Delete a Neo4j user.")
parser.add_argument("--add", action="store_true", default=False,
                    help="Add additional data to Neo4j database. (default: False)")
parser.add_argument("--delete", action="store_true", default=False,
                    help="Delete all nodes and relationships from this Neo4j database. (default: False)")
args = parser.parse_args()

statement_user = """
  MERGE (user:Username{ user: $user }) 
  SET user.rights = $rights, user.sid = $sid, user.rank = $rank, user.status = $status, 
      user.counts = $counts, user.counts4624 = $counts4624, user.counts4625 = $counts4625, 
      user.counts4768 = $counts4768, user.counts4769 = $counts4769, user.counts4776 = $counts4776, 
      user.detect = $detect
  RETURN user
  """

statement_ip = """
  MERGE (ip:IPAddress{ IP: $IP }) 
  SET ip.rank = $rank, ip.hostname = $hostname
  RETURN ip
  """

statement_r = """
  MATCH (user:Username{ user: $user })
  MATCH (ip:IPAddress{ IP: $IP })
  CREATE (ip)-[event:Event]->(user) 
  SET event.id = $id, event.logintype = $logintype, event.status = $status, 
      event.count = $count, event.authname = $authname, event.servicename = $servicename, 
      event.ticketencryptiontype = $ticketencryptiontype, event.date = $date
  RETURN user, ip
  """

statement_date = """
  MERGE (date:Date{ date: $Daterange }) 
  SET date.start = $start, date.end = $end
  RETURN date
  """

statement_domain = """
  MERGE (domain:Domain{ domain: $domain })
  RETURN domain
  """

statement_dr = """
  MATCH (domain:Domain{ domain: $domain })
  MATCH (user:Username{ user: $user })
  CREATE (user)-[group:Group]->(domain)
  RETURN user, domain
  """

statement_del = """
  MERGE (date:Deletetime{ date: $deletetime }) 
  SET date.user = $user, date.domain = $domain
  RETURN date
  """

statement_pl = """
  MERGE (id:ID{ id: $id }) 
  SET id.changetime = $changetime, id.category = $category, id.sub = $sub
  RETURN id
  """

statement_pr = """
  MATCH (id:ID{ id: $id })
  MATCH (user:Username{ user: $user })
  CREATE (user)-[group:Policy]->(id) 
  SET group.date = $date
  RETURN user, id
  """

statement_cd = """
  CREATE DATABASE {case};
  """

statement_dd = """
  DROP DATABASE {case};
  """

statement_cu = """
  CREATE USER {username} SET PASSWORD $password CHANGE NOT REQUIRED;
  """

# for Neo4j enterprise edition
#statement_cu = """
#  CREATE USER {username} SET PASSWORD $password CHANGE NOT REQUIRED SET STATUS ACTIVE;
#  """

statement_au = """
  ALTER CURRENT USER SET PASSWORD FROM $oldPassword TO $newPassword;
  """

statement_du = """
  DROP USER {username};
  """

statement_su = """
  ALTER USER {username} SET STATUS {action};
  """

statement_role_add = """
  CREATE OR REPLACE ROLE {username}_role AS COPY OF {role};
  """

statement_role_revoke = """
  REVOKE ACCESS ON DATABASE {database} FROM {username}_role;
  """

statement_role_set = """
  GRANT ROLE {username}_role TO {username};
  """

statement_role_set_admin = """
  GRANT ROLE admin TO {username};
  """

statement_default_db_access = """
  GRANT ACCESS ON DATABASE neo4j TO {username}_role;
  """

statement_db_access = """
  GRANT ACCESS ON DATABASE {database} TO {username}_role;
  """

es_doc_user = """
  {{"@timestamp":"{datetime}", "user":"{user}", "rights":"{rights}", "sid":"{sid}", "status":"{status}", "rank":{rank}}}
  """

es_doc_ip = """
  {{"@timestamp":"{datetime}", "IP":"{IP}", "hostname":"{hostname}", "rank":{rank}}}
  """

if not has_flask_login:
    logger.error("[!] flask-login must be installed for this script.")
    sys.exit(1)

if not has_flask_sqlalchemy:
    logger.error("[!] flask-sqlalchemy must be installed for this script.")
    sys.exit(1)

if not has_pyyaml:
    logger.error("[!] pyyaml must be installed for this script.")
    sys.exit(1)

if not has_flask_wtf:
    logger.error("[!] flask_wtf must be installed for this script.")
    sys.exit(1)

if args.config:
    config_path = args.config
else:
    config_path = FPATH + "/config/config.yml"

with open(config_path, 'r') as config_open:
    config_data = yaml.safe_load(config_open)["settings"]

# neo4j password
NEO4J_PASSWORD = config_data["neo4j"]["NEO4J_PASSWORD"]
# neo4j user name
NEO4J_USER = config_data["neo4j"]["NEO4J_USER"]
# neo4j server
NEO4J_SERVER = config_data["neo4j"]["NEO4J_SERVER"]
# neo4j HTTP port (for legacy compatibility)
NEO4J_HTTP_PORT = config_data["neo4j"]["NEO4J_PORT"]
# neo4j Bolt port (for driver connections)
NEO4J_PORT = config_data["neo4j"]["WS_PORT"]
# Web application port
WEB_PORT = config_data["logontracer"]["WEB_PORT"]
# Web application address
WEB_HOST = config_data["logontracer"]["WEB_HOST"]
# Flag for SESSION_COOKIE_SECURE
USE_HTTPS = config_data["logontracer"]["SESSION_COOKIE_SECURE"]
# Websocket port
WS_PORT = config_data["neo4j"]["WS_PORT"]
# Elastic Search server
ES_SERVER = config_data["elastic"]["ES_SERVER"]
# Elastic index
ES_INDEX = config_data["elastic"]["ES_INDEX"]
# Elastic prefix
ES_PREFIX = config_data["elastic"]["ES_PREFIX"]
# Elastic auth user
ES_USER = config_data["elastic"]["ES_USER"]
# logontracer default user
default_user = config_data["logontracer"]["default_user"]
# logontracer default password
default_password = config_data["logontracer"]["default_password"]
# logontracer user info database
database_name = config_data["logontracer"]["database_name"]
# Default neo4j database name
CASE_NAME = config_data["logontracer"]["default_case"]
# Sigma rules url
SIGMA_URL = config_data["sigma"]["git_url"]
# Sigma scan result file
SIGMA_RESULTS_FILE = config_data["sigma"]["results"]

if args.user:
    NEO4J_USER = args.user

if args.password:
    NEO4J_PASSWORD = args.password

if args.server:
    NEO4J_SERVER = args.server

if args.port:
    WEB_PORT = args.port

if args.host:
    WEB_HOST = args.host

if args.wsport:
    WS_PORT = args.wsport

if args.esserver:
    ES_SERVER = args.esserver

if args.esindex:
    ES_INDEX = args.esindex

if args.esprefix:
    ES_PREFIX = args.esprefix

if args.esuser:
    ES_USER = args.esuser

if args.espassword:
    ES_PASSWORD = args.espassword

if args.escafile:
    ES_CAFILE = args.escafile

if args.case:
    CASE_NAME = args.case

# Setup login user
app.config["SESSION_COOKIE_SECURE"] = USE_HTTPS
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + database_name

# Persist SECRET_KEY across restarts
_secret_key_file = os.path.join(FPATH, '.secret_key')
if os.path.exists(_secret_key_file):
    with open(_secret_key_file, 'rb') as _f:
        _secret_key = _f.read()
else:
    _secret_key = os.urandom(32)
    with open(_secret_key_file, 'wb') as _f:
        _f.write(_secret_key)
    os.chmod(_secret_key_file, 0o600)
app.config["SECRET_KEY"] = _secret_key

app.permanent_session_lifetime = datetime.timedelta(minutes=60)

# Initialize SQLAlchemy
db = SQLAlchemy()
db.init_app(app)

# Server-side credential cache (opaque token in session, credentials in memory)
_cred_cache = {}
_cred_cache_lock = threading.Lock()

def store_neo4j_creds(username, password):
    """Store Neo4j credentials server-side; save only opaque key in session."""
    cache_key = secrets.token_urlsafe(32)
    expires = utc_now() + datetime.timedelta(minutes=60)
    with _cred_cache_lock:
        _cred_cache[cache_key] = {"username": username, "password": password, "expires": expires}
    session["neo4j_cache_key"] = cache_key

def get_neo4j_creds():
    """Retrieve Neo4j credentials from server-side cache."""
    cache_key = session.get("neo4j_cache_key")
    if not cache_key:
        return None, None
    with _cred_cache_lock:
        entry = _cred_cache.get(cache_key)
        if entry is None:
            return None, None
        if entry["expires"] < utc_now():
            _cred_cache.pop(cache_key, None)
            return None, None
        return entry["username"], entry["password"]

def invalidate_neo4j_creds():
    """Remove credentials from server-side cache on logout."""
    cache_key = session.get("neo4j_cache_key")
    if cache_key:
        with _cred_cache_lock:
            _cred_cache.pop(cache_key, None)
        session.pop("neo4j_cache_key", None)

# Initialize CSRF protection
csrf = CSRFProtect(app)

@app.after_request
def set_csrf_cookie(response):
    response.set_cookie('csrf_token', generate_csrf(), samesite='Lax')
    return response

@app.after_request
def set_security_headers(response):
    """Add security headers to every response."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    if USE_HTTPS:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    # Content-Security-Policy: allow inline scripts (required for current templates),
    # CDN resources (Bootstrap, jQuery, Cytoscape, Chart.js, DataTables, Font Awesome, etc.),
    # and Neo4j bolt connections via connect-src
    _cdn = (
        "https://cdn.jsdelivr.net "
        "https://cdnjs.cloudflare.com "
        "https://ajax.googleapis.com "
        "https://cdn.datatables.net "
        "https://maxcdn.bootstrapcdn.com "
        "https://use.fontawesome.com"
    )
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' " + _cdn + "; "
        "style-src 'self' 'unsafe-inline' " + _cdn + "; "
        "img-src 'self' data: blob:; "
        "font-src 'self' data: " + _cdn + "; "
        "connect-src 'self' bolt: bolts: bolt+ssc: wss: ws:; "
        "frame-ancestors 'none'"
    )
    return response

# Initialize rate limiter
if has_flask_limiter:
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=[],
        storage_uri="memory://"
    )
else:
    # No-op limiter stub when flask-limiter is not installed
    class _NoopLimiter:
        def limit(self, *args, **kwargs):
            return lambda f: f
    limiter = _NoopLimiter()

# Initialize LoginManager
login_manager = LoginManager()
login_manager.init_app(app)

# Define User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    urole = db.Column(db.String(20))

    def __init__(self, username, urole):
            self.username = username
            self.urole = urole
    def get_id(self):
            return self.id
    def get_username(self):
            return self.username
    def get_urole(self):
            return self.urole


class SettingForm(FlaskForm):
    password1 = PasswordField('Password', validators=[DataRequired(), EqualTo('password2', message='Passwords must match.'), Length(min=3, max=20)])
    password2 = PasswordField('Password (again)', validators=[DataRequired(), Length(min=3, max=20)])

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=3, max=50),
        Regexp(r'^[a-zA-Z0-9_-]+$',
               message='Username can only contain letters, numbers, underscores, and hyphens.')
    ])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=3, max=20)])

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=3, max=50),
        Regexp(r'^[a-zA-Z0-9_-]+$',
               message='Username can only contain letters, numbers, underscores, and hyphens.')
    ])
    password1 = PasswordField('Password', validators=[DataRequired(), EqualTo('password2', message='Passwords must match.'), Length(min=3, max=20)])
    password2 = PasswordField('Password (again)', validators=[DataRequired(), Length(min=3, max=20)])

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('This username is already registered.')

class CaseForm(FlaskForm):
    case = StringField('Case', validators=[DataRequired()])

class AISettingForm(FlaskForm):
    ai_enabled = BooleanField('Enable AI Analysis')
    openai_api_key = StringField('OpenAI API Key', validators=[Optional()])
    openai_model = SelectField('OpenAI Model', 
                              choices=[('gpt-5', 'GPT-5'),
                                     ('gpt-5-mini', 'GPT-5 Mini'),
                                     ('gpt-5.1', 'GPT-5.1'),
                                     ('gpt-5.2', 'GPT-5.2'),
                                     ('gpt-5.4', 'GPT-5.4'),
                                     ('gpt-5.4-mini', 'GPT-5.4 Mini'),],
                              default='gpt-5-mini')
    max_completion_tokens = IntegerField('Max Completion Tokens', default=8000, validators=[Optional()])
    temperature = FloatField('Temperature', default=1, validators=[Optional()])
    agent_max_iterations = IntegerField('Agent Max Iterations', default=10, validators=[Optional()])
    response_language = SelectField('Response Language',
                                  choices=[('en', 'English'),
                                         ('ja', '日本語 (Japanese)'),
                                         ('fr', 'Français (French)')],
                                  default='en')

class AISetting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ai_enabled = db.Column(db.Boolean, default=True)  # default Enable
    openai_api_key = db.Column(db.String(255), nullable=True)
    openai_model = db.Column(db.String(50), default='gpt-5-mini')
    max_completion_tokens = db.Column(db.Integer, default=8000)
    temperature = db.Column(db.Float, default=1)
    agent_max_iterations = db.Column(db.Integer, default=10)
    response_language = db.Column(db.String(10), default='en')  # Language for AI responses
    created_at = db.Column(db.DateTime, default=utc_now_naive)
    updated_at = db.Column(db.DateTime, default=utc_now_naive, onupdate=utc_now_naive)

# Initialize database tables and default user
with app.app_context():
    db.create_all()
    
    user_query = User.query.filter_by(username=default_user).first()
    if user_query is None:
        create_user = User(username=default_user, urole="ADMIN")
        db.session.add(create_user)
        db.session.commit()

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@login_manager.unauthorized_handler
def unauthorized():
    return redirect('/login')

# Web application logging decorater
def http_request_logging(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            app.logger.info('%s - %s - %s - %s', request.remote_addr, request.method, request.url, request.query_string)
        except Exception as e:
            app.logger.exception(e)
            pass
        return f(*args, **kwargs)
    return decorated_function


def is_safe_path(base_dir, user_path):
    """
    Validate that a user-provided path is within the allowed base directory.

    Args:
        base_dir: The allowed base directory (absolute path)
        user_path: The user-provided path to validate
    
    Returns:
        bool: True if the path is safe, False otherwise
    """
    # Resolve both paths to absolute, normalized paths
    base_dir = os.path.realpath(base_dir)
    full_path = os.path.realpath(os.path.join(base_dir, user_path))
    
    # Check if the resolved path is within the base directory
    return full_path.startswith(base_dir + os.sep) or full_path == base_dir


def sanitize_filename(filename, file_type=None):
    """
    Sanitize a filename. Only allows alphanumeric characters and safe punctuation.

    Args:
        filename: The filename to sanitize
        file_type: Optional file type restriction ('evtx', 'xml', etc.)
    
    Returns:
        tuple: (sanitized_filename or None, error_message or None)
    """
    if not filename or not isinstance(filename, str):
        return None, "Filename is required"
    
    # Check length limit
    if len(filename) > 255:
        return None, "Filename too long (max 255 characters)"
    
    dangerous_patterns = ['..', '\x00', '\n', '\r', '\t', '/', '\\', '|', ';', '&', '$', '`', '>', '<', '\'', '"']
    for pattern in dangerous_patterns:
        if pattern in filename:
            return None, f"Filename contains forbidden characters"
    
    # Whitelist check on ORIGINAL input: Only allow alphanumeric, dash, underscore, dot, and space
    if not ALLOWED_FILENAME_PATTERN.match(filename):
        return None, "Filename contains invalid characters (only alphanumeric, dash, underscore, dot, and space allowed)"
    
    # Now safe to use basename (should be same as input since no path separators allowed)
    filename = os.path.basename(filename)
    
    # Check for empty filename after basename
    if not filename:
        return None, "Invalid filename"
    
    # Check for file type restriction
    if file_type:
        if file_type.lower() == 'evtx':
            if not ALLOWED_EVTX_FILENAME_PATTERN.match(filename):
                return None, "Only .evtx files are allowed"
        elif file_type.lower() == 'xml':
            if not filename.lower().endswith('.xml'):
                return None, "Only .xml files are allowed"
    
    # Prevent hidden files (starting with dot)
    if filename.startswith('.'):
        return None, "Hidden files are not allowed"
    
    return filename, None


def validate_relative_path(path, allowed_prefixes=None):
    """
    Validate a relative path for security.
    Uses whitelist approach - only allows specific characters.
    
    Args:
        path: The path to validate
        allowed_prefixes: List of allowed path prefixes (e.g., ['sigma', 'upload'])
    
    Returns:
        tuple: (is_valid, error_message)
    """
    if not path or not isinstance(path, str):
        return False, "Path is required"
    
    # Check length limit
    if len(path) > 500:
        return False, "Path too long (max 500 characters)"
    
    # Check for null bytes and control characters
    if '\x00' in path or any(ord(c) < 32 for c in path):
        return False, "Invalid characters in path"
    
    # Reject parent directory references
    if '..' in path:
        return False, "Directory traversal not allowed"
    
    # Check for absolute paths
    if path.startswith('/') or (len(path) > 1 and path[1] == ':'):
        return False, "Absolute paths not allowed"
    
    # Whitelist: Only allow alphanumeric, underscore, dash, dot, and forward slash
    if not ALLOWED_PATH_PATTERN.match(path):
        return False, "Path contains invalid characters (only alphanumeric, underscore, dash, dot, and slash allowed)"
    
    # Check for double slashes
    if '//' in path:
        return False, "Invalid path format"
    
    # Check allowed prefixes if specified
    if allowed_prefixes:
        if not any(path == prefix or path.startswith(prefix + '/') for prefix in allowed_prefixes):
            return False, f"Path must start with one of: {', '.join(allowed_prefixes)}"
    
    return True, None


def validate_input_string(value, field_name, max_length=200, allowed_pattern=None):
    """
    Generic input validation for string values.
    
    Args:
        value: The input value to validate
        field_name: Name of the field (for error messages)
        max_length: Maximum allowed length
        allowed_pattern: Regex pattern for allowed characters (optional)
    
    Returns:
        tuple: (is_valid, error_message)
    """
    if value is None:
        return False, f"{field_name} is required"
    
    if not isinstance(value, str):
        return False, f"{field_name} must be a string"
    
    if len(value) > max_length:
        return False, f"{field_name} too long (max {max_length} characters)"
    
    # Check for null bytes and control characters
    if '\x00' in value or any(ord(c) < 32 and c not in '\n\r\t' for c in value):
        return False, f"{field_name} contains invalid characters"
    
    # Check allowed pattern if specified
    if allowed_pattern and not allowed_pattern.match(value):
        return False, f"{field_name} contains invalid characters"
    
    return True, None


def is_valid_timezone(value):
    """
    Validate a UTC timezone offset string.
    Accepts integer values in the range -12 to +14 (inclusive),
    which covers all real-world UTC offsets defined by ISO 8601.

    Args:
        value: The timezone string to validate (e.g. "9", "-5", "14")

    Returns:
        bool: True if valid, False otherwise
    """
    if not isinstance(value, str):
        return False
    # Must be an optional leading minus followed by 1-2 digits
    if not re.fullmatch(r"-?[0-9]{1,2}", value):
        return False
    tz_int = int(value)
    return -12 <= tz_int <= 14


# Costom login_required with role
def login_required(role="ANY"):
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            # Ensure Neo4j is imported for authenticated routes
            ensure_neo4j_imported()
            if not current_user.is_authenticated:
               return login_manager.unauthorized()
            urole = current_user.get_urole()
            if ((urole != role) and (role != "ANY")):
                return login_manager.unauthorized()
            return fn(*args, **kwargs)
        return decorated_view
    return wrapper


# Web application login page
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute; 50 per hour")
@http_request_logging
@with_neo4j
def login():
    if current_user.is_authenticated:
        return redirect('/')

    session.permanent = True
    session["case"] = CASE_NAME

    form = LoginForm(request.form)
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        remember = True if request.form.get("remember") else False

        # Server-side username format check
        if not USERNAME_PATTERN.match(username):
            return render_template('login.html', form=form,
                                   messages=Markup('<div class="alert alert-danger" role="alert">Invalid username format.</div>'))

        session["username"] = username
        store_neo4j_creds(username, password)

        try:
            # Test Neo4j connection with user credentials
            neo4j_uri = "bolt://" + NEO4J_SERVER + ":" + NEO4J_PORT
            driver = GraphDatabase.driver(neo4j_uri, auth=(username, password))
            with driver.session() as test_session:
                test_session.run("RETURN 1")
            driver.close()

            user = User.query.filter_by(username=username).first()
            logger.info("[+] login user {0}.".format(username))
            login_user(user, remember=remember)
            return redirect('/')
        except Exception as e:
            logger.error("[!] login failed user {0}: {1}".format(username, str(e)))
            return render_template('login.html', form=form,
                                   messages=Markup('<div class="alert alert-danger" role="alert">Invalid username or password.</div>'))

    return render_template('login.html', form=form, messages="")


# Web application signup page
@app.route('/signup', methods=['GET', 'POST'])
@http_request_logging
@login_required(role="ADMIN")
def signup():
    form = RegistrationForm(request.form)
    if form.validate_on_submit():
        username = form.username.data
        password = form.password1.data
        admin = True if request.form.get("admin") else False

        if admin:
            role = "ADMIN"
            role_neo4j = "admin"
        else:
            role = "USER"
            role_neo4j = "architect"

        with app.app_context():
            user = User(username=username, urole=role)
            db.session.add(user)
            db.session.commit()

        try:
            # Use admin credentials for user creation
            neo4j_uri = "bolt://" + NEO4J_SERVER + ":" + NEO4J_PORT
            _admin_user, _admin_pass = get_neo4j_creds()
            if _admin_user is None:
                return render_template('signup.html', form=form, messages=Markup('<div class="alert alert-danger" role="alert">Session expired. Please log in again.</div>'))
            admin_driver = GraphDatabase.driver(neo4j_uri, auth=(_admin_user, _admin_pass))
        except Exception as e:
            logger.error("[!] Can't connect Neo4j Database: {0}".format(str(e)))
            return render_template('signup.html', form=form, messages=Markup('<div class="alert alert-danger" role="alert">Database connection failed.</div>'))

        create_neo4j_user(admin_driver, username, password, role_neo4j)
        admin_driver.close()

        return redirect('/')
    else:
        return render_template('signup.html', form=form)


# Web application change password page
@app.route('/setting', methods=['GET', 'POST'])
@http_request_logging
@login_required(role="ANY")
def setting():
    form = SettingForm(request.form)
    if form.validate_on_submit():
        username = current_user.username
        password = form.password1.data

        with app.app_context():
            user_query = User.query.filter_by(username=username).first()
            db.session.delete(user_query)
            db.session.commit()

            user = User(username=username, urole=user_query.urole)
            db.session.add(user)
            db.session.commit()

        try:
            # Use current user credentials to connect
            neo4j_uri = "bolt://" + NEO4J_SERVER + ":" + NEO4J_PORT
            _cur_user, _cur_pass = get_neo4j_creds()
            if _cur_user is None:
                return render_template('setting.html', form=form, messages=Markup('<div class="alert alert-danger" role="alert">Session expired. Please log in again.</div>'))
            driver = GraphDatabase.driver(neo4j_uri, auth=(_cur_user, _cur_pass))
        except Exception as e:
            logger.error("[!] Can't connect Neo4j Database: {0}".format(str(e)))
            return render_template('setting.html', form=form, messages=Markup('<div class="alert alert-danger" role="alert">Database connection failed.</div>'))

        try:
            with driver.session(database="system") as neo4j_session:
                neo4j_session.run(statement_au, {"oldPassword": _cur_pass, "newPassword": password})
            logger.info("[+] Change user {0} password for neo4j.".format(username))

            # Update server-side credential cache with new password
            store_neo4j_creds(username, password)

        except Exception as e:
            if "User does not exist" in str(e):
                logger.error("[!] User does not exist {0}.".format(username))
            elif "Unsupported administration command" in str(e):
                logger.error("[!] Can't change password.")
            else:
                logger.error(str(e))
        finally:
            driver.close()

        return redirect('/')
    else:
        return render_template('setting.html', form=form)


# Web application logout
@app.route('/logout')
@http_request_logging
@login_required(role="ANY")
def logout():
    invalidate_neo4j_creds()
    logout_user()
    return redirect('/login')


# Web application create case
@app.route('/addcase', methods=['GET', 'POST'])
@http_request_logging
@login_required(role="ADMIN")
def addcase():
    # Check if user has access to Enterprise features
    try:
        neo4j_uri = "bolt://" + NEO4J_SERVER + ":" + NEO4J_PORT
        _u, _p = get_neo4j_creds()
        if _u is None:
            return redirect('/login')
        driver = GraphDatabase.driver(neo4j_uri, auth=(_u, _p))

        if not check_neo4j_enterprise(driver):
            driver.close()
            flash('Case management is only available with Neo4j Enterprise edition.', 'warning')
            return render_template("index.html", case_name=CASE_NAME)
    except Exception as e:
        logger.error("[!] Can't connect Neo4j Database: {0}".format(str(e)))
        flash('Database connection failed.', 'error')
        return render_template("index.html", case_name=CASE_NAME)

    form = CaseForm(request.form)
    if form.validate_on_submit():
        case = form.case.data
        if not re.search(r"\A[0-9a-zA-Z]{2,20}\Z", case):
            driver.close()
            return render_template('addcase.html', form=form,
                                   messages=Markup('<div class="alert alert-danger" role="alert">You can use letters upper/lowercase and numbers.</div>'))

        session["case"] = case
        create_database(driver, case)
        driver.close()

        return render_template("index.html", case_name=case)
    else:
        driver.close()
        return render_template('addcase.html', form=form, messages='')


# Web application delete case
@app.route('/delcase', methods=['GET', 'POST'])
@http_request_logging
@login_required(role="ADMIN")
def delcase():
    # Check if user has access to Enterprise features
    try:
        neo4j_uri = "bolt://" + NEO4J_SERVER + ":" + NEO4J_PORT
        _u, _p = get_neo4j_creds()
        if _u is None:
            return redirect('/login')
        driver = GraphDatabase.driver(neo4j_uri, auth=(_u, _p))

        if not check_neo4j_enterprise(driver):
            driver.close()
            flash('Case management is only available with Neo4j Enterprise edition.', 'warning')
            return render_template("delcase.html", case_name=session["case"],
                                   messages=Markup('<div><div class="alert alert-danger" role="alert">This feature is in Neo4j Enterprise.</div></div>'))
    except Exception as e:
        logger.error("[!] Can't connect Neo4j Database: {0}".format(str(e)))
        flash('Database connection failed.', 'error')
        return render_template("index.html", case_name=CASE_NAME)

    if request.method == "POST":
        case_name = request.form.get('caseName')

        if re.search(r"\A[0-9a-zA-Z]{2,20}\Z", case_name):
            delete_database(driver, case_name)
            message = Markup('<div><div class="alert alert-success" role="alert">Deleted case ') + escape(case_name) + Markup('</div></div>')
        else:
            message = Markup('<div><div class="alert alert-danger" role="alert">Invalid case name.</div></div>')

        driver.close()
        return render_template("delcase.html", case_name=session["case"], messages=message)
    else:
        driver.close()
        return render_template("delcase.html", case_name=session["case"], messages='')


# Web application change case
@app.route('/changecase', methods=['GET', 'POST'])
@http_request_logging
@login_required(role="ANY")
def changecase():
    if request.method == "POST":
        case_name = request.form.get('caseName')
        if not re.search(r"\A[0-9a-zA-Z]{2,20}\Z", case_name):
            return redirect('/')

        session["case"] = case_name

        return render_template("index.html", case_name=case_name)
    else:
        return render_template("changecase.html")


@app.route('/changecase_t', methods=['GET', 'POST'])
@http_request_logging
@login_required(role="ANY")
def changecase_t():
    if request.method == "POST":
        case_name = request.form.get('caseName')
        if not re.search(r"\A[0-9a-zA-Z]{2,20}\Z", case_name):
            return redirect('/')

        session["case"] = case_name

        return render_template("timeline.html", case_name=case_name)
    else:
        return render_template("changecase.html")


# Web application add case management
@app.route('/casemng', methods=['GET', 'POST'])
@http_request_logging
@login_required(role="ADMIN")
def case_management():
    # Check if user has access to Enterprise features
    try:
        neo4j_uri = "bolt://" + NEO4J_SERVER + ":" + NEO4J_PORT
        _u, _p = get_neo4j_creds()
        if _u is None:
            return redirect('/login')
        driver = GraphDatabase.driver(neo4j_uri, auth=(_u, _p))

        if not check_neo4j_enterprise(driver):
            driver.close()
            flash('Case management is only available with Neo4j Enterprise edition.', 'warning')
            return render_template("casemng.html", case_name=session["case"],
                                   messages=Markup('<div><div class="alert alert-danger" role="alert">This feature is in Neo4j Enterprise.</div></div>'))
    except Exception as e:
        logger.error("[!] Can't connect Neo4j Database: {0}".format(str(e)))
        flash('Database connection failed.', 'error')
        return render_template("index.html", case_name=CASE_NAME)

    if request.method == "POST":
        user = request.form.get("userSelect")
        case_name = request.form.get('caseName')

        if not re.search(UCHECK, user) and re.search(r"\A[0-9a-zA-Z]{2,20}\Z", case_name):
            add_db_access_role(driver, user, case_name)
            message = Markup('<div><div class="alert alert-success" role="alert">Added access role for case ') + escape(case_name) + Markup(' of user ') + escape(user) + Markup('</div></div>')
        else:
            message = Markup('<div><div class="alert alert-danger" role="alert">Invalid user or case name.</div></div>')

        driver.close()
        return render_template("casemng.html", case_name=session["case"], messages=message)
    else:
        driver.close()
        return render_template("casemng.html", case_name=session["case"], messages='')


# Web application delete case management
@app.route('/delcasemng', methods=['GET', 'POST'])
@http_request_logging
@login_required(role="ADMIN")
def case_management_del():
    # Check if user has access to Enterprise features
    try:
        neo4j_uri = "bolt://" + NEO4J_SERVER + ":" + NEO4J_PORT
        _u, _p = get_neo4j_creds()
        if _u is None:
            return redirect('/login')
        driver = GraphDatabase.driver(neo4j_uri, auth=(_u, _p))

        if not check_neo4j_enterprise(driver):
            driver.close()
            flash('Case management is only available with Neo4j Enterprise edition.', 'warning')
            return render_template("delcasemng.html", case_name=session["case"],
                                   messages=Markup('<div><div class="alert alert-danger" role="alert">This feature is in Neo4j Enterprise.</div></div>'))
    except Exception as e:
        logger.error("[!] Can't connect Neo4j Database: {0}".format(str(e)))
        flash('Database connection failed.', 'error')
        return render_template("index.html", case_name=CASE_NAME)

    if request.method == "POST":
        user_db = [userlist.split("_") for userlist in request.form.getlist("userlist")]

        messages = []
        for user_data in user_db:
            if len(user_data) >= 2:
                user = user_data[0]
                dbname = user_data[1]
                if not re.search(UCHECK, user) and re.search(r"\A[0-9a-zA-Z]{2,20}\Z", dbname):
                    delete_db_access_role(driver, user, dbname)
                    messages.append(Markup('<div class="alert alert-success" role="alert">Deleted access role for case ') + escape(dbname) + Markup(' of user ') + escape(user) + Markup('</div>'))

        driver.close()
        if messages:
            message_html = Markup('<div>') + Markup('').join(messages) + Markup('</div>')
        else:
            message_html = Markup('<div><div class="alert alert-info" role="alert">No valid selections processed.</div></div>')
        return render_template("delcasemng.html", case_name=session["case"], messages=message_html)
    else:
        driver.close()
        return render_template("delcasemng.html", case_name=session["case"], messages='')


# Web application user management
@app.route('/usermng', methods=['GET', 'POST'])
@http_request_logging
@login_required(role="ADMIN")
def user_management():
    if request.method == "POST":
        users = [userlist.removeprefix("Check_") for userlist in request.form.getlist("userlist")]
        action = request.form.get("action", "")

        VALID_ACTIONS = {"delete", "suspended", "active"}
        if action not in VALID_ACTIONS:
            logger.warning("[!] Security: Invalid action rejected: %s", action)
            return render_template("usermng.html")

        try:
            neo4j_uri = "bolt://" + NEO4J_SERVER + ":" + NEO4J_PORT
            _u, _p = get_neo4j_creds()
            if _u is None:
                return redirect('/login')
            driver = GraphDatabase.driver(neo4j_uri, auth=(_u, _p))
        except Exception as e:
            logger.error("[!] Can't connect Neo4j Database: {0}".format(str(e)))
            return render_template("usermng.html")

        if action == "delete":
            for user in users:
                if not re.search(UCHECK, user):
                    delete_neo4j_user(driver, user)
                    with app.app_context():
                        user_query = User.query.filter_by(username=user).first()
                        if user_query:
                            db.session.delete(user_query)
                            db.session.commit()
        elif action in ("suspended", "active"):
            for user in users:
                if not re.search(UCHECK, user):
                    change_status_neo4j_user(driver, user, action)

        driver.close()
        return render_template("usermng.html")
    else:
        return render_template("usermng.html")


# Web application index.html
@app.route('/')
@http_request_logging
@login_required(role="ANY")
def index():
    return render_template("index.html", case_name=session["case"])


# Timeline view
@app.route('/timeline')
@login_required(role="ANY")
@http_request_logging
def timeline():
    return render_template("timeline.html", case_name=session["case"])


# Web application logs
@app.route('/log')
@login_required(role="ANY")
def logs():
    with open(FPATH + "/static/logontracer.log", "r") as lf:
        logdata = lf.read()
    from flask import Response
    return Response(logdata, mimetype='text/plain')


# Sigma rule scan results
@app.route('/sigma')
@login_required(role="ANY")
def sigma():
    # Support both JSON and CSV formats
    json_path = FPATH + "/static/" + SIGMA_RESULTS_FILE
    
    if os.path.exists(json_path):
        with open(json_path, "r", encoding='utf-8') as sf:
            sigma_data = json.load(sf)
        return jsonify(sigma_data)
    else:
        return jsonify({"error": "No Sigma results found"}), 404


# Sigma detection results view
@app.route('/sigma_view')
@login_required(role="ANY")
@http_request_logging
def sigma_view():
    return render_template("sigma.html", neo4j_user=session["username"], case_name=session["case"])


# Neo4j API endpoints
@app.route('/api/neo4j/credentials')
@login_required(role="ANY")
def neo4j_credentials():
    """Return Neo4j connection info for visualization pages (no password in HTML)."""
    _u, _p = get_neo4j_creds()
    if _u is None:
        return jsonify({"error": "Session expired"}), 401
    return jsonify({
        "server": NEO4J_SERVER,
        "port": WS_PORT,
        "username": _u,
        "password": _p,
        "case_name": session.get("case", CASE_NAME)
    })


@app.route('/api/neo4j/users')
@login_required(role="ANY")
def neo4j_users():
    """Return list of Neo4j users (SHOW USERS)."""
    try:
        _u, _p = get_neo4j_creds()
        if _u is None:
            return jsonify({"error": "Session expired"}), 401
        neo4j_uri = "bolt://" + NEO4J_SERVER + ":" + NEO4J_PORT
        driver = GraphDatabase.driver(neo4j_uri, auth=(_u, _p))
        users = []
        with driver.session(database="system") as s:
            result = s.run("SHOW USERS")
            for record in result:
                row = {"user": record.get("user", "")}
                if "roles" in record.keys():
                    row["roles"] = list(record.get("roles") or [])
                if "suspended" in record.keys():
                    row["suspended"] = record.get("suspended")
                users.append(row)
        driver.close()
        return jsonify(users)
    except Exception as e:
        logger.error("[!] neo4j_users error: {0}".format(str(e)))
        return jsonify({"error": str(e)}), 500


@app.route('/api/neo4j/databases')
@login_required(role="ANY")
def neo4j_databases():
    """Return list of Neo4j databases (SHOW DATABASES)."""
    try:
        _u, _p = get_neo4j_creds()
        if _u is None:
            return jsonify({"error": "Session expired"}), 401
        neo4j_uri = "bolt://" + NEO4J_SERVER + ":" + NEO4J_PORT
        driver = GraphDatabase.driver(neo4j_uri, auth=(_u, _p))
        databases = []
        with driver.session(database="system") as s:
            result = s.run("SHOW DATABASES")
            for record in result:
                databases.append(record.get("name", ""))
        driver.close()
        return jsonify(databases)
    except Exception as e:
        logger.error("[!] neo4j_databases error: {0}".format(str(e)))
        return jsonify({"error": str(e)}), 500


@app.route('/api/neo4j/user-privileges')
@login_required(role="ANY")
def neo4j_user_privileges():
    """Return privilege info for all users (SHOW USER X PRIVILEGES)."""
    try:
        _u, _p = get_neo4j_creds()
        if _u is None:
            return jsonify({"error": "Session expired"}), 401
        neo4j_uri = "bolt://" + NEO4J_SERVER + ":" + NEO4J_PORT
        driver = GraphDatabase.driver(neo4j_uri, auth=(_u, _p))
        # First get users, then get their privileges
        users = []
        with driver.session(database="system") as s:
            result = s.run("SHOW USERS")
            for record in result:
                users.append(record.get("user", ""))
        privileges = []
        for user in users:
            try:
                with driver.session(database="system") as s:
                    safe_user = _safe_neo4j_identifier(user, "username")
                    result = s.run("SHOW USER " + safe_user + " PRIVILEGES")
                    for record in result:
                        priv = {"user": user}
                        if "graph" in record.keys():
                            priv["graph"] = record.get("graph", "")
                        if "access" in record.keys():
                            priv["access"] = record.get("access", "")
                        privileges.append(priv)
            except Exception:
                pass
        driver.close()
        return jsonify(privileges)
    except Exception as e:
        logger.error("[!] neo4j_user_privileges error: {0}".format(str(e)))
        return jsonify({"error": str(e)}), 500


# Sigma rescan API
@app.route('/sigma_rescan', methods=["POST"])
@login_required(role="ANY")
@http_request_logging
def sigma_rescan():
    """
    Re-scan EVTX files with Sigma rules.
    Request JSON: { 
        "rules_path": "sigma/rules",  (optional, defaults to "sigma")
        "evtx_files": ["file1.evtx", "file2.evtx"]  (optional, defaults to files in upload folder)
    }
    """
    try:
        data = request.get_json() or {}
        rules_path = data.get("rules_path", "sigma")
        evtx_files_input = data.get("evtx_files", [])
        
        # Validate rules_path input type
        if not isinstance(rules_path, str):
            return jsonify({"error": "Invalid rules_path type"}), 400
        
        # Validate and resolve rules path using security helper
        if not rules_path:
            rules_path = "sigma"
        
        # Security: validate relative path with allowed prefixes
        is_valid, error_msg = validate_relative_path(rules_path, allowed_prefixes=['sigma'])
        if not is_valid:
            logger.warning(f"[!] Security: Invalid rules_path rejected: {rules_path} - {error_msg}")
            return jsonify({"error": f"Invalid rules path: {error_msg}"}), 400
        
        full_rules_path = os.path.join(FPATH, rules_path)
        
        # Security: verify path is within allowed directory
        if not is_safe_path(FPATH, rules_path):
            logger.warning(f"[!] Security: Path traversal attempt detected: {rules_path}")
            return jsonify({"error": "Invalid rules path"}), 400
        
        if not os.path.exists(full_rules_path):
            return jsonify({"error": f"Rules path not found: {rules_path}"}), 404
        
        # Determine EVTX files to scan
        upload_dir = os.path.join(FPATH, 'upload')
        sample_dir = os.path.join(FPATH, 'sample')
        evtx_files = []
        
        # Validate evtx_files_input type
        if not isinstance(evtx_files_input, list):
            return jsonify({"error": "evtx_files must be a list"}), 400
        
        if evtx_files_input:
            # Use specified files
            for filename in evtx_files_input:
                # Validate each filename type
                if not isinstance(filename, str):
                    return jsonify({"error": "Invalid filename type"}), 400
                
                # Security: sanitize filename with EVTX type restriction
                safe_filename, error_msg = sanitize_filename(filename, file_type='evtx')
                if safe_filename is None:
                    logger.warning(f"[!] Security: Invalid filename rejected: {filename} - {error_msg}")
                    return jsonify({"error": f"Invalid file name: {error_msg}"}), 400
                
                # Try upload folder first, then sample folder
                filepath = os.path.join(upload_dir, safe_filename)
                if not os.path.exists(filepath):
                    filepath = os.path.join(sample_dir, safe_filename)
                
                # Security: verify final path is within allowed directories
                if os.path.exists(filepath):
                    real_path = os.path.realpath(filepath)
                    if not (real_path.startswith(os.path.realpath(upload_dir) + os.sep) or 
                            real_path.startswith(os.path.realpath(sample_dir) + os.sep)):
                        logger.warning(f"[!] Security: File path traversal attempt: {filename}")
                        return jsonify({"error": f"Invalid file path: {filename}"}), 400
                    evtx_files.append(filepath)
                else:
                    return jsonify({"error": f"File not found: {filename}"}), 404
        else:
            # Scan all EVTX files in upload folder
            if os.path.exists(upload_dir):
                for filename in os.listdir(upload_dir):
                    if filename.lower().endswith('.evtx'):
                        evtx_files.append(os.path.join(upload_dir, filename))
        
        if not evtx_files:
            return jsonify({"error": "No EVTX files found. Please upload EVTX files first."}), 404
        
        # Run Sigma scan
        logger.info(f"[+] Starting Sigma rescan: {len(evtx_files)} files with rules from {rules_path}")
        sigma_results = sigma_scan_evtx(evtx_files, full_rules_path, timezone=0)
        
        # Save results to file
        output_path = FPATH + "/static/" + SIGMA_RESULTS_FILE
        with open(output_path, 'w', encoding='utf8') as f:
            json.dump(sigma_results, f, ensure_ascii=False, indent=2)
        
        logger.info(f"[+] Sigma rescan completed: {len(sigma_results)} detections")
        
        return jsonify({
            "success": True,
            "rules_path": rules_path,
            "files_scanned": len(evtx_files),
            "file_names": [os.path.basename(f) for f in evtx_files],
            "detections": len(sigma_results)
        })
        
    except Exception as e:
        logger.error(f"[!] Sigma rescan error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


# Sigma rescan with uploaded files
@app.route('/sigma_rescan_with_upload', methods=["POST"])
@login_required(role="ANY")
@http_request_logging
def sigma_rescan_with_upload():
    """
    Re-scan EVTX files with Sigma rules uploaded from the client.
    Form data:
        - sigma_files: multipart files (Sigma rule .yml files)
        - evtx_files: JSON string of EVTX filenames to scan
    """
    import tempfile
    import shutil
    
    temp_dir = None
    try:
        # Get uploaded Sigma files
        sigma_files = request.files.getlist('sigma_files')
        evtx_files_json = request.form.get('evtx_files', '[]')
        
        if not sigma_files:
            return jsonify({"error": "No Sigma rule files uploaded"}), 400
        
        # Parse EVTX files list
        try:
            evtx_files_input = json.loads(evtx_files_json)
        except json.JSONDecodeError:
            evtx_files_input = []
        
        # Create temporary directory for uploaded Sigma rules
        temp_dir = tempfile.mkdtemp(prefix='sigma_upload_')
        logger.info(f"[+] Created temporary directory for uploaded Sigma rules: {temp_dir}")
        
        # Save uploaded files to temporary directory
        saved_files = 0
        for sigma_file in sigma_files:
            if sigma_file.filename:
                # Security: sanitize filename
                filename = sigma_file.filename
                # Remove path separators for security
                filename = os.path.basename(filename)
                
                # Only accept .yml and .yaml files
                if not (filename.lower().endswith('.yml') or filename.lower().endswith('.yaml')):
                    continue
                
                # Validate filename doesn't contain dangerous characters
                if '..' in filename or filename.startswith('.'):
                    logger.warning(f"[!] Security: Invalid filename rejected: {filename}")
                    continue
                
                # Save file
                file_path = os.path.join(temp_dir, filename)
                sigma_file.save(file_path)
                saved_files += 1
        
        if saved_files == 0:
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
            return jsonify({"error": "No valid Sigma rule files (.yml or .yaml) were uploaded"}), 400
        
        logger.info(f"[+] Saved {saved_files} Sigma rule files to temporary directory")
        
        # Determine EVTX files to scan
        upload_dir = os.path.join(FPATH, 'upload')
        sample_dir = os.path.join(FPATH, 'sample')
        evtx_files = []
        
        if evtx_files_input and isinstance(evtx_files_input, list):
            # Use specified files
            for filename in evtx_files_input:
                if not isinstance(filename, str):
                    continue
                
                # Security: sanitize filename with EVTX type restriction
                safe_filename, error_msg = sanitize_filename(filename, file_type='evtx')
                if safe_filename is None:
                    logger.warning(f"[!] Security: Invalid filename rejected: {filename}")
                    continue
                
                # Try upload folder first, then sample folder
                filepath = os.path.join(upload_dir, safe_filename)
                if not os.path.exists(filepath):
                    filepath = os.path.join(sample_dir, safe_filename)
                
                if os.path.exists(filepath):
                    real_path = os.path.realpath(filepath)
                    if (real_path.startswith(os.path.realpath(upload_dir) + os.sep) or 
                        real_path.startswith(os.path.realpath(sample_dir) + os.sep)):
                        evtx_files.append(filepath)
        else:
            # Scan all EVTX files in upload folder
            if os.path.exists(upload_dir):
                for filename in os.listdir(upload_dir):
                    if filename.lower().endswith('.evtx'):
                        evtx_files.append(os.path.join(upload_dir, filename))
        
        if not evtx_files:
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
            return jsonify({"error": "No EVTX files found. Please upload EVTX files first."}), 404
        
        # Run Sigma scan with uploaded rules
        logger.info(f"[+] Starting Sigma scan: {len(evtx_files)} files with {saved_files} uploaded rules")
        sigma_results = sigma_scan_evtx(evtx_files, temp_dir, timezone=0)
        
        # Save results to file
        output_path = FPATH + "/static/" + SIGMA_RESULTS_FILE
        with open(output_path, 'w', encoding='utf8') as f:
            json.dump(sigma_results, f, ensure_ascii=False, indent=2)
        
        logger.info(f"[+] Sigma scan completed: {len(sigma_results)} detections")
        
        # Cleanup temporary directory
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
            logger.info(f"[+] Cleaned up temporary Sigma rules directory")
        
        return jsonify({
            "success": True,
            "rules_uploaded": saved_files,
            "files_scanned": len(evtx_files),
            "file_names": [os.path.basename(f) for f in evtx_files],
            "detections": len(sigma_results)
        })
        
    except Exception as e:
        logger.error(f"[!] Sigma rescan with upload error: {str(e)}")
        import traceback
        traceback.print_exc()
        
        # Cleanup on error
        if temp_dir and os.path.exists(temp_dir):
            try:
                shutil.rmtree(temp_dir)
            except:
                pass
        
        return jsonify({"error": str(e)}), 500


# List available EVTX files
@app.route('/sigma_files')
@login_required(role="ANY")
def sigma_files():
    """Return list of available EVTX files in upload folder"""
    files = []
    upload_dir = os.path.join(FPATH, 'upload')
    
    if os.path.exists(upload_dir):
        for filename in sorted(os.listdir(upload_dir)):
            filepath = os.path.join(upload_dir, filename)
            if os.path.isfile(filepath) and filename.lower().endswith('.evtx'):
                # Get file size
                size = os.path.getsize(filepath)
                size_str = f"{size / 1024 / 1024:.1f} MB" if size > 1024*1024 else f"{size / 1024:.1f} KB"
                files.append({
                    "name": filename,
                    "size": size_str,
                    "path": filename
                })
    
    return jsonify(files)


# List available Sigma rule folders
@app.route('/sigma_folders')
@login_required(role="ANY")
def sigma_folders():
    """Return list of available Sigma rule folders"""
    folders = []
    sigma_base = os.path.join(FPATH, 'sigma')
    
    if os.path.exists(sigma_base):
        # Add root sigma folder
        folders.append({"path": "sigma", "name": "sigma (default)"})
        
        # Add subfolders
        for item in sorted(os.listdir(sigma_base)):
            item_path = os.path.join(sigma_base, item)
            if os.path.isdir(item_path) and not item.startswith('.'):
                folders.append({"path": f"sigma/{item}", "name": f"sigma/{item}"})
                
                # Add second level folders (e.g., sigma/rules/windows)
                for subitem in sorted(os.listdir(item_path)):
                    subitem_path = os.path.join(item_path, subitem)
                    if os.path.isdir(subitem_path) and not subitem.startswith('.'):
                        folders.append({"path": f"sigma/{item}/{subitem}", "name": f"sigma/{item}/{subitem}"})
    
    return jsonify(folders)


# Web application upload
@app.route("/upload", methods=["POST"])
@login_required(role="ANY")
@http_request_logging
def do_upload():
    UPLOAD_DIR = os.path.join(FPATH, 'upload')
    filelist = []

    if os.path.exists(UPLOAD_DIR) is False:
        os.makedirs(UPLOAD_DIR)
        logger.info("[+] make upload folder {0}.".format(UPLOAD_DIR))

    try:
        timezone = request.form["timezone"]
        logtype = request.form["logtype"]
        addlog = request.form["addlog"]
        sigmascan = request.form["sigmascan"]
        casename = request.form["casename"]
        
        # Generate unique timestamp for this upload batch
        from datetime import datetime
        upload_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        for i in range(0, len(request.files)):
            loadfile = "file" + str(i)
            file = request.files[loadfile]
            if file and file.filename:
                # Create unique filename: timestamp_index.ext
                if "EVTX" in logtype:
                    unique_filename = f"{upload_timestamp}_{i:02d}.evtx"
                    filename = os.path.join(UPLOAD_DIR, unique_filename)
                elif "XML" in logtype:
                    unique_filename = f"{upload_timestamp}_{i:02d}.xml"
                    filename = os.path.join(UPLOAD_DIR, unique_filename)
                else:
                    continue
                file.save(filename)
                filelist.append(filename)
                logger.info(f"[+] Uploaded file saved as: {unique_filename}")
                
        if "EVTX" in logtype:
            logoption = "-e"
        elif "XML" in logtype:
            logoption = "-x"
        else:
            return "FAIL"
        if not is_valid_timezone(timezone):
            return "FAIL"
        if addlog in "true":
            add_option = "--add"
        else:
            add_option = "--delete"
        if sigmascan in "true":
            sigma_option = ["--sigma"]
        else:
            sigma_option = []
        if not re.search(r"\A[0-9a-zA-Z]{2,20}\Z", casename):
            return "FAIL"

        log_file = os.path.join(FPATH, "static", "logontracer.log")
        if os.path.exists(log_file):
            os.remove(log_file)

        _up_user, _up_pass = get_neo4j_creds()
        if _up_user is None:
            return "FAIL"
        parse_command = ["python3", os.path.join(FPATH, "logontracer.py"),
                         add_option, "--case", casename, "-z", timezone,
                         logoption] + filelist + sigma_option + [
                         "-s", NEO4J_SERVER,
                         "-u", _up_user,
                         "-p", _up_pass]
        with open(log_file, "w") as lf:
            subprocess.Popen(parse_command, stdout=lf, stderr=subprocess.STDOUT)
        # parse_evtx(filename)
        return "SUCCESS"

    except:
        return "FAIL"


# Load from Elasticsearch
@app.route("/esload", methods=["POST"])
@login_required(role="ANY")
@http_request_logging
def es_load():
    try:
        fromdatetime = request.form["fromdatetime"]
        todatetime = request.form["todatetime"]
        timezone = request.form["timezone"]
        es_server = request.form["es_server"]
        addlog = request.form["addlog"]
        casename = request.form["casename"]
        addes = request.form["addes"]

        from_option = []
        if fromdatetime not in "false":
            try:
                datetime.datetime.strptime(fromdatetime, "%Y-%m-%dT%H:%M:%S")
                from_option = ["-f", fromdatetime]
            except:
                return "FAIL"

        to_option = []
        if todatetime not in "false":
            try:
                datetime.datetime.strptime(todatetime, "%Y-%m-%dT%H:%M:%S")
                to_option = ["-t", todatetime]
            except:
                return "FAIL"

        es_ip, es_port = es_server.split(":")
        if (re.search(IPv4_PATTERN, es_ip) or es_ip in "localhost") and re.search(r"\A\d{2,5}\Z", es_port):
            es_server_option = ["--es-server", es_server]
        else:
            return "FAIL"

        if not is_valid_timezone(timezone):
            return "FAIL"

        if addlog in "true":
            log_option = "--add"
        else:
            log_option = "--delete"

        if addes in "true":
            es_option = ["--postes"]
        else:
            es_option = []

        if not re.search(r"\A[0-9a-zA-Z]{2,20}\Z", casename):
            return "FAIL"

        log_file = os.path.join(FPATH, "static", "logontracer.log")
        if os.path.exists(log_file):
            os.remove(log_file)

        _es_user, _es_pass = get_neo4j_creds()
        if _es_user is None:
            return "FAIL"
        parse_command = ["python3", os.path.join(FPATH, "logontracer.py"),
                         "--es", log_option] + es_option + [
                         "--case", casename, "-z", timezone
                         ] + from_option + to_option + es_server_option + [
                         "-s", NEO4J_SERVER,
                         "-u", _es_user,
                         "-p", _es_pass,
                         "--es-index", ES_INDEX,
                         "--es-prefix", ES_PREFIX]
        with open(log_file, "w") as lf:
            subprocess.Popen(parse_command, stdout=lf, stderr=subprocess.STDOUT)
        return "SUCCESS"

    except:
        return "FAIL"


@app.route("/favicon.ico")
def favicon():
    return app.send_static_file("favicon.ico")


# AI Analysis API Endpoints
@app.route("/api/analyze-security-pattern", methods=["POST"])
@login_required(role="ANY")
def analyze_security_pattern():
    """AI-powered security pattern analysis"""
    try:
        from intelligence.analysis_engine import SecurityAnalysisEngine
        
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400
        
        query_type = data.get('query_type', 'general_analysis')
        analysis_data = data.get('analysis_data', {})
        graph_stats = data.get('graph_stats', {})
        
        # Initialize AI analysis engine
        engine = SecurityAnalysisEngine()
        
        # Run async analysis
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            analysis_result = loop.run_until_complete(
                engine.analyze_query_results(query_type, analysis_data, graph_stats)
            )
        finally:
            loop.close()
        
        return jsonify({
            "success": True,
            "analysis": analysis_result
        })
        
    except Exception as e:
        logger.error(f"AI analysis error: {str(e)}")
        return jsonify({
            "success": False,
            "error": f"Analysis failed: {str(e)}"
        }), 500


@app.route("/api/ai-status", methods=["GET"])
@login_required(role="ANY")
def ai_status():
    """Get AI analysis engine status"""
    try:
        from intelligence.analysis_engine import SecurityAnalysisEngine
        
        engine = SecurityAnalysisEngine()
        status = engine.get_status()
        
        return jsonify({
            "success": True,
            "status": status
        })
        
    except Exception as e:
        logger.error(f"AI status check error: {str(e)}")
        return jsonify({
            "success": False,
            "error": f"Status check failed: {str(e)}"
        }), 500


# LLM Agent API Endpoints
@app.route("/api/ai/agent-detect", methods=["POST"])
@login_required(role="ANY")
def ai_agent_detect():
    """Run autonomous threat detection using LLM Agent"""
    try:
        from intelligence.agent_engine import LLMDetectionAgent
        
        data = request.get_json()
        initial_context = data.get("context", "Detect suspicious logon behavior in Active Directory")

        _agent_user, _agent_pass = get_neo4j_creds()
        if _agent_user is None:
            return jsonify({"success": False, "error": "Session expired. Please log in again."}), 401

        # Create agent instance
        neo4j_uri = f"bolt://{NEO4J_SERVER}:{WS_PORT}"
        agent = LLMDetectionAgent(neo4j_uri, _agent_user, _agent_pass, session.get('case', CASE_NAME))
        
        # Run autonomous detection
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            result = loop.run_until_complete(
                agent.run_autonomous_detection(initial_context)
            )
        finally:
            loop.close()
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Agent detection error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e),
            'investigation_completed': False,
            'threats_discovered': 0
        }), 500

@app.route("/api/ai/agent-status", methods=["GET"])
@login_required(role="ANY")
def ai_agent_status():
    """Get LLM Agent status"""
    try:
        from intelligence.agent_engine import LLMDetectionAgent
        
        _agent_user, _agent_pass = get_neo4j_creds()
        if _agent_user is None:
            return jsonify({"success": False, "error": "Session expired. Please log in again."}), 401

        # Check agent configuration
        neo4j_uri = f"bolt://{NEO4J_SERVER}:{WS_PORT}"
        agent = LLMDetectionAgent(neo4j_uri, _agent_user, _agent_pass, session.get('case', CASE_NAME))
        
        return jsonify({
            'success': True,
            'max_iterations': agent.max_iterations,
            'model': agent.config.model if agent.is_enabled else None
        })
        
    except Exception as e:
        logger.error(f"Agent status error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e),
        }), 500


@app.route("/api/ai/generate-sigma-rules", methods=["POST"])
@login_required(role="ANY")
def ai_generate_sigma_rules():
    """Generate Sigma rules from AI Analysis results"""
    try:
        from intelligence.openai_client import OpenAIClient
        from intelligence.llm_config import get_llm_config, validate_config
        
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'message': 'No analysis result provided',
                'sigma_rules': []
            }), 400
        
        analysis_result = data.get('analysis_result', {})
        
        if not analysis_result:
            return jsonify({
                'success': False,
                'message': 'Empty analysis result',
                'sigma_rules': []
            }), 400
        
        # Check risk level - look in multiple locations
        risk_level = (
            analysis_result.get('overall_risk_level') or 
            analysis_result.get('risk_level') or 
            analysis_result.get('final_report', {}).get('overall_risk_level') or
            'low'
        )
        
        if risk_level.lower() not in ['high', 'critical']:
            return jsonify({
                'success': False,
                'message': f'Sigma rule generation requires High or Critical risk level. Current level: {risk_level}',
                'sigma_rules': []
            }), 400
        
        # Initialize OpenAI client using proper config loading
        from intelligence.llm_config import get_llm_config, validate_config
        
        config = get_llm_config()
        if not validate_config(config):
            return jsonify({
                'success': False,
                'message': 'AI Analysis is not enabled. Please configure API key.',
                'sigma_rules': []
            }), 400
        
        client = OpenAIClient(config)
        
        # Generate Sigma rules (async)
        async def generate():
            return await client.generate_sigma_rules(analysis_result)
        
        result = asyncio.run(generate())
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Sigma rule generation error: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Error: {str(e)}',
            'sigma_rules': []
        }), 500


# Calculate ChangeFinder
def adetection(counts, users, starttime, tohours):
    import numpy as np
    import changefinder
    
    count_array = np.zeros((5, len(users), tohours + 1))
    count_all_array = []
    result_array = []
    cfdetect = {}
    for _, event in counts.iterrows():
        column = int((datetime.datetime.strptime(event["dates"], "%Y-%m-%d  %H:%M:%S") - starttime).total_seconds() / 3600)
        row = users.index(event["username"])
        # count_array[row, column, 0] = count_array[row, column, 0] + count
        if event["eventid"] == 4624:
            count_array[0, row, column] = event["count"]
        elif event["eventid"] == 4625:
            count_array[1, row, column] = event["count"]
        elif event["eventid"] == 4768:
            count_array[2, row, column] = event["count"]
        elif event["eventid"] == 4769:
            count_array[3, row, column] = event["count"]
        elif event["eventid"] == 4776:
            count_array[4, row, column] = event["count"]

    # count_average = count_array.mean(axis=0)
    count_sum = np.sum(count_array, axis=0)
    count_average = count_sum.mean(axis=0)
    num = 0
    for udata in count_sum:
        cf = changefinder.ChangeFinder(r=0.04, order=1, smooth=5)
        ret = []
        for i in count_average:
            cf.update(i)

        for i in udata:
            score = cf.update(i)
            ret.append(round(score, 2))
        result_array.append(ret)

        cfdetect[users[num]] = max(ret)

        count_all_array.append(udata.tolist())
        for var in range(0, 5):
            con = []
            for i in range(0, tohours + 1):
                con.append(count_array[var, num, i])
            count_all_array.append(con)
        num += 1

    return count_all_array, result_array, cfdetect


# Calculate PageRank
def pagerank(event_set, admins, hmm, cf, ntml):
    graph = {}
    nodes = []
    for _, events in event_set.iterrows():
        nodes.append(events["ipaddress"])
        nodes.append(events["username"])

    for node in list(set(nodes)):
        links = []
        for _, events in event_set.iterrows():
            if node in events["ipaddress"]:
                links.append(events["username"])
            if node in events["username"]:
                links.append(events["ipaddress"])
        graph[node] = links

    # d = 0.85
    numloops = 30
    ranks = {}
    d = {}
    npages = len(graph)

    # Calc damping factor and initial value
    for page in graph:
        if page in admins:
            df = 0.6
        elif "@" in page[-1]:
            df = 0.85
        else:
            df = 0.8
        if page in hmm:
            df -= 0.2
        if page in ntml:
            df -= 0.1
        if page in cf:
            df -= cf[page] / 200

        d[page] = df
        ranks[page] = 1.0 / npages

    for i in range(0, numloops):
        newranks = {}
        for page in graph:
            newrank = (1 - d[page]) / npages
            for node in graph:
                if page in graph[node]:
                    newrank = newrank + d[node] * ranks[node]/len(graph[node])
            newranks[page] = newrank
        ranks = newranks

    nranks = {}
    max_v = max(ranks.values())
    min_v = min(ranks.values())
    for key, value in ranks.items():
        nranks[key] = (value - min_v) / (max_v - min_v)

    return nranks


# Calculate Hidden Markov Model
def decodehmm(frame, users, stime):
    import numpy as np
    import joblib
    
    detect_hmm = []
    model = joblib.load(FPATH + "/model/hmm.pkl")
    while(1):
        date = stime.strftime("%Y-%m-%d")
        for user in users:
            hosts = np.unique(frame[(frame["user"] == user)].host.values)
            for host in hosts:
                udata = []
                for _, data in frame[(frame["date"].str.contains(date)) & (frame["user"] == user) & (frame["host"] == host)].iterrows():
                    id = data["id"]
                    if id == 4776:
                        udata.append(0)
                    elif id == 4768:
                        udata.append(1)
                    elif id == 4769:
                        udata.append(2)
                    elif id == 4624:
                        udata.append(3)
                    elif id == 4625:
                        udata.append(4)
                if len(udata) > 2:
                    data_decode = model.predict(np.array([np.array(udata)], dtype="int").T)
                    unique_data = np.unique(data_decode)
                    if unique_data.shape[0] == 2:
                        if user not in detect_hmm:
                            detect_hmm.append(user)

        stime += datetime.timedelta(days=1)
        if frame.loc[(frame["date"].str.contains(date))].empty:
            break

    return detect_hmm


# Learning Hidden Markov Model
def learnhmm(frame, users, stime):
    import numpy as np
    from hmmlearn import hmm
    import joblib
    
    lengths = []
    data_array = np.array([])
    # start_probability = np.array([0.52, 0.37, 0.11])
    emission_probability = np.array([[0.09,   0.05,   0.35,   0.51],
                                     [0.0003, 0.0004, 0.0003, 0.999],
                                     [0.0003, 0.0004, 0.0003, 0.999]])
    while(1):
        date = stime.strftime("%Y-%m-%d")
        for user in users:
            hosts = np.unique(frame[(frame["user"] == user)].host.values)
            for host in hosts:
                udata = np.array([])
                for _, data in frame[(frame["date"].str.contains(date)) & (frame["user"] == user) & (frame["host"] == host)].iterrows():
                    id = data["id"]
                    udata = np.append(udata, id)
                # udata = udata[(udata*np.sign(abs(np.diff(np.concatenate(([0], udata)))))).nonzero()]
                if udata.shape[0] > 2:
                    data_array = np.append(data_array, udata)
                    lengths.append(udata.shape[0])

        stime += datetime.timedelta(days=1)
        if frame.loc[(frame["date"].str.contains(date))].empty:
            break

    data_array[data_array == 4776] = 0
    data_array[data_array == 4768] = 1
    data_array[data_array == 4769] = 2
    data_array[data_array == 4624] = 3
    data_array[data_array == 4625] = 4
    # model = hmm.GaussianHMM(n_components=3, covariance_type="full", n_iter=10000)
    model = hmm.CategoricalHMM(n_components=3, n_iter=10000)
    # model.startprob_ = start_probability
    model.emissionprob_ = emission_probability
    model.fit(np.array([data_array], dtype="int").T, lengths)
    joblib.dump(model, FPATH + "/model/hmm.pkl")


# Post to Elastic Search cluster
def post_es(index, es, doc):
    es.index(index=index, body=doc)


# Create mattings to Elastic Search
def create_map(es, index):
    with open(FPATH + "/es-index/" + index + ".json", "r") as f:
        body = f.read()
    es.indices.create(index=index, body=body)


def to_lxml(record_xml):
    from lxml import etree
    
    rep_xml = record_xml.replace("xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"", "")
    fin_xml = rep_xml.encode("utf-8")
    parser = etree.XMLParser(resolve_entities=False)
    return etree.fromstring(fin_xml, parser)


def xml_records(filename):
    from evtx import PyEvtxParser
    from lxml import etree
    
    if args.evtx:
        with open(filename, "rb") as evtx:
            parser = PyEvtxParser(evtx)
            for record in parser.records():
                try:
                    yield to_lxml(record["data"]), None
                except etree.XMLSyntaxError as e:
                    yield record["data"], e

    if args.xmls:
        xdata = ""
        with open(filename, 'r') as fx:
            for line in fx:
                xdata += line.replace("<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>", "").replace("</Events>", "").replace("<Events>", "")
            # fixdata = xdata.replace("<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>", "")
            xml_list = re.split("<Event xmlns=[\'\"]http://schemas.microsoft.com/win/2004/08/events/event[\'\"]>", xdata)
            del xdata
            for xml in xml_list:
                if xml.startswith("<System>"):
                    try:
                        yield to_lxml("<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\" ?><Event>" + xml), None
                    except etree.XMLSyntaxError as e:
                        yield xml, e


def convert_logtime(logtime, tzone):
    tzless = re.sub(r'[^0-9-:\s]', ' ', logtime.split(".")[0]).strip()
    try:
        return datetime.datetime.strptime(tzless, "%Y-%m-%d %H:%M:%S") + datetime.timedelta(hours=tzone)
    except:
        return datetime.datetime.strptime(tzless, "%Y-%m-%dT%H:%M:%S") + datetime.timedelta(hours=tzone)


def _safe_neo4j_identifier(value, label="identifier"):
    """
    Validate and backtick-quote a Neo4j identifier (database name, username, role).
    Raises ValueError if the value is not a safe identifier.
    """
    if not value or not isinstance(value, str):
        raise ValueError(f"Invalid {label}: empty or wrong type")
    if len(value) > 50:
        raise ValueError(f"Invalid {label}: too long (max 50)")
    if not NEO4J_IDENTIFIER_PATTERN.match(value):
        raise ValueError(f"Invalid {label}: only alphanumeric and underscore allowed")
    # Backtick-quote the identifier
    return "`" + value + "`"


# Check Neo4j edition
def check_neo4j_enterprise(driver):
    """
    Check if Neo4j is Enterprise edition
    Returns True if Enterprise, False if Community
    """
    try:
        with driver.session(database="system") as session:
            result = session.run("CALL dbms.components() YIELD name, edition")
            service_info = result.single()
            if service_info:
                edition = service_info.get("edition", "").lower()
                return "enterprise" in edition
            return False
    except Exception as e:
        logger.warning("[!] Could not determine Neo4j edition: {0}. Assuming Community edition.".format(str(e)))
        return False


# Create database for neo4j
def create_database(driver, database):
    from neo4j.exceptions import ClientError

    try:
        safe_db = _safe_neo4j_identifier(database, "database name")
    except ValueError as e:
        logger.error("[!] Invalid database name: {0}".format(str(e)))
        return "neo4j"

    try:
        with driver.session(database="system") as system:
            system.run("CREATE DATABASE " + safe_db + ";")
        logger.info("[+] Created database {0}.".format(database))
    except ClientError as e:
        if "Database already exists" in str(e):
            logger.info("[+] Use database {0}.".format(database))
        elif "Unsupported administration command" in str(e):
            logger.info("[+] Can't create database. This feature is in Neo4j Enterprise.")
            database = "neo4j"
    except:
        database = "neo4j"

    return database


# Delete database for neo4j
def delete_database(driver, database):
    from neo4j.exceptions import ClientError

    try:
        safe_db = _safe_neo4j_identifier(database, "database name")
    except ValueError as e:
        logger.error("[!] Invalid database name: {0}".format(str(e)))
        return

    try:
        with driver.session(database="system") as system:
            system.run("DROP DATABASE " + safe_db + ";")
        logger.info("[+] Delete database {0}.".format(database))
    except ClientError as e:
        if "Database does not exist" in str(e):
            logger.error("[!] Database does not exist {0}.".format(database))
        elif "Unsupported administration command" in str(e):
            logger.error("[!] Can't delete database. This feature is in Neo4j Enterprise.")
        else:
            logger.error(str(e))


# Create user for neo4j
def create_neo4j_user(driver, username, password, role):
    from neo4j.exceptions import ClientError

    try:
        safe_user = _safe_neo4j_identifier(username, "username")
        safe_role = _safe_neo4j_identifier(role, "role")
    except ValueError as e:
        logger.error("[!] Invalid identifier: {0}".format(str(e)))
        return

    try:
        with driver.session(database="system") as system:
            system.run("CREATE USER " + safe_user + " SET PASSWORD $password CHANGE NOT REQUIRED;",
                        {"password": password})
        logger.info("[+] Created user {0} for neo4j.".format(username))
    except ClientError as e:
        if "User already exists" in str(e):
            logger.error("[!] User already exists {0}.".format(username))
        elif "Unsupported administration command" in str(e):
            logger.error("[!] Can't create user.")
        else:
            logger.error(str(e))

    # Check if Neo4j Enterprise features are available and set up roles
    try:
        with driver.session(database="system") as system:
            # Test if this is Neo4j Enterprise by trying to check components
            result = system.run("CALL dbms.components() YIELD name, edition")
            service_info = result.single()
            is_enterprise = "enterprise" in str(service_info)

            if is_enterprise:
                # For admin role, grant admin privileges directly
                if "admin" in role:
                    system.run("GRANT ROLE admin TO " + safe_user + ";")
                    logger.info("[+] Set {0} admin role for neo4j.".format(username))
                else:
                    # For other roles, create custom role and manage database access
                    safe_role_name = _safe_neo4j_identifier(username + "_role", "role name")
                    system.run("CREATE OR REPLACE ROLE " + safe_role_name + " AS COPY OF " + safe_role + ";")
                    # Note: Revoke all access and then grant specific access
                    try:
                        system.run("REVOKE ACCESS ON DATABASE * FROM " + safe_role_name + ";")
                    except:
                        logger.info("[!] Could not revoke all database access. This may be expected in some Neo4j configurations.")
                    system.run("GRANT ROLE " + safe_role_name + " TO " + safe_user + ";")
                    system.run("GRANT ACCESS ON DATABASE neo4j TO " + safe_role_name + ";")
                    logger.info("[+] Created {0}_role for neo4j.".format(username))
            else:
                logger.info("[+] Neo4j Community Edition detected. Role management is limited.")

    except ClientError as e:
        if "Role already exists" in str(e):
            logger.error("[!] Role already exists {0}.".format(username))
        elif "Unsupported administration command" in str(e):
            logger.error("[!] Can't create role. This feature is in Neo4j Enterprise.")
        else:
            logger.error(str(e))
    except Exception as e:
        logger.warning("[!] Could not determine Neo4j edition or set up roles: {0}".format(str(e)))

    logger.info("[+] User creation completed for {0}.".format(username))


# Delete user for neo4j
def delete_neo4j_user(driver, username):
    from neo4j.exceptions import ClientError

    try:
        safe_user = _safe_neo4j_identifier(username, "username")
    except ValueError as e:
        logger.error("[!] Invalid username: {0}".format(str(e)))
        return

    try:
        with driver.session(database="system") as system:
            system.run("DROP USER " + safe_user + ";")
        logger.info("[+] Delete user {0} for neo4j.".format(username))
    except ClientError as e:
        if "User does not exist" in str(e):
            logger.error("[!] User does not exist {0}.".format(username))
        elif "Unsupported administration command" in str(e):
            logger.error("[!] Can't delete user.")
        else:
            logger.error(str(e))


# Change user status for neo4j
def change_status_neo4j_user(driver, username, action):
    VALID_STATUS = {"suspended": "SUSPENDED", "active": "ACTIVE"}
    safe_action = VALID_STATUS.get(action)
    if safe_action is None:
        logger.error("[!] Invalid action for user status change: {0}".format(action))
        return

    try:
        safe_user = _safe_neo4j_identifier(username, "username")
    except ValueError as e:
        logger.error("[!] Invalid username: {0}".format(str(e)))
        return

    try:
        with driver.session(database="system") as neo4j_session:
            neo4j_session.run("ALTER USER " + safe_user + " SET STATUS " + safe_action + ";")
        logger.info("[+] Change user {0} status {1} for neo4j.".format(username, safe_action))
    except Exception as e:
        if "User does not exist" in str(e):
            logger.error("[!] User does not exist {0}.".format(username))
        elif "Unsupported administration command" in str(e):
            logger.error("[!] Can't change user status.")
        else:
            logger.error(str(e))


# Add user access role for database
def add_db_access_role(driver, username, dbname):
    try:
        safe_role_name = _safe_neo4j_identifier(username + "_role", "role name")
        safe_db = _safe_neo4j_identifier(dbname, "database name")
    except ValueError as e:
        logger.error("[!] Invalid identifier: {0}".format(str(e)))
        return

    try:
        with driver.session(database="system") as neo4j_session:
            neo4j_session.run("GRANT ACCESS ON DATABASE " + safe_db + " TO " + safe_role_name + ";")
        logger.info("[+] Added database access role: user {0} database {1}.".format(username, dbname))
    except Exception as e:
        if "Role does not exist" in str(e):
            logger.error("[!] User does not exist {0}.".format(username))
        elif "Unsupported administration command" in str(e):
            logger.error("[!] Can't add database access role.")
        else:
            logger.error(str(e))


# Delete user access role for database
def delete_db_access_role(driver, username, dbname):
    try:
        safe_role_name = _safe_neo4j_identifier(username + "_role", "role name")
        safe_db = _safe_neo4j_identifier(dbname, "database name")
    except ValueError as e:
        logger.error("[!] Invalid identifier: {0}".format(str(e)))
        return

    try:
        with driver.session(database="system") as neo4j_session:
            neo4j_session.run("REVOKE ACCESS ON DATABASE " + safe_db + " FROM " + safe_role_name + ";")
        logger.info("[+] Deleted database access role: user {0} database {1}.".format(username, dbname))
    except Exception as e:
        if "Role does not exist" in str(e):
            logger.error("[!] User does not exist {0}.".format(username))
        elif "Unsupported administration command" in str(e):
            logger.error("[!] Can't delete database access role.")
        else:
            logger.error(str(e))


# git clone or pull from url
def git_clone_pull(url, download_path):
    import git
    
    if os.path.exists(download_path):
        try:
            repo = git.Repo(download_path)
            o = repo.remotes.origin
            o.pull()
            logger.info("[+] git pull {0} repository.".format(download_path))
        except:
            logger.error("[!] Can't pull {0} repository.".format(download_path))
    else:
        try:
            git.Repo.clone_from(url, download_path)
            logger.info("[+] git clone {0} to {1}.".format(url, download_path))
        except:
            logger.error("[!] Can't clone git repository {0}.".format(url))


# Load sigma rules
def load_sigma(download_path):
    """
    Load Sigma rules
    Returns: (sigma_rules, eventids_set)
        sigma_rules: List of [event_ids, detection_conditions, title, description, level]
        eventids_set: Set of all Event IDs from loaded rules
    """
    # Lazy import for Sigma rule processing - must import at function level for availability
    import glob
    from sigma.collection import SigmaCollection
    from sigma.rule import SigmaRule
    
    # Note: rule.status is an Enum, so we convert to string for comparison
    allowed_status_str = ["stable", "test"]  # "experimental" etc can be added
    sigma_rules = []
    eventids = []

    if os.path.exists(download_path):
        logger.info("[+] Load sigma rules from {0}.".format(download_path))
        sigma_rules_files = glob.glob(download_path + '/**/*.yml', recursive=True)
        
        for rules_file in sigma_rules_files:
            # ignore rules
            if ".github" in rules_file or "config" in rules_file or "test" in rules_file:
                continue

            try:
                # Load using modern SigmaCollection API
                collection = SigmaCollection.load_ruleset([rules_file], collect_errors=True)
                
                for rule in collection.rules:
                    # Check for errors in rule
                    if rule.errors:
                        logger.debug(f"[+] Rule {rules_file} has errors: {rule.errors}")
                        continue
                    
                    # Check logsource - must be Windows Security logs
                    logsource = rule.logsource
                    if not logsource:
                        continue
                        
                    product = logsource.product if logsource.product else ""
                    service = logsource.service if logsource.service else ""
                    
                    if "windows" not in product.lower() or "security" not in service.lower():
                        continue
                    
                    # Check status (Enum comparison - convert to string)
                    status_str = str(rule.status).lower() if rule.status else ""
                    if status_str not in allowed_status_str:
                        continue
                    
                    # Skip count-based detection conditions
                    condition_str = " ".join(rule.detection.condition) if rule.detection.condition else ""
                    if re.search(r"count", condition_str, re.IGNORECASE):
                        continue
                    
                    # Extract detection conditions using modern API
                    try:
                        detection_dict = extract_detection_conditions(rule)
                        if not detection_dict:
                            continue
                    except Exception as e:
                        logger.debug(f"[+] Can't extract detection from {rules_file}: {e}")
                        continue
                    
                    # Extract Event IDs
                    eid_list = extract_event_ids(detection_dict)
                    eventids.extend(eid_list)
                    
                    # Get rule metadata
                    title = rule.title if rule.title else "Untitled"
                    description = rule.description if rule.description else ""
                    # Convert Enum to string for level
                    level = str(rule.level).lower() if rule.level else "unknown"
                    
                    sigma_rules.append([eid_list, detection_dict, title, description, level])
                    
            except Exception as e:
                logger.debug(f"[+] Can't load sigma rule file {rules_file}: {e}")
                continue
    else:
        logger.error("[!] Not found {0}.".format(download_path))

    logger.info("[+] Loaded {0} sigma rules for security event log analysis.".format(len(sigma_rules)))
    
    return sigma_rules, set(eventids)


def sigma_scan_evtx(evtx_files, sigma_rules_path, timezone=0):
    """
    Sigma scan only mode - scan EVTX files with Sigma rules without Neo4j processing
    
    Args:
        evtx_files: List of EVTX file paths to scan
        sigma_rules_path: Path to Sigma rules folder
        timezone: Timezone offset (default: 0)
    
    Returns:
        List of detection results
    """
    from evtx import PyEvtxParser
    from lxml import etree as lxml_etree
    
    # Load Sigma rules
    git_clone_pull(SIGMA_URL, os.path.join(FPATH, 'sigma'))
    sigma_rules, sigma_eventids = load_sigma(sigma_rules_path)
    
    if not sigma_rules:
        logger.error("[!] No Sigma rules loaded from {0}".format(sigma_rules_path))
        return []
    
    sigma_results = []
    total_events = 0
    matched_events = 0
    
    logger.info("[+] Starting Sigma-only scan on {0} file(s)".format(len(evtx_files)))
    
    for evtx_file in evtx_files:
        logger.info("[+] Scanning: {0}".format(evtx_file))
        
        # Check file exists and is EVTX format
        if not os.path.exists(evtx_file):
            logger.error("[!] File not found: {0}".format(evtx_file))
            continue
            
        with open(evtx_file, "rb") as fb:
            fb_data = fb.read(8)
            if fb_data != EVTX_HEADER:
                logger.error("[!] Not an EVTX file: {0}".format(evtx_file))
                continue
        
        # Parse EVTX file directly (not using xml_records which depends on args)
        try:
            with open(evtx_file, "rb") as evtx:
                parser = PyEvtxParser(evtx)
                for record in parser.records():
                    total_events += 1
                    
                    if not total_events % 1000:
                        sys.stdout.write("\r[+] Processed {0} events, {1} detections".format(total_events, matched_events))
                        sys.stdout.flush()
                    
                    try:
                        node = to_lxml(record["data"])
                    except lxml_etree.XMLSyntaxError:
                        continue
                    
                    try:
                        eventid = int(node.xpath("/Event/System/EventID")[0].text)
                    except:
                        continue
                    
                    # Only process events that match Sigma rule event IDs
                    if eventid not in sigma_eventids:
                        continue
                    
                    # Get timestamp
                    try:
                        logtime = node.xpath("/Event/System/TimeCreated")[0].get("SystemTime")
                        etime = convert_logtime(logtime, timezone)
                    except:
                        etime = None
                    
                    # Get event data
                    event_data = node.xpath("/Event/EventData/Data")
                    
                    # Add EventID as a data element for matching
                    eventid_elem = lxml_etree.Element("Data")
                    eventid_elem.set("Name", "EventID")
                    eventid_elem.text = str(eventid)
                    enriched_event_data = list(event_data) + [eventid_elem]
                    
                    # Match against each Sigma rule
                    for search_eid, detection_dict, sigma_title, sigma_details, sigma_level in sigma_rules:
                        if eventid not in search_eid:
                            continue
                        
                        try:
                            if evaluate_sigma_condition(detection_dict, enriched_event_data):
                                matched_events += 1
                                
                                # Parse event XML into structured data
                                event_xml_bytes = lxml_etree.tostring(node, encoding="utf-8")
                                event_parsed = parse_event_xml(event_xml_bytes)
                                
                                sigma_results.append({
                                    "timestamp": etime.strftime("%Y-%m-%d %H:%M:%S") if etime else "-",
                                    "sigma_level": sigma_level,
                                    "sigma_title": sigma_title,
                                    "sigma_description": sigma_details,
                                    "event": event_parsed,
                                    "source_file": os.path.basename(evtx_file)
                                })
                        except Exception as e:
                            logger.debug("[!] Error evaluating rule '{0}': {1}".format(sigma_title, str(e)))
                            continue
        except Exception as e:
            logger.error("[!] Error parsing EVTX file {0}: {1}".format(evtx_file, str(e)))
            continue
    
    print()  # New line after progress
    logger.info("[+] Sigma scan completed: {0} detections from {1} events".format(matched_events, total_events))
    
    return sigma_results


def extract_detection_conditions(rule):
    """
    Extract detection conditions from modern SigmaRule object using parsed condition tree
    Returns dict with field:value mappings or complex nested structure
    
    This implementation uses pySigma's parsed condition tree to accurately handle
    complex conditions including parentheses, nested AND/OR/NOT, and field expressions.
    """
    if not rule.detection or not rule.detection.parsed_condition:
        return None
    
    # Get the parsed condition tree from pySigma
    # parsed_condition is a list, typically with one SigmaCondition
    sigma_condition = rule.detection.parsed_condition[0]
    
    if not sigma_condition.parsed:
        return None
    
    # Recursively walk the parsed condition tree
    return _parse_condition_node(sigma_condition.parsed)


def _parse_condition_node(node):
    """
    Recursively parse a pySigma condition tree node
    Returns a dict structure compatible with evaluate_sigma_condition()
    """
    from sigma.conditions import (
        ConditionAND, ConditionOR, ConditionNOT,
        ConditionFieldEqualsValueExpression,
        ConditionItem
    )
    
    node_type = type(node).__name__
    
    # Handle AND nodes
    if isinstance(node, ConditionAND):
        if hasattr(node, 'args') and node.args:
            args = [_parse_condition_node(arg) for arg in node.args]
            # Filter out None values
            args = [a for a in args if a is not None]
            if len(args) == 0:
                return None
            elif len(args) == 1:
                return args[0]
            else:
                return {"AND": args}
        return None
    
    # Handle OR nodes
    elif isinstance(node, ConditionOR):
        if hasattr(node, 'args') and node.args:
            args = [_parse_condition_node(arg) for arg in node.args]
            # Filter out None values
            args = [a for a in args if a is not None]
            if len(args) == 0:
                return None
            elif len(args) == 1:
                return args[0]
            else:
                return {"OR": args}
        return None
    
    # Handle NOT nodes
    elif isinstance(node, ConditionNOT):
        if hasattr(node, 'args') and node.args:
            # NOT should have exactly one argument
            inner = _parse_condition_node(node.args[0])
            if inner is not None:
                return {"NOT": inner}
        return None
    
    # Handle field=value expressions
    elif isinstance(node, ConditionFieldEqualsValueExpression):
        field = node.field
        value = node.value
        
        # Detect modifier from value type and add to field name if not already present
        # pySigma uses typed value objects (SigmaCIDRExpression, etc.) instead of field modifiers
        modifier_suffix = ""
        
        # Check value type to determine modifier
        value_class = type(value).__name__
        if 'CIDR' in value_class:
            modifier_suffix = "|cidr"
        elif 'Regex' in value_class:
            modifier_suffix = "|re"
        
        # Add modifier to field name if detected and not already present
        if modifier_suffix and '|' not in field:
            field = field + modifier_suffix
        
        # Convert SigmaNumber and other types to appropriate format
        if hasattr(value, 'number'):  # SigmaNumber
            value = str(value.number)
        elif hasattr(value, 'cidr'):  # SigmaCIDRExpression
            value = str(value.cidr)
        elif isinstance(value, (list, tuple)):
            converted_values = []
            for v in value:
                if hasattr(v, 'number'):
                    converted_values.append(str(v.number))
                elif hasattr(v, 'cidr'):
                    converted_values.append(str(v.cidr))
                else:
                    converted_values.append(str(v))
            value = converted_values
        else:
            value = str(value)
        
        return {field: value}
    
    # Handle other ConditionItem types (future expansion)
    elif isinstance(node, ConditionItem):
        # For now, return None for unsupported condition types
        return None
    
    # Unknown node type
    else:
        return None


def parse_event_xml(xml_bytes):
    """
    Parse Windows Event Log XML and extract structured data
    
    Args:
        xml_bytes: XML bytes from lxml etree.tostring()
    
    Returns:
        dict: Structured event data with System and EventData fields
    """
    try:
        from lxml import etree as lxml_etree
        
        # Parse XML bytes
        if isinstance(xml_bytes, bytes):
            root = lxml_etree.fromstring(xml_bytes)
        else:
            root = xml_bytes
        
        event_data = {}
        
        # Extract System section
        system = root.find(".//{http://schemas.microsoft.com/win/2004/08/events/event}System")
        if system is None:
            system = root.find(".//System")
        
        if system is not None:
            event_data["System"] = {}
            
            # EventID
            eventid_elem = system.find(".//{http://schemas.microsoft.com/win/2004/08/events/event}EventID")
            if eventid_elem is None:
                eventid_elem = system.find(".//EventID")
            if eventid_elem is not None:
                event_data["System"]["EventID"] = eventid_elem.text
            
            # TimeCreated
            time_elem = system.find(".//{http://schemas.microsoft.com/win/2004/08/events/event}TimeCreated")
            if time_elem is None:
                time_elem = system.find(".//TimeCreated")
            if time_elem is not None:
                event_data["System"]["TimeCreated"] = time_elem.get("SystemTime")
            
            # Computer
            computer_elem = system.find(".//{http://schemas.microsoft.com/win/2004/08/events/event}Computer")
            if computer_elem is None:
                computer_elem = system.find(".//Computer")
            if computer_elem is not None:
                event_data["System"]["Computer"] = computer_elem.text
            
            # Channel
            channel_elem = system.find(".//{http://schemas.microsoft.com/win/2004/08/events/event}Channel")
            if channel_elem is None:
                channel_elem = system.find(".//Channel")
            if channel_elem is not None:
                event_data["System"]["Channel"] = channel_elem.text
        
        # Extract EventData section
        eventdata = root.find(".//{http://schemas.microsoft.com/win/2004/08/events/event}EventData")
        if eventdata is None:
            eventdata = root.find(".//EventData")
        
        if eventdata is not None:
            event_data["EventData"] = {}
            
            # Extract all Data elements with Name attribute
            for data_elem in eventdata.findall(".//{http://schemas.microsoft.com/win/2004/08/events/event}Data"):
                name = data_elem.get("Name")
                if name:
                    event_data["EventData"][name] = data_elem.text or ""
            
            # Also try without namespace
            if not event_data["EventData"]:
                for data_elem in eventdata.findall(".//Data"):
                    name = data_elem.get("Name")
                    if name:
                        event_data["EventData"][name] = data_elem.text or ""
        
        return event_data
        
    except Exception as e:
        logger.debug(f"[!] Error parsing event XML: {e}")
        return {}


def detection_item_to_dict(detection_item):
    """
    Convert SigmaDetection/SigmaDetectionItem to dict structure
    Converts all values to strings to match EVTX text data
    """
    try:
        # Use to_plain() method to convert to dict/list/value
        plain = detection_item.to_plain()
        
        # Convert all values to strings to match event data
        if isinstance(plain, dict):
            str_plain = {}
            for k, v in plain.items():
                if isinstance(v, list):
                    str_plain[k] = [str(item) for item in v]
                else:
                    str_plain[k] = str(v)
            return str_plain
        else:
            return plain
    except Exception as e:
        logger.debug(f"[+] Can't convert detection item to dict: {e}")
        return None


def extract_event_ids(detection_dict):
    """
    Extract Event IDs from detection dictionary
    Returns list of event IDs (as integers for comparison with parsed eventid)
    """
    event_ids = []
    
    def search_eventid(obj):
        """Recursively search for EventID field"""
        if isinstance(obj, dict):
            for key, value in obj.items():
                if key.lower() == "eventid":
                    if isinstance(value, list):
                        # Convert to int for comparison
                        event_ids.extend([int(v) for v in value])
                    else:
                        # Convert to int for comparison
                        event_ids.append(int(value))
                else:
                    search_eventid(value)
        elif isinstance(obj, list):
            for item in obj:
                search_eventid(item)
    
    search_eventid(detection_dict)
    return event_ids


# Sigma rule matching helpers (updated for modern pySigma)

def match_cidr(ip_address, cidr_range):
    """
    Check if an IP address is within a CIDR range.
    
    Args:
        ip_address: IP address string to check
        cidr_range: CIDR range string (e.g., '10.0.0.0/8')
    
    Returns:
        bool: True if IP is in the range, False otherwise
    """
    try:
        import ipaddress
        
        # Handle empty or invalid input
        if not ip_address or ip_address == '-':
            return False
        
        # Parse the IP address
        try:
            ip = ipaddress.ip_address(ip_address.strip())
        except ValueError:
            return False
        
        # Parse the network
        try:
            network = ipaddress.ip_network(cidr_range.strip(), strict=False)
        except ValueError:
            return False
        
        # Check if IP is in network
        return ip in network
        
    except Exception:
        return False


def match_field_with_modifier(field_name, field_value, event_value):
    """
    Match a field value considering Sigma modifiers.
    
    Args:
        field_name: Field name (may include modifiers like 'IpAddress|cidr')
        field_value: Expected value(s) from Sigma rule
        event_value: Actual value from event data
    
    Returns:
        bool: True if match found
    """
    if event_value is None:
        return False
    
    # Parse field name and modifiers
    parts = field_name.split('|')
    base_field = parts[0]
    modifiers = [m.lower() for m in parts[1:]] if len(parts) > 1 else []
    
    # Convert to list for uniform handling
    values = field_value if isinstance(field_value, list) else [field_value]
    
    for value in values:
        matched = False
        value_str = str(value)
        event_str = str(event_value)
        
        # Handle CIDR modifier
        if 'cidr' in modifiers:
            if match_cidr(event_str, value_str):
                matched = True
        
        # Handle contains modifier
        elif 'contains' in modifiers:
            if value_str.lower() in event_str.lower():
                matched = True
        
        # Handle startswith modifier
        elif 'startswith' in modifiers:
            if event_str.lower().startswith(value_str.lower()):
                matched = True
        
        # Handle endswith modifier
        elif 'endswith' in modifiers:
            if event_str.lower().endswith(value_str.lower()):
                matched = True
        
        # Handle re (regex) modifier
        elif 're' in modifiers:
            try:
                if re.search(value_str, event_str, re.IGNORECASE):
                    matched = True
            except re.error:
                pass
        
        # Handle base64 modifier (decode and compare)
        elif 'base64' in modifiers:
            try:
                import base64
                decoded = base64.b64decode(event_str).decode('utf-8', errors='ignore')
                if value_str.lower() in decoded.lower():
                    matched = True
            except Exception:
                pass
        
        # Handle all modifier (all values must be present - for multi-value fields)
        elif 'all' in modifiers:
            # For 'all', we need all values to match (handled at higher level)
            pattern = convert_to_regex_pattern(value_str)
            if re.fullmatch(pattern, event_str, re.IGNORECASE):
                matched = True
        
        # Default: exact match with wildcard support
        else:
            pattern = convert_to_regex_pattern(value_str)
            if re.fullmatch(pattern, event_str, re.IGNORECASE):
                matched = True
        
        # For OR logic within a field (any value matches)
        if matched:
            return True
    
    return False


def sigma_search(sigma_filter, event_data):
    """
    Search for a single Sigma filter in event data.
    Supports field modifiers like cidr, contains, startswith, endswith, re.
    
    Returns True if match found, False otherwise
    """
    if not sigma_filter:
        return False
    
    for sigma_key, sigma_text in sigma_filter.items():
        field_matched = False
        
        # Parse field name (may include modifiers)
        parts = sigma_key.split('|')
        base_field = parts[0]
        
        for data in event_data:
            if data.get("Name") == base_field and data.text is not None:
                # Use modifier-aware matching
                if match_field_with_modifier(sigma_key, sigma_text, data.text):
                    field_matched = True
                    break
        
        # If any required field doesn't match, the filter fails (implicit AND)
        if not field_matched:
            return False
    
    # All fields matched
    return True


def convert_to_regex_pattern(value):
    """
    Convert Sigma value to regex pattern
    Handles wildcards (* and ?) and returns escaped regex
    """
    if value is None:
        return ".*"
    
    # Convert to string
    value_str = str(value)
    
    # If it already looks like a pattern with wildcards
    if '*' in value_str or '?' in value_str:
        # Escape special regex characters except * and ?
        escaped = re.escape(value_str)
        # Convert Sigma wildcards to regex
        escaped = escaped.replace(r'\*', '.*')  # * -> .*
        escaped = escaped.replace(r'\?', '.')   # ? -> .
        return escaped
    else:
        # Exact match - escape all special characters
        return re.escape(value_str)


def evaluate_sigma_condition(detection_dict, event_data):
    """
    Evaluate Sigma detection conditions against event data
    
    Args:
        detection_dict: Detection dictionary from modern pySigma API
        event_data: Event data to match against
    
    Returns:
        True if condition matches, False otherwise
    """
    if not detection_dict:
        return False
    
    # Simple dict case: direct field matching (implicit AND)
    if isinstance(detection_dict, dict):
        # Check for explicit condition operators
        if "AND" in detection_dict:
            # AND all items
            items = detection_dict["AND"]
            if isinstance(items, list):
                return all(evaluate_sigma_condition(item, event_data) for item in items)
            else:
                return evaluate_sigma_condition(items, event_data)
        
        elif "OR" in detection_dict:
            # OR all items
            items = detection_dict["OR"]
            if isinstance(items, list):
                return any(evaluate_sigma_condition(item, event_data) for item in items)
            else:
                return evaluate_sigma_condition(items, event_data)
        
        elif "NOT" in detection_dict:
            # NOT the item
            item = detection_dict["NOT"]
            return not evaluate_sigma_condition(item, event_data)
        
        else:
            # Normal field:value matching (implicit AND of all fields)
            return sigma_search(detection_dict, event_data)
    
    # List case: evaluate each item
    elif isinstance(detection_dict, list):
        # Default to OR logic for lists
        return any(evaluate_sigma_condition(item, event_data) for item in detection_dict)
    
    # Single value case
    else:
        return False


# Helpers
def convert_ticket_encryption_type(encryption_type_id):
    """
    Convert Ticket Encryption Type ID to Type Name
    Based on Microsoft documentation: 
    https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768
    
    Handles input formats like "0x17", "23", "RC4-HMAC" etc.
    """
    if encryption_type_id is None or encryption_type_id == "-":
        return "-"
    
    # Remove any whitespace and convert to string
    type_id = str(encryption_type_id).strip()
    
    # If empty string, return default
    if not type_id:
        return "-"
    
    # Try direct lookup first (for pre-formatted values)
    if type_id in TICKET_ENCRYPTION_TYPES:
        return TICKET_ENCRYPTION_TYPES[type_id]

    # Return original value if no conversion found
    return type_id

def flatten(l):
    for i in l:
        if type(i) == list:
            yield from flatten(i)
        else:
            yield i

def reescape(data):
    return str(data).replace('*', '.*').replace('\\', '\\\\' ).replace('$', '\\$' )

def depth(k):
    if not k:
        return 0
    else:
        if isinstance(k, list):
            return 1 + max(depth(i) for i in k)
        else:
            return 0


# Parse the EVTX file
def parse_evtx(evtx_list, case):
    import pandas as pd
    import pickle
    from evtx import PyEvtxParser
    from neo4j import GraphDatabase
    
    cache_dir = os.path.join(FPATH, 'cache', case)

    # Download sigma rules from github
    if args.sigma:
        git_clone_pull(SIGMA_URL, os.path.join(FPATH, 'sigma'))

        # Load sigma rules
        sigma_rules, sigma_eventids = load_sigma(os.path.join(FPATH, 'sigma'))
    else:
        sigma_eventids = []

    # Load cache files
    if args.add and os.path.exists(cache_dir) and len(os.listdir(cache_dir)):
        logger.info("[+] Load cashe files.")
        event_set = pd.read_pickle(os.path.join(cache_dir, "event_set.pkl"))
        count_set = pd.read_pickle(os.path.join(cache_dir, "count_set.pkl"))
        ml_frame = pd.read_pickle(os.path.join(cache_dir, "ml_frame.pkl"))
        with open(os.path.join(cache_dir, "username_set.pkl"), "rb") as f:
            username_set = pickle.load(f)
        with open(os.path.join(cache_dir, "domain_set.pkl"), "rb") as f:
            domain_set = pickle.load(f)
        with open(os.path.join(cache_dir, "admins.pkl"), "rb") as f:
            admins = pickle.load(f)
        with open(os.path.join(cache_dir, "domains.pkl"), "rb") as f:
            domains = pickle.load(f)
        with open(os.path.join(cache_dir, "ntmlauth.pkl"), "rb") as f:
            ntmlauth = pickle.load(f)
        with open(os.path.join(cache_dir, "deletelog.pkl"), "rb") as f:
            deletelog = pickle.load(f)
        with open(os.path.join(cache_dir, "policylist.pkl"), "rb") as f:
            policylist = pickle.load(f)
        with open(os.path.join(cache_dir, "addusers.pkl"), "rb") as f:
            addusers = pickle.load(f)
        with open(os.path.join(cache_dir, "delusers.pkl"), "rb") as f:
            delusers = pickle.load(f)
        with open(os.path.join(cache_dir, "addgroups.pkl"), "rb") as f:
            addgroups = pickle.load(f)
        with open(os.path.join(cache_dir, "removegroups.pkl"), "rb") as f:
            removegroups = pickle.load(f)
        with open(os.path.join(cache_dir, "sids.pkl"), "rb") as f:
            sids = pickle.load(f)
        with open(os.path.join(cache_dir, "hosts.pkl"), "rb") as f:
            hosts = pickle.load(f)
        with open(os.path.join(cache_dir, "dcsync.pkl"), "rb") as f:
            dcsync = pickle.load(f)
        with open(os.path.join(cache_dir, "dcshadow.pkl"), "rb") as f:
            dcshadow = pickle.load(f)
        with open(os.path.join(cache_dir, "date.pkl"), "rb") as f:
            starttime, endtime = pickle.load(f)
    else:
        event_set = pd.DataFrame(index=[], columns=["eventid", "ipaddress", "username", "logintype", "status", "authname", "servicename", "ticketencryptiontype", "date"])
        count_set = pd.DataFrame(index=[], columns=["dates", "eventid", "username"])
        ml_frame = pd.DataFrame(index=[], columns=["date", "user", "host", "id"])
        username_set = []
        domain_set = []
        admins = []
        domains = []
        ntmlauth = []
        deletelog = []
        policylist = []
        sigma_results = []
        addusers = {}
        delusers = {}
        addgroups = {}
        removegroups = {}
        sids = {}
        hosts = {}
        dcsync = {}
        dcshadow = {}
        starttime = None
        endtime = None

    dcsync_count = {}
    dcshadow_check = []
    count = 0
    record_sum = 0

    if os.path.exists(cache_dir) is False:
        os.makedirs(cache_dir)
        logger.info("[+] make cache folder {0}.".format(cache_dir))

    if args.timezone:
        try:
            datetime.timezone(datetime.timedelta(hours=args.timezone))
            tzone = args.timezone
            logger.info("[+] Time zone is {0}.".format(args.timezone))
        except:
            logger.error("[!] Can't load time zone {0}.".format(args.timezone))
            sys.exit(1)
    else:
        tzone = 0

    if args.fromdate:
        try:
            fdatetime = datetime.datetime.strptime(args.fromdate, "%Y-%m-%dT%H:%M:%S")
            logger.info("[+] Parse the EVTX from {0}.".format(fdatetime.strftime("%Y-%m-%d %H:%M:%S")))
        except:
            logger.error("[!] From date does not match format '%Y-%m-%dT%H:%M:%S'.")
            sys.exit(1)

    if args.todate:
        try:
            tdatetime = datetime.datetime.strptime(args.todate, "%Y-%m-%dT%H:%M:%S")
            logger.info("[+] Parse the EVTX from {0}.".format(tdatetime.strftime("%Y-%m-%d %H:%M:%S")))
        except:
            logger.error("[!] To date does not match format '%Y-%m-%dT%H:%M:%S'.")
            sys.exit(1)

    for evtx_file in evtx_list:
        if args.evtx:
            with open(evtx_file, "rb") as fb:
                fb_data = fb.read(8)
                if fb_data != EVTX_HEADER:
                    logger.error("[!] This file is not EVTX format {0}.".format(evtx_file))
                    sys.exit(1)

            with open(evtx_file, "rb") as evtx:
                parser = PyEvtxParser(evtx)
                records = list(parser.records())
                record_sum += len(records)

        if args.xmls:
            with open(evtx_file, "r", encoding="utf8", errors="ignore") as fb:
                fb_header = fb.read(6)
                if "<?xml" not in fb_header:
                    logger.error("[!] This file is not XML format {0}.".format(evtx_file))
                    sys.exit(1)
                for line in fb:
                    record_sum += line.count("<System>")

    logger.info("[+] Last record number is {0}.".format(record_sum))

    # Parse Event log
    logger.info("[+] Start parsing the EVTX file.")
    
    # Batch processing variables
    batch_size = 1000
    batch_events = []
    batch_ml_events = []
    batch_count_events = []

    for evtx_file in evtx_list:
        logger.info("[+] Parse the EVTX file {0}.".format(evtx_file))

        for node, err in xml_records(evtx_file):
            if err is not None:
                continue
            count += 1
            eventid = int(node.xpath("/Event/System/EventID")[0].text)

            if not count % 100:
                sys.stdout.write("\r[+] Now loading {0} records.".format(count))
                sys.stdout.flush()

            if eventid in EVENT_ID or eventid in sigma_eventids:
                logtime = node.xpath("/Event/System/TimeCreated")[0].get("SystemTime")
                etime = convert_logtime(logtime, tzone)
                stime = datetime.datetime(*etime.timetuple()[:4])
                if args.fromdate or args.todate:
                    if args.fromdate and fdatetime > etime:
                        continue
                    if args.todate and tdatetime < etime:
                        endtime = stime
                        break

                if starttime is None:
                    starttime = stime
                elif starttime > etime:
                    starttime = stime

                if endtime is None:
                    endtime = stime
                elif endtime < etime:
                    endtime = stime

                event_data = node.xpath("/Event/EventData/Data")
                logintype = 0
                username = "-"
                domain = "-"
                ipaddress = "-"
                hostname = "-"
                status = "-"
                sid = "-"
                authname = "-"
                guid = "-"

                ###
                # Detect admin users
                #  EventID 4672: Special privileges assigned to new logon
                ###
                if eventid == 4672:
                    for data in event_data:
                        if data.get("Name") in "SubjectUserName" and data.text is not None and not re.search(UCHECK, data.text):
                            username = data.text.split("@")[0]
                            if username[-1:] not in "$":
                                username = username.lower() + "@"
                            else:
                                username = "-"
                    if username not in admins and username != "-":
                        admins.append(username)
                ###
                # Detect removed user account and added user account.
                #  EventID 4720: A user account was created
                #  EventID 4726: A user account was deleted
                ###
                elif eventid in [4720, 4726]:
                    for data in event_data:
                        if data.get("Name") in "TargetUserName" and data.text is not None and not re.search(UCHECK, data.text):
                            username = data.text.split("@")[0]
                            if username[-1:] not in "$":
                                username = username.lower() + "@"
                            else:
                                username = "-"
                    if eventid == 4720:
                        addusers[username] = etime.strftime("%Y-%m-%d %H:%M:%S")
                    else:
                        delusers[username] = etime.strftime("%Y-%m-%d %H:%M:%S")
                ###
                # Detect Audit Policy Change
                #  EventID 4719: System audit policy was changed
                ###
                elif eventid == 4719:
                    for data in event_data:
                        if data.get("Name") in "SubjectUserName" and data.text is not None and not re.search(UCHECK, data.text):
                            username = data.text.split("@")[0]
                            if username[-1:] not in "$":
                                username = username.lower() + "@"
                            else:
                                username = "-"
                        if data.get("Name") in "CategoryId" and data.text is not None and re.search(r"\A%%\d{4}\Z", data.text):
                            category = data.text
                        if data.get("Name") in "SubcategoryGuid" and data.text is not None and re.search(r"\A{[\w\-]*}\Z", data.text):
                            guid = data.text
                    policylist.append([etime.strftime("%Y-%m-%d %H:%M:%S"), username, category, guid.lower(), int(stime.timestamp())])
                ###
                # Detect added users from specific group
                #  EventID 4728: A member was added to a security-enabled global group
                #  EventID 4732: A member was added to a security-enabled local group
                #  EventID 4756: A member was added to a security-enabled universal group
                ###
                elif eventid in [4728, 4732, 4756]:
                    for data in event_data:
                        if data.get("Name") in "TargetUserName" and data.text is not None and not re.search(UCHECK, data.text):
                            groupname = data.text
                        elif data.get("Name") in "MemberSid" and data.text not in "-" and data.text is not None and re.search(r"\AS-[0-9\-]*\Z", data.text):
                            usid = data.text
                    addgroups[usid] = "AddGroup: " + groupname + "(" + etime.strftime("%Y-%m-%d %H:%M:%S") + ") "
                ###
                # Detect removed users from specific group
                #  EventID 4729: A member was removed from a security-enabled global group
                #  EventID 4733: A member was removed from a security-enabled local group
                #  EventID 4757: A member was removed from a security-enabled universal group
                ###
                elif eventid in [4729, 4733, 4757]:
                    for data in event_data:
                        if data.get("Name") in "TargetUserName" and data.text is not None and not re.search(UCHECK, data.text):
                            groupname = data.text
                        elif data.get("Name") in "MemberSid" and data.text not in "-" and data.text is not None and re.search(r"\AS-[0-9\-]*\Z", data.text):
                            usid = data.text
                    removegroups[usid] = "RemoveGroup: " + groupname + "(" + etime.strftime("%Y-%m-%d %H:%M:%S") + ") "
                ###
                # Detect DCSync
                #  EventID 4662: An operation was performed on an object
                ###
                elif eventid == 4662:
                    for data in event_data:
                        if data.get("Name") in "SubjectUserName" and data.text is not None and not re.search(UCHECK, data.text):
                            username = data.text.split("@")[0]
                            if username[-1:] not in "$":
                                username = username.lower() + "@"
                            else:
                                username = "-"
                        dcsync_count[username] = dcsync_count.get(username, 0) + 1
                        if dcsync_count[username] == 3:
                            dcsync[username] = etime.strftime("%Y-%m-%d %H:%M:%S")
                            dcsync_count[username] = 0
                ###
                # Detect DCShadow
                #  EventID 5137: A directory service object was created
                #  EventID 5141: A directory service object was deleted
                ###
                elif eventid in [5137, 5141]:
                    for data in event_data:
                        if data.get("Name") in "SubjectUserName" and data.text is not None and not re.search(UCHECK, data.text):
                            username = data.text.split("@")[0]
                            if username[-1:] not in "$":
                                username = username.lower() + "@"
                            else:
                                username = "-"
                        if etime.strftime("%Y-%m-%d %H:%M:%S") in dcshadow_check:
                            dcshadow[username] = etime.strftime("%Y-%m-%d %H:%M:%S")
                        else:
                            dcshadow_check.append(etime.strftime("%Y-%m-%d %H:%M:%S"))
                ###
                # Parse logon logs
                #  EventID 4624: An account was successfully logged on
                #  EventID 4625: An account failed to log on
                #  EventID 4768: A Kerberos authentication ticket (TGT) was requested
                #  EventID 4769: A Kerberos service ticket was requested
                #  EventID 4776: The domain controller attempted to validate the credentials for an account
                ###
                else:
                    servicename = "-"
                    ticketencryptiontype = "-"
                    for data in event_data:
                        # parse IP Address
                        if data.get("Name") in ["IpAddress", "Workstation"] and data.text is not None and (not re.search(HCHECK, data.text) or re.search(IPv4_PATTERN, data.text) or re.search(r"\A::ffff:\d+\.\d+\.\d+\.\d+\Z", data.text) or re.search(IPv6_PATTERN, data.text)):
                            ipaddress = data.text.split("@")[0]
                            ipaddress = ipaddress.lower().replace("::ffff:", "")
                            ipaddress = ipaddress.replace("\\", "")
                        # Parse hostname
                        if data.get("Name") == "WorkstationName" and data.text is not None and (not re.search(HCHECK, data.text) or re.search(IPv4_PATTERN, data.text) or re.search(r"\A::ffff:\d+\.\d+\.\d+\.\d+\Z", data.text) or re.search(IPv6_PATTERN, data.text)):
                            hostname = data.text.split("@")[0]
                            hostname = hostname.lower().replace("::ffff:", "")
                            hostname = hostname.replace("\\", "")
                        # Parse username
                        if data.get("Name") in "TargetUserName" and data.text is not None and not re.search(UCHECK, data.text):
                            username = data.text.split("@")[0]
                            if username[-1:] not in "$":
                                username = username.lower() + "@"
                            else:
                                username = "-"
                        # Parse targeted domain name
                        if data.get("Name") in "TargetDomainName" and data.text is not None and not re.search(HCHECK, data.text):
                            domain = data.text
                        # parse trageted user SID
                        if data.get("Name") in ["TargetUserSid", "TargetSid"] and data.text is not None and re.search(r"\AS-[0-9\-]*\Z", data.text):
                            sid = data.text
                        # parse lonon type
                        if data.get("Name") in "LogonType" and re.search(r"\A\d{1,2}\Z", data.text):
                            logintype = int(data.text)
                        # parse status
                        if data.get("Name") in "Status" and re.search(r"\A0x\w{8}\Z", data.text):
                            status = data.text
                        # parse Authentication package name
                        if data.get("Name") in "AuthenticationPackageName" and re.search(r"\A\w*\Z", data.text):
                            authname = data.text
                        # parse Service Name for EventID 4768 and 4769
                        if eventid in [4768, 4769] and data.get("Name") == "ServiceName" and data.text is not None:
                            servicename = data.text
                        # parse Ticket Encryption Type for EventID 4768 and 4769
                        if eventid in [4768, 4769] and data.get("Name") == "TicketEncryptionType" and data.text is not None:
                            ticketencryptiontype = convert_ticket_encryption_type(data.text)

                    if username != "-" and username != "anonymous logon" and ipaddress != "::1" and ipaddress != "127.0.0.1" and (ipaddress != "-" or hostname != "-"):
                        # accumulate event data for batch processing
                        if ipaddress != "-":
                            batch_events.append([eventid, ipaddress, username, logintype, status, authname, servicename, ticketencryptiontype, int(stime.timestamp())])
                            batch_ml_events.append([etime.strftime("%Y-%m-%d %H:%M:%S"), username, ipaddress, eventid])
                        else:
                            batch_events.append([eventid, hostname, username, logintype, status, authname, servicename, ticketencryptiontype, int(stime.timestamp())])
                            batch_ml_events.append([etime.strftime("%Y-%m-%d %H:%M:%S"), username, hostname, eventid])
                        
                        batch_count_events.append([stime.strftime("%Y-%m-%d %H:%M:%S"), eventid, username])

                        # Process batch when it reaches batch_size
                        if len(batch_events) >= batch_size:
                            # Create DataFrames from batch data
                            batch_df = pd.DataFrame(batch_events, columns=event_set.columns)
                            batch_ml_df = pd.DataFrame(batch_ml_events, columns=ml_frame.columns)
                            batch_count_df = pd.DataFrame(batch_count_events, columns=count_set.columns)
                            
                            # Concatenate batch DataFrames to main DataFrames
                            event_set = pd.concat([event_set, batch_df], ignore_index=True)
                            ml_frame = pd.concat([ml_frame, batch_ml_df], ignore_index=True)
                            count_set = pd.concat([count_set, batch_count_df], ignore_index=True)
                            
                            # Clear batch lists
                            batch_events.clear()
                            batch_ml_events.clear()
                            batch_count_events.clear()

                        if domain != "-":
                            domain_set.append([username, domain])

                        if username not in username_set:
                            username_set.append(username)

                        if domain not in domains and domain != "-":
                            domains.append(domain)

                        if sid != "-":
                            sids[username] = sid

                        if hostname != "-" and ipaddress != "-":
                            hosts[ipaddress] = hostname

                        if authname in "NTML" and authname not in ntmlauth:
                            ntmlauth.append(username)
                ###
                # Sigma rule detection
                ###
                if args.sigma:
                    if eventid in sigma_eventids:
                        for search_eid, detection_dict, sigma_title, sigma_details, sigma_level in sigma_rules:
                            if eventid in search_eid:
                                # Evaluate Sigma detection conditions
                                try:
                                    enriched_event_data = list(event_data)
                                    from lxml import etree as lxml_etree
                                    eventid_elem = lxml_etree.Element("Data")
                                    eventid_elem.set("Name", "EventID")
                                    eventid_elem.text = str(eventid)
                                    enriched_event_data.append(eventid_elem)
                                    
                                    if evaluate_sigma_condition(detection_dict, enriched_event_data):
                                        from lxml import etree as lxml_etree
                                        # Parse event XML into structured data
                                        event_xml_bytes = lxml_etree.tostring(node, encoding="utf-8")
                                        event_parsed = parse_event_xml(event_xml_bytes)
                                        
                                        sigma_results.append({
                                            "timestamp": etime.strftime("%Y-%m-%d %H:%M:%S"),
                                            "sigma_level": sigma_level,
                                            "sigma_title": sigma_title,
                                            "sigma_description": sigma_details,
                                            "event": event_parsed
                                        })
                                except Exception as e:
                                    logger.debug("[!] Error evaluating Sigma rule '{0}': {1}".format(sigma_title, str(e)))
                                    continue
                                
            ###
            # Detect the audit log deletion
            # EventID 1102: The audit log was cleared
            ###
            if eventid == 1102:
                logtime = node.xpath("/Event/System/TimeCreated")[0].get("SystemTime")
                etime = convert_logtime(logtime, tzone)
                deletelog.append(etime.strftime("%Y-%m-%d %H:%M:%S"))

                namespace = "http://manifests.microsoft.com/win/2004/08/windows/eventlog"
                user_data = node.xpath("/Event/UserData/ns:LogFileCleared/ns:SubjectUserName", namespaces={"ns": namespace})
                domain_data = node.xpath("/Event/UserData/ns:LogFileCleared/ns:SubjectDomainName", namespaces={"ns": namespace})

                if user_data[0].text is not None:
                    username = user_data[0].text.split("@")[0]
                    if username[-1:] not in "$":
                        deletelog.append(username.lower())
                    else:
                        deletelog.append("-")
                else:
                    deletelog.append("-")

                if domain_data[0].text is not None:
                    deletelog.append(domain_data[0].text)
                else:
                    deletelog.append("-")

    # Process remaining events in batches (final batch)
    if batch_events:
        batch_df = pd.DataFrame(batch_events, columns=event_set.columns)
        batch_ml_df = pd.DataFrame(batch_ml_events, columns=ml_frame.columns)
        batch_count_df = pd.DataFrame(batch_count_events, columns=count_set.columns)
        
        event_set = pd.concat([event_set, batch_df], ignore_index=True)
        ml_frame = pd.concat([ml_frame, batch_ml_df], ignore_index=True)
        count_set = pd.concat([count_set, batch_count_df], ignore_index=True)
        logger.info("\n[+] Load finished.")
    logger.info("[+] Total Event log is {0}.".format(count))

    if not username_set or not len(event_set):
        logger.error("[!] This event log did not include logs to be visualized. Please check the details of the event log.")
        sys.exit(1)
    else:
        logger.info("[+] Filtered Event log is {0}.".format(len(event_set)))

    tohours = int((endtime - starttime).total_seconds() / 3600)

    # Create Event log cache files
    logger.info("[+] Create cache files.")
    pd.to_pickle(event_set, os.path.join(cache_dir, "event_set.pkl"))
    pd.to_pickle(count_set, os.path.join(cache_dir, "count_set.pkl"))
    pd.to_pickle(ml_frame, os.path.join(cache_dir, "ml_frame.pkl"))
    with open(os.path.join(cache_dir, "username_set.pkl"), "wb") as f:
        pickle.dump(username_set, f)
    with open(os.path.join(cache_dir, "domain_set.pkl"), "wb") as f:
        pickle.dump(domain_set, f)
    with open(os.path.join(cache_dir, "admins.pkl"), "wb") as f:
        pickle.dump(admins, f)
    with open(os.path.join(cache_dir, "domains.pkl"), "wb") as f:
        pickle.dump(domains, f)
    with open(os.path.join(cache_dir, "ntmlauth.pkl"), "wb") as f:
        pickle.dump(ntmlauth, f)
    with open(os.path.join(cache_dir, "deletelog.pkl"), "wb") as f:
        pickle.dump(deletelog, f)
    with open(os.path.join(cache_dir, "policylist.pkl"), "wb") as f:
        pickle.dump(policylist, f)
    with open(os.path.join(cache_dir, "addusers.pkl"), "wb") as f:
        pickle.dump(addusers, f)
    with open(os.path.join(cache_dir, "delusers.pkl"), "wb") as f:
        pickle.dump(delusers, f)
    with open(os.path.join(cache_dir, "addgroups.pkl"), "wb") as f:
        pickle.dump(addgroups, f)
    with open(os.path.join(cache_dir, "removegroups.pkl"), "wb") as f:
        pickle.dump(removegroups, f)
    with open(os.path.join(cache_dir, "sids.pkl"), "wb") as f:
        pickle.dump(sids, f)
    with open(os.path.join(cache_dir, "hosts.pkl"), "wb") as f:
        pickle.dump(hosts, f)
    with open(os.path.join(cache_dir, "dcsync.pkl"), "wb") as f:
        pickle.dump(dcsync, f)
    with open(os.path.join(cache_dir, "dcshadow.pkl"), "wb") as f:
        pickle.dump(dcshadow, f)
    with open(os.path.join(cache_dir, "date.pkl"), "wb") as f:
        pickle.dump([starttime, endtime], f)

    if hosts:
        event_set = event_set.replace(hosts)

    event_set_bydate = event_set
    event_set_bydate["count"] = event_set_bydate.groupby(["eventid", "ipaddress", "username", "logintype", "status", "authname", "servicename", "ticketencryptiontype", "date"])["eventid"].transform("count")
    event_set_bydate = event_set_bydate.drop_duplicates()
    event_set = event_set.drop("date", axis=1)
    event_set["count"] = event_set.groupby(["eventid", "ipaddress", "username", "logintype", "status", "authname", "servicename", "ticketencryptiontype"])["eventid"].transform("count")
    event_set = event_set.drop_duplicates()
    count_set["count"] = count_set.groupby(["dates", "eventid", "username"])["dates"].transform("count")
    count_set = count_set.drop_duplicates()
    domain_set_uniq = list(map(list, set(map(tuple, domain_set))))

    # Create Sigma scan results file
    if args.sigma:
        logger.info("[+] {0} event logs hit the Sigma rules.".format(len(sigma_results)))
        
        output_path = FPATH + "/static/" + SIGMA_RESULTS_FILE
        
        with open(output_path, 'w', encoding='utf8') as f:
            json.dump(sigma_results, f, ensure_ascii=False, indent=2)
        
        logger.info("[+] Created Sigma scan results file {0}.".format(output_path))

    # Learning event logs using Hidden Markov Model
    if hosts:
        ml_frame = ml_frame.replace(hosts)
    ml_frame = ml_frame.sort_values(by="date")
    if args.learn:
        logger.info("[+] Learning event logs using Hidden Markov Model.")
        learnhmm(ml_frame, username_set, datetime.datetime(*starttime.timetuple()[:3]))

    # Calculate ChangeFinder
    logger.info("[+] Calculate ChangeFinder.")
    timelines, detects, detect_cf = adetection(count_set, username_set, starttime, tohours)

    # Calculate Hidden Markov Model
    logger.info("[+] Calculate Hidden Markov Model.")
    detect_hmm = decodehmm(ml_frame, username_set, datetime.datetime(*starttime.timetuple()[:3]))

    # Calculate PageRank
    logger.info("[+] Calculate PageRank.")
    ranks = pagerank(event_set, admins, detect_hmm, detect_cf, ntmlauth)

    # Create node
    logger.info("[+] Creating a graph data.")

    try:
        neo4j_uri = "bolt://" + NEO4J_SERVER + ":" + NEO4J_PORT
        driver = GraphDatabase.driver(neo4j_uri, auth=(NEO4J_USER, NEO4J_PASSWORD))
        session = driver.session(database=case)
    except Exception as e:
        logger.error("[!] Can't connect Neo4j Database: {0}".format(str(e)))
        sys.exit(1)

    if args.postes:
        # Parse Event log
        logger.info("[+] Start sending the ES.")
        
        # Import for Elasticsearch
        from elasticsearch import Elasticsearch
        from ssl import create_default_context

        # Create a new ES client
        if args.espassword and args.escafile:
            context = create_default_context(cafile=FPATH + ES_CAFILE)
            client = Elasticsearch(ES_SERVER, http_auth=(ES_USER, ES_PASSWORD), scheme="https", ssl_context=context)
        elif args.espassword:
            es_hosts = ES_USER + ":" + ES_PASSWORD + "@" + ES_SERVER
            client = Elasticsearch(hosts=[es_hosts])
        else:
            client = Elasticsearch(ES_SERVER)

        if client.indices.exists(index="logontracer-user-index") and client.indices.exists(index="logontracer-host-index") :
            logger.info("[+] Already created index mappings to ES.")
        else:
            create_map(client, "logontracer-host-index")
            create_map(client, "logontracer-user-index")
            logger.info("[+] Creating index mappings to ES.")

        es_timestamp = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%fZ')

    hosts_inv = {v: k for k, v in hosts.items()}
    for ipaddress in event_set["ipaddress"].drop_duplicates():
        if ipaddress in hosts_inv:
            hostname = hosts_inv[ipaddress]
        else:
            hostname = ipaddress
        # add the IPAddress node to neo4j
        session.run(statement_ip, {"IP": ipaddress, "rank": ranks[ipaddress], "hostname": hostname})

        # add host data to Elasticsearch
        if args.postes:
            es_doc = es_doc_ip.format(**{"datetime": es_timestamp, "IP": ipaddress, "rank": ranks[ipaddress], "hostname": hostname})
            post_es("logontracer-host-index", client, es_doc)

    i = 0
    for username in username_set:
        sid = sids.get(username, "-")
        if username in admins:
            rights = "system"
        else:
            rights = "user"
        ustatus = ""
        if username in addusers:
            ustatus += "Created(" + addusers[username] + ") "
        if username in delusers:
            ustatus += "Deleted(" + delusers[username] + ") "
        if sid in addgroups:
            ustatus += addgroups[sid]
        if sid in removegroups:
            ustatus += removegroups[sid]
        if username in dcsync:
            ustatus += "DCSync(" + dcsync[username] + ") "
        if username in dcshadow:
            ustatus += "DCShadow(" + dcshadow[username] + ") "
        if not ustatus:
            ustatus = "-"

        # add the username node to neo4j
        session.run(statement_user, {"user": username[:-1], "rank": ranks[username], "rights": rights, "sid": sid, "status": ustatus,
                                         "counts": ",".join(map(str, timelines[i*6])), "counts4624": ",".join(map(str, timelines[i*6+1])),
                                         "counts4625": ",".join(map(str, timelines[i*6+2])), "counts4768": ",".join(map(str, timelines[i*6+3])),
                                         "counts4769": ",".join(map(str, timelines[i*6+4])), "counts4776": ",".join(map(str, timelines[i*6+5])),
                                         "detect": ",".join(map(str, detects[i]))})
        i += 1

        # add user data to Elasticsearch
        if args.postes:
            es_doc = es_doc_user.format(**{"datetime": es_timestamp, "user": username[:-1], "rights": rights, "sid": sid, "status": ustatus, "rank": ranks[username]})
            post_es("logontracer-user-index", client, es_doc)

    for domain in domains:
        # add the domain node to neo4j
        session.run(statement_domain, {"domain": domain})

    for _, events in event_set_bydate.iterrows():
        # add the (username)-(event)-(ip) link to neo4j
        session.run(statement_r, {"user": events["username"][:-1], "IP": events["ipaddress"], "id": events["eventid"], "logintype": events["logintype"],
                                      "status": events["status"], "count": events["count"], "authname": events["authname"], "date": events["date"], "servicename": events["servicename"],
                                      "ticketencryptiontype": events["ticketencryptiontype"]})

    for username, domain in domain_set_uniq:
        # add (username)-()-(domain) link to neo4j
        session.run(statement_dr, {"user": username[:-1], "domain": domain})

    # add the date node to neo4j
    session.run(statement_date, {"Daterange": "Daterange", "start": datetime.datetime(*starttime.timetuple()[:4]).strftime("%Y-%m-%d %H:%M:%S"),
                                     "end": datetime.datetime(*endtime.timetuple()[:4]).strftime("%Y-%m-%d %H:%M:%S")})

    if len(deletelog):
        # add the delete flag node to neo4j
        session.run(statement_del, {"deletetime": deletelog[0], "user": deletelog[1], "domain": deletelog[2]})

    if len(policylist):
        id = 0
        for policy in policylist:
            if policy[2] in CATEGORY_IDs:
                category = CATEGORY_IDs[policy[2]]
            else:
                category = policy[2]
            if policy[3] in AUDITING_CONSTANTS:
                sub = AUDITING_CONSTANTS[policy[3]]
            else:
                sub = policy[3]
            username = policy[1]
            # add the policy id node to neo4j
            session.run(statement_pl, {"id": id, "changetime": policy[0], "category": category, "sub": sub})
            # add (username)-(policy)-(id) link to neo4j
            session.run(statement_pr, {"user": username[:-1], "id": id, "date": policy[4]})
            id += 1

    #tx.process()
    logger.info("[+] Creation of a graph data finished.")

# Parse from Elastic Search cluster
# Porting by 0xThiebaut
def parse_es(case):        
    event_set = pd.DataFrame(index=[], columns=["eventid", "ipaddress", "username", "logintype", "status", "authname", "servicename", "ticketencryptiontype", "date"])
    count_set = pd.DataFrame(index=[], columns=["dates", "eventid", "username"])
    ml_frame = pd.DataFrame(index=[], columns=["date", "user", "host", "id"])
    username_set = []
    domain_set = []
    admins = []
    domains = []
    ntmlauth = []
    deletelog = []
    policylist = []
    addusers = {}
    delusers = {}
    addgroups = {}
    removegroups = {}
    sids = {}
    hosts = {}
    dcsync_count = {}
    dcsync = {}
    dcshadow_check = []
    dcshadow = {}
    count = 0
    starttime = None
    endtime = None
    fdatetime = None
    tdatetime = None

    if args.timezone:
        try:
            datetime.timezone(datetime.timedelta(hours=args.timezone))
            tzone = args.timezone
            logger.info("[+] Time zone is {0}.".format(args.timezone))
        except:
            logger.error("[!] Can't load time zone {0}.".format(args.timezone))
            sys.exit(1)

    else:
        tzone = 0

    if args.fromdate:
        try:
            fdatetime = datetime.datetime.strptime(args.fromdate, "%Y-%m-%dT%H:%M:%S")
            logger.info("[+] Search ES from {0}.".format(fdatetime.strftime("%Y-%m-%d %H:%M:%S")))
        except:
            logger.error("[!] From date does not match format '%Y-%m-%dT%H:%M:%S'.")
            sys.exit(1)

    if args.todate:
        try:
            tdatetime = datetime.datetime.strptime(args.todate, "%Y-%m-%dT%H:%M:%S")
            logger.info("[+] Search ES to {0}.".format(tdatetime.strftime("%Y-%m-%d %H:%M:%S")))
        except:
            logger.error("[!] To date does not match format '%Y-%m-%dT%H:%M:%S'.")
            sys.exit(1)
    # Parse Event log
    logger.info("[+] Start searching the ES.")
    
    # Import for Elasticsearch
    from elasticsearch import Elasticsearch
    from elasticsearch_dsl import Search, Q
    from ssl import create_default_context

    # Create a new ES client
    if args.espassword and args.escafile:
        context = create_default_context(cafile=FPATH + ES_CAFILE)
        client = Elasticsearch(ES_SERVER, http_auth=(ES_USER, ES_PASSWORD), scheme="https", ssl_context=context)
    elif args.espassword:
        es_hosts = ES_USER + ":" + ES_PASSWORD + "@" + ES_SERVER
        client = Elasticsearch(hosts=[es_hosts])
    else:
        client = Elasticsearch(ES_SERVER)

    # Create the search
    s = Search(using=client, index=ES_INDEX)

    if fdatetime or tdatetime:
        filter = {"format": "epoch_millis"}
        if fdatetime:
            filter["gte"] = int(fdatetime.timestamp() * 1000)
        if tdatetime:
            filter["lt"] = int(tdatetime.timestamp() * 1000)
        s = s.filter("range", **{'@timestamp': filter})

    # Split the prefix
    parts = ES_PREFIX.strip(".")
    if len(parts) > 0:
        parts = parts.split(".")
    else:
        parts = []
    # Search for any event in EVENT_ID
    parts.append("event_id")
    field = ".".join(parts)
    parts.pop()
    queries = [Q("term", **{field:1102})]
    for event_id in EVENT_ID:
        queries.append(Q("term", **{field:event_id}))
    query = Q("bool",
              should=queries,
              minimum_should_match=1)
    s = s.query(query)

    # Execute the search
    for hit in s.scan():
        event = hit
        prefixed = True
        for part in parts:
            if hasattr(event, part):
                event = getattr(event, part)
            else:
                prefixed = False
                break

        if not prefixed:
            print("Skipping unexpected event...")
            continue

        count += 1
        eventid = event.event_id

        if not count % 100:
            sys.stdout.write("\r[+] Now loading {0} records.".format(count))
            sys.stdout.flush()

        if eventid in EVENT_ID:
            logtime = hit["@timestamp"].replace("T", " ").split(".")[0]
            etime = convert_logtime(logtime, tzone)

            stime = datetime.datetime(*etime.timetuple()[:4])

            if starttime is None:
                starttime = stime
            elif starttime > etime:
                starttime = stime

            if endtime is None:
                endtime = stime
            elif endtime < etime:
                endtime = stime

            logintype = 0
            username = "-"
            domain = "-"
            ipaddress = "-"
            hostname = "-"
            status = "-"
            sid = "-"
            authname = "-"
            guid = "-"

            ###
            # Detect admin users
            #  EventID 4672: Special privileges assigned to new logon
            ###
            if eventid == 4672:
                username = event.event_data.SubjectUserName.split("@")[0]
                if username[-1:] not in "$":
                    username = username.lower() + "@"
                else:
                    username = "-"
                if username not in admins and username != "-":
                    admins.append(username)
            ###
            # Detect removed user account and added user account.
            #  EventID 4720: A user account was created
            #  EventID 4726: A user account was deleted
            ###
            elif eventid in [4720, 4726]:
                username = event.event_data.TargetUserName.split("@")[0]
                if username[-1:] not in "$":
                    username = username.lower() + "@"
                else:
                    username = "-"
                if eventid == 4720:
                    addusers[username] = etime.strftime("%Y-%m-%d %H:%M:%S")
                else:
                    delusers[username] = etime.strftime("%Y-%m-%d %H:%M:%S")
            ###
            # Detect Audit Policy Change
            #  EventID 4719: System audit policy was changed
            ###
            elif eventid == 4719:
                username = event.event_data.SubjectUserName.split("@")[0]
                if username[-1:] not in "$":
                    username = username.lower() + "@"
                else:
                    username = "-"
                category = event.event_data.CategoryId
                guid = event.event_data.SubcategoryGuid
                policylist.append([etime.strftime("%Y-%m-%d %H:%M:%S"), username, category, guid.lower(), int(stime.timestamp())])
            ###
            # Detect added users from specific group
            #  EventID 4728: A member was added to a security-enabled global group
            #  EventID 4732: A member was added to a security-enabled local group
            #  EventID 4756: A member was added to a security-enabled universal group
            ###
            elif eventid in [4728, 4732, 4756]:
                groupname = event.event_data.TargetUserName
                usid = event.event_data.MemberSid
                addgroups[usid] = "AddGroup: " + groupname + "(" + etime.strftime("%Y-%m-%d %H:%M:%S") + ") "
            ###
            # Detect removed users from specific group
            #  EventID 4729: A member was removed from a security-enabled global group
            #  EventID 4733: A member was removed from a security-enabled local group
            #  EventID 4757: A member was removed from a security-enabled universal group
            ###
            elif eventid in [4729, 4733, 4757]:
                groupname = event.event_data.TargetUserName
                usid = event.event_data.MemberSid
                removegroups[usid] = "RemoveGroup: " + groupname + "(" + etime.strftime("%Y-%m-%d %H:%M:%S") + ") "
            ###
            # Detect DCSync
            #  EventID 4662: An operation was performed on an object
            ###
            elif eventid == 4662:
                username = event.event_data.SubjectUserName.split("@")[0]
                if username[-1:] not in "$":
                    username = username.lower() + "@"
                else:
                    username = "-"
                dcsync_count[username] = dcsync_count.get(username, 0) + 1
                if dcsync_count[username] == 3:
                    dcsync[username] = etime.strftime("%Y-%m-%d %H:%M:%S")
                    dcsync_count[username] = 0
            ###
            # Detect DCShadow
            #  EventID 5137: A directory service object was created
            #  EventID 5141: A directory service object was deleted
            ###
            elif eventid in [5137, 5141]:
                username = event.event_data.SubjectUserName.split("@")[0]
                if username[-1:] not in "$":
                    username = username.lower() + "@"
                else:
                    username = "-"
                if etime.strftime("%Y-%m-%d %H:%M:%S") in dcshadow_check:
                    dcshadow[username] = etime.strftime("%Y-%m-%d %H:%M:%S")
                else:
                    dcshadow_check.append(etime.strftime("%Y-%m-%d %H:%M:%S"))
            ###
            # Parse logon logs
            #  EventID 4624: An account was successfully logged on
            #  EventID 4625: An account failed to log on
            #  EventID 4768: A Kerberos authentication ticket (TGT) was requested
            #  EventID 4769: A Kerberos service ticket was requested
            #  EventID 4776: The domain controller attempted to validate the credentials for an account
            ###
            else:
                servicename = "-"
                ticketencryptiontype = "-"
                for data in event_data:
                    # parse IP Address
                    if data.get("Name") in ["IpAddress", "Workstation"] and data.text is not None and (not re.search(HCHECK, data.text) or re.search(IPv4_PATTERN, data.text) or re.search(r"\A::ffff:\d+\.\d+\.\d+\.\d+\Z", data.text) or re.search(IPv6_PATTERN, data.text)):
                        ipaddress = data.text.split("@")[0]
                        ipaddress = ipaddress.lower().replace("::ffff:", "")
                        ipaddress = ipaddress.replace("\\", "")
                    # Parse hostname
                    if data.get("Name") == "WorkstationName" and data.text is not None and (not re.search(HCHECK, data.text) or re.search(IPv4_PATTERN, data.text) or re.search(r"\A::ffff:\d+\.\d+\.\d+\.\d+\Z", data.text) or re.search(IPv6_PATTERN, data.text)):
                        hostname = data.text.split("@")[0]
                        hostname = hostname.lower().replace("::ffff:", "")
                        hostname = hostname.replace("\\", "")
                    # Parse username
                    if data.get("Name") in "TargetUserName" and data.text is not None and not re.search(UCHECK, data.text):
                        username = data.text.split("@")[0]
                        if username[-1:] not in "$":
                            username = username.lower() + "@"
                        else:
                            username = "-"
                    # Parse targeted domain name
                    if data.get("Name") in "TargetDomainName" and data.text is not None and not re.search(HCHECK, data.text):
                        domain = data.text
                    # parse trageted user SID
                    if data.get("Name") in ["TargetUserSid", "TargetSid"] and data.text is not None and re.search(r"\AS-[0-9\-]*\Z", data.text):
                        sid = data.text
                    # parse lonon type
                    if data.get("Name") in "LogonType" and re.search(r"\A\d{1,2}\Z", data.text):
                        logintype = int(data.text)
                    # parse status
                    if data.get("Name") in "Status" and re.search(r"\A0x\w{8}\Z", data.text):
                        status = data.text
                    # parse Authentication package name
                    if data.get("Name") in "AuthenticationPackageName" and re.search(r"\A\w*\Z", data.text):
                        authname = data.text
                    # parse Service Name for EventID 4768 and 4769
                    if eventid in [4768, 4769] and data.get("Name") == "ServiceName" and data.text is not None:
                        servicename = data.text
                    # parse Ticket encryption type for EventID 4768 and 4769
                    if eventid in [4768, 4769] and data.get("Name") == "TicketEncryptionType" and data.text is not None:
                        ticketencryptiontype = convert_ticket_encryption_type(data.text)

                if username != "-" and username != "anonymous logon" and ipaddress != "::1" and ipaddress != "127.0.0.1" and (ipaddress != "-" or hostname != "-"):
                    # generate pandas series
                    if ipaddress != "-":
                        event_series = pd.Series([eventid, ipaddress, username, logintype, status, authname, servicename, ticketencryptiontype, int(stime.timestamp())], index=event_set.columns)
                        ml_series = pd.Series([etime.strftime("%Y-%m-%d %H:%M:%S"), username, ipaddress, eventid],  index=ml_frame.columns)
                    else:
                        event_series = pd.Series([eventid, hostname, username, logintype, status, authname, servicename, ticketencryptiontype, int(stime.timestamp())], index=event_set.columns)
                        ml_series = pd.Series([etime.strftime("%Y-%m-%d %H:%M:%S"), username, hostname, eventid],  index=ml_frame.columns)
                    # append pandas series to dataframe
                    event_set = pd.concat([event_set, event_series.set_axis(event_set.columns).to_frame().T], ignore_index=True)
                    ml_frame = pd.concat([ml_frame, ml_series.set_axis(ml_frame.columns).to_frame().T], ignore_index=True)
                    # print("%s,%i,%s,%s,%s,%s" % (eventid, ipaddress, username, comment, logintype))
                    count_series = pd.Series([stime.strftime("%Y-%m-%d %H:%M:%S"), eventid, username], index=count_set.columns)
                    count_set = pd.concat([count_set, count_series.set_axis(count_set.columns).to_frame().T], ignore_index=True)
                    # print("%s,%s" % (stime.strftime("%Y-%m-%d %H:%M:%S"), username))

                    if domain != "-":
                        domain_set.append([username, domain])

                    if username not in username_set:
                        username_set.append(username)

                    if domain not in domains and domain != "-":
                        domains.append(domain)

                    if sid != "-":
                        sids[username] = sid

                    if hostname != "-" and ipaddress != "-":
                        hosts[ipaddress] = hostname

                    if authname in "NTML" and authname not in ntmlauth:
                        ntmlauth.append(username)
                                        
        ###
        # Detect the audit log deletion
        # EventID 1102: The audit log was cleared
        ###
        if eventid == 1102:
            logtime = hit["@timestamp"]
            etime = convert_logtime(logtime, tzone)
            deletelog.append(etime.strftime("%Y-%m-%d %H:%M:%S"))

            if hasattr(event.user_data, "SubjectUserName"):
                username = event.user_data.SubjectUserName.split("@")[0]
                if username[-1:] not in "$":
                    deletelog.append(username.lower())
                else:
                    deletelog.append("-")
            else:
                deletelog.append("-")

            if hasattr(event.user_data, "SubjectDomainName"):
                deletelog.append(event.user_data.SubjectDomainName)
            else:
                deletelog.append("-")

    print("\n[+] Load finished.")
    logger.info("[+] Total Event log is {0}.".format(count))

    if not username_set or not len(event_set):
        logger.error("[!] This event log did not include logs to be visualized. Please check the details of the event log.")
        sys.exit(1)
    else:
        logger.info("[+] Filtered Event log is {0}.".format(len(event_set)))

    tohours = int((endtime - starttime).total_seconds() / 3600)

    if hosts:
        event_set = event_set.replace(hosts)
    event_set_bydate = event_set
    event_set_bydate["count"] = event_set_bydate.groupby(["eventid", "ipaddress", "username", "logintype", "status", "authname", "servicename", "ticketencryptiontype", "date"])["eventid"].transform("count")
    event_set_bydate = event_set_bydate.drop_duplicates()
    event_set = event_set.drop("date", axis=1)
    event_set["count"] = event_set.groupby(["eventid", "ipaddress", "username", "logintype", "status", "authname", "servicename", "ticketencryptiontype"])["eventid"].transform("count")
    event_set = event_set.drop_duplicates()
    count_set["count"] = count_set.groupby(["dates", "eventid", "username"])["dates"].transform("count")
    count_set = count_set.drop_duplicates()
    domain_set_uniq = list(map(list, set(map(tuple, domain_set))))

    # Learning event logs using Hidden Markov Model
    if hosts:
        ml_frame = ml_frame.replace(hosts)
    ml_frame = ml_frame.sort_values(by="date")
    if args.learn:
        logger.info("[+] Learning event logs using Hidden Markov Model.")
        learnhmm(ml_frame, username_set, datetime.datetime(*starttime.timetuple()[:3]))

    # Calculate ChangeFinder
    logger.info("[+] Calculate ChangeFinder.")
    timelines, detects, detect_cf = adetection(count_set, username_set, starttime, tohours)

    # Calculate Hidden Markov Model
    logger.info("[+] Calculate Hidden Markov Model.")
    detect_hmm = decodehmm(ml_frame, username_set, datetime.datetime(*starttime.timetuple()[:3]))

    # Calculate PageRank
    logger.info("[+] Calculate PageRank.")
    ranks = pagerank(event_set, admins, detect_hmm, detect_cf, ntmlauth)

    # Create node
    logger.info("[+] Creating a graph data.")

    try:
        neo4j_uri = "bolt://" + NEO4J_SERVER + ":" + NEO4J_PORT
        driver = GraphDatabase.driver(neo4j_uri, auth=(NEO4J_USER, NEO4J_PASSWORD))
        session = driver.session(database=case)
    except Exception as e:
        logger.error("[!] Can't connect Neo4j Database: {0}".format(str(e)))
        sys.exit(1)

    if args.postes:
        # Parse Event log
        logger.info("[+] Start sending the ES.")

        if client.indices.exists(index="logontracer-user-index") and client.indices.exists(index="logontracer-host-index") :
            logger.info("[+] Already created index mappings to ES.")
        else:
            create_map(client, "logontracer-host-index")
            create_map(client, "logontracer-user-index")
            logger.info("[+] Creating index mappings to ES.")

        es_timestamp = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%fZ')

    hosts_inv = {v: k for k, v in hosts.items()}
    for ipaddress in event_set["ipaddress"].drop_duplicates():
        if ipaddress in hosts_inv:
            hostname = hosts_inv[ipaddress]
        else:
            hostname = ipaddress
        # add the IPAddress node to neo4j
        session.run(statement_ip, {"IP": ipaddress, "rank": ranks[ipaddress], "hostname": hostname})

        # add host data to Elasticsearch
        if args.postes:
            es_doc = es_doc_ip.format(**{"datetime": es_timestamp, "IP": ipaddress, "rank": ranks[ipaddress], "hostname": hostname})
            post_es("logontracer-host-index", client, es_doc)

    i = 0
    for username in username_set:
        sid = sids.get(username, "-")
        if username in admins:
            rights = "system"
        else:
            rights = "user"
        ustatus = ""
        if username in addusers:
            ustatus += "Created(" + addusers[username] + ") "
        if username in delusers:
            ustatus += "Deleted(" + delusers[username] + ") "
        if sid in addgroups:
            ustatus += addgroups[sid]
        if sid in removegroups:
            ustatus += removegroups[sid]
        if username in dcsync:
            ustatus += "DCSync(" + dcsync[username] + ") "
        if username in dcshadow:
            ustatus += "DCShadow(" + dcshadow[username] + ") "
        if not ustatus:
            ustatus = "-"

        # add the username node to neo4j
        session.run(statement_user, {"user": username[:-1], "rank": ranks[username], "rights": rights, "sid": sid, "status": ustatus,
                                         "counts": ",".join(map(str, timelines[i*6])), "counts4624": ",".join(map(str, timelines[i*6+1])),
                                         "counts4625": ",".join(map(str, timelines[i*6+2])), "counts4768": ",".join(map(str, timelines[i*6+3])),
                                         "counts4769": ",".join(map(str, timelines[i*6+4])), "counts4776": ",".join(map(str, timelines[i*6+5])),
                                         "detect": ",".join(map(str, detects[i]))})
        i += 1

        # add user data to Elasticsearch
        if args.postes:
            es_doc = es_doc_user.format(**{"datetime": es_timestamp, "user": username[:-1], "rights": rights, "sid": sid, "status": ustatus, "rank": ranks[username]})
            post_es("logontracer-user-index", client, es_doc)

    for domain in domains:
        # add the domain node to neo4j
        session.run(statement_domain, {"domain": domain})

    for _, events in event_set_bydate.iterrows():
        # add the (username)-(event)-(ip) link to neo4j
        session.run(statement_r, {"user": events["username"][:-1], "IP": events["ipaddress"], "id": events["eventid"], "logintype": events["logintype"],
                                      "status": events["status"], "count": events["count"], "authname": events["authname"], "date": events["date"], "servicename": events["servicename"],
                                      "ticketencryptiontype": events["ticketencryptiontype"]})

    for username, domain in domain_set_uniq:
        # add (username)-()-(domain) link to neo4j
        session.run(statement_dr, {"user": username[:-1], "domain": domain})

    # add the date node to neo4j
    session.run(statement_date, {"Daterange": "Daterange", "start": datetime.datetime(*starttime.timetuple()[:4]).strftime("%Y-%m-%d %H:%M:%S"),
                                     "end": datetime.datetime(*endtime.timetuple()[:4]).strftime("%Y-%m-%d %H:%M:%S")})

    if len(deletelog):
        # add the delete flag node to neo4j
        session.run(statement_del, {"deletetime": deletelog[0], "user": deletelog[1], "domain": deletelog[2]})

    if len(policylist):
        id = 0
        for policy in policylist:
            if policy[2] in CATEGORY_IDs:
                category = CATEGORY_IDs[policy[2]]
            else:
                category = policy[2]
            if policy[3] in AUDITING_CONSTANTS:
                sub = AUDITING_CONSTANTS[policy[3]]
            else:
                sub = policy[3]
            username = policy[1]
            # add the policy id node to neo4j
            session.run(statement_pl, {"id": id, "changetime": policy[0], "category": category, "sub": sub})
            # add (username)-(policy)-(id) link to neo4j
            session.run(statement_pr, {"user": username[:-1], "id": id, "date": policy[4]})
            id += 1

    logger.info("[+] Creation of a graph data finished.")

# AI Settings page
@app.route('/ai-settings', methods=['GET', 'POST'])
@http_request_logging
@login_required(role="ADMIN")
def ai_settings():
    """AI Settings page"""
    form = AISettingForm()
    
    # Get current settings
    current_setting = AISetting.query.first()
    if not current_setting:
        current_setting = AISetting()
        db.session.add(current_setting)
        db.session.commit()
    
    if request.method == 'GET':
        # Populate form with current settings
        form.ai_enabled.data = current_setting.ai_enabled
        form.openai_api_key.data = current_setting.openai_api_key
        form.openai_model.data = current_setting.openai_model
        form.max_completion_tokens.data = current_setting.max_completion_tokens
        form.temperature.data = current_setting.temperature
        form.agent_max_iterations.data = current_setting.agent_max_iterations
        form.response_language.data = current_setting.response_language
    
    if form.validate_on_submit():
        # Update settings from form
        current_setting.ai_enabled = form.ai_enabled.data
        current_setting.openai_api_key = form.openai_api_key.data
        current_setting.openai_model = form.openai_model.data
        current_setting.max_completion_tokens = form.max_completion_tokens.data
        current_setting.temperature = form.temperature.data
        current_setting.agent_max_iterations = form.agent_max_iterations.data
        current_setting.response_language = form.response_language.data
        current_setting.updated_at = utc_now_naive()
        
        try:
            db.session.commit()
            flash('AI settings have been updated successfully.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating AI settings: {str(e)}', 'error')
            
        return redirect(url_for('ai_settings'))
    
    return render_template('ai_settings.html', form=form, current_setting=current_setting)

def main():
    if not has_neo4j:
        logger.error("[!] neo4j driver must be installed for this script.")
        sys.exit(1)

    if not has_evtx:
        logger.error("[!] evtx must be installed for this script.")
        sys.exit(1)

    if not has_lxml:
        logger.error("[!] lxml must be installed for this script.")
        sys.exit(1)

    if not has_numpy:
        logger.error("[!] numpy must be installed for this script.")
        sys.exit(1)

    if not has_changefinder:
        logger.error("[!] changefinder must be installed for this script.")
        sys.exit(1)

    if not has_pandas:
        logger.error("[!] pandas must be installed for this script.")
        sys.exit(1)

    if not has_hmmlearn:
        logger.error("[!] hmmlearn must be installed for this script.")
        sys.exit(1)

    if not has_sklearn:
        logger.error("[!] scikit-learn must be installed for this script.")
        sys.exit(1)

    if not has_es:
        logger.error("[!] elasticsearch-dsl must be installed for this script.")
        sys.exit(1)

    if not has_git:
        logger.error("[!] GitPython must be installed for this script.")
        sys.exit(1)

    if not has_sigma:
        logger.error("[!] sigma must be installed for this script.")
        sys.exit(1)
    
    # Import Neo4j modules
    from neo4j import GraphDatabase
    from neo4j.exceptions import ClientError, ServiceUnavailable, AuthError, ConfigurationError
    
    try:
        neo4j_uri = "bolt://" + NEO4J_SERVER + ":" + NEO4J_PORT
        driver = GraphDatabase.driver(neo4j_uri, auth=(NEO4J_USER, NEO4J_PASSWORD))
        # Test connection
        with driver.session() as session:
            result = session.run("RETURN 1")
            result.single()
        logger.info("[+] Successfully connected to Neo4j Database.")
    except Exception as e:
        logger.error("[!] Can't connect Neo4j Database: {0}".format(str(e)))
        sys.exit(1)

    logger.info("[+] Script start. {0}".format(datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")))

    try:
        # Get Neo4j version info
        with driver.session() as session:
            result = session.run("CALL dbms.components() YIELD name, versions")
            for record in result:
                if record["name"] == "Neo4j Kernel":
                    logger.info("[+] Neo4j version {0}".format(record["versions"][0]))
                    break
    except:
        logger.warning("[!] Can't get Neo4j version.")

    case = create_database(driver, CASE_NAME)

    if args.create_user and args.create_password:
        if args.role:
            role = args.role
        else:
            role = "reader"
        create_neo4j_user(driver, args.create_user, args.create_password, role)

    if args.delete_user:
        delete_neo4j_user(driver, args.delete_user)

    if args.run:
        try:
            app.run(threaded=True, host=WEB_HOST, port=WEB_PORT)
        except:
            logger.error("[!] Can't runnning web application.")
            sys.exit(1)

    # Delete database data
    if args.delete:
        try:
            neo4j_uri = "bolt://" + NEO4J_SERVER + ":" + NEO4J_PORT
            delete_driver = GraphDatabase.driver(neo4j_uri, auth=(NEO4J_USER, NEO4J_PASSWORD))
            with delete_driver.session(database=case) as session:
                session.run("MATCH (n) DETACH DELETE n")
            delete_driver.close()
        except Exception as e:
            logger.error("[!] Can't connect Neo4j Database: {0}".format(str(e)))
            sys.exit(1)

        logger.info("[+] Delete all nodes and relationships from this Neo4j database.")

        cache_dir = os.path.join(FPATH, 'cache', case)
        if os.path.exists(cache_dir):
            shutil.rmtree(cache_dir)
            logger.info("[+] Delete cache folder {0}.".format(cache_dir))

    # Sigma-only scan mode (does not require Neo4j processing)
    if args.sigma_only:
        if not args.evtx and not args.xmls:
            logger.error("[!] --sigma-only requires -e (EVTX file) or -x (XML file) option.")
            sys.exit(1)
        
        # Determine Sigma rules path
        if args.sigma_rules_path:
            sigma_rules_path = args.sigma_rules_path
            if not sigma_rules_path.startswith('/'):
                sigma_rules_path = os.path.join(FPATH, sigma_rules_path)
        else:
            sigma_rules_path = os.path.join(FPATH, 'sigma')
        
        # Get timezone
        timezone = args.timezone if args.timezone else 0
        
        # Get file list
        evtx_files = args.evtx if args.evtx else args.xmls
        
        # Run Sigma scan
        sigma_results = sigma_scan_evtx(evtx_files, sigma_rules_path, timezone)
        
        # Save results
        output_path = FPATH + "/static/" + SIGMA_RESULTS_FILE
        with open(output_path, 'w', encoding='utf8') as f:
            json.dump(sigma_results, f, ensure_ascii=False, indent=2)
        
        logger.info("[+] Sigma scan results saved to {0}".format(output_path))
        logger.info("[+] Script end. {0}".format(datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")))
        sys.exit(0)

    if args.evtx:
        for evtx_file in args.evtx:
            if not os.path.isfile(evtx_file):
                logger.error("[!] Can't open file {0}.".format(evtx_file))
                sys.exit(1)
        parse_evtx(args.evtx, case)

    if args.xmls:
        for xml_file in args.xmls:
            if not os.path.isfile(xml_file):
                logger.error("[!] Can't open file {0}.".format(xml_file))
                sys.exit(1)
        parse_evtx(args.xmls, case)

    if args.es:
        parse_es(case)

    logger.info("[+] Script end. {0}".format(datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")))


if __name__ == "__main__":
    main()
