#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# LICENSE
# https://github.com/JPCERTCC/LogonTracer/blob/master/LICENSE.txt
#

import os
import re
import sys
import csv
import glob
import pickle
import shutil
import argparse
import datetime
import subprocess
from functools import wraps
from logging import getLogger
from logging.config import dictConfig
from ssl import create_default_context

try:
    from lxml import etree
    has_lxml = True
except ImportError:
    has_lxml = False

try:
    from evtx import PyEvtxParser
    has_evtx = True
except ImportError:
    has_evtx = False

try:
    from py2neo import Graph, GraphService, ClientError
    has_py2neo = True
except ImportError:
    has_py2neo = False

try:
    import numpy as np
    has_numpy = True
except ImportError:
    has_numpy = False

try:
    import changefinder
    has_changefinder = True
except ImportError:
    has_changefinder = False

try:
    from flask import Flask, render_template, request, redirect, session
    has_flask = True
except ImportError:
    has_flask = False

try:
    import pandas as pd
    has_pandas = True
except ImportError:
    has_pandas = False

try:
    from hmmlearn import hmm
    has_hmmlearn = True
except ImportError:
    has_hmmlearn = False

try:
    import joblib
    has_sklearn = True
except ImportError:
    has_sklearn = False

try:
    from elasticsearch import Elasticsearch
    from elasticsearch_dsl import Search, Q
    has_es = True
except ImportError:
    has_es = False

try:
    import yaml
    has_pyyaml = True
except ImportError:
    has_pyyaml = False

try:
    from flask_login import UserMixin, LoginManager, login_user, logout_user, current_user
    has_flask_login = True
except ImportError:
    has_flask_login = False

try:
    from flask_sqlalchemy import SQLAlchemy
    has_flask_sqlalchemy = True
except ImportError:
    has_flask_sqlalchemy = False

try:
    from flask_wtf import FlaskForm
    has_flask_wtf = True
except ImportError:
    has_flask_wtf = False

try:
    from wtforms import StringField, PasswordField
    from wtforms.validators import ValidationError, DataRequired, EqualTo, Length
    has_wtforms = True
except ImportError:
    has_wtforms = False

try:
    import git
    has_git = True
except ImportError:
    has_git = False

try:
    from sigma.parser.rule import SigmaParser
    from sigma.configuration import SigmaConfiguration
    from sigma.parser.condition import ConditionAND, ConditionOR, ConditionNOT, NodeSubexpression
    has_sigma = True
except ImportError:
    has_sigma = False

# Check Event Id
EVENT_ID = [4624, 4625, 4662, 4768, 4769, 4776, 4672, 4720, 4726, 4728, 4729, 4732, 4733, 4756, 4757, 4719, 5137, 5141]

# EVTX Header
EVTX_HEADER = b"\x45\x6C\x66\x46\x69\x6C\x65\x00"

# String Check list
UCHECK = r"[%*+=\[\]\\/|;:\"<>?,&]"
HCHECK = r"[*\\/|:\"<>?&]"

# IPv4 regex
IPv4_PATTERN = re.compile(r"\A\d+\.\d+\.\d+\.\d+\Z", re.DOTALL)

# IPv6 regex
IPv6_PATTERN = re.compile(r"\A(::(([0-9a-f]|[1-9a-f][0-9a-f]{1,3})(:([0-9a-f]|[1-9a-f][0-9a-f]{1,3})){0,5})?|([0-9a-f]|[1-9a-f][0-9a-f]{1,3})(::(([0-9a-f]|[1-9a-f][0-9a-f]{1,3})(:([0-9a-f]|[1-9a-f][0-9a-f]{1,3})){0,4})?|:([0-9a-f]|[1-9a-f][0-9a-f]{1,3})(::(([0-9a-f]|[1-9a-f][0-9a-f]{1,3})(:([0-9a-f]|[1-9a-f][0-9a-f]{1,3})){0,3})?|:([0-9a-f]|[1-9a-f][0-9a-f]{1,3})(::(([0-9a-f]|[1-9a-f][0-9a-f]{1,3})(:([0-9a-f]|[1-9a-f][0-9a-f]{1,3})){0,2})?|:([0-9a-f]|[1-9a-f][0-9a-f]{1,3})(::(([0-9a-f]|[1-9a-f][0-9a-f]{1,3})(:([0-9a-f]|[1-9a-f][0-9a-f]{1,3}))?)?|:([0-9a-f]|[1-9a-f][0-9a-f]{1,3})(::([0-9a-f]|[1-9a-f][0-9a-f]{1,3})?|(:([0-9a-f]|[1-9a-f][0-9a-f]{1,3})){3}))))))\Z", re.DOTALL)

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

# Load logging config
with open(FPATH + "/config/logging.yml", 'r') as logging_open:
    logging_data = yaml.safe_load(logging_open)

dictConfig(logging_data)
logger = getLogger("agent_logger")

# Flask instance
if not has_flask:
    logger.error("[!] Flask must be installed for this script.")
    sys.exit(1)
else:
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
  MERGE (user:Username{{ user:'{user}' }}) set user.rights='{rights}', user.sid='{sid}', user.rank={rank}, user.status='{status}', user.counts='{counts}', user.counts4624='{counts4624}', user.counts4625='{counts4625}', user.counts4768='{counts4768}', user.counts4769='{counts4769}', user.counts4776='{counts4776}', user.detect='{detect}'
  RETURN user
  """

statement_ip = """
  MERGE (ip:IPAddress{{ IP:'{IP}' }}) set ip.rank={rank}, ip.hostname='{hostname}'
  RETURN ip
  """

statement_r = """
  MATCH (user:Username{{ user:'{user}' }})
  MATCH (ip:IPAddress{{ IP:'{IP}' }})
  CREATE (ip)-[event:Event]->(user) set event.id={id}, event.logintype={logintype}, event.status='{status}', event.count={count}, event.authname='{authname}', event.date={date}

  RETURN user, ip
  """

statement_date = """
  MERGE (date:Date{{ date:'{Daterange}' }}) set date.start='{start}', date.end='{end}'
  RETURN date
  """

statement_domain = """
  MERGE (domain:Domain{{ domain:'{domain}' }})
  RETURN domain
  """

statement_dr = """
  MATCH (domain:Domain{{ domain:'{domain}' }})
  MATCH (user:Username{{ user:'{user}' }})
  CREATE (user)-[group:Group]->(domain)

  RETURN user, domain
  """

statement_del = """
  MERGE (date:Deletetime{{ date:'{deletetime}' }}) set date.user='{user}', date.domain='{domain}'
  RETURN date
  """

statement_pl = """
  MERGE (id:ID{{ id:{id} }}) set id.changetime='{changetime}', id.category='{category}', id.sub='{sub}'
  RETURN id
  """

statement_pr = """
  MATCH (id:ID{{ id:{id} }})
  MATCH (user:Username{{ user:'{user}' }})
  CREATE (user)-[group:Policy]->(id) set group.date='{date}'

  RETURN user, id
  """

statement_cd = """
  CREATE DATABASE {case};
  """

statement_dd = """
  DROP DATABASE {case};
  """

statement_cu = """
  CREATE USER {username} SET PASSWORD '{password}' CHANGE NOT REQUIRED;
  """

# for Neo4j enterprise edition
#statement_cu = """
#  CREATE USER {username} SET PASSWORD '{password}' CHANGE NOT REQUIRED SET STATUS ACTIVE;
#  """

statement_au = """
  ALTER CURRENT USER SET PASSWORD FROM '{oldPassword}' TO '{newPassword}';
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

statement_role_revole = """
  REVOKE GRANT ACCESS ON DATABASES {database} FROM {username}_role;
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

if not has_wtforms:
    logger.error("[!] wtforms must be installed for this script.")
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
# neo4j listen port
NEO4J_PORT = config_data["neo4j"]["NEO4J_PORT"]
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
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + database_name
app.config["SECRET_KEY"] = os.urandom(24)
app.permanent_session_lifetime = datetime.timedelta(minutes=60)
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

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
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=50)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=3, max=20)])

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=50)])
    password1 = PasswordField('Password', validators=[DataRequired(), EqualTo('password2', message='Passwords must match.'), Length(min=3, max=20)])
    password2 = PasswordField('Password (again)', validators=[DataRequired(), Length(min=3, max=20)])

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('This username is already registered.')

class CaseForm(FlaskForm):
    case = StringField('Case', validators=[DataRequired()])

with app.app_context():
    db.create_all()

    user_query = User.query.filter_by(username=default_user).first()
    if user_query is None:
        create_user = User(username=default_user, urole="ADMIN")
        db.session.add(create_user)
        db.session.commit()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

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


# Costom login_required with role
def login_required(role="ANY"):
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
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
@http_request_logging
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

        session["username"] = username
        session["password"] = password

        try:
            GraphService(host=NEO4J_SERVER, user=session["username"], password=session["password"])
            user = User.query.filter_by(username=username).first()
            logger.info("[+] login user {0}.".format(username))
            login_user(user, remember=remember)
            return redirect('/')
        except:
            logger.error("[!] login failed user {0}.".format(username))
            return render_template('login.html', form=form, messages='<div class="alert alert-danger" role="alert">Invalid username or password.</div>')

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
            service = GraphService(host=NEO4J_SERVER, user=session["username"], password=session["password"])
        except:
            logger.error("[!] Can't connect Neo4j Database GraphService.")
            sys.exit(1)

        create_neo4j_user(service, username, password, role_neo4j)

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
            service = GraphService(host=NEO4J_SERVER, user=session["username"], password=session["password"])
        except:
            logger.error("[!] Can't connect Neo4j Database GraphService.")
            sys.exit(1)

        try:
            system = service.system_graph
            system.run(statement_au.format(**{"oldPassword": session["password"], "newPassword": password}))
            logger.info("[+] Change user {0} password for neo4j.".format(username))
        except ClientError as e:
            if "User does not exist" in str(e):
                logger.error("[!] User does not exist {0}.".format(username))
            elif "Unsupported administration command" in str(e):
                logger.error("[!] Can't change password.")
            else:
                logger.error(str(e))

        session["password"] = password

        return redirect('/')
    else:
        return render_template('setting.html', form=form)


# Web application logout
@app.route('/logout')
@http_request_logging
@login_required(role="ANY")
def logout():
    logout_user()
    return redirect('/login')


# Web application create case
@app.route('/addcase', methods=['GET', 'POST'])
@http_request_logging
@login_required(role="ADMIN")
def addcase():
    form = CaseForm(request.form)
    if form.validate_on_submit():
        try:
            service = GraphService(host=NEO4J_SERVER, user=session["username"], password=session["password"])
        except:
            logger.error("[!] Can't connect Neo4j Database GraphService.")
            sys.exit(1)

        if "Enterprise" in service.product:
            case = form.case.data
            if not re.search(r"\A[0-9a-zA-Z]{2,20}\Z", case):
                return render_template('addcase.html', form=form, messages='<div class="alert alert-danger" role="alert">You can use letters upper/lowercase and numbers.</div>')

            session["case"] = case
            create_database(service, case)

            return render_template("index.html", server_ip=NEO4J_SERVER, ws_port=WS_PORT, neo4j_password=session["password"], neo4j_user=session["username"], case_name=case)
        else:
            return render_template("index.html", server_ip=NEO4J_SERVER, ws_port=WS_PORT, neo4j_password=session["password"], neo4j_user=session["username"], case_name=CASE_NAME)
    else:
        return render_template('addcase.html', form=form, messages='<div class="alert alert-info" role="alert">This feature is in Neo4j Enterprise.</div>')


# Web application delete case
@app.route('/delcase', methods=['GET', 'POST'])
@http_request_logging
@login_required(role="ADMIN")
def delcase():
    if request.method == "POST":
        case_name = request.form.get('caseName')

        try:
            service = GraphService(host=NEO4J_SERVER, user=session["username"], password=session["password"])
        except:
            logger.error("[!] Can't connect Neo4j Database GraphService.")
            sys.exit(1)

        if "Enterprise" in service.product:
            if re.search(r"\A[0-9a-zA-Z]{2,20}\Z", case_name):
                delete_database(service, case_name)

            return render_template("delcase.html", server_ip=NEO4J_SERVER, ws_port=WS_PORT, neo4j_password=session["password"], neo4j_user=session["username"], case_name=session["case"], messages='<div><div class="alert alert-success" role="alert">Deleted case ' + case_name + '</div></div>')
        else:
            return render_template("delcase.html", server_ip=NEO4J_SERVER, ws_port=WS_PORT, neo4j_password=session["password"], neo4j_user=session["username"], case_name=session["case"], messages='<div><div class="alert alert-danger" role="alert">This feature is in Neo4j Enterprise.</div></div>')
    else:
        return render_template("delcase.html", server_ip=NEO4J_SERVER, ws_port=WS_PORT, neo4j_password=session["password"], neo4j_user=session["username"], case_name=session["case"], messages='')


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

        return render_template("index.html", server_ip=NEO4J_SERVER, ws_port=WS_PORT, neo4j_password=session["password"], neo4j_user=session["username"], case_name=case_name)
    else:
        return render_template("changecase.html", server_ip=NEO4J_SERVER, ws_port=WS_PORT, neo4j_password=session["password"], neo4j_user=session["username"])


@app.route('/changecase_t', methods=['GET', 'POST'])
@http_request_logging
@login_required(role="ANY")
def changecase_t():
    if request.method == "POST":
        case_name = request.form.get('caseName')
        if not re.search(r"\A[0-9a-zA-Z]{2,20}\Z", case_name):
            return redirect('/')

        session["case"] = case_name

        return render_template("timeline.html", server_ip=NEO4J_SERVER, ws_port=WS_PORT, neo4j_password=session["password"], neo4j_user=session["username"], case_name=case_name)
    else:
        return render_template("changecase.html", server_ip=NEO4J_SERVER, ws_port=WS_PORT, neo4j_password=session["password"], neo4j_user=session["username"])


# Web application add case management
@app.route('/casemng', methods=['GET', 'POST'])
@http_request_logging
@login_required(role="ADMIN")
def case_management():
    if request.method == "POST":
        user = request.form.get("userSelect")
        case_name = request.form.get('caseName')

        try:
            service = GraphService(host=NEO4J_SERVER, user=session["username"], password=session["password"])
        except:
            logger.error("[!] Can't connect Neo4j Database GraphService.")
            sys.exit(1)

        if "Enterprise" in service.product:
            if not re.search(UCHECK, user) and re.search(r"\A[0-9a-zA-Z]{2,20}\Z", case_name):
                add_db_access_role(service, user, case_name)

            return render_template("casemng.html", server_ip=NEO4J_SERVER, ws_port=WS_PORT, neo4j_password=session["password"], neo4j_user=session["username"], case_name=session["case"], messages='<div><div class="alert alert-success" role="alert">Added access role for case ' + case_name + ' of user ' + user + '</div></div>')
        else:
            return render_template("casemng.html", server_ip=NEO4J_SERVER, ws_port=WS_PORT, neo4j_password=session["password"], neo4j_user=session["username"], case_name=session["case"], messages='<div><div class="alert alert-danger" role="alert">This feature is in Neo4j Enterprise.</div></div>')
    else:
        return render_template("casemng.html", server_ip=NEO4J_SERVER, ws_port=WS_PORT, neo4j_password=session["password"], neo4j_user=session["username"], case_name=session["case"], messages='')


# Web application delete case management
@app.route('/delcasemng', methods=['GET', 'POST'])
@http_request_logging
@login_required(role="ADMIN")
def case_management_del():
    if request.method == "POST":
        user_db = [userlist.split("_") for userlist in request.form.getlist("userlist")]

        try:
            service = GraphService(host=NEO4J_SERVER, user=session["username"], password=session["password"])
        except:
            logger.error("[!] Can't connect Neo4j Database GraphService.")
            sys.exit(1)

        if "Enterprise" in service.product:
            for user, case_name in user_db:
                if not re.search(UCHECK, user) and re.search(r"\A[0-9a-zA-Z]{2,20}\Z", case_name):
                    delete_db_access_role(service, user, case_name)

            return render_template("delcasemng.html", server_ip=NEO4J_SERVER, ws_port=WS_PORT, neo4j_password=session["password"], neo4j_user=session["username"], case_name=session["case"], messages='<div><div class="alert alert-success" role="alert">Deleted access role to case ' + case_name + ' for user ' + user + '</div></div>')
        else:
            return render_template("delcasemng.html", server_ip=NEO4J_SERVER, ws_port=WS_PORT, neo4j_password=session["password"], neo4j_user=session["username"], case_name=session["case"], messages='<div><div class="alert alert-danger" role="alert">This feature is in Neo4j Enterprise.</div></div>')
    else:
        return render_template("delcasemng.html", server_ip=NEO4J_SERVER, ws_port=WS_PORT, neo4j_password=session["password"], neo4j_user=session["username"], case_name=session["case"], messages='')


# Web application user management
@app.route('/usermng', methods=['GET', 'POST'])
@http_request_logging
@login_required(role="ADMIN")
def user_management():
    if request.method == "POST":
        users = [userlist.strip("Check_") for userlist in request.form.getlist("userlist")]
        action = request.form.get("action")

        try:
            service = GraphService(host=NEO4J_SERVER, user=session["username"], password=session["password"])
        except:
            logger.error("[!] Can't connect Neo4j Database GraphService.")
            sys.exit(1)

        if "delete" in action:
            for user in users:
                if not re.search(UCHECK, user):
                    delete_neo4j_user(service, user)
                    with app.app_context():
                        user_query = User.query.filter_by(username=user).first()
                        db.session.delete(user_query)
                        db.session.commit()
        elif ("suspended" in action or "active" in action) and "Enterprise" in service.product:
            for user in users:
                if not re.search(UCHECK, user):
                    change_status_neo4j_user(service, user, action)

        return render_template("usermng.html", server_ip=NEO4J_SERVER, ws_port=WS_PORT, neo4j_password=session["password"], neo4j_user=session["username"])
    else:
        return render_template("usermng.html", server_ip=NEO4J_SERVER, ws_port=WS_PORT, neo4j_password=session["password"], neo4j_user=session["username"])


# Web application index.html
@app.route('/')
@http_request_logging
@login_required(role="ANY")
def index():
    return render_template("index.html", server_ip=NEO4J_SERVER, ws_port=WS_PORT, neo4j_password=session["password"], neo4j_user=session["username"], case_name=session["case"])


# Timeline view
@app.route('/timeline')
@login_required(role="ANY")
@http_request_logging
def timeline():
    return render_template("timeline.html", server_ip=NEO4J_SERVER, ws_port=WS_PORT, neo4j_password=session["password"], neo4j_user=session["username"], case_name=session["case"])


# Web application logs
@app.route('/log')
@login_required(role="ANY")
def logs():
    with open(FPATH + "/static/logontracer.log", "r") as lf:
        logdata = lf.read()
    return logdata


# Sigma rule scan results
@app.route('/sigma')
@login_required(role="ANY")
def sigma():
    with open(FPATH + "/static/sigma_results.csv", "r") as sf:
        sigma_logs = sf.read()
    return sigma_logs


# Web application upload
@app.route("/upload", methods=["POST"])
@login_required(role="ANY")
@http_request_logging
def do_upload():
    UPLOAD_DIR = os.path.join(FPATH, 'upload')
    filelist = ""

    if os.path.exists(UPLOAD_DIR) is False:
        os.makedirs(UPLOAD_DIR)
        logger.info("[+] make upload folder {0}.".format(UPLOAD_DIR))

    try:
        timezone = request.form["timezone"]
        logtype = request.form["logtype"]
        addlog = request.form["addlog"]
        sigmascan = request.form["sigmascan"]
        casename = request.form["casename"]
        for i in range(0, len(request.files)):
            loadfile = "file" + str(i)
            file = request.files[loadfile]
            if file and file.filename:
                if "EVTX" in logtype:
                    filename = os.path.join(UPLOAD_DIR, str(i) + ".evtx")
                elif "XML" in logtype:
                    filename = os.path.join(UPLOAD_DIR, str(i) + ".xml")
                else:
                    continue
                file.save(filename)
                filelist += filename + " "
        if "EVTX" in logtype:
            logoption = " -e "
        elif "XML" in logtype:
            logoption = " -x "
        else:
            return "FAIL"
        if not re.search(r"\A-{0,1}[0-9]{1,2}\Z", timezone):
            return "FAIL"
        if addlog in "true":
            add_option = "--add"
        else:
            add_option = "--delete"
        if sigmascan in "true":
            add_option += " --sigma"
        if not re.search(r"\A[0-9a-zA-Z]{2,20}\Z", casename):
            return "FAIL"

        parse_command = "nohup python3 " + FPATH + "/logontracer.py " + add_option + " --case " + casename + " -z " + timezone + logoption + filelist + " -s " + NEO4J_SERVER + " -u " + session["username"] + " -p " + session["password"] + " >  " + FPATH + "/static/logontracer.log 2>&1 &"
        subprocess.call("rm -f " + FPATH + "/static/logontracer.log > /dev/null", shell=True)
        subprocess.call(parse_command, shell=True)
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

        if fromdatetime not in "false":
            try:
                datetime.datetime.strptime(fromdatetime, "%Y-%m-%dT%H:%M:%S")
                fromdatetime = " -f " + fromdatetime
            except:
                return "FAIL"
        else:
            fromdatetime = ""

        if todatetime not in "false":
            try:
                datetime.datetime.strptime(todatetime, "%Y-%m-%dT%H:%M:%S")
                todatetime = " -t " + todatetime
            except:
                return "FAIL"
        else:
            todatetime = ""

        es_ip, es_port = es_server.split(":")
        if (re.search(IPv4_PATTERN, es_ip) or es_ip in "localhost") and re.search(r"\A\d{2,5}\Z", es_port):
            es_server = " --es-server " + es_server
        else:
            return "FAIL"

        if not re.search(r"\A-{0,1}[0-9]{1,2}\Z", timezone):
            return "FAIL"

        if addlog in "true":
            log_option = "--add"
        else:
            log_option = "--delete"

        if addes in "true":
            es_option = " --postes "
        else:
            es_option = ""

        if not re.search(r"\A[0-9a-zA-Z]{2,20}\Z", casename):
            return "FAIL"

        parse_command = "nohup python3 " + FPATH + "/logontracer.py --es " + log_option + es_option + " --case " + casename + " -z " + timezone + fromdatetime + todatetime + es_server  + " -s " + NEO4J_SERVER + " -u " + session["username"] + " -p " + session["password"] + " --es-index " + ES_INDEX + " --es-prefix " + ES_PREFIX + " >  " + FPATH + "/static/logontracer.log 2>&1 &"
        subprocess.call("rm -f " + FPATH + "/static/logontracer.log > /dev/null", shell=True)
        subprocess.call(parse_command, shell=True)
        return "SUCCESS"

    except:
        return "FAIL"


@app.route("/favicon.ico")
def favicon():
    return app.send_static_file("favicon.ico")


# Calculate ChangeFinder
def adetection(counts, users, starttime, tohours):
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
    rep_xml = record_xml.replace("xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"", "")
    fin_xml = rep_xml.encode("utf-8")
    parser = etree.XMLParser(resolve_entities=False)
    return etree.fromstring(fin_xml, parser)


def xml_records(filename):
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
    tzless = re.sub('[^0-9-:\s]', ' ', logtime.split(".")[0]).strip()
    try:
        return datetime.datetime.strptime(tzless, "%Y-%m-%d %H:%M:%S") + datetime.timedelta(hours=tzone)
    except:
        return datetime.datetime.strptime(tzless, "%Y-%m-%dT%H:%M:%S") + datetime.timedelta(hours=tzone)


# Create database for neo4j
def create_database(service, database):
    try:
        system = service.system_graph
        system.run(statement_cd.format(**{"case": database}))
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


# Create database for neo4j
def delete_database(service, database):
    try:
        system = service.system_graph
        system.run(statement_dd.format(**{"case": database}))
        logger.info("[+] Delete database {0}.".format(database))
    except ClientError as e:
        if "Database does not exist" in str(e):
            logger.error("[!] Database does not exist {0}.".format(database))
        elif "Unsupported administration command" in str(e):
            logger.error("[!] Can't delete database. This feature is in Neo4j Enterprise.")
        else:
            logger.error(str(e))


# Create user for neo4j
def create_neo4j_user(service, username, password, role):
    system = service.system_graph

    try:
        system.run(statement_cu.format(**{"username": username, "password": password}))
        logger.info("[+] Created user {0} for neo4j.".format(username))
    except ClientError as e:
        if "User already exists" in str(e):
            logger.error("[!] User already exists {0}.".format(username))
        elif "Unsupported administration command" in str(e):
            logger.error("[!] Can't create user.")
        else:
            logger.error(str(e))

    if "Enterprise" in service.product:
        try:
            # For admin role, do not revokes database access.
            if "admin" in role:
                system.run(statement_role_set_admin.format(**{"username": username}))
                logger.info("[+] Set {0} admin role for neo4j.".format(username))
            else:
                system.run(statement_role_add.format(**{"username": username, "role": role}))
                system.run(statement_role_revole.format(**{"database": "*", "username": username}))
                system.run(statement_role_set.format(**{"username": username}))
                system.run(statement_default_db_access.format(**{"username": username}))
                logger.info("[+] Created {0}_role for neo4j.".format(username))
        except ClientError as e:
            if "Role already exists" in str(e):
                logger.error("[!] Role already exists {0}.".format(username))
            elif "Unsupported administration command" in str(e):
                logger.error("[!] Can't create role. This feature is in Neo4j Enterprise.")
            else:
                logger.error(str(e))


# Delete user for neo4j
def delete_neo4j_user(service, username):
    try:
        system = service.system_graph
        system.run(statement_du.format(**{"username": username}))
        logger.info("[+] Delete user {0} for neo4j.".format(username))
    except ClientError as e:
        if "User does not exist" in str(e):
            logger.error("[!] User does not exist {0}.".format(username))
        elif "Unsupported administration command" in str(e):
            logger.error("[!] Can't delete user.")
        else:
            logger.error(str(e))


# Change user status for neo4j
def change_status_neo4j_user(service, username, action):
    try:
        system = service.system_graph
        system.run(statement_su.format(**{"username": username, "action": action}))
        logger.info("[+] Change user {0} status {1} for neo4j.".format(username, action))
    except ClientError as e:
        if "User does not exist" in str(e):
            logger.error("[!] User does not exist {0}.".format(username))
        elif "Unsupported administration command" in str(e):
            logger.error("[!] Can't delete user.")
        else:
            logger.error(str(e))


# Add user access role for database
def add_db_access_role(service, username, dbname):
    try:
        system = service.system_graph
        system.run(statement_db_access.format(**{"username": username, "database": dbname}))
        logger.info("[+] Added database access role: user {0} database {1}.".format(username, dbname))
    except ClientError as e:
        if "Role does not exist" in str(e):
            logger.error("[!] User does not exist {0}.".format(username))
        elif "Unsupported administration command" in str(e):
            logger.error("[!] Can't delete user.")
        else:
            logger.error(str(e))


# Delete user access role for database
def delete_db_access_role(service, username, dbname):
    print("test")
    try:
        system = service.system_graph
        system.run(statement_role_revole.format(**{"database": dbname, "username": username}))
        logger.info("[+] Deleted database access role: user {0} database {1}.".format(username, dbname))
    except ClientError as e:
        if "Role does not exist" in str(e):
            logger.error("[!] User does not exist {0}.".format(username))
        elif "Unsupported administration command" in str(e):
            logger.error("[!] Can't delete user.")
        else:
            logger.error(str(e))


# git clone or pull from url
def git_clone_pull(url, download_path):
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
    sigma_status = ["stable", "test", None] 
    sigma_rules = []
    eventids = []

    config = SigmaConfiguration()

    if os.path.exists(download_path):
        logger.info("[+] Load sigma rules from {0}.".format(download_path))
        sigma_rules_files = glob.glob(download_path + '/**/*.yml', recursive=True)
        for rules_file in sigma_rules_files:
            # ignore rules
            if ".github" in rules_file or "config" in rules_file or "test" in rules_file:
                continue

            with open(rules_file, "r", encoding='utf-8') as file:
                try:
                    parser = SigmaParser(yaml.safe_load(file), config)
                except:
                    logger.info("[+] Can't load sigma rule file {0}.".format(rules_file))
                    continue

                if not 'product' in parser.parsedyaml["logsource"].keys() or not 'service' in parser.parsedyaml["logsource"].keys():
                    continue

                if "windows" in parser.parsedyaml["logsource"]["product"] and "security" in parser.parsedyaml["logsource"]["service"] and parser.parsedyaml["status"] in sigma_status:
                    if not re.search("count", str(parser.parsedyaml["detection"]["condition"])):
                        for parsed in parser.condparsed:
                            try:
                                parsed_sigma = generateQuery(parsed)[0]
                            except:
                                logger.info("[+] Can't parse sigma rule file {0}.".format(rules_file))
                        
                        for sigma_rule_path in list(load_sigma_rules(parsed_sigma)):
                            #print(sigma_rule_path)
                            if depth(sigma_rule_path) == 1:
                                break
                        else:
                            continue
                        
                        # export event id from sigma rules
                        eid = []
                        if isinstance(parsed_sigma, dict):
                            eid.append(parsed_sigma['EventID'])
                        else:
                            for d in flatten(parsed_sigma):
                                if isinstance(d, dict):
                                    if 'EventID' in d.keys():
                                        eid.append(d['EventID'])
                        eid_list = list(flatten(eid))
                        eventids.extend(eid_list)
                        sigma_rules.append([eid_list, parsed_sigma, parser.parsedyaml["title"], parser.parsedyaml["description"], parser.parsedyaml["level"]])
    else:
        logger.error("[!] Not found {0}.".format(download_path))

    logger.info("[+] Loaded {0} sigma rules for security event log analysis.".format(len(sigma_rules)))
    
    return sigma_rules, set(eventids)


# Sigma rule parse helpers
def generateQuery(parsed):
    nodes = []

    if type(parsed.parsedSearch) == NodeSubexpression:
        nodes.append(parsed.parsedSearch.items)
    elif isinstance(parsed.parsedSearch, tuple):
        nodes.append(parsed.parsedSearch)
    else:
        nodes.append(parsed.parsedSearch)
    
    return generateANDNode(nodes)


def generateNode(node):
    if type(node) == ConditionAND:
        return generateANDNode(node)
    elif type(node) == ConditionOR:
        return generateORNode(node)
    elif type(node) == ConditionNOT:
        return generateNOTNode(node)
    elif type(node) == NodeSubexpression:
        return generateSubexpressionNode(node)
    elif type(node) == tuple:
        return dict((node,))
    else:
        raise TypeError("Node type %s was not expected in Sigma parse tree" % (str(type(node))))


def generateANDNode(node):
    if type(node) == ConditionAND:
        return ["AND", [generateNode(val) for val in node]]
    else:
        return [generateNode(val) for val in node]


def generateORNode(node):
    return ["OR", [generateNode(val) for val in node]]


def generateNOTNode(node):
    return ["NOT", generateNode(node.item)]


def generateSubexpressionNode(node):
    if type(node.items) == NodeSubexpression:
        return [check_condition(node), dict(list(flatten(node.items)))]
    else:
        return generateNode(node.items)


def check_condition(parsed):
    if isinstance(parsed.items, ConditionOR):
        return "OR"
    elif isinstance(parsed.items, ConditionAND):
        return "AND"
    elif isinstance(parsed, ConditionNOT):
        return "NOT"
    else:
        return None


# Sigma compare helpers
def load_sigma_rules(node):
    val, *children = node
    if any(children):
        for child in children: 
            if isinstance(child, dict):
                yield [val, child]
            else:
                for path in load_sigma_rules(child):
                    yield [val] + path
    else:
        yield [val]


def sigma_search(sigma_filter, event_data):
    sigma_hit = 1
    for sigma_key, sigma_text in sigma_filter.items():
        for data in event_data:
            if data.get("Name") in sigma_key and data.text is not None:
                if type(sigma_text) is list and sigma_hit >= 1:
                    for data_field in sigma_text:
                        if re.fullmatch(reescape(data_field), data.text):
                            sigma_hit = 2
                            break
                        else:
                            sigma_hit = 0
                elif sigma_hit >= 1:
                    if re.fullmatch(reescape(sigma_text), data.text):
                        sigma_hit = 2
                    else:
                        sigma_hit = 0
                        break
        if sigma_hit == 0:
            break
    return sigma_hit


# Helpers
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
        event_set = pd.DataFrame(index=[], columns=["eventid", "ipaddress", "username", "logintype", "status", "authname", "date"])
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

                    if username != "-" and username != "anonymous logon" and ipaddress != "::1" and ipaddress != "127.0.0.1" and (ipaddress != "-" or hostname != "-"):
                        # generate pandas series
                        if ipaddress != "-":
                            event_series = pd.Series([eventid, ipaddress, username, logintype, status, authname, int(stime.timestamp())], index=event_set.columns)
                            ml_series = pd.Series([etime.strftime("%Y-%m-%d %H:%M:%S"), username, ipaddress, eventid],  index=ml_frame.columns)
                        else:
                            event_series = pd.Series([eventid, hostname, username, logintype, status, authname, int(stime.timestamp())], index=event_set.columns)
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
                # Sigma rule detection
                ###
                if args.sigma:
                    if eventid in sigma_eventids:
                        for search_eid, sigma_filters, sigma_title, sigma_details, sigma_level in sigma_rules:
                            if eventid in search_eid:
                                sigma_hit = 1

                                # If the detection rule is only event id
                                if isinstance(sigma_filters, dict):
                                    sigma_results.append([etime.strftime("%Y-%m-%d %H:%M:%S"), sigma_level, sigma_title, sigma_details, etree.tostring(node, encoding="utf-8")])
                                    continue
                                
                                for sigma_filter_list in load_sigma_rules(sigma_filters):
                                    for sigma_filter_list_path in sigma_filter_list:
                                        if isinstance(sigma_filter_list_path, dict):
                                            sigma_hit = sigma_search(sigma_filter_list_path, event_data)
                                        if sigma_hit == 0:
                                            break
                                    if sigma_hit == 0:
                                        break

                                if sigma_hit == 2:
                                    sigma_results.append([etime.strftime("%Y-%m-%d %H:%M:%S"), sigma_level, sigma_title, sigma_details, etree.tostring(node, encoding="utf-8")])
                                
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
    event_set_bydate["count"] = event_set_bydate.groupby(["eventid", "ipaddress", "username", "logintype", "status", "authname", "date"])["eventid"].transform("count")
    event_set_bydate = event_set_bydate.drop_duplicates()
    event_set = event_set.drop("date", axis=1)
    event_set["count"] = event_set.groupby(["eventid", "ipaddress", "username", "logintype", "status", "authname"])["eventid"].transform("count")
    event_set = event_set.drop_duplicates()
    count_set["count"] = count_set.groupby(["dates", "eventid", "username"])["dates"].transform("count")
    count_set = count_set.drop_duplicates()
    domain_set_uniq = list(map(list, set(map(tuple, domain_set))))

    # Create Sigma scan results file
    if args.sigma:
        logger.info("[+] {0} event logs hit the Sigma rules.".format(len(sigma_results)))
        with open(FPATH + "/static/" + SIGMA_RESULTS_FILE, 'w', newline='', encoding='utf8') as f:
            writer = csv.writer(f)
            writer.writerow(["date","sigma_level","sigma_title","sigma_details","event_log"])
            writer.writerows(sigma_results)
        logger.info("[+] Created Sigma scan results file {0}.".format(FPATH + "/static/" + SIGMA_RESULTS_FILE))

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
        graph_http = "http://" + NEO4J_USER + ":" + NEO4J_PASSWORD + "@" + NEO4J_SERVER + ":" + NEO4J_PORT + "/db/data/"
        GRAPH = Graph(graph_http, name=case)
    except:
        logger.error("[!] Can't connect Neo4j Database.")
        sys.exit(1)

    if args.postes:
        # Parse Event log
        logger.info("[+] Start sending the ES.")

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

    tx = GRAPH.begin()
    hosts_inv = {v: k for k, v in hosts.items()}
    for ipaddress in event_set["ipaddress"].drop_duplicates():
        if ipaddress in hosts_inv:
            hostname = hosts_inv[ipaddress]
        else:
            hostname = ipaddress
        # add the IPAddress node to neo4j
        tx.run(statement_ip.format(**{"IP": ipaddress, "rank": ranks[ipaddress], "hostname": hostname}))

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
        tx.run(statement_user.format(**{"user": username[:-1], "rank": ranks[username], "rights": rights, "sid": sid, "status": ustatus,
                                         "counts": ",".join(map(str, timelines[i*6])), "counts4624": ",".join(map(str, timelines[i*6+1])),
                                         "counts4625": ",".join(map(str, timelines[i*6+2])), "counts4768": ",".join(map(str, timelines[i*6+3])),
                                         "counts4769": ",".join(map(str, timelines[i*6+4])), "counts4776": ",".join(map(str, timelines[i*6+5])),
                                         "detect": ",".join(map(str, detects[i]))}))
        i += 1

        # add user data to Elasticsearch
        if args.postes:
            es_doc = es_doc_user.format(**{"datetime": es_timestamp, "user": username[:-1], "rights": rights, "sid": sid, "status": ustatus, "rank": ranks[username]})
            post_es("logontracer-user-index", client, es_doc)

    for domain in domains:
        # add the domain node to neo4j
        tx.run(statement_domain.format(**{"domain": domain}))

    for _, events in event_set_bydate.iterrows():
        # add the (username)-(event)-(ip) link to neo4j
        tx.run(statement_r.format(**{"user": events["username"][:-1], "IP": events["ipaddress"], "id": events["eventid"], "logintype": events["logintype"],
                                      "status": events["status"], "count": events["count"], "authname": events["authname"], "date": events["date"]}))

    for username, domain in domain_set_uniq:
        # add (username)-()-(domain) link to neo4j
        tx.run(statement_dr.format(**{"user": username[:-1], "domain": domain}))

    # add the date node to neo4j
    tx.run(statement_date.format(**{"Daterange": "Daterange", "start": datetime.datetime(*starttime.timetuple()[:4]).strftime("%Y-%m-%d %H:%M:%S"),
                                     "end": datetime.datetime(*endtime.timetuple()[:4]).strftime("%Y-%m-%d %H:%M:%S")}))

    if len(deletelog):
        # add the delete flag node to neo4j
        tx.run(statement_del.format(**{"deletetime": deletelog[0], "user": deletelog[1], "domain": deletelog[2]}))

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
            tx.run(statement_pl.format(**{"id": id, "changetime": policy[0], "category": category, "sub": sub}))
            # add (username)-(policy)-(id) link to neo4j
            tx.run(statement_pr.format(**{"user": username[:-1], "id": id, "date": policy[4]}))
            id += 1

    #tx.process()
    try:
        # for py2neo 2021.1 or later
        GRAPH.commit(tx)
    except:
        # for py2neo 2021.0 or earlier
        tx.commit()

    logger.info("[+] Creation of a graph data finished.")

# Parse from Elastic Search cluster
# Porting by 0xThiebaut
def parse_es(case):        
    event_set = pd.DataFrame(index=[], columns=["eventid", "ipaddress", "username", "logintype", "status", "authname", "date"])
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
                # parse IP Address
                if hasattr(event.event_data, "IpAddress"):
                    ipaddress = event.event_data.IpAddress.split("@")[0]
                    ipaddress = ipaddress.lower().replace("::ffff:", "")
                    ipaddress = ipaddress.replace("\\", "")
                elif hasattr(event.event_data, "Workstation"):
                    ipaddress = event.event_data.Workstation.split("@")[0]
                    ipaddress = ipaddress.lower().replace("::ffff:", "")
                    ipaddress = ipaddress.replace("\\", "")
                # Parse hostname
                if hasattr(event.event_data, "WorkstationName"):
                    hostname = event.event_data.WorkstationName.split("@")[0]
                    hostname = hostname.lower().replace("::ffff:", "")
                    hostname = hostname.replace("\\", "")
                # Parse username
                if hasattr(event.event_data, "TargetUserName"):
                    username = event.event_data.TargetUserName.split("@")[0]
                    if username[-1:] not in "$":
                        username = username.lower() + "@"
                    else:
                        username = "-"
                # Parse targeted domain name
                if hasattr(event.event_data, "TargetDomainName"):
                    domain = event.event_data.TargetDomainName
                # parse trageted user SID
                if hasattr(event.event_data, "TargetUserSid"):
                    sid = event.event_data.TargetUserSid
                if hasattr(event.event_data, "TargetSid"):
                    sid = event.event_data.TargetSid
                # parse login type
                if hasattr(event.event_data, "LogonType"):
                    logintype = event.event_data.LogonType
                # parse status
                if hasattr(event.event_data, "Status"):
                    status = event.event_data.Status
                # parse Authentication package name
                if hasattr(event.event_data, "AuthenticationPackageName"):
                    authname = event.event_data.AuthenticationPackageName
                if username != "-" and username != "anonymous logon" and ipaddress != "::1" and ipaddress != "127.0.0.1" and (ipaddress != "-" or hostname != "-"):
                    # generate pandas series
                    if ipaddress != "-":
                        event_series = pd.Series([eventid, ipaddress, username, logintype, status, authname, int(stime.timestamp())], index=event_set.columns)
                        ml_series = pd.Series([etime.strftime("%Y-%m-%d %H:%M:%S"), username, ipaddress, eventid],  index=ml_frame.columns)
                    else:
                        event_series = pd.Series([eventid, hostname, username, logintype, status, authname, int(stime.timestamp())], index=event_set.columns)
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
    event_set_bydate["count"] = event_set_bydate.groupby(["eventid", "ipaddress", "username", "logintype", "status", "authname", "date"])["eventid"].transform("count")
    event_set_bydate = event_set_bydate.drop_duplicates()
    event_set = event_set.drop("date", axis=1)
    event_set["count"] = event_set.groupby(["eventid", "ipaddress", "username", "logintype", "status", "authname"])["eventid"].transform("count")
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
        graph_http = "http://" + NEO4J_USER + ":" + NEO4J_PASSWORD + "@" + NEO4J_SERVER + ":" + NEO4J_PORT + "/db/data/"
        GRAPH = Graph(graph_http, name=case)
    except:
        logger.error("[!] Can't connect Neo4j Database.")
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

    tx = GRAPH.begin()
    hosts_inv = {v: k for k, v in hosts.items()}
    for ipaddress in event_set["ipaddress"].drop_duplicates():
        if ipaddress in hosts_inv:
            hostname = hosts_inv[ipaddress]
        else:
            hostname = ipaddress
        # add the IPAddress node to neo4j
        tx.run(statement_ip.format(**{"IP": ipaddress, "rank": ranks[ipaddress], "hostname": hostname}))

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
        tx.run(statement_user.format(**{"user": username[:-1], "rank": ranks[username], "rights": rights, "sid": sid, "status": ustatus,
                                         "counts": ",".join(map(str, timelines[i*6])), "counts4624": ",".join(map(str, timelines[i*6+1])),
                                         "counts4625": ",".join(map(str, timelines[i*6+2])), "counts4768": ",".join(map(str, timelines[i*6+3])),
                                         "counts4769": ",".join(map(str, timelines[i*6+4])), "counts4776": ",".join(map(str, timelines[i*6+5])),
                                         "detect": ",".join(map(str, detects[i]))}))
        i += 1

        # add user data to Elasticsearch
        if args.postes:
            es_doc = es_doc_user.format(**{"datetime": es_timestamp, "user": username[:-1], "rights": rights, "sid": sid, "status": ustatus, "rank": ranks[username]})
            post_es("logontracer-user-index", client, es_doc)

    for domain in domains:
        # add the domain node to neo4j
        tx.run(statement_domain.format(**{"domain": domain}))

    for _, events in event_set_bydate.iterrows():
        # add the (username)-(event)-(ip) link to neo4j
        tx.run(statement_r.format(**{"user": events["username"][:-1], "IP": events["ipaddress"], "id": events["eventid"], "logintype": events["logintype"],
                                      "status": events["status"], "count": events["count"], "authname": events["authname"], "date": events["date"]}))

    for username, domain in domain_set_uniq:
        # add (username)-()-(domain) link to neo4j
        tx.run(statement_dr.format(**{"user": username[:-1], "domain": domain}))

    # add the date node to neo4j
    tx.run(statement_date.format(**{"Daterange": "Daterange", "start": datetime.datetime(*starttime.timetuple()[:4]).strftime("%Y-%m-%d %H:%M:%S"),
                                     "end": datetime.datetime(*endtime.timetuple()[:4]).strftime("%Y-%m-%d %H:%M:%S")}))

    if len(deletelog):
        # add the delete flag node to neo4j
        tx.run(statement_del.format(**{"deletetime": deletelog[0], "user": deletelog[1], "domain": deletelog[2]}))

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
            tx.run(statement_pl.format(**{"id": id, "changetime": policy[0], "category": category, "sub": sub}))
            # add (username)-(policy)-(id) link to neo4j
            tx.run(statement_pr.format(**{"user": username[:-1], "id": id, "date": policy[4]}))
            id += 1

    #tx.process()
    try:
        # for py2neo 2021.1 or later
        GRAPH.commit(tx)
    except:
        # for py2neo 2021.0 or earlier
        tx.commit()

    logger.info("[+] Creation of a graph data finished.")

def main():
    if not has_py2neo:
        logger.error("[!] py2neo must be installed for this script.")
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
        
    try:
        service = GraphService(host=NEO4J_SERVER, user=NEO4J_USER, password=NEO4J_PASSWORD)
    except:
        logger.error("[!] Can't connect Neo4j Database GraphService.")
        sys.exit(1)

    logger.info("[+] Script start. {0}".format(datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")))

    try:
        logger.info("[+] {0}".format(service.product))
    except:
        logger.warning("[!] Can't get Neo4j kernel version.")

    case = create_database(service, CASE_NAME)

    if args.create_user and args.create_password:
        if args.role:
            role = args.role
        else:
            role = "reader"
        create_neo4j_user(service, args.create_user, args.create_password, role)

    if args.delete_user:
        delete_neo4j_user(service, args.delete_user)

    if args.run:
        try:
            app.run(threaded=True, host=WEB_HOST, port=WEB_PORT)
        except:
            logger.error("[!] Can't runnning web application.")
            sys.exit(1)

    # Delete database data
    if args.delete:
        try:
            graph_http = "http://" + NEO4J_USER + ":" + NEO4J_PASSWORD + "@" + NEO4J_SERVER + ":" + NEO4J_PORT + "/db/data/"
            GRAPH = Graph(graph_http, name=case)
        except:
            logger.error("[!] Can't connect Neo4j Database.")
            sys.exit(1)

        GRAPH.delete_all()
        logger.info("[+] Delete all nodes and relationships from this Neo4j database.")

        cache_dir = os.path.join(FPATH, 'cache', case)
        if os.path.exists(cache_dir):
            shutil.rmtree(cache_dir)
            logger.info("[+] Delete cache folder {0}.".format(cache_dir))

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
