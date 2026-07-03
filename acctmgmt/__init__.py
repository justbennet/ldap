# acctmgmt/__init__.py

import ldap3
from ldap3 import Server, Connection, ALL, AUTO_BIND_TLS_BEFORE_BIND

LDAP_URI = "ldaprw.uvm.edu"

LDAP_ADMIN = "cn=VACC Management,ou=Admin,dc=uvm,dc=edu"
LDAP_ADMIN_PASSWD_FILE = "/gpfs1/cluster/tiers/VACC/.vacc.ldap.passwd"

LDAP_READER = "cn=VACC Querier,ou=Admin,dc=uvm,dc=edu"
LDAP_READER_PASSWD_FILE = "/gpfs1/cluster/tiers/userMgmt/.vacc_querier.pw"

LDAP_BASE = "dc=uvm,dc=edu"
GROUPS_BASE = "ou=Groups,dc=uvm,dc=edu"
PEOPLE_BASE = "ou=People,dc=uvm,dc=edu"

MIN_GID_NUMBER = 170000
MAX_GID_NUMBER = 180000


def _read_password(path):
    """Returns the password from the file specified"""
    with open(path, "r") as f:
        return f.read().strip()


def _bind(user, passwd_file):
    """Binds to LDAP as the user specified, using the password in the file
    Returns and ldap3.Connection object"""
    pw = _read_password(passwd_file)
    server = Server(LDAP_URI, get_info=ALL)
    conn = Connection(
        server,
        user=user,
        password=pw,
        check_names=False,
        auto_bind=AUTO_BIND_TLS_BEFORE_BIND,
    )
    return conn


def be_an_admin():
    """Return a Connection bound as the admin (read/write) identity."""
    return _bind(LDAP_ADMIN, LDAP_ADMIN_PASSWD_FILE)


def be_a_reader():
    """Return a Connection bound as the read-only identity."""
    return _bind(LDAP_READER, LDAP_READER_PASSWD_FILE)

