#
# Configuration file for LDAP and database settings
# Milos Ivanovic 2026.
#

import os

LDAP_CONFIG = {
    'ldap_url': os.getenv('LDAP_URL', 'ldap://ldap.example.com:389'),
    'ldap_base_dn': os.getenv('LDAP_BASE_DN', 'ou=People,dc=example,dc=com'),
    'bind_dn': os.getenv('LDAP_BIND_DN', 'uid=service_account,ou=People,dc=example,dc=com'),
    'bind_password': os.getenv('LDAP_BIND_PASSWORD', 'service_password'),
    'use_tls': os.getenv('LDAP_USE_TLS', 'False').lower() == 'true',
    'user_search_filter': os.getenv('LDAP_USER_SEARCH_FILTER', '(&(uid={username})(memberOf=cn=research_group,ou=Groups,dc=example,dc=com))')
}

# Parse LDAP_DOMAINS from comma-separated string
ldap_domains_str = os.getenv('LDAP_DOMAINS', '@example.edu,@example.com')
LDAP_DOMAINS = [domain.strip() for domain in ldap_domains_str.split(',')]

AUTHORITY_URL = os.getenv('AUTHORITY_URL', 'https://api.example.com/bibliography?authority=1&orcid=')

SQLITE_DB_PATH = os.getenv('SQLITE_DB_PATH', './instance/customers.db')
#SQLITE_DB_PATH = os.getenv('SQLITE_DB_PATH', '/data/instance/customers.db')
SQLALCHEMY_DATABASE_URL = f"sqlite:///{SQLITE_DB_PATH}"

# CORS configuration
allowed_origins_str = os.getenv('ALLOWED_ORIGINS', '*')
if allowed_origins_str == '*':
    ALLOWED_ORIGINS = ["*"]
else:
    ALLOWED_ORIGINS = [origin.strip() for origin in allowed_origins_str.split(',')]
