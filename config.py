#
# Configuration file for LDAP and database settings
# Milos Ivanovic 2026.
#

'''
LDAP_CONFIG = dict(
    ldap_url="ldap://spider.pmf.kg.ac.rs:389",
    ldap_base_dn="dc=pmf,dc=kg,dc=ac,dc=rs",
    bind_dn="cn=guest,dc=pmf,dc=kg,dc=ac,dc=rs",
    bind_password="!guest13",
    use_tls=False,
    user_search_filter="(uid={username})"
)
'''

LDAP_CONFIG = dict(
    ldap_url="ldap://ldap.unic.kg.ac.rs:389",
    ldap_base_dn="ou=People,dc=kg,dc=ac,dc=rs",
    bind_dn="uid=radius,ou=People,dc=kg,dc=ac,dc=rs",
    bind_password="radunic",
    use_tls=False,
    user_search_filter="(&(uid={username})(memberOf=cn=scidar,ou=Groups,dc=kg,dc=ac,dc=rs))"
)

LDAP_DOMAINS = ["@pmf.kg.ac.rs", "@kg.ac.rs"]

AUTHORITY_URL = "https://scidar.kg.ac.rs/bibliography?authority=1&orcid="

SQLALCHEMY_DATABASE_URL = "sqlite:///./instance/customers.db"

ALLOWED_ORIGINS = ["*"]
