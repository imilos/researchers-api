#
# Configuration file for LDAP and database settings
# Milos Ivanovic 2026.
#

LDAP_CONFIG = dict(
    ldap_url="ldap://example.com:389",
    ldap_base_dn="ou=People,dc=com",
    bind_dn="uid=guest,ou=People,dc=com",
    bind_password="password123",
    use_tls=False,
    user_search_filter="(&(uid={username})(memberOf=cn=your_group,ou=Groups,dc=com))"
)

LDAP_DOMAINS = ["@domain.com", "@domain.org"]

AUTHORITY_URL = "https://scidar.kg.ac.rs/bibliography?authority=1&orcid="

SQLALCHEMY_DATABASE_URL = "sqlite:///./instance/customers.db"

ALLOWED_ORIGINS = ["*"]
