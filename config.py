#
# Configuration file for LDAP and database settings
#

LDAP_CONFIG = dict(
    ldap_url="ldap://ldap.example.org:389",
    ldap_base_dn="dc=example,dc=org",
    bind_dn="cn=read-only-admin,dc=example,dc=org",
    bind_password="your_secure_password_here",
    use_tls=True,  # Production
    user_search_filter="(uid={username})"
)

# List of enabled users
LDAP_USER_LIST = ["authorized.user1", "authorized.user2"]

# SQLite database
SQLALCHEMY_DATABASE_URL = "sqlite:///./instance/instance.db"

# CORS in production should be limited
ALLOWED_ORIGINS = ["*"]

