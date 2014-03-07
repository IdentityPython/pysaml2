from saml2.assertion import Policy

PORT = 8087
HTTPS = False

# Which groups of entity categories to use
POLICY = Policy(
    {
        "default": {"entity_categories": ["swamid", "edugain"]}
    }
)

# HTTPS cert information
SERVER_CERT = "pki/ssl.crt"
SERVER_KEY = "pki/ssl.pem"
CERT_CHAIN = ""