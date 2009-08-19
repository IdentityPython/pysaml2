import base64
import saml2
from saml2 import samlp, saml
import urllib
import zlib

SERVICE_URL = "http://lingon.catalogix.se/cgi-bin/repo"
MY_NAME = "My Test SP"

SSO_LOCATION = \
        "http://xenosmilus.umdc.umu.se/simplesaml/saml2/idp/SSOService.php"

def create_authn_request(query_id, destination, position=SERVICE_URL, provider=MY_NAME):
    """ Creates an Authenication Request
    
    :param query_id: Query identifier
    :param destination: Where to send the request
    :param position: Where the user should be sent afterwards
    :param provider: Who I am 
    
    :return: A string representation of the authentication request
    """
    authn_request = samlp.AuthnRequest(query_id)
    authn_request.assertion_consumer_service_url = position
    authn_request.destination = destination
    authn_request.protocol_binding = saml2.BINDING_HTTP_POST
    authn_request.provider_name = provider

    name_id_policy = samlp.NameIDPolicy()
    name_id_policy.format = saml.NAMEID_FORMAT_EMAILADDRESS
    name_id_policy.sp_name_qualifier = saml.NAMEID_FORMAT_PERSISTENT
    name_id_policy.allow_create = 'false'

    authn_request.name_id_policy = name_id_policy

    return "%s" % authn_request

        
authn_req = create_authn_request("0123456789",SSO_LOCATION)

b64 = base64.b64encode(authn_req)

print base64.b64decode(b64)

sr = """<?xml version='1.0' encoding='UTF-8'?>
<ns0:AuthnRequest AssertionConsumerServiceURL="http://lingon.catalogix.se/cgi-bin/repo" Destination="http://xenosmilus.umdc.umu.se/simplesaml/saml2/idp/SSOService.php" ID="oglagncepmkklpejlhmkhdpifonhjffgnmjidljj" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" ProviderName="My Test SP" xmlns:ns0="urn:oasis:names:tc:SAML:2.0:protocol"><ns0:NameIDPolicy AllowCreate="false" SPNameQualifier="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" /></ns0:AuthnRequest>"""

for i in range(1,9):
    fb = urllib.quote_plus(base64.b64encode(zlib.compress(sr,i)))
    print
    print zlib.decompress(base64.b64decode(urllib.unquote_plus(fb)))

one = """fZHBbtswDIbvA%2FYOgi45xc56GoQ4RdagaIF29Wr3AVSZtulIlCbKWfr2k9Nihx164YH4%2F4%2Fkz%2B312VlxgsjoqVp9KzYrAWR8hzRUq5f2dv19db37%2BmVLvFH7OY30DL9n4CT2zBBTdt144tlBbCCe0MDL80Mlx5SCKkubKZ4Ko5O2fsBzwVCaAdevSGWE4KU4ZBSSXjj%2FXGcgzw7tzMXsOpPLvBgZXbDA2tlyKVcldqFsmqePuUUYgxT3h0r6weqBDAR3PNoAkx3dcewC9p7Gqe8HchN2dpqkqKNP3nj7A%2BlysJwjKa8ZWZF2wCoZ1ewfH9RVsVGv7yJWd21br%2Bunpr0ATthB%2FJnVlXx8E%2B0STVNLkWOlTOHN59DwsYHcXRJeOPeH2ls0b2Jvrf9zE0GnzO61ZZAZvUh%2BzdpijxA%2Fhy8d7Na9j04nFZYncwJKUpS7bfn%2FR3d%2FAQ%3D%3D"""

print zlib.decompress(base64.b64decode(urllib.unquote_plus(one)), -15)
# d1 = base64.b64decode(d0)
# print zlib.decompress(d1)

zl = zlib.compress(sr)
# This is supposed to be safe
zl = zl[2:-4]
print urllib.quote_plus(base64.b64encode(zl))