import os
import urllib
import saml2
import base64
import time
import hashlib
import zlib

from saml2 import samlp, saml
from saml2.utils import create_id
    
DEFAULT_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"

FORM_SPEC = """<form method="post" action="%s">
   <input type="hidden" name="SAMLRequest" value="%s" />
   <input type="hidden" name="RelayState" value="%s" />
   <input type="submit" value="Submit" />
</form>"""

def _sid(seed=""):
    """The hash of the server time + seed makes an unique SID for each session.
    """
    sid = hashlib.md5()
    sid.update(repr(time.time()))
    if seed:
        sid.update(seed)
    return sid.hexdigest()

#form = cgi.FieldStorage()

class Saml2Client:
    
    def __init__(self, environ, session=None, service_url=None):
        self.session = session or {}
        self.environ = environ

    def create_authn_request(self, query_id, destination, position,
                                requestor, my_name):
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
        authn_request.provider_name = my_name

        name_id_policy = samlp.NameIDPolicy()
        name_id_policy.format = saml.NAMEID_FORMAT_EMAILADDRESS
        name_id_policy.sp_name_qualifier = saml.NAMEID_FORMAT_PERSISTENT
        name_id_policy.allow_create = 'true'

        authn_request.name_id_policy = name_id_policy
        authn_request.issuer = saml.Issuer(text=requestor)
        
        return "%s" % authn_request
           
    def _compress_and_encode(self, packet):
        """ Information packets must be compressed and base64 encoded before 
        sent.
        Due to the fact that zlib adds a zlib header/tail (RFC1950), those has
        to be remove before the packet can be base64 encoded. Using [2:-4] is 
        supposedly safe.
        
        :param packet: The information that should be compressed and encoded
        :returns: compressed and encoded information
        """
        return base64.b64encode(zlib.compress(packet)[2:-4])
        
    def response(self, post, requestor, outstanding, log=None):
        
        # If the request contains a samlResponse, try to validate it
        if post.has_key("SAMLResponse"):
            saml_response =  post['SAMLResponse'].value
            if saml_response:
                identity = self.verify(saml_response, requestor, outstanding, 
                                        log)
                # relay_state = self.environ.get("RelayState", "")
                # if not relay_state:
                #     relay_state = self.environ.keys()
                return identity
        else:
            return None
            
    def authenticate(self, spentityid, location="", position="", requestor="",
                        my_name="", binding=saml2.BINDING_HTTP_REDIRECT):
        """ Either verifies an authentication Response or if none is present
        send an authentication request.
        
        :param binding: How the authentication request should be sent to the 
            IdP
        :param location: Where the IdP is.
        :return: response
        """
        
        sid = create_id()
        authen_req = self.create_authn_request(sid, location, position, 
                            requestor, my_name)
        if binding == saml2.BINDING_HTTP_POST:
            # No valid ticket; Send a form to the client
            # THIS IS NOT TO BE USED RIGHT NOW
            response = []
            response.append("<head>")
            response.append("""<title>SAML 2.0 POST</title>""")
            response.append("</head><body>")
            #login_url = location + '?spentityid=' + "lingon.catalogix.se"
            response.append(FORM_SPEC % (location, base64.b64encode(authen_req),
                                os.environ['REQUEST_URI']))
            response.append("""<script type="text/javascript">""")
            response.append("     window.onload = function ()")
            response.append(" { document.forms[0].submit(); ")
            response.append("""</script>""")
            response.append("</body>")
        elif binding == saml2.BINDING_HTTP_REDIRECT:
            query = "&".join([
                        "RelayState=%s" % urllib.quote_plus(
                                            self.environ.get('REQUEST_URI','')),
                        "SAMLRequest=%s" % urllib.quote_plus(
                                            self._compress_and_encode(
                                                authen_req)),
                        "spentityid=%s" % spentityid
                    ])
            login_url = "?".join([location, query])
            response = ('Location', login_url)
        else:
            raise Exception("Unkown binding type: %s" % binding)
        return (sid, response)
            
    def verify(self, xml_response, requestor, outstanding, log=None ):
        """ Verify a authentication response
        
        :param xml_response: The response as a XML string
        :param requestor: The hostname of the machine
        :param outstanding: A collection of outstanding authentication requests
        :return: An identity description
        """
        response = samlp.response_from_string(base64.b64decode(xml_response))
        # get list of subjectConfirmationData
        
        log and log.info("response: %s" % (response,))
        try:
            (ava, name_id) = self.do_response(response, requestor, outstanding, 
                                                log)
        except AttributeError, exc:
            log and log.error("AttributeError: %s" % (exc,))
            return {}
        except Exception, exc:
            log and log.error("Exception: %s" % (exc,))
                                    
        # should return userid and attribute value assertions
        identity = {}
        identity["login"] = name_id
        identity["password"] = ""
        identity['repoze.who.userid'] = name_id
        identity.update(ava)
        return identity
  
    def do_response(self, response, requestor, outstanding, log=None):
        """
        Parse a authentication response, verify that it is a response for me and
        expected by me and that it is correct.

        :param response: The response as a structure
        :param requestor: The host (me) that asked for a AuthN response
        :param outstanding: A dictionary with IdPs as keys and 2-tuples of 
            session IDs and request URIs.
        :result: A 2-tuple with attribute value assertions as a dictionary and
            the NameID
        """
        
        log and log.info( "Outstanding: %s" % outstanding)
        log and log.info( "In response to: %s" % (response.in_response_to,))
        log and log.info( "Destination: %s" % (response.destination,))
        
        # MUST contain *one* assertion
        assert len(response.assertion) == 1
        assertion = response.assertion[0]

        if response.status:
            status = response.status
            if status.status_code.value != "urn:oasis:names:tc:SAML:2.0:status:Success":
                raise Exception("Not successfull according to status code")
            
        if response.issuer:
            issuer = response.issuer.text.strip()
            if issuer not in outstanding:
                raise Exception("A response from someone I didn't ask for one")
            else:
                tup = (response.in_response_to, response.destination)
                if tup not in outstanding[issuer]:
                    raise Exception(
                        "Combination of session id and requestURI " +
                        "in Issuer I don't recall")
                
        # the assertion MUST contain one AuthNStatement
        assert len(assertion.authn_statement) == 1
        authn_statement = assertion.authn_statement[0]
        # check authn_statement.session_index

        # The assertion can contain zero or one attributeStatements
        assert len(assertion.attribute_statement) <= 1
        if assertion.attribute_statement:
            ava = get_attribute_values(assertion.attribute_statement[0])
        else:
            ava = {}

        log and log.info("AVA: %s" % (ava,))

        # The assertion must contain a Subject
        assert assertion.subject
        subject = assertion.subject
        subject_confirmation = subject.subject_confirmation
        data = subject_confirmation.subject_confirmation_data
        tup = (data.recipient, data.in_response_to)
        if tup in outstanding[issuer]:
            outstanding[issuer].remove(tup)
        else:
            raise Exception("Combination of session id and requestURI I don't recall")
        
        # The subject must contain a name_id
        assert subject.name_id
        name_id = subject.name_id.text.strip()

        log and log.info("NameID: %s" % (name_id,))

        # The Identity Provider MUST include a <saml:Conditions> element
        #print "Conditions",assertion.conditions
        assert assertion.conditions
        condition = assertion.conditions
        now = time.gmtime()
        if time.strptime(condition.not_on_or_after, TIME_FORMAT) < now:
            # To old ignore
            log and log.info("To old: %s" % condition.not_on_or_after)
            return None
        if not for_me(condition, requestor):
            log and log.info("Not for me!!!")
            return None        # # verify signature

        return (ava, name_id)


#2009-07-05T15:35:29Z
TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

def for_me(condition, myself ):
    for restriction in condition.audience_restriction:
        audience = restriction.audience
        if audience.text.strip() == myself:
            return True

def get_attribute_values(attribute_statement):
    """ Get the attributes and the attribute values 
    
    :param response: The AttributeStatement.
    :return: A dictionary containing attributes and values
    """
    
    result = {}
    for attribute in attribute_statement.attribute:
        # Check name_format ??
        name = attribute.name.strip()
        result[name] = []
        for value in attribute.attribute_value:
            result[name].append(value.text.strip())
    return result

ROW = """<tr><td>%s</td><td>%s</td></tr>"""

def _print_statement(statem):
    """ Print a statement as a HTML table """
    txt = ["""<table border="1">"""]
    for key, val in statem.__dict__.items():
        if key.startswith("_"):
            continue
        else:
            if isinstance(val, basestring):
                txt.append(ROW % (key, val))
            elif isinstance(val, list):
                for value in val:
                    if isinstance(val, basestring):
                        txt.append(ROW % (key, val))
                    elif isinstance(value, saml2.SamlBase):
                        txt.append(ROW % (key, _print_statement(value)))
            elif isinstance(val, saml2.SamlBase):
                txt.append(ROW % (key, _print_statement(val)))
            else:
                txt.append(ROW % (key, val))
                
    txt.append("</table>")
    return "\n".join(txt)

def _print_statements(states):
    """ Print a list statement as HTML tables """
    txt = []
    for stat in states:
        txt.append(_print_statement(stat))
    return "\n".join(txt)

def print_response(resp):
    print _print_statement(resp)
    print resp.to_string()
    
