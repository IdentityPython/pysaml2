import os
import urllib
import saml2
import base64
import time
import hashlib
import zlib

from saml2 import samlp, saml
from saml2.utils import create_id, verify_xml_with_manager
from saml2.metadata import cert_from_assertion
from saml2.metadata import load_certs_to_manager

DEFAULT_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"

FORM_SPEC = """<form method="post" action="%s">
   <input type="hidden" name="SAMLRequest" value="%s" />
   <input type="hidden" name="RelayState" value="%s" />
   <input type="submit" value="Submit" />
</form>"""

LAX = True

def _sid(seed=""):
    """The hash of the server time + seed makes an unique SID for each session.
    """
    sid = hashlib.md5()
    sid.update(repr(time.time()))
    if seed:
        sid.update(seed)
    return sid.hexdigest()

def correctly_signed_response(decoded_xml, import_mngr=None):
    response = samlp.response_from_string(decoded_xml)
    verified = False

        # Try to find the signing cert in the assertion
    for assertion in response.assertion:
        if not import_mngr:
            mngr = load_certs_to_manager(cert_from_assertion(assertion))
        else:
            mngr = import_mngr
            
        #print assertion
        #xml_file_pointer, xml_file = make_temp("%s" % assertion)

        verified = verify_xml_with_manager(mngr, "%s" % assertion)
        if not import_mngr:
            mngr.destroy()
        if verified:
            break

            # verify signature
            #key_file_pointer, key_file = make_temp(cert,".der")
            #verified = verify_xml("%s" % assertion, key_file)
            #key_file_pointer.close()
        
        #xml_file_pointer.close()
    
    if verified:
        return response
    else:
        return None
    
#form = cgi.FieldStorage()

class Saml2Client:
    
    def __init__(self, environ, session=None, service_url=None):
        self.session = session or {}
        self.environ = environ

    def create_authn_request(self, query_id, destination, service_url,
                                requestor, my_name):
        """ Creates an Authenication Request
        
        :param query_id: Query identifier
        :param destination: Where to send the request
        :param position: The page to where the user should be sent afterwards.
        :param provider: Who I am 
        
        :return: A string representation of the authentication request
        """
        authn_request = samlp.AuthnRequest(query_id)
        authn_request.assertion_consumer_service_url = service_url
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
        """ Deal with the AuthnResponse
        
        :param post: The reply as a cgi.FieldStorage instance
        :param requestor: The issuer of the AuthN request
        :param outstanding: A dictionary with session IDs as keys and 
            the original web request from the user before redirection
            as values.
        :param log: where loggin should go.
        :return: A 2-tuple of identity information (in the form of a 
            dictionary) and where the user should really be sent. This
            might differ from what the IdP thinks since I don't want
            to reveal verything to it and it might not trust me.
        """
        # If the request contains a samlResponse, try to validate it
        if post.has_key("SAMLResponse"):
            saml_response =  post['SAMLResponse'].value
            if saml_response:
                (identity, came_from) = self.verify(saml_response, requestor, 
                                                    outstanding, log)
            #relay_state = post["RelayState"].value
            return (identity, came_from)
        else:
            return None
            
    def authenticate(self, spentityid, location="", position="", requestor="",
                        my_name="", relay_state="",
                        binding=saml2.BINDING_HTTP_REDIRECT):
        """ Either verifies an authentication Response or if none is present
        send an authentication request.
        
        :param spentityid: The SP EntityID
        :param binding: How the authentication request should be sent to the 
            IdP
        :param location: Where the IdP is.
        :param position: The service URL
        :param requestor: Issuer of the AuthN request
        :param my_name: The providers name
        :param relay_state: To where the user should be returned after 
            successfull log in.
        :return: AuthnRequest reponse
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
            lista = ["SAMLRequest=%s" % urllib.quote_plus(
                                self._compress_and_encode(
                                    authen_req)),
                    "spentityid=%s" % spentityid]
            if relay_state:
                lista.append("RelayState=%s" % relay_state)
            login_url = "?".join([location, "&".join(lista)])
            response = ('Location', login_url)
        else:
            raise Exception("Unkown binding type: %s" % binding)
        return (sid, response)
            
    def verify(self, xml_response, requestor, outstanding=None, log=None, 
                decode=True ):
        """ Verify a authentication response
        
        :param xml_response: The response as a XML string
        :param requestor: The hostname of the machine
        :param outstanding: A collection of outstanding authentication requests
        :param log: Where logging information should be sent
        :param decode: There for testing purposes
        :return: A 2-tuple consisting of an identity description and the 
            real relay-state
        """

        if not outstanding:
            outstanding = {}
        
        if decode:
            decoded_xml = base64.b64decode(xml_response)
        else:
            decoded_xml = xml_response
        
        response = correctly_signed_response(decoded_xml)
        if not response:
            log and log.error("Response was not correctly signed")
            return ({}, "")
            
        log and log.info("response: %s" % (response,))
        try:
            (ava, name_id, came_from) = self.do_response(response, requestor, 
                                                outstanding, log)
        except AttributeError, exc:
            log and log.error("AttributeError: %s" % (exc,))
            return ({}, "")
        except Exception, exc:
            log and log.error("Exception: %s" % (exc,))
                                    
        # should return userid and attribute value assertions
        ava["__userid"] = name_id
        return (ava, came_from)
  
    def do_response(self, response, requestor, outstanding=None, log=None):
        """
        Parse a authentication response, verify that it is a response for me and
        expected by me and that it is correct.

        :param response: The response as a structure
        :param requestor: The host (me) that asked for a AuthN response
        :param outstanding: A dictionary with session ids as keys and request 
            URIs as values.
        :result: A 2-tuple with attribute value assertions as a dictionary and
            the NameID
        """

        if not outstanding:
            outstanding = {}
                
        # MUST contain *one* assertion
        assert len(response.assertion) == 1
        assertion = response.assertion[0]

        if response.status:
            status = response.status
            if status.status_code.value != samlp.SAMLP_NAMESPACE:
                raise Exception("Not successfull according to status code")
            
        if response.in_response_to:
            if response.in_response_to in outstanding:
                came_from = outstanding[response.in_response_to]
            elif LAX:
                came_from = ""
            else:
                raise Exception("Session id I don't recall using")
                
        # the assertion MUST contain one AuthNStatement
        assert len(assertion.authn_statement) == 1
        # authn_statement = assertion.authn_statement[0]
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
        for subject_confirmation in subject.subject_confirmation:
            data = subject_confirmation.subject_confirmation_data
            if data.in_response_to in outstanding:
                came_from = outstanding[data.in_response_to]
                del outstanding[data.in_response_to]
            elif LAX:
                came_from = ""
            else:
                raise Exception(
                    "Combination of session id and requestURI I don't recall")
        
        # The subject must contain a name_id
        assert subject.name_id
        name_id = subject.name_id.text.strip()

        # The Identity Provider MUST include a <saml:Conditions> element
        #print "Conditions",assertion.conditions
        assert assertion.conditions
        condition = assertion.conditions
        now = time.gmtime()
        if time.strptime(condition.not_on_or_after, TIME_FORMAT) < now:
            # To old ignore
            if not LAX:
                log and log.info("To old: %s" % condition.not_on_or_after)
                return None
        if not for_me(condition, requestor):
            if not LAX:
                log and log.info("Not for me!!!")
                return None        # # verify signature
            
        return (ava, name_id, came_from)


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
    
