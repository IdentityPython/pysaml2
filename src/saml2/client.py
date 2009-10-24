import os
import urllib
import saml2
import base64
import time
try:
    from hashlib import md5
except ImportError:
    from md5 import md5
import zlib

from saml2 import samlp, saml
from saml2.sigver import correctly_signed_response
from saml2.soap import SOAPClient

DEFAULT_BINDING = saml2.BINDING_HTTP_REDIRECT

FORM_SPEC = """<form method="post" action="%s">
   <input type="hidden" name="SAMLRequest" value="%s" />
   <input type="hidden" name="RelayState" value="%s" />
   <input type="submit" value="Submit" />
</form>"""

LAX = True

def _sid(seed=""):
    """The hash of the server time + seed makes an unique SID for each session.
    """
    sid = md5()
    sid.update(repr(time.time()))
    if seed:
        sid.update(seed)
    return sid.hexdigest()

def get_date_and_time(base=None):
    if base is None:
        base = time.time()
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(base))
    
class Saml2Client:
    
    def __init__(self, environ, session=None, service_url=None, metadata=None,
                    xmlsec_binary=None):
        self.session = session or {}
        self.environ = environ
        self.metadata = metadata
        self.xmlsec_binary = xmlsec_binary

    def _init_request(self, request, destination):
        #request.id = _sid()
        request.version = "2.0"
        request.issue_instant = get_date_and_time()
        request.destination = destination
        return request        

    def create_authn_request(self, query_id, destination, service_url,
                                requestor, my_name, sp_name_qualifier=None):
        """ Creates an Authenication Request
        
        :param query_id: Query identifier
        :param destination: Where to send the request
        :param service_url: The page to where the response MUST be sent.
        :param requestor: My official name
        :param my_name: Who I am
        :param sp_name_qualifier: The domain in which the name should be
            valid
        
        :return: An authentication request
        """
        
        authn_request = self._init_request(samlp.AuthnRequest(query_id),
                                            destination)

        authn_request.assertion_consumer_service_url = service_url
        authn_request.protocol_binding = saml2.BINDING_HTTP_POST
        authn_request.provider_name = my_name

        name_id_policy = samlp.NameIDPolicy()
        name_id_policy.allow_create = 'true'
        if sp_name_qualifier:
            name_id_policy.format = saml.NAMEID_FORMAT_PERSISTENT
            name_id_policy.sp_name_qualifier = sp_name_qualifier
        else:
            name_id_policy.format = saml.NAMEID_FORMAT_TRANSIENT


        authn_request.name_id_policy = name_id_policy
        authn_request.issuer = saml.Issuer(text=requestor)
        
        return authn_request
           
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
                (identity, came_from) = self.verify_response(
                                            saml_response, requestor, 
                                            outstanding, log)
            #relay_state = post["RelayState"].value
            return (identity, came_from)
        else:
            return None
            
    def authenticate(self, spentityid, location="", service_url="", 
                        requestor="", my_name="", relay_state="",
                        binding=saml2.BINDING_HTTP_REDIRECT):
        """ Either verifies an authentication Response or if none is present
        send an authentication request.
        
        :param spentityid: The SP EntityID
        :param binding: How the authentication request should be sent to the 
            IdP
        :param location: Where the IdP is.
        :param service_url: The service URL
        :param requestor: Issuer of the AuthN request
        :param my_name: The providers name
        :param relay_state: To where the user should be returned after 
            successfull log in.
        :return: AuthnRequest reponse
        """
        
        sid = _sid()
        authen_req = "%s" % self.create_authn_request(sid, location, 
                                service_url, requestor, my_name)
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
            
    def verify_response(self, xml_response, requestor, outstanding=None, 
                log=None, decode=True ):
        """ Verify a response
        
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
        
        response = correctly_signed_response(decoded_xml, self.xmlsec_binary)
        if not response:
            log and log.error("Response was not correctly signed")
            print "Response was not correctly signed"
            return ({}, "")

        log and log.info("response: %s" % (response,))
        print response
        try:
            (ava, name_id, came_from) = self.do_response(response, 
                                                requestor, outstanding, log)
        except AttributeError, exc:
            log and log.error("AttributeError: %s" % (exc,))
            return ({}, "")
        except Exception, exc:
            log and log.error("Exception: %s" % (exc,))
                                    
        # should return userid and attribute value assertions
        ava["__userid"] = name_id
        return (ava, came_from)
  
    def do_response(self, response, requestor, outstanding=None, 
                            log=None):
        """
        Parse a response, verify that it is a response for me and
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
            if status.status_code.value != samlp.STATUS_SUCCESS:
                raise Exception(
                    "Not successfull according to status code: %s" % \
                    status.status_code.value)
            
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

    def create_attribute_request(self, sid, subject_id, destination, 
            attribute=None, sp_name_qualifier=None, name_qualifier=None):
        """ Constructs an AttributeQuery 
        
        :param subject_id: The identifier of the subject
        :param destination: To whom the query should be sent
        :param attribute: A dictionary of attributes and values that is asked for
        :param sp_name_qualifier: The unique identifier of the 
            service provider or affiliation of providers for whom the 
            identifier was generated.
        :param name_qualifier: The unique identifier of the identity 
            provider that generated the identifier.
        :return: An AttributeQuery instance
        """
        
        attr_query = self._init_request(samlp.AttributeQuery(sid), 
                                        destination)
        
        subject = saml.Subject()
        name_id = saml.NameID()
        name_id.format = saml.NAMEID_FORMAT_PERSISTENT
        if name_qualifier:
            name_id.name_qualifier = name_qualifier
        if sp_name_qualifier:
            name_id.sp_name_qualifier = sp_name_qualifier
        name_id.text = subject_id
        subject.name_id = name_id
        
        attr_query.subject = subject

        if attribute:
            attrs = []
            for attr, values in attribute.items():
                sattr = saml.Attribute()
                sattr.name = attr
                #sattr.name_format = NAME_FORMAT_UNSPECIFIED
                if values:
                    aval = [saml.AttributeValue(text=val) for val in values]
                    sattr.attribute_value = aval
                attrs.append(sattr)
                    
            attr_query.attribute = attrs
        
        return attr_query
    
    def attribute_request(self, subject_id, destination, attribute=None,
                sp_name_qualifier=None, name_qualifier=None, log=None):
        """ Does a attribute request from an attribute authority

        :param subject_id: The identifier of the subject
        :param destination: To whom the query should be sent
        :param attribute: A dictionary of attributes and values that is asked for
        :param sp_name_qualifier: The unique identifier of the 
            service provider or affiliation of providers for whom the 
            identifier was generated.
        :param name_qualifier: The unique identifier of the identity 
            provider that generated the identifier.
        :return: The attributes returned
        """
        
        sid = _sid()
        request = self.create_attribute_request(sid, subject_id, destination,
                    attribute, sp_name_qualifier, name_qualifier )
        
        soapclient = SOAPClient(destination)
        try:
            response = soapclient.send(request)
            if response:
                (identity, came_from) = verify_response(response, requestor,
                                                    outstanding={sid:""}, 
                                                    log=log, decode=True)
                return identity
            else:
                return None
        except Exception, e:
            log and log.info("Exception caught: %s" % (e,))
            return None
        
    def make_logout_request(self, subject_id, reason=None, 
                not_on_or_after=None):
        """ Constructs an LogoutRequest

        :param subject_id: The identifier of the subject
        :param reason: An indication of the reason for the logout, in the 
            form of a URI reference.
        :param not_on_or_after: The time at which the request expires, 
            after which the recipient may discard the message.
        :return: An AttributeQuery instance
        """

        logout_req = self._init_request(samlp.LogoutRequest())
        logout_req.session_index = _sid()
        logout_req.base_id = saml.BaseID(text=subject_id)
        if reason:
            logout_req.reason = reason
        if not_on_or_after:
            logout_req.not_on_or_after = not_on_or_after
            
        return logout_req
        
    def logout(self, subject_id, reason=None, not_on_or_after=None):
        logout_req = self.make_logout_request(subject_id, reason,
                        not_on_or_after)
        
# ----------------------------------------------------------------------

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
    
