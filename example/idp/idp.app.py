#!/usr/bin/env python

import re
import base64
from cgi import escape, parse_qs
import urllib
#import urlparse

from saml2 import server
from saml2.utils import make_instance, sid, decode_base64_and_inflate
from saml2 import samlp, saml
from saml2.time_util import in_a_while, instant

def authn_response(identity, in_response_to, destination, spid):
    global idp
    resp = idp.do_response(
                        destination,    # consumer_url
                        in_response_to, # in_response_to
                        spid,           # sp_entity_id
                        identity        # identity as dictionary
                    )
    
    return ("%s" % resp).split("\n")
    
# -----------------------------------------------------------------------------
def dict_to_table(ava, lev=0, width=1):
    txt = []
    txt.append('<table border=%s bordercolor="black">\n' % width)
    for prop, valarr in ava.items():
        txt.append("<tr>\n")
        if isinstance(valarr, basestring):
            txt.append("<th>%s</th>\n" % str(prop))
            try:
                txt.append("<td>%s</td>\n" % valarr.encode("utf8"))
            except AttributeError:
                txt.append("<td>%s</td>\n" % valarr)
        elif isinstance(valarr, list):
            i = 0
            n = len(valarr)       
            for val in valarr:
                if i == 0:
                    txt.append("<th rowspan=%d>%s</td>\n" % (len(valarr),prop))
                else:
                    txt.append("<tr>\n")
                if isinstance(val, dict):
                    txt.append("<td>\n")
                    txt.extend(dict_to_table(val, lev+1, width-1))
                    txt.append("</td>\n")
                else:
                    try:
                        txt.append("<td>%s</td>\n" % val.encode("utf8"))
                    except AttributeError:
                        txt.append("<td>%s</td>\n" % val)
                if n > 1:
                    txt.append("</tr>\n")
                n -= 1
                i += 1
        elif isinstance(valarr, dict):
            txt.append("<th>%s</th>\n" % prop)
            txt.append("<td>\n")
            txt.extend(dict_to_table(valarr, lev+1, width-1))
            txt.append("</td>\n")
        txt.append("</tr>\n")
    txt.append('</table>\n')
    return txt
    
REPOZE_ID_EQUIVALENT = "uid"
FORM_SPEC = """<form name="myform" method="post" action="%s">
   <input type="hidden" name="SAMLResponse" value="%s" />
   <input type="hidden" name="RelayState" value="%s" />
</form>"""

def sso(environ, start_response, user, logger):
    """ Supposted to return a POST """
    #edict = dict_to_table(environ)
    logger and logger.info("Environ keys: %s" % environ.keys())
    if "QUERY_STRING" in environ:
        logger and logger.info("Query string: %s" % environ["QUERY_STRING"])
        query = parse_qs(environ["QUERY_STRING"])
    elif "s2repoze.qinfo" in environ:
        query = environ["s2repoze.qinfo"]
    # base 64 encoded request
    (consumer, identifier, policies, 
        spid) = idp.parse_authn_request(query["SAMLRequest"][0])
    spentityid = query["spentityid"][0]
    try:
        relayState = query["RelayState"][0]
    except (KeyError, AttributeError):
        relayState = "/"
    start_response('200 OK', [('Content-Type', 'text/html')])
    identity = dict(environ["repoze.who.identity"]["user"])
    if REPOZE_ID_EQUIVALENT:
        identity[REPOZE_ID_EQUIVALENT] = (
                environ["repoze.who.identity"]['repoze.who.userid'])
    authn_resp = authn_response(identity, identifier, consumer, spid)
    logger and logger.info("AuthNResponse: %s" % authn_resp)
    response = []
    response.append("<head>")
    response.append("<title>SAML 2.0 POST</title>")
    response.append("</head><body>")
    #login_url = location + '?spentityid=' + "lingon.catalogix.se"
    response.append(FORM_SPEC % (consumer, 
                                    base64.b64encode("".join(authn_resp)),"/"))
    response.append("""<script type="text/javascript" language="JavaScript">""")
    response.append("     document.myform.submit();")
    response.append("""</script>""")
    response.append("</body>")
    return response
    
def whoami(environ, start_response, user, logger):
    start_response('200 OK', [('Content-Type', 'text/html')])
    identity = environ["repoze.who.identity"].copy()
    for prop in ["login", "password"]:
        try:
            del identity[prop]
        except KeyError:
            continue
    response = dict_to_table(identity)
    return response[:]
    
def not_found(environ, start_response, logger):
    """Called if no URL matches."""
    start_response('404 NOT FOUND', [('Content-Type', 'text/plain')])
    return ['Not Found']

def not_authn(environ, start_response, logger):
    if "QUERY_STRING" in environ:
        query = parse_qs(environ["QUERY_STRING"])
        logger and logger.info("query: %s" % query)
    start_response('401 Unauthorized', [('Content-Type', 'text/plain')])
    return ['Unknown user']
    
# ----------------------------------------------------------------------------

# map urls to functions
urls = [
    (r'whoami$', whoami),
    (r'whoami/(.*)$', whoami),
    (r'sso$', sso),
    (r'sso/(.*)$', sso),
]

# ----------------------------------------------------------------------------

def application(environ, start_response):
    """
    The main WSGI application. Dispatch the current request to
    the functions from above and store the regular expression
    captures in the WSGI environment as  `myapp.url_args` so that
    the functions from above can access the url placeholders.

    If nothing matches call the `not_found` function.
    
    :param environ: The HTTP application environment
    :param start_response: The application to run when the handling of the 
        request is done
    :return: The response as a list of lines
    """
    user = environ.get("REMOTE_USER", "")
    if not user:
        user = environ.get("repoze.who.identity", "")
            
    path = environ.get('PATH_INFO', '').lstrip('/')
    logger = environ.get('repoze.who.logger')
    logger and logger.info( "<application> PATH: %s" % path)
    for regex, callback in urls:
        if user:
            match = re.search(regex, path)
            if match is not None:
                try:
                    environ['myapp.url_args'] = match.groups()[0]
                except IndexError:
                    environ['myapp.url_args'] = path
                return callback(environ, start_response, user, logger)
        else:
            logger and logger.info("-- No USER --")
            return not_authn(environ, start_response, logger)
    return not_found(environ, start_response, logger)

# ----------------------------------------------------------------------------

from repoze.who.config import make_middleware_with_config

app_with_auth = make_middleware_with_config(application, {"here":"."}, 
                        './who.ini', log_file="idpapp.log")

# ----------------------------------------------------------------------------

if __name__ == '__main__':
    import sys
    from wsgiref.simple_server import make_server
    import logging
    LOG_FILENAME = "./idp.log"
    PORT = 8088
    
    logging.basicConfig(filename=LOG_FILENAME,level=logging.DEBUG)    
    
    idp = server.Server(sys.argv[1], logging)
    srv = make_server('localhost', PORT, app_with_auth)
    print "listening on port: %s" % PORT
    srv.serve_forever()