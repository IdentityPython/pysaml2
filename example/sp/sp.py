#!/usr/bin/env python

import re
from cgi import parse_qs
from saml2 import BINDING_HTTP_REDIRECT

# -----------------------------------------------------------------------------
def dict_to_table(ava, lev=0, width=1):
    txt = ['<table border=%s bordercolor="black">\n' % width]
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
                if not i:
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


#noinspection PyUnusedLocal
def whoami(environ, start_response, user, logger):
    identity = environ["repoze.who.identity"]["user"]
    if not identity:
        return not_authn(environ, start_response)
    response = ["<h2>Your identity are supposed to be</h2>"]
    response.extend(dict_to_table(identity))
    response.extend("<a href='logout'>Logout</a>")
    start_response('200 OK', [('Content-Type', 'text/html')])
    return response[:]
    
#noinspection PyUnusedLocal
def not_found(environ, start_response):
    """Called if no URL matches."""
    start_response('404 NOT FOUND', [('Content-Type', 'text/plain')])
    return ['Not Found']

#noinspection PyUnusedLocal
def not_authn(environ, start_response):
    start_response('401 Unauthorized', [('Content-Type', 'text/plain')])
    return ['Unknown user']

#noinspection PyUnusedLocal
def slo(environ, start_response, user, logger):
    # so here I might get either a LogoutResponse or a LogoutRequest
    client = environ['repoze.who.plugins']["saml2auth"]
    sids = None
    if "QUERY_STRING" in environ:
        query = parse_qs(environ["QUERY_STRING"])
        if logger:
            logger.info("query: %s" % query)
        try:
            (sids, code, head, message) = client.saml_client.logout_response(
                                                query["SAMLResponse"][0],
                                                log=logger,
                                                binding=BINDING_HTTP_REDIRECT)
            logger.info("LOGOUT reponse parsed OK")
        except KeyError:
            # return error reply
            pass
    
    if not sids:
        start_response("302 Found", [("Location", "/done")])
        return ["Successfull Logout"]
    
#noinspection PyUnusedLocal
def logout(environ, start_response, user, logger):
    client = environ['repoze.who.plugins']["saml2auth"]
    subject_id = environ["repoze.who.identity"]['repoze.who.userid']
    logger.info("[logout] subject_id: '%s'" % (subject_id,))
    target = "/done"
    # What if more than one
    tmp = client.saml_client.global_logout(subject_id, log=logger, 
                                            return_to=target)
    logger.info("[logout] global_logout > %s" % (tmp,))
    (session_id, code, header, result) = tmp

    if session_id:
        start_response(code, header)
        return result
    else: # All was done using SOAP
        if result: 
            start_response("302 Found", [("Location", target)])
            return ["Successfull Logout"]
        else:
            start_response("500 Internal Server Error")
            return ["Failed to logout from identity services"]

#noinspection PyUnusedLocal
def done(environ, start_response, user, logger):
    # remove cookie and stored info
    logger.info("[done] environ: %s" % environ)
    subject_id = environ["repoze.who.identity"]['repoze.who.userid']
    client = environ['repoze.who.plugins']["saml2auth"]
    logger.info("[logout done] remaining subjects: %s" % (
                                        client.saml_client.users.subjects(),))

    start_response('200 OK', [('Content-Type', 'text/html')])
    return ["<h3>You are now logged out from this service</h3>"]
        
# ----------------------------------------------------------------------------

# map urls to functions
urls = [
    (r'whoami$', whoami),
    (r'logout$', logout),
    (r'done$', done),
    (r'slo$', slo),
    (r'^$', whoami),
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
    if logger:
        logger.info( "<application> PATH: %s" % path)
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
             return not_authn(environ, start_response)
    return not_found(environ, start_response)

# ----------------------------------------------------------------------------

from repoze.who.config import make_middleware_with_config

app_with_auth = make_middleware_with_config(application, {"here":"."}, 
                        './who.ini', log_file="sp.log")

# ----------------------------------------------------------------------------
PORT = 8087

if __name__ == '__main__':
    from wsgiref.simple_server import make_server
    srv = make_server('localhost', PORT, app_with_auth)
    print "SP listening on port: %s" % PORT
    srv.serve_forever()