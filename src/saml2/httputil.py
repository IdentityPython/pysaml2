__author__ = 'rohe0002'

import cgi
from urllib import quote

class Response(object):
    _template = None
    _status = '200 OK'
    _content_type = 'text/html'
    _mako_template = None
    _mako_lookup = None

    def __init__(self, message=None, **kwargs):
        self.status = kwargs.get('status', self._status)
        self.response = kwargs.get('response', self._response)
        self.template = kwargs.get('template', self._template)
        self.mako_template = kwargs.get('mako_template', self._mako_template)
        self.mako_lookup = kwargs.get('template_lookup', self._mako_lookup)

        self.message = message

        self.headers = kwargs.get('headers', [])
        _content_type = kwargs.get('content', self._content_type)
        self.headers.append(('Content-type', _content_type))

    def __call__(self, environ, start_response, **kwargs):
        start_response(self.status, self.headers)
        return self.response(self.message or geturl(environ), **kwargs)

    def _response(self, message="", **argv):
        if self.template:
            return [self.template % message]
        elif self.mako_lookup and self.mako_template:
            argv["message"] = message
            mte = self.mako_lookup.get_template(self.mako_template)
            return [mte.render(**argv)]
        else:
            return [message]

class Created(Response):
    _status = "201 Created"

class Redirect(Response):
    _template = '<html>\n<head><title>Redirecting to %s</title></head>\n' \
        '<body>\nYou are being redirected to <a href="%s">%s</a>\n' \
        '</body>\n</html>'
    _status = '302 Found'

    def __call__(self, environ, start_response):
        location = self.message
        self.headers.append(('location', location))
        start_response(self.status, self.headers)
        return self.response((location, location, location))

class SeeOther(Response):
    _template = '<html>\n<head><title>Redirecting to %s</title></head>\n' \
        '<body>\nYou are being redirected to <a href="%s">%s</a>\n' \
        '</body>\n</html>'
    _status = '303 See Other'

    def __call__(self, environ, start_response):
        location = self.message
        self.headers.append(('location', location))
        start_response(self.status, self.headers)
        return self.response((location, location, location))

class Forbidden(Response):
    _status = '403 Forbidden'
    _template = "<html>Not allowed to mess with: '%s'</html>"

class BadRequest(Response):
    _status = "400 Bad Request"
    _template = "<html>%s</html>"

class Unauthorized(Response):
    _status = "401 Unauthorized"
    _template = "<html>%s</html>"

class NotFound(Response):
    _status = '404 NOT FOUND'

class NotAcceptable(Response):
    _status = '406 Not Acceptable'

class ServiceError(Response):
    _status = '500 Internal Service Error'

def extract(environ, empty=False, err=False):
    """Extracts strings in form data and returns a dict.

    :param environ: WSGI environ
    :param empty: Stops on empty fields (default: Fault)
    :param err: Stops on errors in fields (default: Fault)
    """
    formdata = cgi.parse(environ['wsgi.input'], environ, empty, err)
    # Remove single entries from lists
    for key, value in formdata.iteritems():
        if len(value) == 1:
            formdata[key] = value[0]
    return formdata

def geturl(environ, query=True, path=True):
    """Rebuilds a request URL (from PEP 333).

    :param query: Is QUERY_STRING included in URI (default: True)
    :param path: Is path included in URI (default: True)
    """
    url = [environ['wsgi.url_scheme'] + '://']
    if environ.get('HTTP_HOST'):
        url.append(environ['HTTP_HOST'])
    else:
        url.append(environ['SERVER_NAME'])
        if environ['wsgi.url_scheme'] == 'https':
            if environ['SERVER_PORT'] != '443':
                url.append(':' + environ['SERVER_PORT'])
        else:
            if environ['SERVER_PORT'] != '80':
                url.append(':' + environ['SERVER_PORT'])
    if path:
        url.append(getpath(environ))
    if query and environ.get('QUERY_STRING'):
        url.append('?' + environ['QUERY_STRING'])
    return ''.join(url)

def getpath(environ):
    """Builds a path."""
    return ''.join([quote(environ.get('SCRIPT_NAME', '')),
        quote(environ.get('PATH_INFO', ''))])
