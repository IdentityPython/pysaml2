import urllib
from urlparse import urlparse, parse_qs
from saml2.client_base import IDPDISC_POLICY

__author__ = 'rolandh'

def discovery_service_request_url(entity_id, disc_url, return_url="",
                                  policy="", returnIDParam="",
                                  is_passive=False ):
    """
    Created the HTTP redirect URL needed to send the user to the
    discovery service.

    :param disc_url: The URL of the discovery service
    :param return_url: The discovery service MUST redirect the user agent
        to this location in response to this request
    :param policy: A parameter name used to indicate the desired behavior
        controlling the processing of the discovery service
    :param returnIDParam: A parameter name used to return the unique
        identifier of the selected identity provider to the original
        requester.
    :param is_passive: A boolean value of "true" or "false" that controls
        whether the discovery service is allowed to visibly interact with
        the user agent.
    :return: A URL
    """
    pdir = {"entityID": entity_id}
    if return_url:
        pdir["return"] = return_url
    if policy and policy != IDPDISC_POLICY:
        pdir["policy"] = policy
    if returnIDParam:
        pdir["returnIDParam"] = returnIDParam
    if is_passive:
        pdir["is_passive"] = "true"

    params = urllib.urlencode(pdir)
    return "%s?%s" % (disc_url, params)

def discovery_service_response(query="", url="", returnIDParam=""):
    """
    Deal with the response url from a Discovery Service

    :param url: the url the user was redirected back to
    :param returnIDParam: This is where the identifier of the IdP is
        place if it was specified in the query as not being 'entityID'
    :return: The IdP identifier or "" if none was given
    """

    if url:
        part = urlparse(url)
        qsd = parse_qs(part[4])
    elif query:
        qsd = parse_qs(query)
    else:
        qsd = {}

    if returnIDParam:
        try:
            return qsd[returnIDParam][0]
        except KeyError:
            return ""
    else:
        try:
            return qsd["entityID"][0]
        except KeyError:
            return ""