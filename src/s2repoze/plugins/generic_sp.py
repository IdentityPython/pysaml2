#
"""
A plugin that allows you to use SAML2 SSO as authentication
and SAML2 attribute aggregations as metadata collector in your
WSGI application.

"""
import cgi
import logging
import sys
import platform
import shelve
import traceback
import memcache
import saml2
from urlparse import parse_qs, urlparse
from saml2.md import Extensions
import xmldsig as ds

from StringIO import StringIO

from paste.httpexceptions import HTTPSeeOther, HTTPRedirection
from paste.httpexceptions import HTTPNotImplemented
from paste.httpexceptions import HTTPInternalServerError
from paste.request import parse_dict_querystring
from paste.request import construct_url
from saml2.extension.pefim import SPCertEnc
from saml2.httputil import SeeOther
from saml2.client_base import ECP_SERVICE
from zope.interface import implements

from repoze.who.interfaces import IChallenger, IIdentifier, IAuthenticator
from repoze.who.interfaces import IMetadataProvider

from saml2 import ecp, BINDING_HTTP_REDIRECT, element_to_extension_element
from saml2 import BINDING_HTTP_POST

from saml2.client import Saml2Client
from saml2.ident import code, decode
from saml2.s_utils import sid
from saml2.config import config_factory
from saml2.profile import paos

# from saml2.population import Population
#from saml2.attribute_resolver import AttributeResolver

logger = logging.getLogger(__name__)

PAOS_HEADER_INFO = 'ver="%s";"%s"' % (paos.NAMESPACE, ECP_SERVICE)
CERT_STORE_KEY = 'OUTSTANDING_CERTS'
QUERY_STORE_KEY = 'OUTSTANDING_QUERIES'

def construct_came_from(environ):
	""" The URL that the user used when the process where interupted
	for single-sign-on processing. """
	came_from = environ.get("PATH_INFO")
	qstr = environ.get("QUERY_STRING", "")
	if qstr:
		came_from += '?' + qstr
	return came_from


def exception_trace(tag, exc, log):
	message = traceback.format_exception(*sys.exc_info())
	logger.error("[%s] ExcList: %s" % (tag, "".join(message),))
	logger.error("[%s] Exception: %s" % (tag, exc))


class ECP_response(object):
	code = 200
	title = 'OK'

	def __init__(self, content):
		self.content = content

	#noinspection PyUnusedLocal
	def __call__(self, environ, start_response):
		start_response('%s %s' % (self.code, self.title),
					   [('Content-Type', "text/xml")])
		return [self.content]


class SAML2GenericPlugin(object):
	implements(IChallenger, IIdentifier, IAuthenticator, IMetadataProvider)

	def __init__(self, rememberer_name, config, saml_client, wayf, cache,
				 sid_store=None, sid_store_type=None, discovery="", idp_query_param="",
				 sid_store_cert=None, sid_store_cert_type=None):
		self.rememberer_name = rememberer_name
		self.wayf = wayf
		self.saml_client = saml_client
		self.conf = config
		self.cache = cache
		self.discosrv = discovery
		self.idp_query_param = idp_query_param
		self.sid_store_type = (sid_store_type or 'local').lower()
		self.sid_store_cert_type = (sid_store_cert_type or 'local').lower()
		self.logout_endpoints = [urlparse(ep)[2] for ep in config.endpoint(
			"single_logout_service")]
		try:
			self.metadata = self.conf.metadata
		except KeyError:
			self.metadata = None
		if sid_store:
			if self.sid_store_type == 'memcache':
				self.outstanding_query_store = memcache.Client([sid_store], debug=0)
			else:
				self.outstanding_query_store = shelve.open(sid_store, writeback=True)
		else:
			self.outstanding_queries = {}
		if sid_store_cert:
			if self.sid_store_cert_type == 'memcache':
				self.outstanding_cert_store = memcache.Client([sid_store_cert], debug=0)
			else:
				self.outstanding_cert_store = shelve.open(sid_store_cert, writeback=True)
		else:
			self.outstanding_cert_store = {}

		self.iam = platform.node()

	def _get_outstanding_queries(self):
		if self.sid_store_type == 'memcache':
			return self.outstanding_query_store.get(QUERY_STORE_KEY)

		return self.outstanding_query_store

	def _get_outstanding_query(self, key):
		if self.sid_store_type == 'memcache':
			return self.outstanding_query_store.get(QUERY_STORE_KEY).get(key)

		return self.outstanding_query_store.get(key)

	def _set_outstanding_query(self, key, value):
		if self.sid_store_type == 'memcache':
			queries = self.outstanding_query_store.get(QUERY_STORE_KEY)
			queries[key] = value
			self.outstanding_query_store.set(QUERY_STORE_KEY, queries)
		else:
			self.outstanding_query_store[key] = value

	def _get_outstanding_certs(self):
		if self.sid_store_type == 'memcache':
			return self.outstanding_cert_store.get(CERT_STORE_KEY)

		return self.outstanding_cert_store

	def _get_outstanding_cert(self, key):
		if self.sid_store_type == 'memcache':
			return outstanding_cert_store.get(CERT_STORE_KEY).get(key)

		return self.outstanding_cert_store.get(key)

	def _set_outstanding_cert(self, key, value):
		if self.sid_store_type == 'memcache':
			certs = self.outstanding_cert_store.get(CERT_STORE_KEY)
			certs[key] = value
			self.outstanding_cert_store.set(CERT_STORE_KEY, certs)
		else:
			self.outstanding_cert_store[key] = value

	def _get_rememberer(self, request):
		api = request.get('repoze.who.api', None)
		if not api:
			return None
		api_identifiers = api.identifiers
		rememberer = None
		for rememberer_set in api_identifiers:
			if rememberer_set and rememberer_set[0] == self.rememberer_name:
				rememberer = rememberer_set[1]

		if not rememberer:
			logger.debug("_get_rememberer -- No Remberer of name %s stored in API" % self.rememberer_name)

		return rememberer

	#### IIdentifier ####
	def remember(self, environ, identity, **kw):
		#pcrownov: Commenting out since pyramid_whoauth calls each rememberer plugin causing real one to
		#			be called multiple times
		#logger.debug('saml - remember')
		#rememberer = self._get_rememberer(environ)
		#if not rememberer:
		#	return []
		#return rememberer.remember(environ, identity)
		return []


	#### IIdentifier ####
	def forget(self, environ, identity):
		"""Get headers to forget the identify of the given request.

		This method calls the repoze.who logout() method, which in turn calls
		the forget() method on all configured repoze.who plugins.
		"""
		rememberer = self._get_rememberer(environ)
		return rememberer.forget(environ, identity)

	def _get_post(self, environ):
		"""
		Get the posted information

		:param environ: A dictionary with environment variables
		"""

		body = ''
		try:
			length = int(environ.get('CONTENT_LENGTH', '0'))
		except ValueError:
			length = 0
		if length != 0:
			body = environ['wsgi.input'].read(length)  # get the POST variables
			environ[
				's2repoze.body'] = body  # store the request body for later
				# use by pysaml2
			environ['wsgi.input'] = StringIO(body)  # restore the request body
				# as a stream so that everything seems untouched

		post = parse_qs(body)  # parse the POST fields into a dict

		return post

	def _wayf_redirect(self, came_from):
		sid_ = sid()
		self._set_outstanding_query(sid_, came_from)
		return -1, HTTPSeeOther(headers=[('Location',
										  "%s?%s" % (self.wayf, sid_))])

	#noinspection PyUnusedLocal
	def _pick_idp(self, environ, came_from):
		"""
		If more than one idp and if none is selected, I have to do wayf or
		disco
		"""

		# check headers to see if it's an ECP request
		#		headers = {
		#					'Accept' : 'text/html; application/vnd.paos+xml',
		#					'PAOS'   : 'ver="%s";"%s"' % (paos.NAMESPACE,
		# SERVICE)
		#					}

		_cli = self.saml_client

		logger.info("_pick_idp -- [_pick_idp] Environment: %s" % environ)
		if "HTTP_PAOS" in environ:
			if environ["HTTP_PAOS"] == PAOS_HEADER_INFO:
				if 'application/vnd.paos+xml' in environ["HTTP_ACCEPT"]:
					# Where should I redirect the user to
					# entityid -> the IdP to use
					# relay_state -> when back from authentication

					logger.info("_pick_idp -- - ECP client detected -")

					_relay_state = construct_came_from(environ)
					_entityid = _cli.config.ecp_endpoint(environ["REMOTE_ADDR"])

					if not _entityid:
						return -1, HTTPInternalServerError(
							detail="No IdP to talk to")
					return ecp.ecp_auth_request(_cli, _entityid,
												_relay_state)
				else:
					return -1, HTTPInternalServerError(
						detail='Faulty Accept header')
			else:
				return -1, HTTPInternalServerError(
					detail='unknown ECP version')

		idps = self.metadata.with_descriptor("idpsso")

		idp_entity_id = query = None

		for key in ['s2repoze.body', "QUERY_STRING"]:
			query = environ.get(key)
			if query:
				try:
					_idp_entity_id = dict(parse_qs(query))[
						self.idp_query_param][0]
					if _idp_entity_id in idps:
						idp_entity_id = _idp_entity_id
					break
				except KeyError:
					logger.debug("_pick_idp -- No IdP entity ID in query: %s" % query)
					pass

		if idp_entity_id is None:
			if len(idps) == 1:
				# idps is a dictionary
				idp_entity_id = idps.keys()[0]
			elif not len(idps):
				return -1, HTTPInternalServerError(detail='Misconfiguration')
			else:
				idp_entity_id = ""

				if self.wayf:
					if query:
						try:
							wayf_selected = dict(parse_qs(query))[
								"wayf_selected"][0]
						except KeyError:
							return self._wayf_redirect(came_from)
						idp_entity_id = wayf_selected
					else:
						return self._wayf_redirect(came_from)
				elif self.discosrv:
					if query:
						idp_entity_id = _cli.parse_discovery_service_response(
							query=environ.get("QUERY_STRING"))
					else:
						sid_ = sid()
						self._set_outstanding_query(sid_, came_from)

						eid = _cli.config.entityid
						ret = _cli.config.getattr(
							"endpoints", "sp")["discovery_response"][0][0]
						ret += "?sid=%s" % sid_
						loc = _cli.create_discovery_service_request(
							self.discosrv, eid, **{"return": ret})
						return -1, SeeOther(loc)

				else:
					return -1, HTTPNotImplemented(
						detail='No WAYF or DJ present!')

		return 0, idp_entity_id

	#### IChallenger ####
	#noinspection PyUnusedLocal
	def challenge(self, environ, _status, _app_headers, _forget_headers):
		_cli = self.saml_client

		#TODO: change to remote_user_key env variable
		if 'REMOTE_USER' in environ:
			name_id = decode(environ["REMOTE_USER"])

			_cli = self.saml_client
			path_info = environ['PATH_INFO']

			if 'samlsp.logout' in environ:
				responses = _cli.global_logout(name_id)
				return self._handle_logout(responses)

		if 'samlsp.pending' in environ:
			response = environ['samlsp.pending']
			if isinstance(response, HTTPRedirection):
				response.headers += _forget_headers
			return response

		# Which page was accessed to get here
		came_from = construct_came_from(environ)
		environ["myapp.came_from"] = came_from

		# Am I part of a virtual organization or more than one ?
		try:
			vorg_name = environ["myapp.vo"]
		except KeyError:
			try:
				vorg_name = _cli.vorg._name
			except AttributeError:
				vorg_name = ""

		# If more than one idp and if none is selected, I have to do wayf
		(done, response) = self._pick_idp(environ, came_from)
		# Three cases: -1 something went wrong or Discovery service used
		#			   0 I've got an IdP to send a request to
		#			   >0 ECP in progress
		if done == -1:
			return response
		elif done > 0:
			self._set_outstanding_query(done, came_from)
			return ECP_response(response)
		else:
			entity_id = response
			# Do the AuthnRequest
			_binding = BINDING_HTTP_REDIRECT
			try:
				srvs = _cli.metadata.single_sign_on_service(entity_id, _binding)
				dest = srvs[0]["location"]

				extensions = None
				cert = None

				if _cli.config.generate_cert_func is not None:
					cert_str, req_key_str = _cli.config.generate_cert_func()
					cert = {
						"cert": cert_str,
						"key": req_key_str
					}
					spcertenc = SPCertEnc(x509_data=ds.X509Data(
						x509_certificate=ds.X509Certificate(text=cert_str)))
					extensions = Extensions(extension_elements=[
						element_to_extension_element(spcertenc)])

				if _cli.authn_requests_signed:
					_sid = saml2.s_utils.sid(_cli.seed)
					req_id, msg_str = _cli.create_authn_request(
						dest, vorg=vorg_name, sign=_cli.authn_requests_signed,
						message_id=_sid, extensions=extensions)
					_sid = req_id
				else:
					req_id, req = _cli.create_authn_request(
						dest, vorg=vorg_name, sign=False, extensions=extensions)
					msg_str = "%s" % req
					_sid = req_id

				if cert is not None:
					self._set_outstanding_cert(_sid, cert)

				ht_args = _cli.apply_binding(_binding, msg_str,
											 destination=dest,
											 relay_state=came_from)

			except Exception, exc:
				logger.exception(exc)
				raise Exception(
					"Failed to construct the AuthnRequest: %s" % exc)

			try:
				ret = _cli.config.getattr(
					"endpoints", "sp")["discovery_response"][0][0]
				if (environ["PATH_INFO"]) in ret and ret.split(
						environ["PATH_INFO"])[1] == "":
					query = parse_qs(environ["QUERY_STRING"])
					sid = query["sid"][0]
					came_from = self._get_outstanding_query(sid)
			except:
				pass
			# remember the request
			self._set_outstanding_query(_sid, came_from)

			if not ht_args["data"] and ht_args["headers"][0][0] == "Location":
				return HTTPSeeOther(headers=ht_args["headers"])
			else:
				return ht_args["data"]

	def _construct_identity(self, session_info):
		cni = code(session_info["name_id"])
		identity = {
			"login": cni,
			"password": "",
			'repoze.who.userid': cni,
			"userdata": session_info["ava"],
		}

		return identity

	def _eval_authn_response(self, environ, post, binding=BINDING_HTTP_POST):
		try:
			# Evaluate the response, returns a AuthnResponse instance
			try:
				authresp = self.saml_client.parse_authn_request_response(
					post["SAMLResponse"][0], binding, self._get_outstanding_queries(),
					self._get_outstanding_certs())

			except Exception, excp:
				logger.exception("Exception: %s" % (excp,))
				raise

			session_info = authresp.session_info()
		except TypeError, excp:
			return None

		if session_info["came_from"]:
			try:
				path, query = session_info["came_from"].split('?')
				environ["PATH_INFO"] = path
				environ["QUERY_STRING"] = query
			except ValueError:
				environ["PATH_INFO"] = session_info["came_from"]

		return session_info

	def do_ecp_response(self, body, environ):
		response, _relay_state = ecp.handle_ecp_authn_response(self.saml_client,
															   body)

		environ["s2repoze.relay_state"] = _relay_state.text
		session_info = response.session_info()

		return session_info

	#### IIdentifier ####
	def identify(self, environ):
		"""
		Tries to do the identification
		"""
		query = parse_dict_querystring(environ)
		if ("CONTENT_LENGTH" not in environ or not environ[
			"CONTENT_LENGTH"]) and \
						"SAMLResponse" not in query and "SAMLRequest" not in \
				query:
			return None

		# if logger:
		#	 logger.info("ENVIRON: %s" % environ)
		#	 logger.info("self: %s" % (self.__dict__,))

		uri = environ.get('REQUEST_URI', construct_url(environ))

		query = parse_dict_querystring(environ)

		if "SAMLResponse" in query or "SAMLRequest" in query:
			post = query
			binding = BINDING_HTTP_REDIRECT
		else:
			post = self._get_post(environ)
			binding = BINDING_HTTP_POST

		try:
			path_info = environ['PATH_INFO']
			logout = False
			if path_info in self.logout_endpoints:
				logout = True

			if logout and "SAMLRequest" in post:
				print("logout request received")
				try:
					response = self.saml_client.handle_logout_request(
						post["SAMLRequest"][0],
						self.saml_client.users.subjects()[0], binding)
					environ['samlsp.pending'] = self._handle_logout(response)
					return {}
				except:
					import traceback

					traceback.print_exc()
			elif "SAMLResponse" not in post:
				# Not for me, put the post back where next in line can
				# find it
				environ["post.fieldstorage"] = post
				# restore wsgi.input incase that is needed
				# only of s2repoze.body is present
				if 's2repoze.body' in environ:
					environ['wsgi.input'] = StringIO(environ['s2repoze.body'])
				return {}
			else:
				# check for SAML2 authN response
				try:
					if logout:
						response = \
							self.saml_client.parse_logout_request_response(
							post["SAMLResponse"][0], binding)
						if response:
							action = self.saml_client.handle_logout_response(
								response)

							if type(action) == dict:
								request = self._handle_logout(action)
							else:
								#logout complete
								request = HTTPSeeOther(headers=[
									('Location', "/")])
							if request:
								environ['samlsp.pending'] = request
							return {}
					else:
						session_info = self._eval_authn_response(
							environ, post,
							binding=binding)
				except Exception, err:
					environ["s2repoze.saml_error"] = err
					return {}
		except TypeError, exc:
			# might be a ECP (=SOAP) response
			body = environ.get('s2repoze.body', None)
			if body:
				# might be a ECP response
				try:
					session_info = self.do_ecp_response(body, environ)
				except Exception, err:
					environ["post.fieldstorage"] = post
					environ["s2repoze.saml_error"] = err
					return {}
			else:
				exception_trace("sp.identity", exc, logger)
				environ["post.fieldstorage"] = post
				return {}

		if session_info:
			environ["s2repoze.sessioninfo"] = session_info
			return self._construct_identity(session_info)
		else:
			return None

	# used 2 times : one to get the ticket, the other to validate it
	@staticmethod
	def _service_url(environ, qstr=None):
		if qstr is not None:
			url = construct_url(environ, querystring=qstr)
		else:
			url = construct_url(environ)
		return url

	#### IAuthenticatorPlugin ####
	#noinspection PyUnusedLocal
	def authenticate(self, environ, identity=None):
		if identity:
			if identity.get('userdata') and environ.get(
					's2repoze.sessioninfo') and identity.get(
					'userdata') == environ.get('s2repoze.sessioninfo').get('ava'):
				return identity.get('login')

			tktuser = identity.get('altid', None)

			if tktuser and self.saml_client.is_logged_in(decode(tktuser)):
				return tktuser
			return None
		else:
			return None

	@staticmethod
	def _handle_logout(responses):
		if 'data' in responses:
			ht_args = responses
		else:
			ht_args = responses[responses.keys()[0]][1]
		if not ht_args["data"] and ht_args["headers"][0][0] == "Location":
			return HTTPSeeOther(headers=ht_args["headers"])
		else:
			return ht_args["data"]


def make_plugin(remember_name=None,  # plugin for remember
				cache="",  # cache
				# Which virtual organization to support
				virtual_organization="",
				saml_conf="",
				wayf="",
				sid_store="",
				sid_store_type=None,
				sid_store_cert=None,
				sid_store_cert_type=None,
				identity_cache="",
				discovery="",
				idp_query_param=""
):
	logger.info("make_plugin: START")
	if saml_conf is "":
		raise ValueError(
			'must include saml_conf in configuration')

	if remember_name is None:
		raise ValueError('must include remember_name in configuration')

	conf = config_factory("sp", saml_conf)

	scl = Saml2Client(config=conf, identity_cache=identity_cache,
					  virtual_organization=virtual_organization)

	plugin = SAML2GenericPlugin(remember_name, conf, scl, wayf, cache, 
								sid_store, sid_store_type, discovery, idp_query_param,
								sid_store_cert, sid_store_cert_type)
	return plugin
