import inspect
import sys
import traceback
from saml2.md import EntitiesDescriptor
from saml2.saml import NAMEID_FORMAT_TRANSIENT, NAMEID_FORMAT_PERSISTENT
from saml2.saml import NAME_FORMAT_URI
from saml2.sigver import cert_from_key_info
from saml2.sigver import key_from_key_value

__author__ = 'rolandh'

INFORMATION = 0
OK = 1
WARNING = 2
ERROR = 3
CRITICAL = 4
INTERACTION = 5

STATUSCODE = ["INFORMATION", "OK", "WARNING", "ERROR", "CRITICAL",
              "INTERACTION"]

class Check():
    """ General test
    """
    id = "check"
    msg = "OK"

    def __init__(self, **kwargs):
        self._status = OK
        self._message = ""
        self.content = None
        self.url = ""
        self._kwargs = kwargs

    def _func(self, environ):
        return {}

    def __call__(self, environ=None, output=None):
        _stat =  self.response(**self._func(environ))
        output.append(_stat)
        return _stat

    def response(self, **kwargs):
        try:
            name = " ".join([s.strip() for s in self.__doc__.strip().split("\n")])
        except AttributeError:
            name = ""

        res = {
            "id": self.id,
            "status": self._status,
            "name": name
        }

        if self._message:
            res["message"] = self._message

        if kwargs:
            res.update(kwargs)

        return res

class ExpectedError(Check):
    pass

class CriticalError(Check):
    status = CRITICAL

class Error(Check):
    status = ERROR

class Other(CriticalError):
    """ Other error """
    msg  = "Other error"

class WrapException(CriticalError):
    """
    A runtime exception
    """
    id = "exception"
    msg = "Test tool exception"

    def _func(self, environ=None):
        self._status = self.status
        self._message = traceback.format_exception(*sys.exc_info())
        return {}

class CheckHTTPResponse(CriticalError):
    """
    Checks that the HTTP response status is within the 200 or 300 range
    """
    id = "check-http-response"
    msg = "IdP error"

    def _func(self, environ):
        _response = environ["response"]

        res = {}
        if _response.status_code >= 400 :
            self._status = self.status
            self._message = self.msg
            res["url"] = environ["url"]
            res["http_status"] = _response.status_code
            res["content"] = _response.text

        return res

class CheckSaml2IntMetaData(Check):
    """
    Checks that the Metadata follows the profile
    """
    id = "check-saml2int-metadata"
    msg = "Metadata error"

    def verify_key_info(self, ki):
        # key_info
        # one or more key_value and/or x509_data.X509Certificate
        try:
            assert ki.key_value or ki.x509_data
        except AssertionError:
            self._message = "Missing KeyValue or X509Data.X509Certificate"
            self._status = CRITICAL
            return False

        xkeys = cert_from_key_info(ki)
        vkeys = key_from_key_value(ki)

        if xkeys and vkeys:
            # verify that it's the same keys
            pass

        return True

    def verify_key_descriptor(self, kd):
        # key_info
        if not self.verify_key_info(kd.key_info):
            return False

        # use
        if kd.use:
            try:
                assert kd.use in ["encryption", "signing"]
            except AssertionError:
                self._message = "Unknown use specification: '%s'" % kd.use.text
                self._status = CRITICAL
                return False

        return True

    def _func(self, environ):
        if isinstance(environ["metadata"], EntitiesDescriptor):
            ed = environ["metadata"].entity_descriptor[0]
        else:
            ed = environ["metadata"]

        res = {}

        assert len(ed.idpsso_descriptor)
        idpsso = ed.idpsso_descriptor[0]
        for kd in idpsso.key_descriptor:
            if self.verify_key_descriptor(kd) == False:
                return res

        # contact person
        if not idpsso.contact_person:
            self._message = "Metadata should contain contact person information"
            self._status = WARNING
            return res
        else:
            item = {"support": False, "technical": False}
            for contact in idpsso.contact_person:
                try:
                    item[contact.contact_type] = True
                except KeyError:
                    pass

            if item["support"] and item["technical"]:
                pass
            elif not item["support"] and not item["technical"]:
                self._message = "Missing technical and support contact information"
                self._status = WARNING
            elif item["support"]:
                self._message = "Missing technical contact information"
                self._status = WARNING
            elif item["technical"]:
                self._message = "Missing support contact information"
                self._status = WARNING

            if self._message:
                return res

        # NameID format
        if not idpsso.nameid_format:
            self._message = "Metadata should specify NameID format support"
            self._status = WARNING
            return res
        else:
            # should support Transient
            item = {NAMEID_FORMAT_TRANSIENT:False}
            for format in idpsso.nameid_format:
                try:
                    item[format] = True
                except KeyError:
                    pass

            if not item[NAMEID_FORMAT_TRANSIENT]:
                self._message = "IdP should support Transient NameID Format"
                self._status = WARNING
                return res

        return res

class CheckSaml2IntAttributes(Check):
    """
    Any <saml2:Attribute> elements exchanged via any SAML 2.0 messages,
    assertions, or metadata MUST contain a NameFormat of
    urn:oasis:names:tc:SAML:2.0:attrname-format:uri.
    """
    id = "check-saml2int-attributes"
    msg = "Attribute error"

    def _func(self, environ):
        response = environ["response"]
        try:
            opaque_identifier = environ["opaque_identifier"]
        except KeyError:
            opaque_identifier = False
        try:
            name_format_not_specified = environ["name_format_not_specified"]
        except KeyError:
            name_format_not_specified = False

        res = {}

        # should be a list but isn't
        #assert len(response.assertion) == 1
        assertion = response.assertion
        assert len(assertion.authn_statement) == 1
        assert len(assertion.attribute_statement) < 2

        if assertion.attribute_statement:
            atrstat = assertion.attribute_statement[0]
            for attr in atrstat.attribute:
                try:
                    assert attr.name_format == NAME_FORMAT_URI
                except AssertionError:
                    self._message = "Attribute name format error"
                    self._status = CRITICAL
                    return res
                try:
                    assert attr.name.startswith("urn:oid")
                except AssertionError:
                    self._message = "Attribute name should be an OID"
                    self._status = CRITICAL
                    return res

        assert not assertion.subject.encrypted_id
        assert not assertion.subject.base_id

        if opaque_identifier:
            try:
                assert assertion.subject.name_id.format == NAMEID_FORMAT_PERSISTENT
            except AssertionError:
                self._message = "NameID format should be TRANSIENT"
                self._status = WARNING

        if name_format_not_specified:
            try:
                assert assertion.subject.name_id.format == NAMEID_FORMAT_TRANSIENT
            except AssertionError:
                self._message = "NameID format should be TRANSIENT"
                self._status = WARNING

        return res

class CheckSubjectNameIDFormat(Check):
    """
    The <NameIDPolicy> element tailors the name identifier in the subjects of
    assertions resulting from an <AuthnRequest>.
    When this element is used, if the content is not understood by or acceptable
    to the identity provider, then a <Response> message element MUST be
    returned with an error <Status>, and MAY contain a second-level
    <StatusCode> of urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy.
    If the Format value is omitted or set to urn:oasis:names:tc:SAML:2.0:nameid-
    format:unspecified, then the identity provider is free to return any kind
    of identifier, subject to any additional constraints due to the content of
    this element or the policies of the identity provider or principal.
    """
    id = "check-saml2int-attributes"
    msg = "Attribute error"

    def _func(self, environ):
        response = environ["response"]
        request = environ["request"]

        res ={}
        if request.name_id_policy:
            format = request.name_id_policy.format
            sp_name_qualifier = request.name_id_policy.sp_name_qualifier

            subj = response.assertion.subject
            try:
                assert subj.name_id.format == format
                if sp_name_qualifier:
                    assert subj.name_id.sp_name_qualifier == sp_name_qualifier
            except AssertionError:
                self._message = "The IdP returns wrong NameID format"
                self._status = CRITICAL

        return res

class CheckLogoutSupport(Check):
    id = "check-logout-support"
    msg = "Does not support logout"

    def _func(self, environ):
        if isinstance(environ["metadata"], EntitiesDescriptor):
            ed = environ["metadata"].entity_descriptor[0]
        else:
            ed = environ["metadata"]

        assert len(ed.idpsso_descriptor)
        idpsso = ed.idpsso_descriptor[0]
        try:
            assert idpsso.single_logout_service
        except AssertionError:
            self._message = self.msg
            self._status = CRITICAL

        return {}

def factory(id):
    for name, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isclass(obj):
            try:
                if obj.id == id:
                    return obj
            except AttributeError:
                pass

    return None
