import logging

from hashlib import sha1
from pymongo import MongoClient

from saml2.ident import code
from saml2.mdie import to_dict, from_dict

from saml2 import md
from saml2 import saml
from saml2.extension import mdui
from saml2.extension import idpdisc
from saml2.extension import dri
from saml2.extension import mdattr
from saml2.extension import ui
import xmldsig
import xmlenc


ONTS = {
    saml.NAMESPACE: saml,
    mdui.NAMESPACE: mdui,
    mdattr.NAMESPACE: mdattr,
    dri.NAMESPACE: dri,
    ui.NAMESPACE: ui,
    idpdisc.NAMESPACE: idpdisc,
    md.NAMESPACE: md,
    xmldsig.NAMESPACE: xmldsig,
    xmlenc.NAMESPACE: xmlenc
}

__author__ = 'rolandh'

logger = logging.getLogger(__name__)


def context_match(cfilter, cntx):
    # TODO
    return True

# The key to the stored authn statement is placed encrypted in the cookie


class SessionStorage(object):
    """ In memory storage of session information """

    def __init__(self):
        self.db = {"assertion": {}, "authn": {}}
        self.assertion = self.db["assertion"]
        self.authn = self.db["authn"]

    def store_assertion(self, assertion, to_sign):
        self.assertion[assertion.id] = (assertion, to_sign)

    def get_assertion(self, cid):
        return self.assertion[cid]

    def store_authn_statement(self, authn_statement, name_id):
        """

        :param authn_statement:
        :param name_id:
        :return:
        """
        logger.debug("store authn about: %s" % name_id)
        nkey = sha1(code(name_id)).hexdigest()
        logger.debug("Store authn_statement under key: %s" % nkey)
        try:
            self.authn[nkey].append(authn_statement)
        except KeyError:
            self.authn[nkey] = [authn_statement]

        return nkey

    def get_authn_statements(self, name_id, session_index=None,
                             requested_context=None):
        """

        :param name_id:
        :param session_index:
        :param requested_context:
        :return:
        """
        result = []
        key = sha1(code(name_id)).hexdigest()
        try:
            statements = self.authn[key]
        except KeyError:
            logger.info("Unknown subject %s" % name_id)
            return []

        for statement in statements:
            if session_index:
                if statement.session_index != session_index:
                    continue
            if requested_context:
                if not context_match(requested_context,
                                     statement.authn_context):
                    continue
            result.append(statement)

        return result

    def remove_authn_statements(self, name_id):
        logger.debug("remove authn about: %s" % name_id)
        nkey = sha1(code(name_id)).hexdigest()

        del self.authn[nkey]


class SessionStorageMDB(object):
    """ Session information is stored in a MongoDB database"""

    def __init__(self, collection=""):
        connection = MongoClient()
        db = connection[collection]
        self.assertion = db.assertion
        self.authn = db.authn

    def store_assertion(self, assertion, to_sign):
        self.assertion[assertion.id] = {
            "assertion": to_dict(assertion, ONTS.values(), True),
            "to_sign": to_sign}

    def get_assertion(self, cid):
        _dict = self.assertion[cid]
        return {"assertion": from_dict(_dict["assertion"], ONTS, True),
                "to_sign": _dict["to_sign"]}

    def store_authn_statement(self, authn_statement, name_id):
        """

        :param authn_statement:
        :param name_id:
        :return:
        """
        logger.debug("store authn about: %s" % name_id)
        nkey = sha1(code(name_id)).hexdigest()
        logger.debug("Store authn_statement under key: %s" % nkey)
        _as = to_dict(authn_statement, ONTS.values(), True)
        try:
            self.authn[nkey].append(_as)
        except KeyError:
            self.authn[nkey] = [_as]

        return nkey

    def get_authn_statements(self, name_id=None, session_index=None,
                             requested_context=None):
        """

        :param name_id: One of name_id or key can be used to get the authn
            statement
        :param session_index: If match against a session index should be done
        :param requested_context: Authn statements should match a specific
            authn context
        :return:
        """
        result = []
        key = sha1(code(name_id)).hexdigest()
        try:
            statements = [from_dict(t, ONTS, True) for t in self.authn[key]]
        except KeyError:
            logger.info("Unknown subject %s" % name_id)
            return []

        for statement in statements:
            if session_index:
                if statement.session_index != session_index:
                    continue
            if requested_context:
                if not context_match(requested_context,
                                     statement.authn_context):
                    continue
            result.append(statement)

        return result

    def remove_authn_statements(self, name_id):
        logger.debug("remove authn about: %s" % name_id)
        nkey = sha1(code(name_id)).hexdigest()

        del self.authn[nkey]
