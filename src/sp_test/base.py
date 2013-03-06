import cookielib
from rrtest import tool

__author__ = 'rolandh'


class Conversation(tool.Conversation):
    def __init__(self, client, config, trace, interaction,
                 check_factory, entity_id, msg_factory=None,
                 features=None, verbose=False, constraints=None):
        tool.Conversation.__init__(self, client, config, trace,
                                   interaction, check_factory, msg_factory,
                                   features, verbose)
        self.entity_id = entity_id
        self.cjar = {"rp": cookielib.CookieJar()}

        self.args = {}
        self.qargs = {}
        self.response_args = {}
        self.saml_response = []
        self.destination = ""
        self.request = None
        self.position = ""
        self.response = None
        self.oper = None
        self.idp_constraints = constraints

    def init(self, phase):
        pass

    def send(self):
        pass
