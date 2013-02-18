import cookielib
from rrtest import FatalError
from rrtest.check import ExpectedError
from rrtest.interaction import Interaction, Operation
from rrtest.status import STATUSCODE

__author__ = 'rolandh'


class Conversation():
    def __init__(self, client, config, trace, interaction,
                 check_factory=None, msg_factory=None,
                 features=None, verbose=False):
        self.client = client
        self.client_config = config
        self.trace = trace
        self.test_output = []
        self.features = features
        self.verbose = verbose
        self.check_factory = check_factory
        self.msg_factory = msg_factory

        self.environ = {"client": self.client, "response": None}

        self.cjar = {"browser": cookielib.CookieJar(),
                     "rp": cookielib.CookieJar(),
                     "service": cookielib.CookieJar()}

        self.last_response = None
        self.last_content = None
        self.interaction = Interaction(self.client, interaction)

    def check_severity(self, stat):
        if stat["status"] >= 4:
            self.trace.error("WHERE: %s" % stat["id"])
            self.trace.error("STATUS:%s" % STATUSCODE[stat["status"]])
            try:
                self.trace.error("HTTP STATUS: %s" % stat["http_status"])
            except KeyError:
                pass
            try:
                self.trace.error("INFO: %s" % stat["message"])
            except KeyError:
                pass

            raise FatalError

    def do_check(self, test, **kwargs):
        if isinstance(test, basestring):
            chk = self.check_factory(test)(**kwargs)
        else:
            chk = test(**kwargs)
        stat = chk(self.environ, self.test_output)
        self.check_severity(stat)

    def err_check(self, test, err=None, bryt=True):
        if err:
            self.environ["exception"] = err
        chk = self.check_factory(test)()
        chk(self.environ, self.test_output)
        if bryt:
            raise FatalError(test)

    def test_sequence(self, sequence):
        for test in sequence:
            if isinstance(test, tuple):
                test, kwargs = test
            else:
                kwargs = {}
            self.do_check(test, **kwargs)
            if test == ExpectedError:
                return False
        return True

    def my_endpoints(self):
        pass

    def intermit(self):
        _response = self.last_response
        if _response.status_code >= 400:
            done = True
        else:
            done = False

        url = _response.url
        content = _response.text

        while not done:
            while _response.status_code in [302, 301, 303]:
                url = _response.headers["location"]

                self.trace.reply("REDIRECT TO: %s" % url)
                # If back to me
                for_me = False
                for redirect_uri in self.my_endpoints():
                    if url.startswith(redirect_uri):
                        # Back at the RP
                        self.environ["client"].cookiejar = self.cjar["rp"]
                        for_me = True

                if for_me:
                    done = True
                    break
                else:
                    try:
                        _response = self.client.send(url, "GET")
                    except Exception, err:
                        raise FatalError("%s" % err)

                    content = _response.text
                    self.trace.reply("CONTENT: %s" % content)
                    self.environ.update({"url": url, "content": content})
                    self.environ["response"] = _response

                    self.do_check("check-http-response")

            if done or url is None:
                break

            _base = url.split("?")[0]

            try:
                _spec = self.interaction.pick_interaction(_base, content)
            except KeyError:
                self.environ["url"] = url
                self.trace.error("Page Content: %s" % content)
                self.err_check("interaction-needed")

            if len(_spec) > 2:
                self.trace.info(">> %s <<" % _spec["page-type"])
                if _spec["page-type"] == "login":
                    self.environ["login"] = content

            _op = Operation(_spec["control"])

            try:
                _response = _op(self.client, self.environ, self.trace, url,
                                _response, content, self.features)
                if isinstance(_response, dict):
                    self.last_response = _response
                    self.last_content = _response
                    return _response
                content = _response.text
                self.environ.update({"url": url, "content": content})
                self.environ["response"] = _response

                self.do_check("check-http-response")
            except FatalError:
                raise
            except Exception, err:
                self.err_check("exception", err, False)

        self.last_response = _response
        try:
            self.last_content = _response.text
        except AttributeError:
            self.last_content = None

    def init(self, phase):
        pass

    def setup_request(self):
        pass

    def send(self):
        pass

    def handle_result(self):
        pass

    def do_query(self):
        self.setup_request()
        self.send()
        if not self.handle_result():
            self.intermit()
            self.handle_result()

    def do_sequence(self, oper):

        try:
            self.test_sequence(oper["tests"]["pre"])
        except KeyError:
            pass

        for phase in oper["sequence"]:
            self.init(phase)
            try:
                self.do_query()
            except FatalError:
                pass
            except Exception, err:
                self.err_check("exception", err)

        try:
            self.test_sequence(oper["tests"]["post"])
        except KeyError:
            pass
