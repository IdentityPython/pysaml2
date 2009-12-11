# Copyright (C) 2009 Lorenzo Gil Sanchez
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#            http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import cgi

from django.conf import settings
from django.contrib import auth
from django.http import HttpResponse, HttpResponseRedirect

from saml2.client import Saml2Client
from saml2.config import Config


def _load_conf():
    conf = Config()
    conf.load_file(settings.SAML_CONFIG_FILE)
    return conf


def login(request):
    next = request.GET.get('next', '/')
    conf = _load_conf()
    srv = conf['service']['sp']
    idp_url = srv['idp'].values()[0]
    client = Saml2Client(None, conf)
    (session_id, result) = client.authenticate(
        conf['entityid'],
        idp_url,
        srv['url'],
        srv['name'],
        relay_state=next)

    redirect_url = result[1]
    return HttpResponseRedirect(redirect_url)


def assertion_consumer_service(request):
    conf = _load_conf()
    response = cgi.MiniFieldStorage('SAMLResponse',
                                    request.POST['SAMLResponse'])
    post = {'SAMLResponse': response}
    client = Saml2Client(None, conf)
    session_info = client.response(post, conf['entityid'], None)

    user = auth.authenticate(session_info=session_info)
    if user is None:
        return HttpResponse("user not valid")

    auth.login(request, user)
    relay_state = request.POST.get('RelayState', '/')
    return HttpResponseRedirect(relay_state)
