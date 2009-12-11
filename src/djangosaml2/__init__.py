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
#
# Quick Intructions
#
# 1. Configure the authentication backend in the settings.py file:
#
# AUTHENTICATION_BACKENDS = (
#    'djangosaml2.backends.Saml2Backend',
#    'django.contrib.auth.backends.ModelBackend',
#)
#
# 2. Set the login url in the settings.py and include the urls:
#
# settings.py:
# ...
# LOGIN_URL = '/saml2/login/'
# ...
#
# urls.py:
# ...
# (r'^saml2/', include('djangosaml2.urls')),
# ...
#
# 3. Set the SAML config file (see pysaml2 docs for more information
# about this file)
#
# SAML_CONFIG_FILE = path.join(BASEDIR, 'sp.config')
#
# 4. Set the attribute that links the saml identity with the Django username
#
# SAML_USERNAME_ATTRIBUTE = 'uid'
