.. _howto_idp:

How to make a SAML2 identity provider.
======================================

To make an SAML2 identity provider is a bit tricker than doing a service
provider, mainly because you have to divide the functionality between
the application and the plugins. 
Now, to do that you have to understand how repoze.who works.
Basically on every request; the ingress plugins first gets to do there stuff,
then the application and finally the egress plugins.

So in broad terms this is what happens:

1. A GET request is received for where ever the IdP is supposted to be listing.
    
    1.1 Identifiers are checked on ingress and none of them will be able to 
        identify the user since no login has been done.
        
    1.2 After the ingress plugins have had their turn, the control is passed
        to the application, which must state that a 401 reponse should be 
        returned if a user tries to access the IdP without an identification.
    
    1.3 On a 401 response the egress challenger, in this case the plugin 'form', 
        is activated.
    
        The configuration of this plugin is::
    
            [plugin:form]
            use = s2repoze.plugins.formswithhidden:make_plugin
            login_form_qs = __do_login
            rememberer_name = auth_tkt

        What's special with this form plugin is that the form carries the
        query part of the original GET request in hidden fields.
    
    1.4 The form is displayed, the user enters the user name and password and 
        submits the form.

2. The log in form reply is received by the server
     
    2.1 The ingress identifier gets the form and extracts login and password
        and passes it on to the authentication plugin. It will also extract
        the query parameters from the hidden fields and store them in an 
        environment variable ('s2repoze.qinfo').
        If the login and password was correct a cookie is issued. If there is
        a mdprovider plugin defined it will now add extra information about 
        the individual. After this the control is passed on to the 
        application.
    
    2.2 The function that is bound to the path of the IdP now gets to act. 
        This is just the main outline:
        
        *   It finds the query parameters in the 
            environment and parses it::
        
                query = environ["s2repoze.qinfo"]
                (consumer, identifier, name_id_policy, 
                    spid) = IDP.parse_authn_request(query["SAMLRequest"][0])

        *   then for the user information::
        
                identity = environ["repoze.who.identity"]["user"]
                userid = environ["repoze.who.identity"]['repoze.who.userid']

        *   and finally build the response::
        
                authn_resp = IDP.authn_response(identity, identifier, consumer, 
                                            spid, name_id_policy, userid)

        IDP is assumed to be an instance of saml2.server.Server
    
    
