{
    "service": ["sp"],
    "entityid" : "urn:mace:example.com:saml:sp",
    "service_url" : "http://example.com:8087/",
    "idp_url" : "https://example.com/saml2/idp/SSOService.php",
    "my_name" : "My first SP",
    "debug" : 1,
    "key_file" : "./mykey.pem",
    "cert_file" : "./mycert.pem",
    "xmlsec_binary" : "/opt/local/bin/xmlsec1",
    "organization": {
        "name": "Example Co",
        #display_name
        "url":"http://www.example.com/",
    },
    "contact": [{
        "given_name":"John",
        "sur_name": "Smith",
        "email_address": "john.smith@example.com",
        #contact_type
        #company
        #telephone_number
    }]
}