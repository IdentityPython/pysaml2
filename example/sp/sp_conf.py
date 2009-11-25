{
    "entityid" : "urn:mace:umu.se:saml:roland:sp",
    "service": {
        "sp":{
            "name" : "Rolands SP",
            "url" : "http://localhost:8087/",
            "required_attributes": ["surName", "givenName", "mail"],
            "optional_attributes": ["title"],
            "idp": {
                "" : "https://example.com/saml2/idp/SSOService.php",
            },
        }
    },
    "debug" : 1,
    "key_file" : "./mykey.pem",
    "cert_file" : "./mycert.pem",
    "xmlsec_binary" : "/opt/local/bin/xmlsec1",
    "organization": {
        "name": "Example Co.",
        "display_name": "Example Company",
        "url":"http://www.example.com/",
    },
    "contact": [{
        "given_name":"John",
        "sur_name": "Smith",
        "email_address": "john.smith@example.com",
        "contact_type": "technical",
    }]
}