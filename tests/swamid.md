{
  "https://uat.leeds1.emeraldinsight.com/entity": {
    "valid_until": "2012-12-19T20:17:02Z", 
    "entity_id": "https://uat.leeds1.emeraldinsight.com/entity", 
    "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EntityDescriptor", 
    "spsso_descriptor": [
      {
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "assertion_consumer_service": [
          {
            "index": "1", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://uat.leeds1.emeraldinsight.com/Shibboleth.sso/SAML2/Artifact"
          }, 
          {
            "index": "2", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://uat.leeds1.emeraldinsight.com/Shibboleth.sso/SAML2/POST-SimpleSign"
          }, 
          {
            "index": "0", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://uat.leeds1.emeraldinsight.com/Shibboleth.sso/SAML2/POST"
          }
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SPSSODescriptor", 
        "name_id_format": [
          {
            "text": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }
        ], 
        "attribute_consuming_service": [
          {
            "index": "0", 
            "service_description": [
              {
                "lang": "en", 
                "text": "to provide personalized access to journals and papers on social sciences", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }, 
              {
                "lang": "da", 
                "text": "at give adgang til EmeraldInsights tidsskrifter og artikler inden for socialvidenskab", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }
            ], 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AttributeConsumingService", 
            "requested_attribute": [
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.10"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.25178.1.2.9"
              }
            ], 
            "service_name": [
              {
                "lang": "en", 
                "text": "EmeraldInsight", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }, 
              {
                "lang": "da", 
                "text": "EmeraldInsight", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }
            ]
          }
        ], 
        "key_descriptor": [
          {
            "use": "signing", 
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIFEzCCA/ugAwIBAgILAQAAAAABLlieGjMwDQYJKoZIhvcNAQEFBQAwcTELMAkGA1UEBhMCQkUxHTAbBgNVBAsTFERvbWFpbiBWYWxpZGF0aW9uIENBMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSgwJgYDVQQDEx9HbG9iYWxTaWduIERvbWFpbiBWYWxpZGF0aW9uIENBMB4XDTExMDIyNDE2MTAxNloXDTEzMDIyNDE2MTAxMVowgYAxCzAJBgNVBAYTAkdCMSEwHwYDVQQLExhEb21haW4gQ29udHJvbCBWYWxpZGF0ZWQxJjAkBgNVBAoMHXNoaWJib2xldGguZW1lcmFsZGluc2lnaHQuY29tMSYwJAYDVQQDDB1zaGliYm9sZXRoLmVtZXJhbGRpbnNpZ2h0LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMoXI+n3JvgM6LIaYvSRgiJ44vRHXj0VnHsRDDlMevGSVwq5wLk0qI3iQEE12jOxcwx1kAcRmlrNdBwm0DusVSW2HGuODeSF+gqpGKqTayMv85op4x7IpAgUQmkaHZKGMY9NFGHOFcUcD8Bk2h9ytmjBnGyi0f0dF+gQj3sv8rh52zK5OVv/XR6wcYSE/rGGu+nU4OK3o7g3qr5sod9PgTaiyu26zA0miVTrQCEmHQn1waLwRoz358JWXlAAvjATMirJ+KhIsNVBPSxnPcaxPLQqXXI+C5hagIG+oQ0glTG64NstlDXvLCw1BSzlpDgqGYAgdJTOz3OBRP/f5OKbLsUCAwEAAaOCAZowggGWMB8GA1UdIwQYMBaAFDYSTp5xxCZB8frxKUy/F6RTKLbrMEkGCCsGAQUFBwEBBD0wOzA5BggrBgEFBQcwAoYtaHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLm5ldC9jYWNlcnQvZHZoZTEuY3J0MDkGA1UdHwQyMDAwLqAsoCqGKGh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5uZXQvRG9tYWluVmFsMS5jcmwwHQYDVR0OBBYEFNr8wdf+AlkNufl44T52cIFoSkUnMAkGA1UdEwQCMAAwDgYDVR0PAQH/BAQDAgTwMCkGA1UdJQQiMCAGCCsGAQUFBwMBBggrBgEFBQcDAgYKKwYBBAGCNwoDAzBLBgNVHSAERDBCMEAGCSsGAQQBoDIBCjAzMDEGCCsGAQUFBwIBFiVodHRwOi8vd3d3Lmdsb2JhbHNpZ24ubmV0L3JlcG9zaXRvcnkvMBEGCWCGSAGG+EIBAQQEAwIGwDAoBgNVHREEITAfgh1zaGliYm9sZXRoLmVtZXJhbGRpbnNpZ2h0LmNvbTANBgkqhkiG9w0BAQUFAAOCAQEAW6Z0AgKjlbsyi/1EcEQC1ArGYeq6DomTtkpQWFSGWmOkCPpD6l6KJT7Q3/UgbHeCrbmwSwiADYHbJbJUNvQZoxKLcUMOJKA52mTdV8MGh0FBOvwzA8abBT955AI0SNma4CAW7UH0OaNo84PVLAbkDwdhU5TV3LktFIIPyBQLARm07IkmJZ2YdP2zl2BcbrozDy0YHs2dxhLSn+Uh3XrlH12VPHB7GzzeGD54XjjYGLqMoAKHGEqvVpF8hj+lemucvUuy6itdEPU5EgoAU+Pxlw8o+iHNxQ336Od77RWrw4Wa+gD0L6sIdZEOhbCSGLIjPwtEJmKWKaXN8tRYvG1sXw==", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }, 
          {
            "use": "encryption", 
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIFEzCCA/ugAwIBAgILAQAAAAABLlieGjMwDQYJKoZIhvcNAQEFBQAwcTELMAkGA1UEBhMCQkUxHTAbBgNVBAsTFERvbWFpbiBWYWxpZGF0aW9uIENBMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSgwJgYDVQQDEx9HbG9iYWxTaWduIERvbWFpbiBWYWxpZGF0aW9uIENBMB4XDTExMDIyNDE2MTAxNloXDTEzMDIyNDE2MTAxMVowgYAxCzAJBgNVBAYTAkdCMSEwHwYDVQQLExhEb21haW4gQ29udHJvbCBWYWxpZGF0ZWQxJjAkBgNVBAoMHXNoaWJib2xldGguZW1lcmFsZGluc2lnaHQuY29tMSYwJAYDVQQDDB1zaGliYm9sZXRoLmVtZXJhbGRpbnNpZ2h0LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMoXI+n3JvgM6LIaYvSRgiJ44vRHXj0VnHsRDDlMevGSVwq5wLk0qI3iQEE12jOxcwx1kAcRmlrNdBwm0DusVSW2HGuODeSF+gqpGKqTayMv85op4x7IpAgUQmkaHZKGMY9NFGHOFcUcD8Bk2h9ytmjBnGyi0f0dF+gQj3sv8rh52zK5OVv/XR6wcYSE/rGGu+nU4OK3o7g3qr5sod9PgTaiyu26zA0miVTrQCEmHQn1waLwRoz358JWXlAAvjATMirJ+KhIsNVBPSxnPcaxPLQqXXI+C5hagIG+oQ0glTG64NstlDXvLCw1BSzlpDgqGYAgdJTOz3OBRP/f5OKbLsUCAwEAAaOCAZowggGWMB8GA1UdIwQYMBaAFDYSTp5xxCZB8frxKUy/F6RTKLbrMEkGCCsGAQUFBwEBBD0wOzA5BggrBgEFBQcwAoYtaHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLm5ldC9jYWNlcnQvZHZoZTEuY3J0MDkGA1UdHwQyMDAwLqAsoCqGKGh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5uZXQvRG9tYWluVmFsMS5jcmwwHQYDVR0OBBYEFNr8wdf+AlkNufl44T52cIFoSkUnMAkGA1UdEwQCMAAwDgYDVR0PAQH/BAQDAgTwMCkGA1UdJQQiMCAGCCsGAQUFBwMBBggrBgEFBQcDAgYKKwYBBAGCNwoDAzBLBgNVHSAERDBCMEAGCSsGAQQBoDIBCjAzMDEGCCsGAQUFBwIBFiVodHRwOi8vd3d3Lmdsb2JhbHNpZ24ubmV0L3JlcG9zaXRvcnkvMBEGCWCGSAGG+EIBAQQEAwIGwDAoBgNVHREEITAfgh1zaGliYm9sZXRoLmVtZXJhbGRpbnNpZ2h0LmNvbTANBgkqhkiG9w0BAQUFAAOCAQEAW6Z0AgKjlbsyi/1EcEQC1ArGYeq6DomTtkpQWFSGWmOkCPpD6l6KJT7Q3/UgbHeCrbmwSwiADYHbJbJUNvQZoxKLcUMOJKA52mTdV8MGh0FBOvwzA8abBT955AI0SNma4CAW7UH0OaNo84PVLAbkDwdhU5TV3LktFIIPyBQLARm07IkmJZ2YdP2zl2BcbrozDy0YHs2dxhLSn+Uh3XrlH12VPHB7GzzeGD54XjjYGLqMoAKHGEqvVpF8hj+lemucvUuy6itdEPU5EgoAU+Pxlw8o+iHNxQ336Od77RWrw4Wa+gD0L6sIdZEOhbCSGLIjPwtEJmKWKaXN8tRYvG1sXw==", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ]
      }
    ], 
    "cache_duration": "PT345600S"
  }, 
  "https://connect.tut.fi/": {
    "valid_until": "2012-12-19T20:15:01Z", 
    "entity_id": "https://connect.tut.fi/", 
    "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EntityDescriptor", 
    "organization": {
      "organization_name": [
        {
          "lang": "fi", 
          "text": "Tampereen teknillinen yliopisto", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }, 
        {
          "lang": "en", 
          "text": "Tampere University of Technology", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }, 
        {
          "lang": "sv", 
          "text": "Tammerfors tekniska universitet", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }
      ], 
      "organization_display_name": [
        {
          "lang": "fi", 
          "text": "Tampereen teknillinen yliopisto", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }, 
        {
          "lang": "en", 
          "text": "Tampere University of Technology", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }, 
        {
          "lang": "sv", 
          "text": "Tammerfors tekniska universitet", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }
      ], 
      "organization_url": [
        {
          "lang": "fi", 
          "text": "http://www.tut.fi", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }, 
        {
          "lang": "en", 
          "text": "http://www.tut.fi", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }, 
        {
          "lang": "sv", 
          "text": "http://www.tut.fi", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }
      ], 
      "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Organization"
    }, 
    "contact_person": [
      {
        "given_name": {
          "text": "Pasi", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&GivenName"
        }, 
        "email_address": [
          {
            "text": "pasi.hakkinen@tut.fi", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ], 
        "sur_name": {
          "text": "Hakkinen", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SurName"
        }, 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "contact_type": "technical"
      }
    ], 
    "spsso_descriptor": [
      {
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "assertion_consumer_service": [
          {
            "is_default": "true", 
            "index": "1", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://ao4.ee.tut.fi/acp/Shibboleth.sso/SAML2/POST"
          }, 
          {
            "is_default": "false", 
            "index": "2", 
            "binding": "urn:oasis:names:tc:SAML:1.0:profiles:browser-post", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://ao4.ee.tut.fi/acp/Shibboleth.sso/SAML/POST"
          }
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SPSSODescriptor", 
        "extensions": {
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Extensions", 
          "extension_elements": [
            {
              "index": "1", 
              "binding": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol", 
              "__class__": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol&DiscoveryResponse", 
              "location": "https://ao4.ee.tut.fi/Shibboleth.sso/DS"
            }, 
            {
              "attribute_value": [
                {
                  "text": "kalmar", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }, 
                {
                  "text": "finland", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }
              ], 
              "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&Attribute", 
              "name": "tags"
            }
          ]
        }, 
        "name_id_format": [
          {
            "text": "urn:mace:shibboleth:1.0:nameIdentifier", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }, 
          {
            "text": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }
        ], 
        "attribute_consuming_service": [
          {
            "index": "1", 
            "service_name": [
              {
                "lang": "fi", 
                "text": "Acrobat Connect Pro -verkkokokouspalvelu", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }, 
              {
                "lang": "en", 
                "text": "TUT Acrobat Connect Pro", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }, 
              {
                "lang": "sv", 
                "text": "TUT Acrobat Connect Pro", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }
            ], 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AttributeConsumingService", 
            "is_default": "true", 
            "requested_attribute": [
              {
                "friendly_name": "cn", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.3"
              }, 
              {
                "friendly_name": "displayName", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.16.840.1.113730.3.1.241"
              }, 
              {
                "friendly_name": "eduPersonAffiliation", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.1"
              }, 
              {
                "friendly_name": "eduPersonPrincipalName", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
              }, 
              {
                "friendly_name": "mail", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:0.9.2342.19200300.100.1.3"
              }, 
              {
                "friendly_name": "schacHomeOrganization", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.25178.1.2.9"
              }, 
              {
                "friendly_name": "sn", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.4"
              }
            ], 
            "service_description": [
              {
                "lang": "fi", 
                "text": "TTY:n verkkokokouspalvelu.", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }, 
              {
                "lang": "en", 
                "text": "TUT web conference service.", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }, 
              {
                "lang": "sv", 
                "text": "TUT-tjansten for e-moten.", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }
            ]
          }
        ], 
        "key_descriptor": [
          {
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIE5zCCA8+gAwIBAgIQTC0sMFTDx+8bItkWKEE8EjANBgkqhkiG9w0BAQUFADA2\nMQswCQYDVQQGEwJOTDEPMA0GA1UEChMGVEVSRU5BMRYwFAYDVQQDEw1URVJFTkEg\nU1NMIENBMB4XDTEwMDYwODAwMDAwMFoXDTEzMDYwNzIzNTk1OVowgcQxCzAJBgNV\nBAYTAkZJMQ4wDAYDVQQREwUzMzcyMDESMBAGA1UECBMJUGlya2FubWFhMRAwDgYD\nVQQHEwdUYW1wZXJlMRwwGgYDVQQJExNLb3JrZWFrb3VsdW5rYXR1IDEwMSkwJwYD\nVQQKEyBUYW1wZXJlIFVuaXZlcnNpdHkgb2YgVGVjaG5vbG9neTEeMBwGA1UECxMV\nSHlwZXJtZWRpYSBMYWJvcmF0b3J5MRYwFAYDVQQDEw1hbzQuZWUudHV0LmZpMIIB\nIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw+q6HSeOwJOL+dhw2C6rmt+X\nXOC17rS4cqw/GK/MdcEB6OUGGnP7CVnMTt5i7kYRTE2xZZ4puXgunZc4djROOl5U\n9GpKJr1+PrBJ4bhZvJuuP+NGmk36dhPDelgGrl2g2t5Fdqm5gxLU7JBhDQcttbiQ\nIm4KCUD4RaYkVnt5LRb2XZ5rrfyNjphSr06HopVy77k3H0sd7uPlPg3fj1u6h3GB\nUwd+/Gdle78H5VF75+uhPZvmI9IjRT8i0I0hIDTXrnKKM+hmYg/OZteb/eSxTdfD\ncAsm0hfk4C4+i7FeR2ODlY0kegMZEfFLFAxRH950TP2IfRhl7aFHbggQ9zB6XwID\nAQABo4IBYDCCAVwwHwYDVR0jBBgwFoAUDL2TaAzz3qujSWsrN1dH6pDjue0wHQYD\nVR0OBBYEFD7dPRIPwNod9MvHsOo3Ryx8sENGMA4GA1UdDwEB/wQEAwIFoDAMBgNV\nHRMBAf8EAjAAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAYBgNVHSAE\nETAPMA0GCysGAQQBsjEBAgIdMDoGA1UdHwQzMDEwL6AtoCuGKWh0dHA6Ly9jcmwu\ndGNzLnRlcmVuYS5vcmcvVEVSRU5BU1NMQ0EuY3JsMG0GCCsGAQUFBwEBBGEwXzA1\nBggrBgEFBQcwAoYpaHR0cDovL2NydC50Y3MudGVyZW5hLm9yZy9URVJFTkFTU0xD\nQS5jcnQwJgYIKwYBBQUHMAGGGmh0dHA6Ly9vY3NwLnRjcy50ZXJlbmEub3JnMBgG\nA1UdEQQRMA+CDWFvNC5lZS50dXQuZmkwDQYJKoZIhvcNAQEFBQADggEBAC58dIBC\nvOyd04SLE1l+7yZ3ARTE+enLAEDGJzvvjlKG8MdsC/TfDimtTMOXQnNXbnfEzKwj\nZagmu/FRdhkVTQP48354C/hnAl1/Wyfjab8O9LeC6+pfAyY2mWzrb4kfRBm1KE26\nB2nURaYtDmZ+MJmjCyLQGaNMZz1q+eSyluTMMUven1FPVVPGlOGqUnPwOQUOvuVS\nvUyXrqyYfbSpfBsog9tVyW2KwzKvVCFeQ9pbUaxfsWD8qIeeKI17FzHVJEBtg23r\nz+mEW/8SvYpmYBk5YhfB1rTXQahEGyw8XP+kmmsb5h5d5yHgUXtEpEsBI4ORxMu1\nYUyAsGo8rZZF7VE=", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ]
      }
    ]
  }, 
  "https://shibboleth.bbaw.de/shibboleth": {
    "valid_until": "2012-12-19T20:15:01Z", 
    "entity_id": "https://shibboleth.bbaw.de/shibboleth", 
    "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EntityDescriptor", 
    "organization": {
      "organization_name": [
        {
          "lang": "fi", 
          "text": "CLARIN Service Provider Federation/MPI", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }, 
        {
          "lang": "en", 
          "text": "CLARIN Service Provider Federation/MPI", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }, 
        {
          "lang": "sv", 
          "text": "CLARIN Service Provider Federation/MPI", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }
      ], 
      "organization_display_name": [
        {
          "lang": "fi", 
          "text": "CLARIN Service Provider Federation/MPI", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }, 
        {
          "lang": "en", 
          "text": "CLARIN Service Provider Federation/MPI", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }, 
        {
          "lang": "sv", 
          "text": "CLARIN Service Provider Federation/MPI", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }
      ], 
      "organization_url": [
        {
          "lang": "fi", 
          "text": "http://www.clarin.eu", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }, 
        {
          "lang": "en", 
          "text": "http://www.clarin.eu", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }, 
        {
          "lang": "sv", 
          "text": "http://www.clarin.eu", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }
      ], 
      "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Organization"
    }, 
    "contact_person": [
      {
        "given_name": {
          "text": "Kai", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&GivenName"
        }, 
        "email_address": [
          {
            "text": "zimmer@bbaw.de", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ], 
        "sur_name": {
          "text": "Zimmer", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SurName"
        }, 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "contact_type": "technical"
      }
    ], 
    "spsso_descriptor": [
      {
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "assertion_consumer_service": [
          {
            "is_default": "true", 
            "index": "1", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://shibboleth.bbaw.de/Shibboleth.sso/SAML2/POST"
          }, 
          {
            "is_default": "false", 
            "index": "2", 
            "binding": "urn:oasis:names:tc:SAML:1.0:profiles:browser-post", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://shibboleth.bbaw.de/Shibboleth.sso/SAML/POST"
          }
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SPSSODescriptor", 
        "extensions": {
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Extensions", 
          "extension_elements": [
            {
              "index": "1", 
              "binding": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol", 
              "__class__": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol&DiscoveryResponse", 
              "location": "https://shibboleth.bbaw.de/Shibboleth.sso/Login"
            }, 
            {
              "attribute_value": [
                {
                  "text": "kalmar", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }, 
                {
                  "text": "finland", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }
              ], 
              "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&Attribute", 
              "name": "tags"
            }
          ]
        }, 
        "name_id_format": [
          {
            "text": "urn:mace:shibboleth:1.0:nameIdentifier", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }, 
          {
            "text": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }
        ], 
        "attribute_consuming_service": [
          {
            "index": "1", 
            "service_name": [
              {
                "lang": "fi", 
                "text": "German NLP tools from the BBAW/DWDS", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }, 
              {
                "lang": "en", 
                "text": "German NLP tools from the BBAW/DWDS", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }
            ], 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AttributeConsumingService", 
            "is_default": "true", 
            "requested_attribute": [
              {
                "friendly_name": "eduPersonPrincipalName", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
              }, 
              {
                "friendly_name": "mail", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:0.9.2342.19200300.100.1.3"
              }, 
              {
                "friendly_name": "o", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.10"
              }
            ], 
            "service_description": [
              {
                "lang": "en", 
                "text": "Tokenizer, Tagger (Moot), Shallow Parser (SynCop) and Named Entity Recognition for historic texts. For Humanities and Social Sciences researchers.", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }
            ]
          }
        ], 
        "key_descriptor": [
          {
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIFEjCCA/qgAwIBAgIEDxpjazANBgkqhkiG9w0BAQUFADCBnDELMAkGA1UEBhMC\nREUxPDA6BgNVBAoTM0Jlcmxpbi1CcmFuZGVuYnVyZ2lzY2hlIEFrYWRlbWllIGRl\nciBXaXNzZW5zY2hhZnRlbjEgMB4GA1UECxMXSW5mb3JtYXRpb25zdGVjaG5vbG9n\naWUxEjAQBgNVBAMTCUJCQVctQ0EgMTEZMBcGCSqGSIb3DQEJARYKY2FAYmJhdy5k\nZTAeFw0wOTExMTExNjI3MDdaFw0xNDExMTAxNjI3MDdaMGgxCzAJBgNVBAYTAkRF\nMTwwOgYDVQQKEzNCZXJsaW4tQnJhbmRlbmJ1cmdpc2NoZSBBa2FkZW1pZSBkZXIg\nV2lzc2Vuc2NoYWZ0ZW4xGzAZBgNVBAMTEnNoaWJib2xldGguYmJhdy5kZTCCASIw\nDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKqdL1VpZaKldYSwvu4z+8iXzy+j\n+6tpAq1lED8CDcXRJsbgL/F4sioQ9uNylJgX4aromN5kTT8nfmtEN84C9s5ExVg6\n29bkxSPEWviJzdDxKstRqWbl7PzpipFa9Th2b7jOwX4ec3nirC4ijoTACQBge7qd\nGNniTFM/2k5E7D8NPTJg2d9ITWs8JW7Qbx0ezFpKlg1eVWZNZs86L3UShdXWnwrT\noNtZwKm309EbdDNGDvsAgHseFNhmQIV+rOuMxv44nVMxDUSymARAKhzbeJ4CUWth\ngYjByHbQM45twUdQKGO01vQX+DwS+9RmA34PDZ8nRSktRtlG/Llr9SRXf9ECAwEA\nAaOCAY0wggGJMAkGA1UdEwQCMAAwCwYDVR0PBAQDAgXgMB0GA1UdJQQWMBQGCCsG\nAQUFBwMCBggrBgEFBQcDATAdBgNVHQ4EFgQUoy4g7ejcIv8AoY2/BQx6coBR6EIw\nHwYDVR0jBBgwFoAUjKaP8T8UOwK1+SdUTKs8odgbkJgweQYDVR0fBHIwcDA2oDSg\nMoYwaHR0cDovL2NkcDEucGNhLmRmbi5kZS9iYmF3LWNhL3B1Yi9jcmwvY2Fjcmwu\nY3JsMDagNKAyhjBodHRwOi8vY2RwMi5wY2EuZGZuLmRlL2JiYXctY2EvcHViL2Ny\nbC9jYWNybC5jcmwwgZQGCCsGAQUFBwEBBIGHMIGEMEAGCCsGAQUFBzAChjRodHRw\nOi8vY2RwMS5wY2EuZGZuLmRlL2JiYXctY2EvcHViL2NhY2VydC9jYWNlcnQuY3J0\nMEAGCCsGAQUFBzAChjRodHRwOi8vY2RwMi5wY2EuZGZuLmRlL2JiYXctY2EvcHVi\nL2NhY2VydC9jYWNlcnQuY3J0MA0GCSqGSIb3DQEBBQUAA4IBAQBrAUHthoQFOwKU\na8KybrhK1NofkstRQxhVR2jcNWQDhFB+ife+kXdindHuh6OeWgys07llwmPqACQ9\nT6ccWjVBVyV7DqFwuRCn/Ui/4E+c6EHtJEJ6nktXj4jCRla7a7gxmdnBqBKvjoPJ\n7AdIQbn9kpuWDN+2hoiGPdAz+ZBp1zcY28SJhtHoNHdLmAjyNlrCj3fWsppLL7/k\nznAYO9ZznwCtBE+BWq+rxu0TJhYBf84+fn0kwBruvHWgpCrb+57XpX3RN1HxNbvR\n9lvp1UltizFA44damYGbbKBKOLCHFvJbBg6v81WGKxZB+dv9TcZSMDNaj1oqBxUW\neQj7ACg8", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ]
      }
    ]
  }, 
  "https://auth.asiaportal.info": {
    "valid_until": "2012-12-19T20:17:02Z", 
    "entity_id": "https://auth.asiaportal.info", 
    "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EntityDescriptor", 
    "spsso_descriptor": [
      {
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "assertion_consumer_service": [
          {
            "index": "0", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://auth.asiaportal.info/simplesaml/saml2/sp/AssertionConsumerService.php"
          }
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SPSSODescriptor", 
        "name_id_format": [
          {
            "text": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }
        ], 
        "attribute_consuming_service": [
          {
            "index": "0", 
            "service_description": [
              {
                "lang": "en", 
                "text": "to provide remote access to licence-restricted databases and resources purchased as consortium licences by the NIAS Nordic Council", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }, 
              {
                "lang": "da", 
                "text": "at levere fjernadgang til licensbelagte databaser og ressourcer som er indk\u00f8bt som konsortiumlicens af NIAS Nordic Council", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }
            ], 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AttributeConsumingService", 
            "requested_attribute": [
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.5"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.25178.1.2.9"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.10"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.10"
              }
            ], 
            "service_name": [
              {
                "lang": "en", 
                "text": "AsiaPortal \u2013 NIAS", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }, 
              {
                "lang": "da", 
                "text": "AsiaPortal \u2013 NIAS", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }
            ]
          }
        ], 
        "key_descriptor": [
          {
            "use": "signing", 
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIDQjCCAqugAwIBAgIDCi9hMA0GCSqGSIb3DQEBBQUAME4xCzAJBgNVBAYTAlVTMRAwDgYDVQQKEwdFcXVpZmF4MS0wKwYDVQQLEyRFcXVpZmF4IFNlY3VyZSBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkwHhcNMDgxMTE4MDkxMzE3WhcNMTExMTE5MDkxMzE3WjCBzDELMAkGA1UEBhMCREsxHTAbBgNVBAoTFGF1dGguYXNpYXBvcnRhbC5pbmZvMRMwEQYDVQQLEwpHVDczNzI2MTMyMTEwLwYDVQQLEyhTZWUgd3d3Lmdlb3RydXN0LmNvbS9yZXNvdXJjZXMvY3BzIChjKTA4MTcwNQYDVQQLEy5Eb21haW4gQ29udHJvbCBWYWxpZGF0ZWQgLSBRdWlja1NTTCBQcmVtaXVtKFIpMR0wGwYDVQQDExRhdXRoLmFzaWFwb3J0YWwuaW5mbzCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAsc1QDsmxtsjafziHd2MpKFnrb9DIDTK1wxoX42BTqDl2l85tvtbdTGcxkOkHzYmz3B9S/G4s24X6kPCp/mIAfBeyC8iClCop2Xpp4nqqvpyZaKbrTVE8Ris0RRkFwdgPjabZ5sFVo0Cl2ErfBZ9ml3bKbvW3NCinxXMM2r7ow7ECAwEAAaOBrjCBqzAOBgNVHQ8BAf8EBAMCBPAwHQYDVR0OBBYEFJpQeSzk6m3+6ylNVBn80s/JznzuMDoGA1UdHwQzMDEwL6AtoCuGKWh0dHA6Ly9jcmwuZ2VvdHJ1c3QuY29tL2NybHMvc2VjdXJlY2EuY3JsMB8GA1UdIwQYMBaAFEjmaPkr0rKV10fYIyAQTzOYkJ/UMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjANBgkqhkiG9w0BAQUFAAOBgQAZIENBa9r4ielkshXwGmpBg8gLiQDnGbeoREB0YEuioMNQ4otd1pJ6PV1LutT/7ZxE/5QETMyYEkN782CCXIifdLFimsZHxkYZs6hbjbu1jhAApuon2wYPpXDiQFI8hTiE072ahcPQexWZ1xjSuMA+SGZYiSUJh8onRFk45eqkxA==", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }, 
          {
            "use": "encryption", 
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIDQjCCAqugAwIBAgIDCi9hMA0GCSqGSIb3DQEBBQUAME4xCzAJBgNVBAYTAlVTMRAwDgYDVQQKEwdFcXVpZmF4MS0wKwYDVQQLEyRFcXVpZmF4IFNlY3VyZSBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkwHhcNMDgxMTE4MDkxMzE3WhcNMTExMTE5MDkxMzE3WjCBzDELMAkGA1UEBhMCREsxHTAbBgNVBAoTFGF1dGguYXNpYXBvcnRhbC5pbmZvMRMwEQYDVQQLEwpHVDczNzI2MTMyMTEwLwYDVQQLEyhTZWUgd3d3Lmdlb3RydXN0LmNvbS9yZXNvdXJjZXMvY3BzIChjKTA4MTcwNQYDVQQLEy5Eb21haW4gQ29udHJvbCBWYWxpZGF0ZWQgLSBRdWlja1NTTCBQcmVtaXVtKFIpMR0wGwYDVQQDExRhdXRoLmFzaWFwb3J0YWwuaW5mbzCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAsc1QDsmxtsjafziHd2MpKFnrb9DIDTK1wxoX42BTqDl2l85tvtbdTGcxkOkHzYmz3B9S/G4s24X6kPCp/mIAfBeyC8iClCop2Xpp4nqqvpyZaKbrTVE8Ris0RRkFwdgPjabZ5sFVo0Cl2ErfBZ9ml3bKbvW3NCinxXMM2r7ow7ECAwEAAaOBrjCBqzAOBgNVHQ8BAf8EBAMCBPAwHQYDVR0OBBYEFJpQeSzk6m3+6ylNVBn80s/JznzuMDoGA1UdHwQzMDEwL6AtoCuGKWh0dHA6Ly9jcmwuZ2VvdHJ1c3QuY29tL2NybHMvc2VjdXJlY2EuY3JsMB8GA1UdIwQYMBaAFEjmaPkr0rKV10fYIyAQTzOYkJ/UMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjANBgkqhkiG9w0BAQUFAAOBgQAZIENBa9r4ielkshXwGmpBg8gLiQDnGbeoREB0YEuioMNQ4otd1pJ6PV1LutT/7ZxE/5QETMyYEkN782CCXIifdLFimsZHxkYZs6hbjbu1jhAApuon2wYPpXDiQFI8hTiE072ahcPQexWZ1xjSuMA+SGZYiSUJh8onRFk45eqkxA==", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ]
      }
    ], 
    "cache_duration": "PT345600S"
  }, 
  "https://foodl.org/simplesaml/module.php/saml/sp/metadata.php/saml": {
    "valid_until": "2012-12-19T20:14:03Z", 
    "contact_person": [
      {
        "contact_type": "technical", 
        "company": {
          "text": "UNINETT AS", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Company"
        }, 
        "telephone_number": [
          {
            "text": "+47 73557894", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&TelephoneNumber"
          }
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "sur_name": {
          "text": "Solberg", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SurName"
        }, 
        "given_name": {
          "text": "Andreas", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&GivenName"
        }, 
        "email_address": [
          {
            "text": "andreas.solberg@uninett.no", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ]
      }
    ], 
    "entity_id": "https://foodl.org/simplesaml/module.php/saml/sp/metadata.php/saml", 
    "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EntityDescriptor", 
    "spsso_descriptor": [
      {
        "single_logout_service": [
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleLogoutService", 
            "location": "https://foodl.org/simplesaml/module.php/saml/sp/saml2-logout.php/saml"
          }
        ], 
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "assertion_consumer_service": [
          {
            "index": "0", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://foodl.org/simplesaml/module.php/saml/sp/saml2-acs.php/saml"
          }
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SPSSODescriptor", 
        "key_descriptor": [
          {
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIICLzCCAZgCCQDWeshLcjcICTANBgkqhkiG9w0BAQUFADBcMQswCQYDVQQGEwJOTzELMAkGA1UECBMCU1QxEjAQBgNVBAcTCVRyb25kaGVpbTESMBAGA1UEChMJRmVpZGUgUm5EMRgwFgYDVQQDEw9mb29kbGUuZmVpZGUubm8wHhcNMDkwMTMwMTIyMzI4WhcNMzYwNjE2MTIyMzI4WjBcMQswCQYDVQQGEwJOTzELMAkGA1UECBMCU1QxEjAQBgNVBAcTCVRyb25kaGVpbTESMBAGA1UEChMJRmVpZGUgUm5EMRgwFgYDVQQDEw9mb29kbGUuZmVpZGUubm8wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMLZMDXYErToL/IAb8WcTYN4bGZtwnwc8RmsuFSo2Bu3q+27fQIjn5uF/OfC9D2Bs5nqy8PjHSfp4gTG2gL/+Vi8J1rLnTLgTCBl/DacPU1MhkKiw8+dqzsPm96ELoDRJH4+O0vML3rUizkpZidEN5CgWNcg72CyKE83vN7zijevAgMBAAEwDQYJKoZIhvcNAQEFBQADgYEAmw2o4gbWppGxd5Xleyyd+s2kJMVnuXlwjsLiXz8uzeqOifAG1RVTZQDCxIAw8lAse1nLKKGZYj5PyCVwAhVjaVYuATErfeJqyTft9xtbH6Qk5mV99u1GujO2Lx54uaZFOCiCahwQGPfAm+qlrCteDoE8gqo0RJWno/HQxXE6/ac=", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ], 
        "attribute_consuming_service": [
          {
            "index": "0", 
            "service_description": [
              {
                "lang": "en", 
                "text": "Foodle is a generic poll and survey tool for deciding meeting dates.", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }, 
              {
                "lang": "no", 
                "text": "Foodle er et generisk poll og survey verkt\u00f8y for \u00e5 bli enige om m\u00f8tedatoer.", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }, 
              {
                "lang": "nn", 
                "text": "Foodle er eit generisk poll- og survey-verkt\u00f8y for \u00e5 verte einige om m\u00f8tedatoar.", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }
            ], 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AttributeConsumingService", 
            "requested_attribute": [
              {
                "friendly_name": "eduPersonPrincipalName", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
              }, 
              {
                "friendly_name": "mail", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:0.9.2342.19200300.100.1.3"
              }, 
              {
                "friendly_name": "cn", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.3"
              }, 
              {
                "friendly_name": "displayName", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.16.840.1.113730.3.1.241"
              }, 
              {
                "friendly_name": "sn", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.4"
              }, 
              {
                "friendly_name": "givenName", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.42"
              }, 
              {
                "friendly_name": "preferredLanguage", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.16.840.1.113730.3.1.39"
              }
            ], 
            "service_name": [
              {
                "lang": "en", 
                "text": "Foodle", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }
            ]
          }
        ]
      }
    ]
  }, 
  "https://sp.dev.clarin.inl.nl/shibboleth": {
    "valid_until": "2012-12-19T20:15:01Z", 
    "entity_id": "https://sp.dev.clarin.inl.nl/shibboleth", 
    "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EntityDescriptor", 
    "organization": {
      "organization_name": [
        {
          "lang": "fi", 
          "text": "CLARIN Service Provider Federation/MPI", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }, 
        {
          "lang": "en", 
          "text": "CLARIN Service Provider Federation/MPI", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }, 
        {
          "lang": "sv", 
          "text": "CLARIN Service Provider Federation/MPI", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }
      ], 
      "organization_display_name": [
        {
          "lang": "fi", 
          "text": "CLARIN Service Provider Federation/MPI", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }, 
        {
          "lang": "en", 
          "text": "CLARIN Service Provider Federation/MPI", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }, 
        {
          "lang": "sv", 
          "text": "CLARIN Service Provider Federation/MPI", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }
      ], 
      "organization_url": [
        {
          "lang": "fi", 
          "text": "http://www.clarin.eu", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }, 
        {
          "lang": "en", 
          "text": "http://www.clarin.eu", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }, 
        {
          "lang": "sv", 
          "text": "http://www.clarin.eu", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }
      ], 
      "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Organization"
    }, 
    "contact_person": [
      {
        "given_name": {
          "text": "Marco", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&GivenName"
        }, 
        "email_address": [
          {
            "text": "systeembeheer@inl.nl", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ], 
        "sur_name": {
          "text": "Van der Laan", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SurName"
        }, 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "contact_type": "technical"
      }
    ], 
    "spsso_descriptor": [
      {
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "assertion_consumer_service": [
          {
            "is_default": "true", 
            "index": "1", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://sp.dev.clarin.inl.nl/Shibboleth.sso/SAML2/POST"
          }, 
          {
            "is_default": "false", 
            "index": "2", 
            "binding": "urn:oasis:names:tc:SAML:1.0:profiles:browser-post", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://sp.dev.clarin.inl.nl/Shibboleth.sso/SAML/POST"
          }
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SPSSODescriptor", 
        "name_id_format": [
          {
            "text": "urn:mace:shibboleth:1.0:nameIdentifier", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }, 
          {
            "text": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }
        ], 
        "attribute_consuming_service": [
          {
            "index": "1", 
            "service_name": [
              {
                "lang": "fi", 
                "text": "Browsable TST-LRs", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }, 
              {
                "lang": "en", 
                "text": "Browsable TST-LRs", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }, 
              {
                "lang": "sv", 
                "text": "Browsable TST-LRs", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }
            ], 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AttributeConsumingService", 
            "is_default": "true", 
            "requested_attribute": [
              {
                "friendly_name": "eduPersonPrincipalName", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
              }, 
              {
                "friendly_name": "mail", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:0.9.2342.19200300.100.1.3"
              }, 
              {
                "friendly_name": "schacHomeOrganization", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.25178.1.2.9"
              }
            ], 
            "service_description": [
              {
                "lang": "fi", 
                "text": "This website gives you access to the IMDI-based language resources (LRs) housed at the TST-centrale.", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }, 
              {
                "lang": "en", 
                "text": "This website gives you access to the IMDI-based language resources (LRs) housed at the TST-centrale.", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }
            ]
          }
        ], 
        "key_descriptor": [
          {
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIFWDCCBECgAwIBAgIQJ/7FXBoKUGe92mfIdkjkTzANBgkqhkiG9w0BAQUFADCB\niTELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G\nA1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxLzAtBgNV\nBAMTJkNPTU9ETyBIaWdoIEFzc3VyYW5jZSBTZWN1cmUgU2VydmVyIENBMB4XDTA5\nMDYxNTAwMDAwMFoXDTE0MDYxNTIzNTk1OVowgdkxCzAJBgNVBAYTAk5MMRAwDgYD\nVQQREwcyMzExIEJaMRUwEwYDVQQIEwxadWlkLUhvbGxhbmQxDzANBgNVBAcTBkxl\naWRlbjEhMB8GA1UECRMYTWF0dGhpYXMgZGUgVnJpZXNob2YgMi0zMTIwMAYDVQQK\nEylTdCBJbnN0aXR1dXQgdm9vciBOZWRlcmxhbmRzZSBMZXhpY29sb2dpZTEaMBgG\nA1UECxMRQ29tb2RvIEluc3RhbnRTU0wxHTAbBgNVBAMTFHNwLmRldi5jbGFyaW4u\naW5sLm5sMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCo9rdfDu13+/wOF5/f\nAyUVKFtr2lTIEXdafTiYNzddM4A8adWmpaMxhkUeGdviz97L4m23KxI/Pf/J/wq2\nmmHtOEAYwmQgXb+ltT8Gf9aknvyphzEiH/hNYp+qoOxQ1RSFMCnX3QLl5VMrLyHM\norAwTQL0uLr/EuzMcViolKcOnwIDAQABo4IB7DCCAegwHwYDVR0jBBgwFoAUYFnN\ngMfF46uML/xr5VsK9Q/eS/8wHQYDVR0OBBYEFC7a6OPUS99Y35xiMz3fPk2ilJTF\nMA4GA1UdDwEB/wQEAwIFoDAMBgNVHRMBAf8EAjAAMDQGA1UdJQQtMCsGCCsGAQUF\nBwMBBggrBgEFBQcDAgYKKwYBBAGCNwoDAwYJYIZIAYb4QgQBMEYGA1UdIAQ/MD0w\nOwYMKwYBBAGyMQECAQMEMCswKQYIKwYBBQUHAgEWHWh0dHBzOi8vc2VjdXJlLmNv\nbW9kby5uZXQvQ1BTME4GA1UdHwRHMEUwQ6BBoD+GPWh0dHA6Ly9jcmwuY29tb2Rv\nY2EuY29tL0NvbW9kb0hpZ2hBc3N1cmFuY2VTZWN1cmVTZXJ2ZXJDQS5jcmwwfwYI\nKwYBBQUHAQEEczBxMEkGCCsGAQUFBzAChj1odHRwOi8vY3J0LmNvbW9kb2NhLmNv\nbS9Db21vZG9IaWdoQXNzdXJhbmNlU2VjdXJlU2VydmVyQ0EuY3J0MCQGCCsGAQUF\nBzABhhhodHRwOi8vb2NzcC5jb21vZG9jYS5jb20wOQYDVR0RBDIwMIIUc3AuZGV2\nLmNsYXJpbi5pbmwubmyCGHd3dy5zcC5kZXYuY2xhcmluLmlubC5ubDANBgkqhkiG\n9w0BAQUFAAOCAQEAjtEgHw+TblkdTK5utNytnxEuQ3lPT5eEMyN+o6V00L51u+F6\nuh+yPdTH5UBXnTWbAc+RRlfYQDE+5x6v8FDyyO1Znf5pKYFoquO9ym8JqjHXEZQY\ns9z/lt6TM7NKiCZO7S7FC8HHzPrnU0kwzgmf6f+Y7fRzOAuDfLxnUZwlpAaGs1R6\nnS2MgFakP+X/ZNjrWETQriNNGSBGbYfcdB1QuoMgJuXkU6zs7DhmHP838uFAQjYi\nOC/70RsuE1f4nsgjJ+jT9x/DoVqV2YbW0gGNyGpWPTH4csvE23Z1dFINIymVUlt9\nMLV2RZ8HHAgA9AeBjEdJIavF9Q9H6a59eFcx4A==", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ]
      }
    ]
  }, 
  "https://crowd.nordu.net/shibboleth": {
    "valid_until": "2012-12-16T04:23:08Z", 
    "organization": {
      "organization_name": [
        {
          "lang": "en", 
          "text": "NORDUnet", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }
      ], 
      "organization_display_name": [
        {
          "lang": "en", 
          "text": "NORDUnet A/S", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }
      ], 
      "organization_url": [
        {
          "lang": "en", 
          "text": "http://www.nordu.net", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }
      ], 
      "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Organization"
    }, 
    "entity_id": "https://crowd.nordu.net/shibboleth", 
    "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EntityDescriptor", 
    "spsso_descriptor": [
      {
        "single_logout_service": [
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:SOAP", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleLogoutService", 
            "location": "https://crowd.nordu.net/Shibboleth.sso/SLO/SOAP"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleLogoutService", 
            "location": "https://crowd.nordu.net/Shibboleth.sso/SLO/Redirect"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleLogoutService", 
            "location": "https://crowd.nordu.net/Shibboleth.sso/SLO/POST"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleLogoutService", 
            "location": "https://crowd.nordu.net/Shibboleth.sso/SLO/Artifact"
          }
        ], 
        "attribute_consuming_service": [
          {
            "index": "0", 
            "service_description": [
              {
                "lang": "en", 
                "text": "NORDUnet Tools (confluence, jira)", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }
            ], 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AttributeConsumingService", 
            "requested_attribute": [
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:0.9.2342.19200300.100.1.3"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.42"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.4"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.9"
              }
            ], 
            "service_name": [
              {
                "lang": "en", 
                "text": "NORDUnet Tools", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }
            ]
          }
        ], 
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "assertion_consumer_service": [
          {
            "index": "1", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://crowd.nordu.net/Shibboleth.sso/SAML2/POST"
          }, 
          {
            "index": "2", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://crowd.nordu.net/Shibboleth.sso/SAML2/POST-SimpleSign"
          }, 
          {
            "index": "3", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://crowd.nordu.net/Shibboleth.sso/SAML2/Artifact"
          }, 
          {
            "index": "4", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:PAOS", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://crowd.nordu.net/Shibboleth.sso/SAML2/ECP"
          }, 
          {
            "index": "5", 
            "binding": "urn:oasis:names:tc:SAML:1.0:profiles:browser-post", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://crowd.nordu.net/Shibboleth.sso/SAML/POST"
          }, 
          {
            "index": "6", 
            "binding": "urn:oasis:names:tc:SAML:1.0:profiles:artifact-01", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://crowd.nordu.net/Shibboleth.sso/SAML/Artifact"
          }
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SPSSODescriptor", 
        "extensions": {
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Extensions", 
          "extension_elements": [
            {
              "index": "1", 
              "binding": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol", 
              "__class__": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol&DiscoveryResponse", 
              "location": "https://crowd.nordu.net/Shibboleth.sso/DS/ds.swamid.se"
            }, 
            {
              "index": "2", 
              "binding": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol", 
              "__class__": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol&DiscoveryResponse", 
              "location": "https://crowd.nordu.net/Shibboleth.sso/DS/nordu.net"
            }, 
            {
              "index": "3", 
              "binding": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol", 
              "__class__": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol&DiscoveryResponse", 
              "location": "https://crowd.nordu.net/Shibboleth.sso/DS/kalmar2"
            }, 
            {
              "attribute_value": [
                {
                  "text": "kalmar", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }, 
                {
                  "text": "sweden", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }
              ], 
              "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&Attribute", 
              "name": "tags"
            }
          ]
        }, 
        "key_descriptor": [
          {
            "use": "signing", 
            "key_info": {
              "key_name": [
                {
                  "text": "crowd.nordu.net", 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyName"
                }
              ], 
              "x509_data": [
                {
                  "x509_subject_name": {
                    "text": "CN=crowd.nordu.net", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509SubjectName"
                  }, 
                  "x509_certificate": {
                    "text": "MIIC9DCCAdygAwIBAgIJANmt8Ciw6kb/MA0GCSqGSIb3DQEBBQUAMBoxGDAWBgNV\nBAMTD2Nyb3dkLm5vcmR1Lm5ldDAeFw0xMDA1MzExMTI4MzVaFw0yMDA1MjgxMTI4\nMzVaMBoxGDAWBgNVBAMTD2Nyb3dkLm5vcmR1Lm5ldDCCASIwDQYJKoZIhvcNAQEB\nBQADggEPADCCAQoCggEBAPX2dT9VdcfFwxu7VA00KB7MmJj43/ReptLZNF1qEIEY\nLurgE63gRpalC1RLNx40V0a692ae9vlUJwr5SSuPE///KcIGe7MqKYqxMNR0EVUM\ngkLl/Iws6X6IKPXZFg/WeE/C/cmU6OzaTwdPBmg360Ys9veUOnt/3/ddRhSGRlr/\nQhrFJwZpeRQG/G7f8wIrvVT6HvsY1QOjW6YV43fon8eMBFz1WV7dAAx4L5d1JXX3\nEH+vY6a1nRj98qZPXZ7MY4HBMS8uU/B2/zTN+N9DFBpbwHYWvZQynIviGrUlgGi6\nbDMJH2k+sTGgy9EGZcaAqb2AECMidmXJk3/nOsX5cFECAwEAAaM9MDswGgYDVR0R\nBBMwEYIPY3Jvd2Qubm9yZHUubmV0MB0GA1UdDgQWBBTvR6U7d9zdmqbIl+g3SLa9\n8CChvzANBgkqhkiG9w0BAQUFAAOCAQEAWvDhU3Tk+cCZoThs2I2HLChX7cEjsjz9\n3ZHdWbsgJzPS0xVAdoR1FraNf6PYUvZxbDhsoO2UEZS5IUyOxdWWuP2jaqUpVxY/\n1fSTQQbvOujO+fZzNhJ8nIy/4FgFDWWqABHbVTfGVzImcxC1AJoQ8jkU9Dio5dIl\nuKQCDz8fu1hbkQZ/NP53cNDkTV0t/bvRtEHGrOJYc1rEFRuTLSkPvItsGffWHhIC\nmCrhgP7LeIv2iiNK7qgbhaFRHXAs/JMXAc/Y4YD1renUQCA4cLPF679N4oixMvxD\nNeib9lWMnEYRIynoqQE3UXYnb3GDinEg/soKH73QAq0dyjcfuk30FA==", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }, 
          {
            "use": "encryption", 
            "key_info": {
              "key_name": [
                {
                  "text": "crowd.nordu.net", 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyName"
                }
              ], 
              "x509_data": [
                {
                  "x509_subject_name": {
                    "text": "CN=crowd.nordu.net", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509SubjectName"
                  }, 
                  "x509_certificate": {
                    "text": "MIIC9DCCAdygAwIBAgIJANmt8Ciw6kb/MA0GCSqGSIb3DQEBBQUAMBoxGDAWBgNV\nBAMTD2Nyb3dkLm5vcmR1Lm5ldDAeFw0xMDA1MzExMTI4MzVaFw0yMDA1MjgxMTI4\nMzVaMBoxGDAWBgNVBAMTD2Nyb3dkLm5vcmR1Lm5ldDCCASIwDQYJKoZIhvcNAQEB\nBQADggEPADCCAQoCggEBAPX2dT9VdcfFwxu7VA00KB7MmJj43/ReptLZNF1qEIEY\nLurgE63gRpalC1RLNx40V0a692ae9vlUJwr5SSuPE///KcIGe7MqKYqxMNR0EVUM\ngkLl/Iws6X6IKPXZFg/WeE/C/cmU6OzaTwdPBmg360Ys9veUOnt/3/ddRhSGRlr/\nQhrFJwZpeRQG/G7f8wIrvVT6HvsY1QOjW6YV43fon8eMBFz1WV7dAAx4L5d1JXX3\nEH+vY6a1nRj98qZPXZ7MY4HBMS8uU/B2/zTN+N9DFBpbwHYWvZQynIviGrUlgGi6\nbDMJH2k+sTGgy9EGZcaAqb2AECMidmXJk3/nOsX5cFECAwEAAaM9MDswGgYDVR0R\nBBMwEYIPY3Jvd2Qubm9yZHUubmV0MB0GA1UdDgQWBBTvR6U7d9zdmqbIl+g3SLa9\n8CChvzANBgkqhkiG9w0BAQUFAAOCAQEAWvDhU3Tk+cCZoThs2I2HLChX7cEjsjz9\n3ZHdWbsgJzPS0xVAdoR1FraNf6PYUvZxbDhsoO2UEZS5IUyOxdWWuP2jaqUpVxY/\n1fSTQQbvOujO+fZzNhJ8nIy/4FgFDWWqABHbVTfGVzImcxC1AJoQ8jkU9Dio5dIl\nuKQCDz8fu1hbkQZ/NP53cNDkTV0t/bvRtEHGrOJYc1rEFRuTLSkPvItsGffWHhIC\nmCrhgP7LeIv2iiNK7qgbhaFRHXAs/JMXAc/Y4YD1renUQCA4cLPF679N4oixMvxD\nNeib9lWMnEYRIynoqQE3UXYnb3GDinEg/soKH73QAq0dyjcfuk30FA==", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ], 
        "artifact_resolution_service": [
          {
            "index": "1", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:SOAP", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ArtifactResolutionService", 
            "location": "https://crowd.nordu.net/Shibboleth.sso/Artifact/SOAP"
          }
        ], 
        "manage_name_id_service": [
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:SOAP", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ManageNameIDService", 
            "location": "https://crowd.nordu.net/Shibboleth.sso/NIM/SOAP"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ManageNameIDService", 
            "location": "https://crowd.nordu.net/Shibboleth.sso/NIM/Redirect"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ManageNameIDService", 
            "location": "https://crowd.nordu.net/Shibboleth.sso/NIM/POST"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ManageNameIDService", 
            "location": "https://crowd.nordu.net/Shibboleth.sso/NIM/Artifact"
          }
        ]
      }
    ]
  }, 
  "https://idp.it.gu.se/idp/shibboleth": {
    "valid_until": "2012-12-16T04:23:08Z", 
    "entity_id": "https://idp.it.gu.se/idp/shibboleth", 
    "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EntityDescriptor", 
    "idpsso_descriptor": [
      {
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&IDPSSODescriptor", 
        "single_sign_on_service": [
          {
            "binding": "urn:mace:shibboleth:1.0:profiles:AuthnRequest", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleSignOnService", 
            "location": "https://idp.it.gu.se/idp/profile/Shibboleth/SSO"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleSignOnService", 
            "location": "https://idp.it.gu.se/idp/profile/SAML2/POST/SSO"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleSignOnService", 
            "location": "https://idp.it.gu.se/idp/profile/SAML2/POST-SimpleSign/SSO"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleSignOnService", 
            "location": "https://idp.it.gu.se/idp/profile/SAML2/Redirect/SSO"
          }
        ], 
        "extensions": {
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Extensions", 
          "extension_elements": [
            {
              "logo": [
                {
                  "lang": "sv", 
                  "text": "https://www.gu.se/digitalAssets/1374/1374690_lo_gu_left.png", 
                  "width": "344", 
                  "__class__": "urn:oasis:names:tc:SAML:metadata:ui&Logo", 
                  "height": "50"
                }, 
                {
                  "lang": "en", 
                  "text": "https://www.gu.se/digitalAssets/1374/1374690_lo_gu_left.png", 
                  "width": "376", 
                  "__class__": "urn:oasis:names:tc:SAML:metadata:ui&Logo", 
                  "height": "50"
                }
              ], 
              "display_name": [
                {
                  "lang": "sv", 
                  "text": "G\u00f6teborgs universitet", 
                  "__class__": "urn:oasis:names:tc:SAML:metadata:ui&DisplayName"
                }, 
                {
                  "lang": "en", 
                  "text": "University of Gothenburg", 
                  "__class__": "urn:oasis:names:tc:SAML:metadata:ui&DisplayName"
                }
              ], 
              "__class__": "urn:oasis:names:tc:SAML:metadata:ui&UIInfo", 
              "description": [
                {
                  "lang": "sv", 
                  "text": "Identity Provider f\u00f6r anst\u00e4llda och studenter vid G\u00f6teborgs universitet.", 
                  "__class__": "urn:oasis:names:tc:SAML:metadata:ui&Description"
                }, 
                {
                  "lang": "en", 
                  "text": "The University of Gothenburg Identity Provider is used by employees and students at the university.", 
                  "__class__": "urn:oasis:names:tc:SAML:metadata:ui&Description"
                }
              ]
            }, 
            {
              "__class__": "urn:oasis:names:tc:SAML:metadata:ui&DiscoHints", 
              "geolocation_hint": [
                {
                  "text": "geo:57.6986,11.9712", 
                  "__class__": "urn:oasis:names:tc:SAML:metadata:ui&GeolocationHint"
                }
              ], 
              "domain_hint": [
                {
                  "text": "gu.se", 
                  "__class__": "urn:oasis:names:tc:SAML:metadata:ui&DomainHint"
                }
              ]
            }, 
            {
              "attribute_value": [
                {
                  "text": "kalmar", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }, 
                {
                  "text": "sweden", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }
              ], 
              "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&Attribute", 
              "name": "tags"
            }
          ]
        }, 
        "key_descriptor": [
          {
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIDGzCCAgOgAwIBAgIUGLU4YqWFYHboh+F+iLNYkBw8XNAwDQYJKoZIhvcNAQEF\nBQAwFzEVMBMGA1UEAxMMaWRwLml0Lmd1LnNlMB4XDTA5MDgyNDExMzA1OFoXDTI5\nMDgyNDExMzA1OFowFzEVMBMGA1UEAxMMaWRwLml0Lmd1LnNlMIIBIjANBgkqhkiG\n9w0BAQEFAAOCAQ8AMIIBCgKCAQEApOVkzaHuTCe+7lf79UnQ5iQ/8OLbJpwOxPTF\nwEPIHbMMU/aCVnxoZnwNApblqvpP2uOsQvh8d0uDv2iVC5BMN0ff9M+9rN7D/gAo\nL+w8CmWiHRudKyZLu8Gu89SGxyQ59AVCbJzGaEE9h/CmMYHCj/ONJ8mtjG9uw6u+\nVj+L8PHXsPHQsLvcl3/D7duIYH/xHRbPzXS0imux+r/OcSCR3aCPCx3uuAfVPxGS\n9Y/ifynV586V3szIM7O15SeXKenFMKjQhzA23ZPcHhDSxWnVGUDWFDRDNAXfD7BF\nKRBCaUlWZvczqsV3eGtW8XgOmuW/7yJT5REfrrSLOKprAK8yoQIDAQABo18wXTA8\nBgNVHREENTAzggxpZHAuaXQuZ3Uuc2WGI2h0dHBzOi8vaWRwLml0Lmd1LnNlL2lk\ncC9zaGliYm9sZXRoMB0GA1UdDgQWBBSpKDUl7ZRxhQ1/HRmVbFd+NbwxmzANBgkq\nhkiG9w0BAQUFAAOCAQEAXfaYlHQj4KRaJmMbWFV0XyNUlHNio8010vLv3t6WztlZ\njZFL/hTQIFhmYEA04Davdk+1/1JvcRePSpg2VCxT/QwHyOR3eimmQ6FKXWls/zO/\nV01sJrlLdf/53pzXYsVSOf50UK+GtrSB3hhzrFmeaBALOysGqk2h2/UdYISXxa/e\nMyQ/aOI5u+0Wlq2RdIXF8MrtnwBTRhNXLcXYzz4fPsdjd4TmmJLQLXLmFLE/IA+/\nCP9nuvekzvPla7AXlXPwPvbUunwZIZkN3aHzMY/08FKIYRLb9VmqInKXw8tIBSqG\nMoX9SCDPBh2j39QZupTaPkylXDshurod7B2XtXdHPg==", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ], 
        "artifact_resolution_service": [
          {
            "index": "1", 
            "binding": "urn:oasis:names:tc:SAML:1.0:bindings:SOAP-binding", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ArtifactResolutionService", 
            "location": "https://idp.it.gu.se:8443/idp/profile/SAML1/SOAP/ArtifactResolution"
          }, 
          {
            "index": "2", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:SOAP", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ArtifactResolutionService", 
            "location": "https://idp.it.gu.se:8443/idp/profile/SAML2/SOAP/ArtifactResolution"
          }
        ], 
        "name_id_format": [
          {
            "text": "urn:mace:shibboleth:1.0:nameIdentifier", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }, 
          {
            "text": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }
        ]
      }
    ], 
    "attribute_authority_descriptor": [
      {
        "attribute_service": [
          {
            "binding": "urn:oasis:names:tc:SAML:1.0:bindings:SOAP-binding", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AttributeService", 
            "location": "https://idp.it.gu.se:8443/idp/profile/SAML1/SOAP/AttributeQuery"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:SOAP", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AttributeService", 
            "location": "https://idp.it.gu.se:8443/idp/profile/SAML2/SOAP/AttributeQuery"
          }
        ], 
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AttributeAuthorityDescriptor", 
        "extensions": {
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Extensions"
        }, 
        "key_descriptor": [
          {
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIDGzCCAgOgAwIBAgIUGLU4YqWFYHboh+F+iLNYkBw8XNAwDQYJKoZIhvcNAQEF\nBQAwFzEVMBMGA1UEAxMMaWRwLml0Lmd1LnNlMB4XDTA5MDgyNDExMzA1OFoXDTI5\nMDgyNDExMzA1OFowFzEVMBMGA1UEAxMMaWRwLml0Lmd1LnNlMIIBIjANBgkqhkiG\n9w0BAQEFAAOCAQ8AMIIBCgKCAQEApOVkzaHuTCe+7lf79UnQ5iQ/8OLbJpwOxPTF\nwEPIHbMMU/aCVnxoZnwNApblqvpP2uOsQvh8d0uDv2iVC5BMN0ff9M+9rN7D/gAo\nL+w8CmWiHRudKyZLu8Gu89SGxyQ59AVCbJzGaEE9h/CmMYHCj/ONJ8mtjG9uw6u+\nVj+L8PHXsPHQsLvcl3/D7duIYH/xHRbPzXS0imux+r/OcSCR3aCPCx3uuAfVPxGS\n9Y/ifynV586V3szIM7O15SeXKenFMKjQhzA23ZPcHhDSxWnVGUDWFDRDNAXfD7BF\nKRBCaUlWZvczqsV3eGtW8XgOmuW/7yJT5REfrrSLOKprAK8yoQIDAQABo18wXTA8\nBgNVHREENTAzggxpZHAuaXQuZ3Uuc2WGI2h0dHBzOi8vaWRwLml0Lmd1LnNlL2lk\ncC9zaGliYm9sZXRoMB0GA1UdDgQWBBSpKDUl7ZRxhQ1/HRmVbFd+NbwxmzANBgkq\nhkiG9w0BAQUFAAOCAQEAXfaYlHQj4KRaJmMbWFV0XyNUlHNio8010vLv3t6WztlZ\njZFL/hTQIFhmYEA04Davdk+1/1JvcRePSpg2VCxT/QwHyOR3eimmQ6FKXWls/zO/\nV01sJrlLdf/53pzXYsVSOf50UK+GtrSB3hhzrFmeaBALOysGqk2h2/UdYISXxa/e\nMyQ/aOI5u+0Wlq2RdIXF8MrtnwBTRhNXLcXYzz4fPsdjd4TmmJLQLXLmFLE/IA+/\nCP9nuvekzvPla7AXlXPwPvbUunwZIZkN3aHzMY/08FKIYRLb9VmqInKXw8tIBSqG\nMoX9SCDPBh2j39QZupTaPkylXDshurod7B2XtXdHPg==", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ], 
        "name_id_format": [
          {
            "text": "urn:mace:shibboleth:1.0:nameIdentifier", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }, 
          {
            "text": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }
        ]
      }
    ], 
    "organization": {
      "organization_name": [
        {
          "lang": "en", 
          "text": "GU", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }
      ], 
      "organization_display_name": [
        {
          "lang": "en", 
          "text": "G\u00f6teborgs universitet", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }
      ], 
      "organization_url": [
        {
          "lang": "en", 
          "text": "http://www.gu.se", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }
      ], 
      "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Organization"
    }, 
    "contact_person": [
      {
        "company": {
          "text": "G\u00f6teborgs universitet", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Company"
        }, 
        "email_address": [
          {
            "text": "pablo.millet@gu.se", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "contact_type": "technical"
      }
    ]
  }, 
  "https://openwiki.uninett.no/simplesaml/module.php/saml/sp/metadata.php/default-sp": {
    "valid_until": "2012-12-19T20:14:03Z", 
    "contact_person": [
      {
        "contact_type": "technical", 
        "company": {
          "text": "UNINETT AS", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Company"
        }, 
        "telephone_number": [
          {
            "text": "+47 73557894", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&TelephoneNumber"
          }
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "sur_name": {
          "text": "Solberg", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SurName"
        }, 
        "given_name": {
          "text": "Andreas", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&GivenName"
        }, 
        "email_address": [
          {
            "text": "andreas.solberg@uninett.no", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ]
      }
    ], 
    "entity_id": "https://openwiki.uninett.no/simplesaml/module.php/saml/sp/metadata.php/default-sp", 
    "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EntityDescriptor", 
    "spsso_descriptor": [
      {
        "single_logout_service": [
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleLogoutService", 
            "location": "https://openwiki.uninett.no/simplesaml/module.php/saml/sp/saml2-logout.php/default-sp"
          }
        ], 
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "assertion_consumer_service": [
          {
            "index": "0", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://openwiki.uninett.no/simplesaml/module.php/saml/sp/saml2-acs.php/default-sp"
          }
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SPSSODescriptor", 
        "key_descriptor": [
          {
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIEGzCCAwOgAwIBAgIJAOrEig4Ycg6MMA0GCSqGSIb3DQEBBQUAMGYxCzAJBgNVBAYTAk5PMRIwEAYDVQQIEwlUcm9uZGhlaW0xEjAQBgNVBAcTCVRyb25kaGVpbTETMBEGA1UEChMKVU5JTkVUVCBBUzEaMBgGA1UEAxMRb3Blbndpa2kuZmVpZGUubm8wHhcNMTIxMDA1MTIzOTI5WhcNMjIxMDA1MTIzOTI5WjBmMQswCQYDVQQGEwJOTzESMBAGA1UECBMJVHJvbmRoZWltMRIwEAYDVQQHEwlUcm9uZGhlaW0xEzARBgNVBAoTClVOSU5FVFQgQVMxGjAYBgNVBAMTEW9wZW53aWtpLmZlaWRlLm5vMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAySsOo8gS8Gx7oQ19CIhVJ5wyJhAW9w073MH0xsSPseqWMur67LSCeT3gN5KFNJ2SP13xD2Htutc1oTMzufdmWviWGQisArcpmFaBbQoJQHSjdYxbKMQ57NXb9wzzp3uQjkzNrMBqekYFy5LtQirOjlEY3fzatWXjwa9IZvqb2u7B0wxpVZjyvuuoklMSYnHom1d+a/crQrNhYEPwm+6juXn8S4/bNxuOvpfUWcuLp90BVvlx3QOUqHI09hLRMU9Ab2C/nVUViUCDuB4mHSmZoj04IbKpdgNlR9HMJjB1p0RbpMG5IZ4NtmgxQkPbU5+ABj6ItzOK0vcto/zD8DHeGQIDAQABo4HLMIHIMB0GA1UdDgQWBBTCEFpRccjnmaW7kroNrJ2iLTYkgTCBmAYDVR0jBIGQMIGNgBTCEFpRccjnmaW7kroNrJ2iLTYkgaFqpGgwZjELMAkGA1UEBhMCTk8xEjAQBgNVBAgTCVRyb25kaGVpbTESMBAGA1UEBxMJVHJvbmRoZWltMRMwEQYDVQQKEwpVTklORVRUIEFTMRowGAYDVQQDExFvcGVud2lraS5mZWlkZS5ub4IJAOrEig4Ycg6MMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAIWi86krhY7Sou8ggyQmwNtq2+qDnJuvJx2Pt4LMCmubxFH6rFXRsoxj7UmmeklScvgZeOT8pcd4rFhqEgh6eX9V5achDeKYqeCt3RVIjhe33O44Lc+cjNmQCchf55QI+qnG7ATtYdDWu37AzXL6q6POVuxx2XHggWPpSlreU+4QWV5wfqWBXblyEFjLoFXzq3yVfTW4N/yM8UXZTUdPiFKmqQ2gmlDSo7EloCE2OMOsbbyTvoXHLMa3mVjfpyk+iEDNsKq/1AHVgDqekE8EH52pWeTOPmx6lGTbviwPvpIDHGxkBv9AZ2JAoN185KET7AuQN1H6neiB9TGnYYuAZGA=", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ], 
        "attribute_consuming_service": [
          {
            "index": "0", 
            "service_description": [
              {
                "lang": "en", 
                "text": "UNINETT OpenWiki is a wikifarm where Feide users can create their own wiki.", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }, 
              {
                "lang": "no", 
                "text": "UNINETT OpenWiki er en wikifarm hvor Feidebrukere kan lage egne wikier.", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }, 
              {
                "lang": "nn", 
                "text": "UNINETT OpenWiki er ein wikifarm der Feidebrukarar kan lage eigne wikiar.", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }
            ], 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AttributeConsumingService", 
            "requested_attribute": [
              {
                "friendly_name": "eduPersonPrincipalName", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
              }, 
              {
                "friendly_name": "mail", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:0.9.2342.19200300.100.1.3"
              }, 
              {
                "friendly_name": "cn", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.3"
              }, 
              {
                "friendly_name": "displayName", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.16.840.1.113730.3.1.241"
              }, 
              {
                "friendly_name": "sn", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.4"
              }, 
              {
                "friendly_name": "givenName", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.42"
              }, 
              {
                "friendly_name": "preferredLanguage", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.16.840.1.113730.3.1.39"
              }, 
              {
                "friendly_name": "eduPersonAffiliation", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.1"
              }
            ], 
            "service_name": [
              {
                "lang": "en", 
                "text": "UNINETT OpenWiki", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }
            ]
          }
        ]
      }
    ]
  }, 
  "https://connect-stable.sunet.se/shibboleth": {
    "valid_until": "2012-12-16T04:23:08Z", 
    "entity_id": "https://connect-stable.sunet.se/shibboleth", 
    "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EntityDescriptor", 
    "extensions": {
      "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Extensions", 
      "extension_elements": [
        {
          "attribute": [
            {
              "attribute_value": [
                {
                  "text": "http://www.swamid.se/category/research-and-education", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }, 
                {
                  "text": "http://www.swamid.se/category/nren-service", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }, 
                {
                  "text": "http://www.swamid.se/category/eu-adequate-protection", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }
              ], 
              "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&Attribute", 
              "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
              "name": "http://macedir.org/entity-category"
            }
          ], 
          "__class__": "urn:oasis:names:tc:SAML:metadata:attribute&EntityAttributes"
        }, 
        {
          "attribute_value": [
            {
              "text": "kalmar", 
              "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
              "extension_attributes": {
                "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
              }
            }, 
            {
              "text": "sweden", 
              "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
              "extension_attributes": {
                "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
              }
            }
          ], 
          "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&Attribute", 
          "name": "tags"
        }
      ]
    }, 
    "organization": {
      "organization_name": [
        {
          "lang": "en", 
          "text": "NORDUnet", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }
      ], 
      "organization_display_name": [
        {
          "lang": "en", 
          "text": "NORDUnet A/S", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }
      ], 
      "organization_url": [
        {
          "lang": "en", 
          "text": "http://www.nordu.net", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }
      ], 
      "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Organization"
    }, 
    "spsso_descriptor": [
      {
        "single_logout_service": [
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:SOAP", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleLogoutService", 
            "location": "https://connect-stable.sunet.se/Shibboleth.sso/SLO/SOAP"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleLogoutService", 
            "location": "https://connect-stable.sunet.se/Shibboleth.sso/SLO/Redirect"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleLogoutService", 
            "location": "https://connect-stable.sunet.se/Shibboleth.sso/SLO/POST"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleLogoutService", 
            "location": "https://connect-stable.sunet.se/Shibboleth.sso/SLO/Artifact"
          }
        ], 
        "attribute_consuming_service": [
          {
            "index": "0", 
            "service_description": [
              {
                "lang": "en", 
                "text": "SUNET E-Meeting Service (stable)", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }
            ], 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AttributeConsumingService", 
            "requested_attribute": [
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:0.9.2342.19200300.100.1.3"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.42"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.4"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.9"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.1"
              }
            ], 
            "service_name": [
              {
                "lang": "en", 
                "text": "SUNET E-Meeting Service (stable)", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }
            ]
          }
        ], 
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "assertion_consumer_service": [
          {
            "index": "1", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://connect-stable.sunet.se/Shibboleth.sso/SAML2/POST"
          }, 
          {
            "index": "2", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://connect-stable.sunet.se/Shibboleth.sso/SAML2/POST-SimpleSign"
          }, 
          {
            "index": "3", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://connect-stable.sunet.se/Shibboleth.sso/SAML2/Artifact"
          }, 
          {
            "index": "4", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:PAOS", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://connect-stable.sunet.se/Shibboleth.sso/SAML2/ECP"
          }, 
          {
            "index": "5", 
            "binding": "urn:oasis:names:tc:SAML:1.0:profiles:browser-post", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://connect-stable.sunet.se/Shibboleth.sso/SAML/POST"
          }, 
          {
            "index": "6", 
            "binding": "urn:oasis:names:tc:SAML:1.0:profiles:artifact-01", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://connect-stable.sunet.se/Shibboleth.sso/SAML/Artifact"
          }
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SPSSODescriptor", 
        "extensions": {
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Extensions", 
          "extension_elements": [
            {
              "index": "1", 
              "binding": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol", 
              "__class__": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol&DiscoveryResponse", 
              "location": "https://connect-stable.sunet.se/Shibboleth.sso/DS/ds.swamid.se"
            }, 
            {
              "index": "2", 
              "binding": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol", 
              "__class__": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol&DiscoveryResponse", 
              "location": "https://connect-stable.sunet.se/Shibboleth.sso/DS/ds.sunet.se"
            }, 
            {
              "index": "3", 
              "binding": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol", 
              "__class__": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol&DiscoveryResponse", 
              "location": "https://connect-stable.sunet.se/Shibboleth.sso/DS/kalmar2"
            }, 
            {
              "index": "4", 
              "binding": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol", 
              "__class__": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol&DiscoveryResponse", 
              "location": "https://connect-stable.sunet.se/Shibboleth.sso/DS/nordu.net"
            }
          ]
        }, 
        "key_descriptor": [
          {
            "use": "signing", 
            "key_info": {
              "key_name": [
                {
                  "text": "connect-stable.sunet.se", 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyName"
                }
              ], 
              "x509_data": [
                {
                  "x509_subject_name": {
                    "text": "CN=connect-stable.sunet.se", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509SubjectName"
                  }, 
                  "x509_certificate": {
                    "text": "MIIDDDCCAfSgAwIBAgIJAJ+bOx8RXj3iMA0GCSqGSIb3DQEBBQUAMCIxIDAeBgNV\nBAMTF2Nvbm5lY3Qtc3RhYmxlLnN1bmV0LnNlMB4XDTEyMTEwMTE0MTEzNFoXDTIy\nMTAzMDE0MTEzNFowIjEgMB4GA1UEAxMXY29ubmVjdC1zdGFibGUuc3VuZXQuc2Uw\nggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDOuf57LwczW6o8YEv8IlZe\n6mWurJUD3iDMS1jyt9/HxUpHcQfMVrHmei7aBLzYiQMON7sYSi0pQ6/EtFMpoaeN\nWYIAEXdXVfhGVCte9mfTmLEtgxsELyK+YofXwTXkNX1VzBK3z9qRyV6BBqzgA6Zu\n4BkTabmubG4qdwHf+TJWfwJ9QkwOIuy+j+KCXELW8Cgy1q8WUvocpTfEXzILEHL8\nkel1ej8sclf0cdHjYLJpPSaBvJ+2DmvZgVLdZcWxSVLbwoMOFq4g5spFT8bZxemY\nmG185UwcQtFK3VoXdfiBn28HChMgdSxSWvt8CWj3dK49i6/eKaq/0Dam3SPHbJIN\nAgMBAAGjRTBDMCIGA1UdEQQbMBmCF2Nvbm5lY3Qtc3RhYmxlLnN1bmV0LnNlMB0G\nA1UdDgQWBBQW0PGcUIDR4qgsERc7Jy1PpfkPujANBgkqhkiG9w0BAQUFAAOCAQEA\nQ7MY+AQRal0ZYIvqjw36YQZyBCGADzI/v5K1xMxGiPAj+WiSXRIHozVFRL8lqStO\n2zh68/yWkEl4SxyU0dQ+/YpZjolRMVNPxYaUd5YhhvpS4wOwwERhuMo1KOqO/04t\nTfN3/ASiYN5qhxO7DoJy0/jJwhy6QNE8Ey3FU4t2aFo9/FcUIE6huoBqLWMP5M4N\nXc+d9o3tWDW8EzEbxsyZhpin7qczxWHl5MeztPY3kvr4M6lVswf8KkGUxgdy1a5W\nEpnud0wADmhSb4J6hSbUreM6gyvYvMNI4Tzv5xxL/+CTuIv/Ys+IAKh/g2tT3ct0\nSgXS3Q4K3pF+qwGrb3INKQ==", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }, 
          {
            "use": "encryption", 
            "key_info": {
              "key_name": [
                {
                  "text": "connect-stable.sunet.se", 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyName"
                }
              ], 
              "x509_data": [
                {
                  "x509_subject_name": {
                    "text": "CN=connect-stable.sunet.se", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509SubjectName"
                  }, 
                  "x509_certificate": {
                    "text": "MIIDDDCCAfSgAwIBAgIJAJ+bOx8RXj3iMA0GCSqGSIb3DQEBBQUAMCIxIDAeBgNV\nBAMTF2Nvbm5lY3Qtc3RhYmxlLnN1bmV0LnNlMB4XDTEyMTEwMTE0MTEzNFoXDTIy\nMTAzMDE0MTEzNFowIjEgMB4GA1UEAxMXY29ubmVjdC1zdGFibGUuc3VuZXQuc2Uw\nggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDOuf57LwczW6o8YEv8IlZe\n6mWurJUD3iDMS1jyt9/HxUpHcQfMVrHmei7aBLzYiQMON7sYSi0pQ6/EtFMpoaeN\nWYIAEXdXVfhGVCte9mfTmLEtgxsELyK+YofXwTXkNX1VzBK3z9qRyV6BBqzgA6Zu\n4BkTabmubG4qdwHf+TJWfwJ9QkwOIuy+j+KCXELW8Cgy1q8WUvocpTfEXzILEHL8\nkel1ej8sclf0cdHjYLJpPSaBvJ+2DmvZgVLdZcWxSVLbwoMOFq4g5spFT8bZxemY\nmG185UwcQtFK3VoXdfiBn28HChMgdSxSWvt8CWj3dK49i6/eKaq/0Dam3SPHbJIN\nAgMBAAGjRTBDMCIGA1UdEQQbMBmCF2Nvbm5lY3Qtc3RhYmxlLnN1bmV0LnNlMB0G\nA1UdDgQWBBQW0PGcUIDR4qgsERc7Jy1PpfkPujANBgkqhkiG9w0BAQUFAAOCAQEA\nQ7MY+AQRal0ZYIvqjw36YQZyBCGADzI/v5K1xMxGiPAj+WiSXRIHozVFRL8lqStO\n2zh68/yWkEl4SxyU0dQ+/YpZjolRMVNPxYaUd5YhhvpS4wOwwERhuMo1KOqO/04t\nTfN3/ASiYN5qhxO7DoJy0/jJwhy6QNE8Ey3FU4t2aFo9/FcUIE6huoBqLWMP5M4N\nXc+d9o3tWDW8EzEbxsyZhpin7qczxWHl5MeztPY3kvr4M6lVswf8KkGUxgdy1a5W\nEpnud0wADmhSb4J6hSbUreM6gyvYvMNI4Tzv5xxL/+CTuIv/Ys+IAKh/g2tT3ct0\nSgXS3Q4K3pF+qwGrb3INKQ==", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ], 
        "artifact_resolution_service": [
          {
            "index": "1", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:SOAP", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ArtifactResolutionService", 
            "location": "https://connect-stable.sunet.se/Shibboleth.sso/Artifact/SOAP"
          }
        ], 
        "manage_name_id_service": [
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:SOAP", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ManageNameIDService", 
            "location": "https://connect-stable.sunet.se/Shibboleth.sso/NIM/SOAP"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ManageNameIDService", 
            "location": "https://connect-stable.sunet.se/Shibboleth.sso/NIM/Redirect"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ManageNameIDService", 
            "location": "https://connect-stable.sunet.se/Shibboleth.sso/NIM/POST"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ManageNameIDService", 
            "location": "https://connect-stable.sunet.se/Shibboleth.sso/NIM/Artifact"
          }
        ]
      }
    ], 
    "contact_person": [
      {
        "company": {
          "text": "NORDUnet NOC", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Company"
        }, 
        "email_address": [
          {
            "text": "noc@nordu.net", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "contact_type": "technical"
      }
    ]
  }, 
  "https://idp.feide.no": {
    "valid_until": "2012-12-19T20:14:03Z", 
    "entity_id": "https://idp.feide.no", 
    "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EntityDescriptor", 
    "idpsso_descriptor": [
      {
        "single_logout_service": [
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleLogoutService", 
            "location": "https://idp.feide.no/simplesaml/saml2/idp/SingleLogoutService.php"
          }
        ], 
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&IDPSSODescriptor", 
        "single_sign_on_service": [
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleSignOnService", 
            "location": "https://idp.feide.no/simplesaml/saml2/idp/SSOService.php"
          }
        ], 
        "extensions": {
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Extensions", 
          "extension_elements": [
            {
              "attribute_value": [
                {
                  "text": "kalmar", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }, 
                {
                  "text": "norway", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }
              ], 
              "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&Attribute", 
              "name": "tags"
            }
          ]
        }, 
        "key_descriptor": [
          {
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIDhjCCAm4CCQCMHNhxUI2H1TANBgkqhkiG9w0BAQUFADCBhDELMAkGA1UEBhMCTk8xEjAQBgNVBAcTCVRyb25kaGVpbTETMBEGA1UEChMKVW5pbmV0dCBBUzEOMAwGA1UECxMFRkVJREUxFTATBgNVBAMTDGlkcC5mZWlkZS5ubzElMCMGCSqGSIb3DQEJARYWbW9yaWEtZHJpZnRAdW5pbmV0dC5ubzAeFw0wODA5MDUxMTU0MzNaFw0xODA3MTUxMTU0MzNaMIGEMQswCQYDVQQGEwJOTzESMBAGA1UEBxMJVHJvbmRoZWltMRMwEQYDVQQKEwpVbmluZXR0IEFTMQ4wDAYDVQQLEwVGRUlERTEVMBMGA1UEAxMMaWRwLmZlaWRlLm5vMSUwIwYJKoZIhvcNAQkBFhZtb3JpYS1kcmlmdEB1bmluZXR0Lm5vMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4fTsmIsKVGtniXddnerSeiLeAZAlAOL8v+ebzVzYcpTJzMHrplD+lF2tXxRgs7IGEw3t2zRCtxnGbiGkXPW+oCs4T989z+Sq8nh7Lff/XlyK+jQ7BtfC8RUYQ+eNEQy0Fif+81JyPbiwZovbiL4WrK1GOG81/2CF7rvwyXJkDD1YXJ5W18/c06YLfYJjuzZgEoCVRq6ecgQyPKg1xwIpW2GpkKOBXA7oKWtev+xcmSiLZwZE96mSHjty0L+wW6NUuf2/8VSCc4IED0EbzqFUoeHuGXqPak+tu9+VpP6vmmyp4gSCxsmWtoKm7UC8P1QeCyZxwQaoGlIp78wsE5ao5wIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQACUWuuirUSwDWksdkwKuqsNttnNmivwUMLtKDjHbMcwVK/b4qWjrAjfmJXxamUSYlnGjeoiqSQQuc3/qHCPAZUnN8VqXcZUCBXWjMO7Y/AnnsFKHpkYm51jWckjudeyfUr4UnH7te0OuUrGRIVrRRg3DqLdgrcbkJ98JyT97hnaDMke4qNVwrQFF+yvxYs1aYkILySBB/KPGSTh5sxJovcyWd7GY4ad5nH5oEjXF1yZzndmUuHGlTTzk6SGzmUJgqKyba+KJ/jauy6qNC1gPqfnbntWKDkE9a9ow8tlsi3jHI9AZu9U6LnOvTJ8MjhyXOEByCaDnTpK8JiZr6JvCaV", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ]
      }
    ], 
    "organization": {
      "organization_name": [
        {
          "lang": "en", 
          "text": "Feide - Norwegian Educational and Research Institusions", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }, 
        {
          "lang": "no", 
          "text": "Feide - Norske utdannings og forsknings-institusjoner", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }
      ], 
      "organization_display_name": [
        {
          "lang": "en", 
          "text": "Feide - Norwegian Educational and Research Institusions", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }, 
        {
          "lang": "no", 
          "text": "Feide - Norske utdannings og forsknings-institusjoner", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }
      ], 
      "organization_url": [
        {
          "lang": "en", 
          "text": "http://www.feide.no/introducing-feide", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }, 
        {
          "lang": "no", 
          "text": "http://www.feide.no/", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }
      ], 
      "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Organization"
    }, 
    "contact_person": [
      {
        "given_name": {
          "text": "Feide Support", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&GivenName"
        }, 
        "email_address": [
          {
            "text": "support@feide.no", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "contact_type": "technical"
      }, 
      {
        "given_name": {
          "text": "Feide Support", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&GivenName"
        }, 
        "email_address": [
          {
            "text": "support@feide.no", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "contact_type": "administrative"
      }
    ]
  }, 
  "https://nordunet.tv/shibboleth": {
    "valid_until": "2012-12-16T04:23:08Z", 
    "entity_id": "https://nordunet.tv/shibboleth", 
    "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EntityDescriptor", 
    "spsso_descriptor": [
      {
        "single_logout_service": [
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:SOAP", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleLogoutService", 
            "location": "https://nordunet.tv/Shibboleth.sso/SLO/SOAP"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleLogoutService", 
            "location": "https://nordunet.tv/Shibboleth.sso/SLO/Redirect"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleLogoutService", 
            "location": "https://nordunet.tv/Shibboleth.sso/SLO/POST"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleLogoutService", 
            "location": "https://nordunet.tv/Shibboleth.sso/SLO/Artifact"
          }
        ], 
        "attribute_consuming_service": [
          {
            "index": "0", 
            "service_description": [
              {
                "lang": "en", 
                "text": "NORDUnet Media Distribution Site", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }
            ], 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AttributeConsumingService", 
            "requested_attribute": [
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:0.9.2342.19200300.100.1.3"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.42"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.4"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.9"
              }
            ], 
            "service_name": [
              {
                "lang": "en", 
                "text": "NORDUnet TV", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }
            ]
          }
        ], 
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "assertion_consumer_service": [
          {
            "index": "1", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://nordunet.tv/Shibboleth.sso/SAML2/POST"
          }, 
          {
            "index": "2", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://nordunet.tv/Shibboleth.sso/SAML2/POST-SimpleSign"
          }, 
          {
            "index": "3", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://nordunet.tv/Shibboleth.sso/SAML2/Artifact"
          }, 
          {
            "index": "4", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:PAOS", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://nordunet.tv/Shibboleth.sso/SAML2/ECP"
          }, 
          {
            "index": "5", 
            "binding": "urn:oasis:names:tc:SAML:1.0:profiles:browser-post", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://nordunet.tv/Shibboleth.sso/SAML/POST"
          }, 
          {
            "index": "6", 
            "binding": "urn:oasis:names:tc:SAML:1.0:profiles:artifact-01", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://nordunet.tv/Shibboleth.sso/SAML/Artifact"
          }
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SPSSODescriptor", 
        "extensions": {
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Extensions", 
          "extension_elements": [
            {
              "index": "1", 
              "binding": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol", 
              "__class__": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol&DiscoveryResponse", 
              "location": "https://nordunet.tv/Shibboleth.sso/Login"
            }, 
            {
              "attribute_value": [
                {
                  "text": "kalmar", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }, 
                {
                  "text": "sweden", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }
              ], 
              "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&Attribute", 
              "name": "tags"
            }
          ]
        }, 
        "key_descriptor": [
          {
            "use": "signing", 
            "key_info": {
              "key_name": [
                {
                  "text": "nordunet.tv", 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyName"
                }
              ], 
              "x509_data": [
                {
                  "x509_subject_name": {
                    "text": "CN=nordunet.tv", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509SubjectName"
                  }, 
                  "x509_certificate": {
                    "text": "MIIC9TCCAd2gAwIBAgIJAJbH0STVcsEQMA0GCSqGSIb3DQEBBQUAMBYxFDASBgNV\nBAMTC25vcmR1bmV0LnR2MB4XDTExMDUzMTE1NDg1NloXDTIxMDUyODE1NDg1Nlow\nFjEUMBIGA1UEAxMLbm9yZHVuZXQudHYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw\nggEKAoIBAQDgvw+Ecpy85/x9dFLRnI11QoYRx9eRC/H23k5ItE5g/HOinHkl7tT2\nKYhXE8orDVpvtj1edXppIE0C3XWkgltdJTvPOXxnfto2rQOx6h8lZHldFzNhlaD1\ngNNzrNLD/PqOJ4vGgqFogV7BAQFHBWz1hiU98xle7Jqa8/7rWj2V1T7ZcjkfaRhU\nq/4EoJg0UTy0NURQjhgD8pk4gw9PdUfnxWBeiukIFFIiRzPVy6E/DnMHO/Lj3UYU\nhlVK4CZJ1eMaDlqq2msAM2NXFEvfG7jd/XfCdx8ZSqKCRsa4o8pTOcbAW9cxhso8\nrC2gcjgeZypevNVxHzcepMMeCrbs1rblAgMBAAGjRjBEMCMGA1UdEQQcMBqCC25v\ncmR1bmV0LnR2hgtub3JkdW5ldC50djAdBgNVHQ4EFgQULkNNPNMu2YQkJwXc62KQ\ngVs9cTcwDQYJKoZIhvcNAQEFBQADggEBAEQw4jnSd7l+50jXx9lDY4Ffn9s2m69M\npdKjSUlCN/0+MFRzpZcgJcVSrivqiICeDOW1QHNJZLmiZXzOV4QHwrOGObCMCclo\n+lCmV0sLvZ/N9E5mAne/61kx251w1ub/aQJ5H2HV+wgcGMLyrJN+Fas3Z6D0WIwE\nln9IKS3JyKG+VBcpLWosX1jaSP6XFJe7kZ58SVbRnAoaGoIWh7tww13KsHkPEmU3\nUuGq63xCD7WDlXE0wpoWBE2dJUti1P4OovwFCUN4aqYT1c2y4wneVj/KTEWy8qKz\n000W3/HStrhj0L5kZNAkal6vzZ0Ux9n3V/9/ZoeSilM5ZiFD9whUQho=", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }, 
          {
            "use": "encryption", 
            "key_info": {
              "key_name": [
                {
                  "text": "nordunet.tv", 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyName"
                }
              ], 
              "x509_data": [
                {
                  "x509_subject_name": {
                    "text": "CN=nordunet.tv", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509SubjectName"
                  }, 
                  "x509_certificate": {
                    "text": "MIIC9TCCAd2gAwIBAgIJAJbH0STVcsEQMA0GCSqGSIb3DQEBBQUAMBYxFDASBgNV\nBAMTC25vcmR1bmV0LnR2MB4XDTExMDUzMTE1NDg1NloXDTIxMDUyODE1NDg1Nlow\nFjEUMBIGA1UEAxMLbm9yZHVuZXQudHYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw\nggEKAoIBAQDgvw+Ecpy85/x9dFLRnI11QoYRx9eRC/H23k5ItE5g/HOinHkl7tT2\nKYhXE8orDVpvtj1edXppIE0C3XWkgltdJTvPOXxnfto2rQOx6h8lZHldFzNhlaD1\ngNNzrNLD/PqOJ4vGgqFogV7BAQFHBWz1hiU98xle7Jqa8/7rWj2V1T7ZcjkfaRhU\nq/4EoJg0UTy0NURQjhgD8pk4gw9PdUfnxWBeiukIFFIiRzPVy6E/DnMHO/Lj3UYU\nhlVK4CZJ1eMaDlqq2msAM2NXFEvfG7jd/XfCdx8ZSqKCRsa4o8pTOcbAW9cxhso8\nrC2gcjgeZypevNVxHzcepMMeCrbs1rblAgMBAAGjRjBEMCMGA1UdEQQcMBqCC25v\ncmR1bmV0LnR2hgtub3JkdW5ldC50djAdBgNVHQ4EFgQULkNNPNMu2YQkJwXc62KQ\ngVs9cTcwDQYJKoZIhvcNAQEFBQADggEBAEQw4jnSd7l+50jXx9lDY4Ffn9s2m69M\npdKjSUlCN/0+MFRzpZcgJcVSrivqiICeDOW1QHNJZLmiZXzOV4QHwrOGObCMCclo\n+lCmV0sLvZ/N9E5mAne/61kx251w1ub/aQJ5H2HV+wgcGMLyrJN+Fas3Z6D0WIwE\nln9IKS3JyKG+VBcpLWosX1jaSP6XFJe7kZ58SVbRnAoaGoIWh7tww13KsHkPEmU3\nUuGq63xCD7WDlXE0wpoWBE2dJUti1P4OovwFCUN4aqYT1c2y4wneVj/KTEWy8qKz\n000W3/HStrhj0L5kZNAkal6vzZ0Ux9n3V/9/ZoeSilM5ZiFD9whUQho=", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ], 
        "artifact_resolution_service": [
          {
            "index": "1", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:SOAP", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ArtifactResolutionService", 
            "location": "https://nordunet.tv/Shibboleth.sso/Artifact/SOAP"
          }
        ], 
        "manage_name_id_service": [
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:SOAP", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ManageNameIDService", 
            "location": "https://nordunet.tv/Shibboleth.sso/NIM/SOAP"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ManageNameIDService", 
            "location": "https://nordunet.tv/Shibboleth.sso/NIM/Redirect"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ManageNameIDService", 
            "location": "https://nordunet.tv/Shibboleth.sso/NIM/POST"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ManageNameIDService", 
            "location": "https://nordunet.tv/Shibboleth.sso/NIM/Artifact"
          }
        ]
      }
    ]
  }, 
  "https://atlases.muni.cz/shibboleth": {
    "valid_until": "2012-12-19T20:17:02Z", 
    "entity_id": "https://atlases.muni.cz/shibboleth", 
    "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EntityDescriptor", 
    "spsso_descriptor": [
      {
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "assertion_consumer_service": [
          {
            "index": "0", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://atlases.muni.cz/Shibboleth.sso/SAML2/POST"
          }
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SPSSODescriptor", 
        "name_id_format": [
          {
            "text": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }
        ], 
        "attribute_consuming_service": [
          {
            "index": "0", 
            "service_description": [
              {
                "lang": "en", 
                "text": "to provide access to the three atlases: (1) Dermatopathology, (2) Fetal and Neonatal Pathology, (3) Pathology for Pre-graduate Students of Medicine. The atlases may serve as sources of teaching material for pre-graduate as well as postgraduate students of pathology", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }, 
              {
                "lang": "da", 
                "text": "give adgang til tre atlasser: (1) Dermato-patologi, (2) Foster- og neonatal patologi, (3) Patologi for medicinstuderende. Atlasserne kan bruges som undervisningsmateriale for patologistuderende", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }
            ], 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AttributeConsumingService", 
            "requested_attribute": [
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.10"
              }
            ], 
            "service_name": [
              {
                "lang": "en", 
                "text": "Pathology Images", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }, 
              {
                "lang": "da", 
                "text": "Patologi-atlasser", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }
            ]
          }
        ], 
        "key_descriptor": [
          {
            "use": "signing", 
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIEZzCCA0+gAwIBAgILAQAAAAABID3xVZIwDQYJKoZIhvcNAQEFBQAwajEjMCEGA1UECxMaT3JnYW5pemF0aW9uIFZhbGlkYXRpb24gQ0ExEzARBgNVBAoTCkdsb2JhbFNpZ24xLjAsBgNVBAMTJUdsb2JhbFNpZ24gT3JnYW5pemF0aW9uIFZhbGlkYXRpb24gQ0EwHhcNMDkwMzI1MTMwNTE0WhcNMTIwNTA5MDcwNzU3WjCBgzELMAkGA1UEBhMCREsxETAPBgNVBAgTCE9kZW5zZSBNMREwDwYDVQQHEwhPZGVuc2UgTTEbMBkGA1UECxMSV0FZRiAtIFNlY3JldGFyaWF0MR0wGwYDVQQKExRTeWRkYW5zayBVbml2ZXJzaXRldDESMBAGA1UEAxQJKi53YXlmLmRrMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDBsuiyO84OVwkKR0TL6w8viWV4jMg+Jy7LgiEtYfHdnVBCvdM9XJJetS0MiJtulBH4/4ZWrfeGeHgLPvSjp6FiRdI1nDg/33ofc0TdNytxX4tBCzvxM0C4yCCaEXda+tqXJmGua+mVubMhS8kizHjL+s7A8xUqXoEFqOMHtgqoAQIDAQABo4IBdjCCAXIwHwYDVR0jBBgwFoAUfW0q7Garp1E2qwJp8XCPxFkLmh8wSQYIKwYBBQUHAQEEPTA7MDkGCCsGAQUFBzAChi1odHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24ubmV0L2NhY2VydC9vcmd2MS5jcnQwPwYDVR0fBDgwNjA0oDKgMIYuaHR0cDovL2NybC5nbG9iYWxzaWduLm5ldC9Pcmdhbml6YXRpb25WYWwxLmNybDAdBgNVHQ4EFgQUvlkjTc0iuzcvi752QgktLT01obgwCQYDVR0TBAIwADAOBgNVHQ8BAf8EBAMCBaAwKQYDVR0lBCIwIAYIKwYBBQUHAwEGCCsGAQUFBwMCBgorBgEEAYI3CgMDMEsGA1UdIAREMEIwQAYJKwYBBAGgMgEUMDMwMQYIKwYBBQUHAgEWJWh0dHA6Ly93d3cuZ2xvYmFsc2lnbi5uZXQvcmVwb3NpdG9yeS8wEQYJYIZIAYb4QgEBBAQDAgbAMA0GCSqGSIb3DQEBBQUAA4IBAQCKPVJYHjKOrzWtjPBTEJOwIzE0wSIcA+9+GNR5Pvk+6OTf2QTUDDHpXiiIEcYPL1kN/BEvA+N2y+7qyI5MlL7DNIu9clx1lcqhXiQ0lWcu7Bmb7VNPKq5WS1W81GhbZrO6BJtsQctU6odDXMoORay7FxnaxGHOaJlCSQDgT7QrRhzyd80X8NxrSV25byCTb31du8xoO+WagnqAp6xbKs6IsESDw2r/i3rLOXbL37B7lnbjcLC963xN6j7+kiyqiCjvrP0GLfSV4/FN9i9hWrdMlcbnvr23yz5Jflc1oFPtJx7GZqtV0uTijGxCr+aRaUzBPqc3kyavHJcCsn5TcL1t", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }, 
          {
            "use": "encryption", 
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIEZzCCA0+gAwIBAgILAQAAAAABID3xVZIwDQYJKoZIhvcNAQEFBQAwajEjMCEGA1UECxMaT3JnYW5pemF0aW9uIFZhbGlkYXRpb24gQ0ExEzARBgNVBAoTCkdsb2JhbFNpZ24xLjAsBgNVBAMTJUdsb2JhbFNpZ24gT3JnYW5pemF0aW9uIFZhbGlkYXRpb24gQ0EwHhcNMDkwMzI1MTMwNTE0WhcNMTIwNTA5MDcwNzU3WjCBgzELMAkGA1UEBhMCREsxETAPBgNVBAgTCE9kZW5zZSBNMREwDwYDVQQHEwhPZGVuc2UgTTEbMBkGA1UECxMSV0FZRiAtIFNlY3JldGFyaWF0MR0wGwYDVQQKExRTeWRkYW5zayBVbml2ZXJzaXRldDESMBAGA1UEAxQJKi53YXlmLmRrMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDBsuiyO84OVwkKR0TL6w8viWV4jMg+Jy7LgiEtYfHdnVBCvdM9XJJetS0MiJtulBH4/4ZWrfeGeHgLPvSjp6FiRdI1nDg/33ofc0TdNytxX4tBCzvxM0C4yCCaEXda+tqXJmGua+mVubMhS8kizHjL+s7A8xUqXoEFqOMHtgqoAQIDAQABo4IBdjCCAXIwHwYDVR0jBBgwFoAUfW0q7Garp1E2qwJp8XCPxFkLmh8wSQYIKwYBBQUHAQEEPTA7MDkGCCsGAQUFBzAChi1odHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24ubmV0L2NhY2VydC9vcmd2MS5jcnQwPwYDVR0fBDgwNjA0oDKgMIYuaHR0cDovL2NybC5nbG9iYWxzaWduLm5ldC9Pcmdhbml6YXRpb25WYWwxLmNybDAdBgNVHQ4EFgQUvlkjTc0iuzcvi752QgktLT01obgwCQYDVR0TBAIwADAOBgNVHQ8BAf8EBAMCBaAwKQYDVR0lBCIwIAYIKwYBBQUHAwEGCCsGAQUFBwMCBgorBgEEAYI3CgMDMEsGA1UdIAREMEIwQAYJKwYBBAGgMgEUMDMwMQYIKwYBBQUHAgEWJWh0dHA6Ly93d3cuZ2xvYmFsc2lnbi5uZXQvcmVwb3NpdG9yeS8wEQYJYIZIAYb4QgEBBAQDAgbAMA0GCSqGSIb3DQEBBQUAA4IBAQCKPVJYHjKOrzWtjPBTEJOwIzE0wSIcA+9+GNR5Pvk+6OTf2QTUDDHpXiiIEcYPL1kN/BEvA+N2y+7qyI5MlL7DNIu9clx1lcqhXiQ0lWcu7Bmb7VNPKq5WS1W81GhbZrO6BJtsQctU6odDXMoORay7FxnaxGHOaJlCSQDgT7QrRhzyd80X8NxrSV25byCTb31du8xoO+WagnqAp6xbKs6IsESDw2r/i3rLOXbL37B7lnbjcLC963xN6j7+kiyqiCjvrP0GLfSV4/FN9i9hWrdMlcbnvr23yz5Jflc1oFPtJx7GZqtV0uTijGxCr+aRaUzBPqc3kyavHJcCsn5TcL1t", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ]
      }
    ], 
    "cache_duration": "PT345600S"
  }, 
  "https://www.emeraldinsight.com/entity": {
    "valid_until": "2012-12-19T20:17:02Z", 
    "entity_id": "https://www.emeraldinsight.com/entity", 
    "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EntityDescriptor", 
    "spsso_descriptor": [
      {
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "assertion_consumer_service": [
          {
            "index": "1", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://www.emeraldinsight.com/Shibboleth.sso/SAML2/Artifact"
          }, 
          {
            "index": "2", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://www.emeraldinsight.com/Shibboleth.sso/SAML2/POST-SimpleSign"
          }, 
          {
            "index": "0", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://www.emeraldinsight.com/Shibboleth.sso/SAML2/POST"
          }
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SPSSODescriptor", 
        "name_id_format": [
          {
            "text": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }
        ], 
        "attribute_consuming_service": [
          {
            "index": "0", 
            "service_description": [
              {
                "lang": "en", 
                "text": "provide personalized access to journals and papers on social sciences", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }, 
              {
                "lang": "da", 
                "text": "give adgang til EmeraldInsights tidsskrifter og artikler indenfor socialvidenskab", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }
            ], 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AttributeConsumingService", 
            "requested_attribute": [
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.10"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.25178.1.2.9"
              }
            ], 
            "service_name": [
              {
                "lang": "en", 
                "text": "EmeraldInsight", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }, 
              {
                "lang": "da", 
                "text": "EmeraldInsight", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }
            ]
          }
        ], 
        "key_descriptor": [
          {
            "use": "signing", 
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIFEzCCA/ugAwIBAgILAQAAAAABLlieGjMwDQYJKoZIhvcNAQEFBQAwcTELMAkGA1UEBhMCQkUxHTAbBgNVBAsTFERvbWFpbiBWYWxpZGF0aW9uIENBMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSgwJgYDVQQDEx9HbG9iYWxTaWduIERvbWFpbiBWYWxpZGF0aW9uIENBMB4XDTExMDIyNDE2MTAxNloXDTEzMDIyNDE2MTAxMVowgYAxCzAJBgNVBAYTAkdCMSEwHwYDVQQLExhEb21haW4gQ29udHJvbCBWYWxpZGF0ZWQxJjAkBgNVBAoMHXNoaWJib2xldGguZW1lcmFsZGluc2lnaHQuY29tMSYwJAYDVQQDDB1zaGliYm9sZXRoLmVtZXJhbGRpbnNpZ2h0LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMoXI+n3JvgM6LIaYvSRgiJ44vRHXj0VnHsRDDlMevGSVwq5wLk0qI3iQEE12jOxcwx1kAcRmlrNdBwm0DusVSW2HGuODeSF+gqpGKqTayMv85op4x7IpAgUQmkaHZKGMY9NFGHOFcUcD8Bk2h9ytmjBnGyi0f0dF+gQj3sv8rh52zK5OVv/XR6wcYSE/rGGu+nU4OK3o7g3qr5sod9PgTaiyu26zA0miVTrQCEmHQn1waLwRoz358JWXlAAvjATMirJ+KhIsNVBPSxnPcaxPLQqXXI+C5hagIG+oQ0glTG64NstlDXvLCw1BSzlpDgqGYAgdJTOz3OBRP/f5OKbLsUCAwEAAaOCAZowggGWMB8GA1UdIwQYMBaAFDYSTp5xxCZB8frxKUy/F6RTKLbrMEkGCCsGAQUFBwEBBD0wOzA5BggrBgEFBQcwAoYtaHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLm5ldC9jYWNlcnQvZHZoZTEuY3J0MDkGA1UdHwQyMDAwLqAsoCqGKGh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5uZXQvRG9tYWluVmFsMS5jcmwwHQYDVR0OBBYEFNr8wdf+AlkNufl44T52cIFoSkUnMAkGA1UdEwQCMAAwDgYDVR0PAQH/BAQDAgTwMCkGA1UdJQQiMCAGCCsGAQUFBwMBBggrBgEFBQcDAgYKKwYBBAGCNwoDAzBLBgNVHSAERDBCMEAGCSsGAQQBoDIBCjAzMDEGCCsGAQUFBwIBFiVodHRwOi8vd3d3Lmdsb2JhbHNpZ24ubmV0L3JlcG9zaXRvcnkvMBEGCWCGSAGG+EIBAQQEAwIGwDAoBgNVHREEITAfgh1zaGliYm9sZXRoLmVtZXJhbGRpbnNpZ2h0LmNvbTANBgkqhkiG9w0BAQUFAAOCAQEAW6Z0AgKjlbsyi/1EcEQC1ArGYeq6DomTtkpQWFSGWmOkCPpD6l6KJT7Q3/UgbHeCrbmwSwiADYHbJbJUNvQZoxKLcUMOJKA52mTdV8MGh0FBOvwzA8abBT955AI0SNma4CAW7UH0OaNo84PVLAbkDwdhU5TV3LktFIIPyBQLARm07IkmJZ2YdP2zl2BcbrozDy0YHs2dxhLSn+Uh3XrlH12VPHB7GzzeGD54XjjYGLqMoAKHGEqvVpF8hj+lemucvUuy6itdEPU5EgoAU+Pxlw8o+iHNxQ336Od77RWrw4Wa+gD0L6sIdZEOhbCSGLIjPwtEJmKWKaXN8tRYvG1sXw==", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }, 
          {
            "use": "encryption", 
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIFEzCCA/ugAwIBAgILAQAAAAABLlieGjMwDQYJKoZIhvcNAQEFBQAwcTELMAkGA1UEBhMCQkUxHTAbBgNVBAsTFERvbWFpbiBWYWxpZGF0aW9uIENBMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSgwJgYDVQQDEx9HbG9iYWxTaWduIERvbWFpbiBWYWxpZGF0aW9uIENBMB4XDTExMDIyNDE2MTAxNloXDTEzMDIyNDE2MTAxMVowgYAxCzAJBgNVBAYTAkdCMSEwHwYDVQQLExhEb21haW4gQ29udHJvbCBWYWxpZGF0ZWQxJjAkBgNVBAoMHXNoaWJib2xldGguZW1lcmFsZGluc2lnaHQuY29tMSYwJAYDVQQDDB1zaGliYm9sZXRoLmVtZXJhbGRpbnNpZ2h0LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMoXI+n3JvgM6LIaYvSRgiJ44vRHXj0VnHsRDDlMevGSVwq5wLk0qI3iQEE12jOxcwx1kAcRmlrNdBwm0DusVSW2HGuODeSF+gqpGKqTayMv85op4x7IpAgUQmkaHZKGMY9NFGHOFcUcD8Bk2h9ytmjBnGyi0f0dF+gQj3sv8rh52zK5OVv/XR6wcYSE/rGGu+nU4OK3o7g3qr5sod9PgTaiyu26zA0miVTrQCEmHQn1waLwRoz358JWXlAAvjATMirJ+KhIsNVBPSxnPcaxPLQqXXI+C5hagIG+oQ0glTG64NstlDXvLCw1BSzlpDgqGYAgdJTOz3OBRP/f5OKbLsUCAwEAAaOCAZowggGWMB8GA1UdIwQYMBaAFDYSTp5xxCZB8frxKUy/F6RTKLbrMEkGCCsGAQUFBwEBBD0wOzA5BggrBgEFBQcwAoYtaHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLm5ldC9jYWNlcnQvZHZoZTEuY3J0MDkGA1UdHwQyMDAwLqAsoCqGKGh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5uZXQvRG9tYWluVmFsMS5jcmwwHQYDVR0OBBYEFNr8wdf+AlkNufl44T52cIFoSkUnMAkGA1UdEwQCMAAwDgYDVR0PAQH/BAQDAgTwMCkGA1UdJQQiMCAGCCsGAQUFBwMBBggrBgEFBQcDAgYKKwYBBAGCNwoDAzBLBgNVHSAERDBCMEAGCSsGAQQBoDIBCjAzMDEGCCsGAQUFBwIBFiVodHRwOi8vd3d3Lmdsb2JhbHNpZ24ubmV0L3JlcG9zaXRvcnkvMBEGCWCGSAGG+EIBAQQEAwIGwDAoBgNVHREEITAfgh1zaGliYm9sZXRoLmVtZXJhbGRpbnNpZ2h0LmNvbTANBgkqhkiG9w0BAQUFAAOCAQEAW6Z0AgKjlbsyi/1EcEQC1ArGYeq6DomTtkpQWFSGWmOkCPpD6l6KJT7Q3/UgbHeCrbmwSwiADYHbJbJUNvQZoxKLcUMOJKA52mTdV8MGh0FBOvwzA8abBT955AI0SNma4CAW7UH0OaNo84PVLAbkDwdhU5TV3LktFIIPyBQLARm07IkmJZ2YdP2zl2BcbrozDy0YHs2dxhLSn+Uh3XrlH12VPHB7GzzeGD54XjjYGLqMoAKHGEqvVpF8hj+lemucvUuy6itdEPU5EgoAU+Pxlw8o+iHNxQ336Od77RWrw4Wa+gD0L6sIdZEOhbCSGLIjPwtEJmKWKaXN8tRYvG1sXw==", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ]
      }
    ], 
    "cache_duration": "PT345600S"
  }, 
  "https://moodle.utu.fi": {
    "valid_until": "2012-12-19T20:15:01Z", 
    "entity_id": "https://moodle.utu.fi", 
    "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EntityDescriptor", 
    "organization": {
      "organization_name": [
        {
          "lang": "fi", 
          "text": "Turun yliopisto", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }, 
        {
          "lang": "en", 
          "text": "University of Turku", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }, 
        {
          "lang": "sv", 
          "text": "Abo universitet", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }
      ], 
      "organization_display_name": [
        {
          "lang": "fi", 
          "text": "Turun yliopisto", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }, 
        {
          "lang": "en", 
          "text": "University of Turku", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }, 
        {
          "lang": "sv", 
          "text": "Abo universitet", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }
      ], 
      "organization_url": [
        {
          "lang": "fi", 
          "text": "http://www.utu.fi/", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }, 
        {
          "lang": "en", 
          "text": "http://www.utu.fi/", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }, 
        {
          "lang": "sv", 
          "text": "http://www.utu.fi/", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }
      ], 
      "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Organization"
    }, 
    "contact_person": [
      {
        "given_name": {
          "text": "Nadja", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&GivenName"
        }, 
        "email_address": [
          {
            "text": "hakajasen@utu.fi", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ], 
        "sur_name": {
          "text": "Plankevitch", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SurName"
        }, 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "contact_type": "technical"
      }, 
      {
        "given_name": {
          "text": "Nadja", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&GivenName"
        }, 
        "email_address": [
          {
            "text": "hakajasen@utu.fi", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ], 
        "sur_name": {
          "text": "Plankevitch", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SurName"
        }, 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "contact_type": "support"
      }
    ], 
    "spsso_descriptor": [
      {
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "assertion_consumer_service": [
          {
            "is_default": "true", 
            "index": "1", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://moodle.utu.fi/Shibboleth.sso/SAML2/POST"
          }, 
          {
            "is_default": "false", 
            "index": "2", 
            "binding": "urn:oasis:names:tc:SAML:1.0:profiles:browser-post", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://moodle.utu.fi/Shibboleth.sso/SAML/POST"
          }
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SPSSODescriptor", 
        "extensions": {
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Extensions", 
          "extension_elements": [
            {
              "index": "1", 
              "binding": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol", 
              "__class__": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol&DiscoveryResponse", 
              "location": "https://moodle.utu.fi/Shibboleth.sso/DS"
            }, 
            {
              "attribute_value": [
                {
                  "text": "kalmar", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }, 
                {
                  "text": "finland", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }
              ], 
              "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&Attribute", 
              "name": "tags"
            }
          ]
        }, 
        "name_id_format": [
          {
            "text": "urn:mace:shibboleth:1.0:nameIdentifier", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }, 
          {
            "text": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }
        ], 
        "attribute_consuming_service": [
          {
            "index": "1", 
            "service_name": [
              {
                "lang": "fi", 
                "text": "Turun yliopiston Moodle-oppimisalusta", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }, 
              {
                "lang": "en", 
                "text": "University of Turku's Moodle learning management system", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }
            ], 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AttributeConsumingService", 
            "is_default": "true", 
            "requested_attribute": [
              {
                "friendly_name": "displayName", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.16.840.1.113730.3.1.241"
              }, 
              {
                "friendly_name": "eduPersonPrincipalName", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
              }, 
              {
                "friendly_name": "mail", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:0.9.2342.19200300.100.1.3"
              }, 
              {
                "friendly_name": "schacHomeOrganization", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.25178.1.2.9"
              }, 
              {
                "friendly_name": "schacPersonalUniqueCode", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.25178.1.2.14"
              }, 
              {
                "friendly_name": "sn", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.4"
              }
            ], 
            "service_description": [
              {
                "lang": "fi", 
                "text": "Moodle-oppimisalusta", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }, 
              {
                "lang": "en", 
                "text": "Moodle learning management system", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }
            ]
          }
        ], 
        "key_descriptor": [
          {
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIE2DCCA8CgAwIBAgIRAIzFEsSaNiwZ9NKWqNV1nEUwDQYJKoZIhvcNAQEFBQAw\nNjELMAkGA1UEBhMCTkwxDzANBgNVBAoTBlRFUkVOQTEWMBQGA1UEAxMNVEVSRU5B\nIFNTTCBDQTAeFw0xMDExMDMwMDAwMDBaFw0xMzExMDIyMzU5NTlaMIG0MQswCQYD\nVQQGEwJGSTEOMAwGA1UEERMFMjA1MDAxGDAWBgNVBAgTD1dlc3Rlcm4gRmlubGFu\nZDEOMAwGA1UEBxMFVHVya3UxGjAYBgNVBAkTEUFzc2lzdGVudGlua2F0dSA1MRww\nGgYDVQQKExNVbml2ZXJzaXR5IG9mIFR1cmt1MRkwFwYDVQQLExBDb21wdXRpbmcg\nQ2VudHJlMRYwFAYDVQQDEw1tb29kbGUudXR1LmZpMIIBIjANBgkqhkiG9w0BAQEF\nAAOCAQ8AMIIBCgKCAQEAu57V8S33XIdPWR0LrBU3P7BUaGjMQQXLIvyJG30hdL6L\neVmhgdGLmquH4PstOhkovAyU2oRnV8qgRGTvS/dpyjiBgLBZ3bM2RHKYmPTzUxW6\nyYeQskZeRva28BZPtCo7cI6Z0tzrN0svt6hvQAvcQr0hpi4eYmflRcLN+Vogwvo2\nU67xxIxBEqUPC9ESsiIjh3AppAZcO8QzMIZO4CVhrWjyXSNpLtq7CS/n7xbw6/ky\n8bqFuaYsIBeyubsjp6nWbvMsuFRrUOh/Mjj3PLVe3kFOb7ueSjxcfAbl+Nd0T2Qa\n7KT7yY8zBI3JEoj19eTpSrZzPcBToA+LHUwiMfeM0wIDAQABo4IBYDCCAVwwHwYD\nVR0jBBgwFoAUDL2TaAzz3qujSWsrN1dH6pDjue0wHQYDVR0OBBYEFHSb32e0HpXD\ngKuD31baDigtJobzMA4GA1UdDwEB/wQEAwIFoDAMBgNVHRMBAf8EAjAAMB0GA1Ud\nJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAYBgNVHSAEETAPMA0GCysGAQQBsjEB\nAgIdMDoGA1UdHwQzMDEwL6AtoCuGKWh0dHA6Ly9jcmwudGNzLnRlcmVuYS5vcmcv\nVEVSRU5BU1NMQ0EuY3JsMG0GCCsGAQUFBwEBBGEwXzA1BggrBgEFBQcwAoYpaHR0\ncDovL2NydC50Y3MudGVyZW5hLm9yZy9URVJFTkFTU0xDQS5jcnQwJgYIKwYBBQUH\nMAGGGmh0dHA6Ly9vY3NwLnRjcy50ZXJlbmEub3JnMBgGA1UdEQQRMA+CDW1vb2Rs\nZS51dHUuZmkwDQYJKoZIhvcNAQEFBQADggEBAMAInGTI7z6J5t8LBcGZPFRW8atX\noaxMsYnrrM//+m3nuJXEZI3Bt/1/zOmQhd+Z7hwGiSLsVwaBlfdSCJwv33Oe4h7O\nSLXPtsPobOmhabdPtpyrwFE+9+Q+kRFgWNXzG2ljZqu0BXMawDIovMlyDu3Bwdu3\nxtXUgyN9ulirTItGNg6f6a0g7OglqdDTzNpB7d2FbznzGx3D9x9ywHw8HKAAEjxV\nHewGXyTGKlQg2OqGI9Pxl+JdUN1oby1ktstPHYPzhZlxjZZF90kqtBlTZ0ATZGVi\nZ/dJiMGOYt1I1CwOpyO8yRc8WeYZqbrKPxO/VsQ9b15tdADxcf+EMeuQNSs=", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ]
      }
    ]
  }, 
  "https://software.msdnaa.dk/": {
    "valid_until": "2012-12-19T20:17:02Z", 
    "entity_id": "https://software.msdnaa.dk/", 
    "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EntityDescriptor", 
    "spsso_descriptor": [
      {
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "assertion_consumer_service": [
          {
            "index": "0", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://software.msdnaa.dk/login.ashx"
          }
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SPSSODescriptor", 
        "name_id_format": [
          {
            "text": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }
        ], 
        "attribute_consuming_service": [
          {
            "index": "0", 
            "service_description": [
              {
                "lang": "en", 
                "text": "to provide access to relevant Microsoft products for qualified students. The student will, for selected products, be notified by e-mail with product registration/activation information", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }, 
              {
                "lang": "da", 
                "text": "at give adgang til relevante Microsoft-produkter for udvalgte studerende. Den studerende vil for udvalgte produkter modtage e-mail vedr\u00f8rende produktregistrering og aktiveringsinformation", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }
            ], 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AttributeConsumingService", 
            "requested_attribute": [
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.25178.1.2.9"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:0.9.2342.19200300.100.1.3"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.9"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.10"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.5"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.7"
              }
            ], 
            "service_name": [
              {
                "lang": "en", 
                "text": "MSDNAA", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }, 
              {
                "lang": "da", 
                "text": "MSDNAA", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }
            ]
          }
        ], 
        "key_descriptor": [
          {
            "use": "signing", 
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIDgDCCAumgAwIBAgIDEzx+MA0GCSqGSIb3DQEBBQUAME4xCzAJBgNVBAYTAlVTMRAwDgYDVQQKEwdFcXVpZmF4MS0wKwYDVQQLEyRFcXVpZmF4IFNlY3VyZSBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkwHhcNMTAwNjA2MDkyMDM3WhcNMTIwNzA4MDcxMjI0WjCB6zEpMCcGA1UEBRMgLWhiZTRROUFVcWItUFRhc2lCSkxwdnYvRUlIcGc0bksxCzAJBgNVBAYTAkRLMRswGQYDVQQKExJzb2Z0d2FyZS5tc2RuYWEuZGsxEzARBgNVBAsTCkdUMDc5NTQ3NjIxMTAvBgNVBAsTKFNlZSB3d3cucmFwaWRzc2wuY29tL3Jlc291cmNlcy9jcHMgKGMpMTAxLzAtBgNVBAsTJkRvbWFpbiBDb250cm9sIFZhbGlkYXRlZCAtIFJhcGlkU1NMKFIpMRswGQYDVQQDExJzb2Z0d2FyZS5tc2RuYWEuZGswgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMAFv3keVCtJjzg1taFiriiPjTMWHmVdYSsW9ZSBA38CXKm9I4Du3SiiX+TuXW65+1WwPSX1AxpTMCluFfIEzs2IvHLAMdU5+AyCZLEE627ux7dClGzwd9A9fpqrU4XI2Cq2GdlaxTrFfsfIw00CUv+PYlohLHXM96D8H6B46uRfAgMBAAGjgc0wgcowHwYDVR0jBBgwFoAUSOZo+SvSspXXR9gjIBBPM5iQn9QwDgYDVR0PAQH/BAQDAgTwMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAdBgNVHREEFjAUghJzb2Z0d2FyZS5tc2RuYWEuZGswOgYDVR0fBDMwMTAvoC2gK4YpaHR0cDovL2NybC5nZW90cnVzdC5jb20vY3Jscy9zZWN1cmVjYS5jcmwwHQYDVR0OBBYEFOMgzsyArmCbYFjO+X4rJFgvplLTMA0GCSqGSIb3DQEBBQUAA4GBAIQVfBTbp8SBQI7B/04g5ExQlLO5HW1Y6AbCZ09rbMMJjX6PwDS/HAI4BOrTpe49kB3jxPcmT/IWQrYbBod2I+hIBNP+W/AfAexL2exVxjzFo14kMJ3oBsxpzeC1IuSNrwQTmxHz5Bfa7LPtZU5O7LfTvzvKppGeewAzW6u7pG4I", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }, 
          {
            "use": "encryption", 
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIDgDCCAumgAwIBAgIDEzx+MA0GCSqGSIb3DQEBBQUAME4xCzAJBgNVBAYTAlVTMRAwDgYDVQQKEwdFcXVpZmF4MS0wKwYDVQQLEyRFcXVpZmF4IFNlY3VyZSBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkwHhcNMTAwNjA2MDkyMDM3WhcNMTIwNzA4MDcxMjI0WjCB6zEpMCcGA1UEBRMgLWhiZTRROUFVcWItUFRhc2lCSkxwdnYvRUlIcGc0bksxCzAJBgNVBAYTAkRLMRswGQYDVQQKExJzb2Z0d2FyZS5tc2RuYWEuZGsxEzARBgNVBAsTCkdUMDc5NTQ3NjIxMTAvBgNVBAsTKFNlZSB3d3cucmFwaWRzc2wuY29tL3Jlc291cmNlcy9jcHMgKGMpMTAxLzAtBgNVBAsTJkRvbWFpbiBDb250cm9sIFZhbGlkYXRlZCAtIFJhcGlkU1NMKFIpMRswGQYDVQQDExJzb2Z0d2FyZS5tc2RuYWEuZGswgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMAFv3keVCtJjzg1taFiriiPjTMWHmVdYSsW9ZSBA38CXKm9I4Du3SiiX+TuXW65+1WwPSX1AxpTMCluFfIEzs2IvHLAMdU5+AyCZLEE627ux7dClGzwd9A9fpqrU4XI2Cq2GdlaxTrFfsfIw00CUv+PYlohLHXM96D8H6B46uRfAgMBAAGjgc0wgcowHwYDVR0jBBgwFoAUSOZo+SvSspXXR9gjIBBPM5iQn9QwDgYDVR0PAQH/BAQDAgTwMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAdBgNVHREEFjAUghJzb2Z0d2FyZS5tc2RuYWEuZGswOgYDVR0fBDMwMTAvoC2gK4YpaHR0cDovL2NybC5nZW90cnVzdC5jb20vY3Jscy9zZWN1cmVjYS5jcmwwHQYDVR0OBBYEFOMgzsyArmCbYFjO+X4rJFgvplLTMA0GCSqGSIb3DQEBBQUAA4GBAIQVfBTbp8SBQI7B/04g5ExQlLO5HW1Y6AbCZ09rbMMJjX6PwDS/HAI4BOrTpe49kB3jxPcmT/IWQrYbBod2I+hIBNP+W/AfAexL2exVxjzFo14kMJ3oBsxpzeC1IuSNrwQTmxHz5Bfa7LPtZU5O7LfTvzvKppGeewAzW6u7pG4I", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ]
      }
    ], 
    "cache_duration": "PT345600S"
  }, 
  "https://meetingtools.nordu.net/shibboleth": {
    "valid_until": "2012-12-16T04:23:08Z", 
    "organization": {
      "organization_name": [
        {
          "lang": "en", 
          "text": "NORDUnet", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }
      ], 
      "organization_display_name": [
        {
          "lang": "en", 
          "text": "NORDUnet A/S", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }
      ], 
      "organization_url": [
        {
          "lang": "en", 
          "text": "http://www.nordu.net", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }
      ], 
      "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Organization"
    }, 
    "entity_id": "https://meetingtools.nordu.net/shibboleth", 
    "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EntityDescriptor", 
    "spsso_descriptor": [
      {
        "single_logout_service": [
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:SOAP", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleLogoutService", 
            "location": "https://meetingtools.nordu.net/Shibboleth.sso/SLO/SOAP"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleLogoutService", 
            "location": "https://meetingtools.nordu.net/Shibboleth.sso/SLO/Redirect"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleLogoutService", 
            "location": "https://meetingtools.nordu.net/Shibboleth.sso/SLO/POST"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleLogoutService", 
            "location": "https://meetingtools.nordu.net/Shibboleth.sso/SLO/Artifact"
          }
        ], 
        "attribute_consuming_service": [
          {
            "index": "0", 
            "service_description": [
              {
                "lang": "en", 
                "text": "NORDUnet E-Meeting Tools", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }
            ], 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AttributeConsumingService", 
            "requested_attribute": [
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:0.9.2342.19200300.100.1.3"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.42"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.4"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.9"
              }
            ], 
            "service_name": [
              {
                "lang": "en", 
                "text": "NORDUnet E-Meeting Tools", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }
            ]
          }
        ], 
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "assertion_consumer_service": [
          {
            "index": "1", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://meetingtools.nordu.net/Shibboleth.sso/SAML2/POST"
          }, 
          {
            "index": "2", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://meetingtools.nordu.net/Shibboleth.sso/SAML2/POST-SimpleSign"
          }, 
          {
            "index": "3", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://meetingtools.nordu.net/Shibboleth.sso/SAML2/Artifact"
          }, 
          {
            "index": "4", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:PAOS", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://meetingtools.nordu.net/Shibboleth.sso/SAML2/ECP"
          }, 
          {
            "index": "5", 
            "binding": "urn:oasis:names:tc:SAML:1.0:profiles:browser-post", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://meetingtools.nordu.net/Shibboleth.sso/SAML/POST"
          }, 
          {
            "index": "6", 
            "binding": "urn:oasis:names:tc:SAML:1.0:profiles:artifact-01", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://meetingtools.nordu.net/Shibboleth.sso/SAML/Artifact"
          }
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SPSSODescriptor", 
        "extensions": {
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Extensions", 
          "extension_elements": [
            {
              "index": "1", 
              "binding": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol", 
              "__class__": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol&DiscoveryResponse", 
              "location": "https://meetingtools.nordu.net/Shibboleth.sso/DS/idp.nordu.net"
            }, 
            {
              "attribute_value": [
                {
                  "text": "kalmar", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }, 
                {
                  "text": "sweden", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }
              ], 
              "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&Attribute", 
              "name": "tags"
            }
          ]
        }, 
        "key_descriptor": [
          {
            "use": "signing", 
            "key_info": {
              "key_name": [
                {
                  "text": "meetingtools.nordu.net", 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyName"
                }
              ], 
              "x509_data": [
                {
                  "x509_subject_name": {
                    "text": "CN=meetingtools.nordu.net", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509SubjectName"
                  }, 
                  "x509_certificate": {
                    "text": "MIIDCTCCAfGgAwIBAgIJAMw0JbtsXnrGMA0GCSqGSIb3DQEBBQUAMCExHzAdBgNV\nBAMTFm1lZXRpbmd0b29scy5ub3JkdS5uZXQwHhcNMTExMDA3MjE0MjU3WhcNMjEx\nMDA0MjE0MjU3WjAhMR8wHQYDVQQDExZtZWV0aW5ndG9vbHMubm9yZHUubmV0MIIB\nIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApF6eyxvsRmbALxDE1Mlxt1IV\nSY9pEr28vv1T3HDQFW0TI2SQeMQlkXmfjux0qxY3F+qI15zejcAwzhZottruFP6M\nTGTgcfC3w2H1esB2O29okFddXBtyaXWW6hVAjF1Bmgy0UwBDWWxCHo4BhXQRyIBe\ncK+hf+xgpgOdFhgC8BJERinuVtZjCRiHqyoZ9WH9/+Qd09BuGGdCXRTrmk/SO/NT\nNcpbvyb4rLriW7xGgHScc3rdmgJnmMeXXKdMQt8q0kjbaSeibq1Z3Jqa7nDQa//1\n1VauaXNcLtiU6eTYP7vf9qLo1evQ7tkIo8PGeqX92dp4fse7lv6zVQdKlP/GiQID\nAQABo0QwQjAhBgNVHREEGjAYghZtZWV0aW5ndG9vbHMubm9yZHUubmV0MB0GA1Ud\nDgQWBBQiAOf3NZwStjuODYT1PI8wpOYO2jANBgkqhkiG9w0BAQUFAAOCAQEAasFD\nWphqHBIxJMIx1TR5LCoabp9ZM8yN7TNpmneCnhSotjNxDRhzHANKsotjRsmV80tA\n5v4yN0ORHXDjN18C1YtkaYZNGSPwEbaLWeY2MulBcgJq0nvNOxDeGhkO57u+stgY\n8Wi/UNX1X9L5TJ60AdR+jE3gVsAA7DqhKRWqSvsh6jfSwUg83A/QYIp7Qi5LfejS\nLjjhavn6zDPLc+ILO7PDrwLBw8FD9bsff4wpngUvwQb1c1jgAy1FNGO/lK5KfX45\nasFBcvwcrKqc1WoJd5PodrX9RFw/bbIceEm5ifzg2KzsS+rWxah/RVXsXWio/nY5\npcqH0yzoEFA0VHDdXA==", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }, 
          {
            "use": "encryption", 
            "key_info": {
              "key_name": [
                {
                  "text": "meetingtools.nordu.net", 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyName"
                }
              ], 
              "x509_data": [
                {
                  "x509_subject_name": {
                    "text": "CN=meetingtools.nordu.net", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509SubjectName"
                  }, 
                  "x509_certificate": {
                    "text": "MIIDCTCCAfGgAwIBAgIJAMw0JbtsXnrGMA0GCSqGSIb3DQEBBQUAMCExHzAdBgNV\nBAMTFm1lZXRpbmd0b29scy5ub3JkdS5uZXQwHhcNMTExMDA3MjE0MjU3WhcNMjEx\nMDA0MjE0MjU3WjAhMR8wHQYDVQQDExZtZWV0aW5ndG9vbHMubm9yZHUubmV0MIIB\nIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApF6eyxvsRmbALxDE1Mlxt1IV\nSY9pEr28vv1T3HDQFW0TI2SQeMQlkXmfjux0qxY3F+qI15zejcAwzhZottruFP6M\nTGTgcfC3w2H1esB2O29okFddXBtyaXWW6hVAjF1Bmgy0UwBDWWxCHo4BhXQRyIBe\ncK+hf+xgpgOdFhgC8BJERinuVtZjCRiHqyoZ9WH9/+Qd09BuGGdCXRTrmk/SO/NT\nNcpbvyb4rLriW7xGgHScc3rdmgJnmMeXXKdMQt8q0kjbaSeibq1Z3Jqa7nDQa//1\n1VauaXNcLtiU6eTYP7vf9qLo1evQ7tkIo8PGeqX92dp4fse7lv6zVQdKlP/GiQID\nAQABo0QwQjAhBgNVHREEGjAYghZtZWV0aW5ndG9vbHMubm9yZHUubmV0MB0GA1Ud\nDgQWBBQiAOf3NZwStjuODYT1PI8wpOYO2jANBgkqhkiG9w0BAQUFAAOCAQEAasFD\nWphqHBIxJMIx1TR5LCoabp9ZM8yN7TNpmneCnhSotjNxDRhzHANKsotjRsmV80tA\n5v4yN0ORHXDjN18C1YtkaYZNGSPwEbaLWeY2MulBcgJq0nvNOxDeGhkO57u+stgY\n8Wi/UNX1X9L5TJ60AdR+jE3gVsAA7DqhKRWqSvsh6jfSwUg83A/QYIp7Qi5LfejS\nLjjhavn6zDPLc+ILO7PDrwLBw8FD9bsff4wpngUvwQb1c1jgAy1FNGO/lK5KfX45\nasFBcvwcrKqc1WoJd5PodrX9RFw/bbIceEm5ifzg2KzsS+rWxah/RVXsXWio/nY5\npcqH0yzoEFA0VHDdXA==", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ], 
        "artifact_resolution_service": [
          {
            "index": "1", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:SOAP", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ArtifactResolutionService", 
            "location": "https://meetingtools.nordu.net/Shibboleth.sso/Artifact/SOAP"
          }
        ], 
        "manage_name_id_service": [
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:SOAP", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ManageNameIDService", 
            "location": "https://meetingtools.nordu.net/Shibboleth.sso/NIM/SOAP"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ManageNameIDService", 
            "location": "https://meetingtools.nordu.net/Shibboleth.sso/NIM/Redirect"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ManageNameIDService", 
            "location": "https://meetingtools.nordu.net/Shibboleth.sso/NIM/POST"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ManageNameIDService", 
            "location": "https://meetingtools.nordu.net/Shibboleth.sso/NIM/Artifact"
          }
        ]
      }
    ]
  }, 
  "https://idp.umu.se/saml2/idp/metadata.php": {
    "valid_until": "2012-12-16T04:23:08Z", 
    "entity_id": "https://idp.umu.se/saml2/idp/metadata.php", 
    "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EntityDescriptor", 
    "idpsso_descriptor": [
      {
        "single_logout_service": [
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleLogoutService", 
            "location": "https://idp.umu.se/saml2/idp/SingleLogoutService.php"
          }
        ], 
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&IDPSSODescriptor", 
        "single_sign_on_service": [
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleSignOnService", 
            "location": "https://idp.umu.se/saml2/idp/SSOService.php"
          }
        ], 
        "extensions": {
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Extensions", 
          "extension_elements": [
            {
              "attribute_value": [
                {
                  "text": "kalmar", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }, 
                {
                  "text": "sweden", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }
              ], 
              "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&Attribute", 
              "name": "tags"
            }
          ]
        }, 
        "key_descriptor": [
          {
            "use": "signing", 
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIDhzCCAm+gAwIBAgIJAI1+B/ykYMKxMA0GCSqGSIb3DQEBBQUAMFoxCzAJBgNVBAYTAlNFMQ0wCwYDVQQHDARVbWVhMRkwFwYDVQQKDBBVbWVhIHVuaXZlcnNpdGV0MQwwCgYDVQQLDANJVFMxEzARBgNVBAMMCmlkcC51bXUuc2UwHhcNMTIwMTE3MDkwNzAyWhcNMjIwMTE0MDkwNzAyWjBaMQswCQYDVQQGEwJTRTENMAsGA1UEBwwEVW1lYTEZMBcGA1UECgwQVW1lYSB1bml2ZXJzaXRldDEMMAoGA1UECwwDSVRTMRMwEQYDVQQDDAppZHAudW11LnNlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxi4TpxJad+Voksq5ArQ1D5yYx0u9Tq6kaNJDFGUQOSb6rzfiiau3p/Uy02Hy5Y/iPAZblYffrTpQOC6dcrYRdoKI20ZWyc7dwc24yuo8mfsnNt5xoAHZbmAO6jw98tvYz0WWXYYcBbkiAwELfSdLd1n8V6mCpx3oLji/xzhBw+B+sLkLUXVaG3p3lTDicRmpuZPnaOKVDexYHWrJ98JZw45k8aw/SpwBZJzcJ4HtaUIrtrjasdbPmfL92nr8XM3mFMQRBjMwZNnt8MIpBnnmZVk9HlzgFooL1OkaujpLMxzhAi2Ft8rHxZYsboGZytlPgPGnfANQ4+bFb67bKFfUXwIDAQABo1AwTjAdBgNVHQ4EFgQUWGMuElpC3shsrqn7K+chLwAGFMAwHwYDVR0jBBgwFoAUWGMuElpC3shsrqn7K+chLwAGFMAwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQUFAAOCAQEAM0k3m+271OHet+AWgHhApuy3TcnobVixJSAdOjiPhX8sIbA62m9NDEFrPBew1HUh2XYaO87rSxZXS2NsXQmkkcOpavAqVISckEX9jpjgBEC/8Kz2uFzf9uf/7eYA1tnJTRVpfy1XLd9D7B3R8B/vjnYBJVgKtlz2qJrDr7RvZ8+twMYcDnqiVcjbvhDN0ItOdW9Wn5arzMQddUUI4Ok9KBPJxO3NP9crHJ7o63gLvB6YjEK+zcKagIHc8y+8xmuXzbg2zaQAY9GKxdyVjbmMQtEm8R99vmrmXgz0qfng8ET8WPkRl7ugPTYCo+H2Bq/rN31pRLF+MVBq/kHc7lPk3w==", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }, 
          {
            "use": "encryption", 
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIDhzCCAm+gAwIBAgIJAI1+B/ykYMKxMA0GCSqGSIb3DQEBBQUAMFoxCzAJBgNVBAYTAlNFMQ0wCwYDVQQHDARVbWVhMRkwFwYDVQQKDBBVbWVhIHVuaXZlcnNpdGV0MQwwCgYDVQQLDANJVFMxEzARBgNVBAMMCmlkcC51bXUuc2UwHhcNMTIwMTE3MDkwNzAyWhcNMjIwMTE0MDkwNzAyWjBaMQswCQYDVQQGEwJTRTENMAsGA1UEBwwEVW1lYTEZMBcGA1UECgwQVW1lYSB1bml2ZXJzaXRldDEMMAoGA1UECwwDSVRTMRMwEQYDVQQDDAppZHAudW11LnNlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxi4TpxJad+Voksq5ArQ1D5yYx0u9Tq6kaNJDFGUQOSb6rzfiiau3p/Uy02Hy5Y/iPAZblYffrTpQOC6dcrYRdoKI20ZWyc7dwc24yuo8mfsnNt5xoAHZbmAO6jw98tvYz0WWXYYcBbkiAwELfSdLd1n8V6mCpx3oLji/xzhBw+B+sLkLUXVaG3p3lTDicRmpuZPnaOKVDexYHWrJ98JZw45k8aw/SpwBZJzcJ4HtaUIrtrjasdbPmfL92nr8XM3mFMQRBjMwZNnt8MIpBnnmZVk9HlzgFooL1OkaujpLMxzhAi2Ft8rHxZYsboGZytlPgPGnfANQ4+bFb67bKFfUXwIDAQABo1AwTjAdBgNVHQ4EFgQUWGMuElpC3shsrqn7K+chLwAGFMAwHwYDVR0jBBgwFoAUWGMuElpC3shsrqn7K+chLwAGFMAwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQUFAAOCAQEAM0k3m+271OHet+AWgHhApuy3TcnobVixJSAdOjiPhX8sIbA62m9NDEFrPBew1HUh2XYaO87rSxZXS2NsXQmkkcOpavAqVISckEX9jpjgBEC/8Kz2uFzf9uf/7eYA1tnJTRVpfy1XLd9D7B3R8B/vjnYBJVgKtlz2qJrDr7RvZ8+twMYcDnqiVcjbvhDN0ItOdW9Wn5arzMQddUUI4Ok9KBPJxO3NP9crHJ7o63gLvB6YjEK+zcKagIHc8y+8xmuXzbg2zaQAY9GKxdyVjbmMQtEm8R99vmrmXgz0qfng8ET8WPkRl7ugPTYCo+H2Bq/rN31pRLF+MVBq/kHc7lPk3w==", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ], 
        "artifact_resolution_service": [
          {
            "index": "0", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:SOAP", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ArtifactResolutionService", 
            "location": "https://idp.umu.se/saml2/idp/ArtifactResolutionService.php"
          }
        ], 
        "name_id_format": [
          {
            "text": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }
        ]
      }
    ], 
    "organization": {
      "organization_name": [
        {
          "lang": "en", 
          "text": "UmU", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }, 
        {
          "lang": "se", 
          "text": "UmU", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }
      ], 
      "organization_display_name": [
        {
          "lang": "en", 
          "text": "Ume\u00e5 University", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }, 
        {
          "lang": "se", 
          "text": "Ume\u00e5 universitet", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }
      ], 
      "organization_url": [
        {
          "lang": "en", 
          "text": "http://www.umu.se/english", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }, 
        {
          "lang": "se", 
          "text": "http://www.umu.se", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }
      ], 
      "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Organization"
    }, 
    "contact_person": [
      {
        "email_address": [
          {
            "text": "datordrift@umdac.umu.se", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ], 
        "sur_name": {
          "text": "Datordrift", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SurName"
        }, 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "contact_type": "technical"
      }
    ]
  }, 
  "https://sp.lux17.mpi.nl": {
    "valid_until": "2012-12-19T20:15:01Z", 
    "entity_id": "https://sp.lux17.mpi.nl", 
    "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EntityDescriptor", 
    "organization": {
      "organization_name": [
        {
          "lang": "fi", 
          "text": "CLARIN Service Provider Federation/MPI", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }, 
        {
          "lang": "en", 
          "text": "CLARIN Service Provider Federation/MPI", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }, 
        {
          "lang": "sv", 
          "text": "CLARIN Service Provider Federation/MPI", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }
      ], 
      "organization_display_name": [
        {
          "lang": "fi", 
          "text": "CLARIN Service Provider Federation/MPI", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }, 
        {
          "lang": "en", 
          "text": "CLARIN Service Provider Federation/MPI", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }, 
        {
          "lang": "sv", 
          "text": "CLARIN Service Provider Federation/MPI", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }
      ], 
      "organization_url": [
        {
          "lang": "fi", 
          "text": "http://www.clarin.eu", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }, 
        {
          "lang": "en", 
          "text": "http://www.clarin.eu", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }, 
        {
          "lang": "sv", 
          "text": "http://www.clarin.eu", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }
      ], 
      "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Organization"
    }, 
    "contact_person": [
      {
        "given_name": {
          "text": "Tobias", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&GivenName"
        }, 
        "email_address": [
          {
            "text": "tobias.vanvalkenhoef@mpi.nl", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ], 
        "sur_name": {
          "text": "van Valkenhoef", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SurName"
        }, 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "contact_type": "technical"
      }
    ], 
    "spsso_descriptor": [
      {
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "assertion_consumer_service": [
          {
            "is_default": "true", 
            "index": "1", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://lux17.mpi.nl/Shibboleth.sso/SAML2/POST"
          }, 
          {
            "is_default": "false", 
            "index": "2", 
            "binding": "urn:oasis:names:tc:SAML:1.0:profiles:browser-post", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://lux17.mpi.nl/Shibboleth.sso/SAML/POST"
          }
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SPSSODescriptor", 
        "name_id_format": [
          {
            "text": "urn:mace:shibboleth:1.0:nameIdentifier", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }, 
          {
            "text": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }
        ], 
        "attribute_consuming_service": [
          {
            "index": "1", 
            "service_name": [
              {
                "lang": "fi", 
                "text": "IMDI Browsable Corpus", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }, 
              {
                "lang": "en", 
                "text": "IMDI Browsable Corpus", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }
            ], 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AttributeConsumingService", 
            "is_default": "true", 
            "requested_attribute": [
              {
                "friendly_name": "eduPersonPrincipalName", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
              }, 
              {
                "friendly_name": "mail", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:0.9.2342.19200300.100.1.3"
              }, 
              {
                "friendly_name": "o", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.10"
              }
            ], 
            "service_description": [
              {
                "lang": "en", 
                "text": "Repository of Linguistic Resources. For Humanities and Social Sciences researchers.", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }
            ]
          }
        ], 
        "key_descriptor": [
          {
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIE1zCCA7+gAwIBAgIEDeB5KTANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJE\nRTEgMB4GA1UEChMXTWF4LVBsYW5jay1HZXNlbGxzY2hhZnQxDzANBgNVBAMTBk1Q\nRyBDQTEcMBoGCSqGSIb3DQEJARYNbXBnLWNhQG1wZy5kZTAeFw0wOTAzMTgxMzQ4\nMTBaFw0xNDAzMTcxMzQ4MTBaMHoxCzAJBgNVBAYTAk5MMSAwHgYDVQQKExdNYXgt\nUGxhbmNrLUdlc2VsbHNjaGFmdDEyMDAGA1UECxMpTWF4LVBsYW5jay1JbnN0aXR1\ndCBmdWVyIFBzeWNob2xpbmd1aXN0aWsxFTATBgNVBAMTDGx1eDE3Lm1waS5ubDCC\nASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL0wTdnMTgPC8/x6+0reirYB\nbifyQwbOLHE0bOtHD6et5oT9WPRosJFpFxnxs2aF/SqR7Kar4Z/7lMBFbL3vdgrJ\nh6fCNVofBI/Zs7d8aCwfcc6aMJORJPlTtFElmNvZD8TE035qzRNfkwqPOYkmwqlC\nCP9pJwebt3kEJSHHOVngydBJaVzSDayJLp1WzQ2FyEVfbPyUaQ2z2RyPGG0C1yX4\nThin64YaRlBH78INIlCf8NpQwc+CCG7SgVSuDq1DEZXbm7z789kUJtqnlNe2Nahj\ninYfMr4Jtc27TwD+We9cs14LjSst4L3gd0kT511Wycs53+BpMWRWVKD4tFMva+EC\nAwEAAaOCAX8wggF7MAkGA1UdEwQCMAAwCwYDVR0PBAQDAgTwMBMGA1UdJQQMMAoG\nCCsGAQUFBwMBMB0GA1UdDgQWBBRY3hAzheVZXJug0vL3ndQWl8CAjTAfBgNVHSME\nGDAWgBQC1h5uCau/WGWnCjxIM2HRzn3DWzB3BgNVHR8EcDBuMDWgM6Axhi9odHRw\nOi8vY2RwMS5wY2EuZGZuLmRlL21wZy1jYS9wdWIvY3JsL2NhY3JsLmNybDA1oDOg\nMYYvaHR0cDovL2NkcDIucGNhLmRmbi5kZS9tcGctY2EvcHViL2NybC9jYWNybC5j\ncmwwgZIGCCsGAQUFBwEBBIGFMIGCMD8GCCsGAQUFBzAChjNodHRwOi8vY2RwMS5w\nY2EuZGZuLmRlL21wZy1jYS9wdWIvY2FjZXJ0L2NhY2VydC5jcnQwPwYIKwYBBQUH\nMAKGM2h0dHA6Ly9jZHAyLnBjYS5kZm4uZGUvbXBnLWNhL3B1Yi9jYWNlcnQvY2Fj\nZXJ0LmNydDANBgkqhkiG9w0BAQUFAAOCAQEAbTiXJjoL5ulDq6yP3g2cBE4tpXN/\nLMe2gNgvBmzWIuvoMtI/qf5CWZI2Z/3T8uPHrzcrhWxjazhcrdMsdCrFEp1YCdUv\n3+ielpse2O+k7ZF/OKZtP2yBBrPqfn46K2luYs7omROhkzfKU76inhSn7aMDH8sp\nA483fjEFPdYorFjq087bpHkXqJuDKHm7Jz91+vjMZMJ5v5IH5oec84pT6yPO1f0k\n7v7NeAtHCybR2fYZnSGrjUOEOPCJx5ufyE5EOzATp5BVLXSLa2H4B0Ws2IOv9ORw\n0cYjl0hBJw+lYT0LPIUaE0SU1jtoOKUHevuygdjyiG0JPNgUks8Ow3+v/A==", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ]
      }
    ]
  }, 
  "https://jabber.nordu.net/shibboleth": {
    "valid_until": "2012-12-16T04:23:08Z", 
    "organization": {
      "organization_name": [
        {
          "lang": "en", 
          "text": "NORDUnet", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }
      ], 
      "organization_display_name": [
        {
          "lang": "en", 
          "text": "NORDUnet A/S", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }
      ], 
      "organization_url": [
        {
          "lang": "en", 
          "text": "http://www.nordu.net", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }
      ], 
      "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Organization"
    }, 
    "entity_id": "https://jabber.nordu.net/shibboleth", 
    "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EntityDescriptor", 
    "spsso_descriptor": [
      {
        "single_logout_service": [
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:SOAP", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleLogoutService", 
            "location": "https://jabber.nordu.net/Shibboleth.sso/SLO/SOAP"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleLogoutService", 
            "location": "https://jabber.nordu.net/Shibboleth.sso/SLO/Redirect"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleLogoutService", 
            "location": "https://jabber.nordu.net/Shibboleth.sso/SLO/POST"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleLogoutService", 
            "location": "https://jabber.nordu.net/Shibboleth.sso/SLO/Artifact"
          }
        ], 
        "attribute_consuming_service": [
          {
            "index": "0", 
            "service_description": [
              {
                "lang": "en", 
                "text": "Jabber at NORDUnet", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }
            ], 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AttributeConsumingService", 
            "requested_attribute": [
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:0.9.2342.19200300.100.1.3"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.42"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.4"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.9"
              }
            ], 
            "service_name": [
              {
                "lang": "en", 
                "text": "Jabber at NORDUnet", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }
            ]
          }
        ], 
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "assertion_consumer_service": [
          {
            "index": "1", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://jabber.nordu.net/Shibboleth.sso/SAML2/POST"
          }, 
          {
            "index": "2", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://jabber.nordu.net/Shibboleth.sso/SAML2/POST-SimpleSign"
          }, 
          {
            "index": "3", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://jabber.nordu.net/Shibboleth.sso/SAML2/Artifact"
          }, 
          {
            "index": "4", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:PAOS", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://jabber.nordu.net/Shibboleth.sso/SAML2/ECP"
          }, 
          {
            "index": "5", 
            "binding": "urn:oasis:names:tc:SAML:1.0:profiles:browser-post", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://jabber.nordu.net/Shibboleth.sso/SAML/POST"
          }, 
          {
            "index": "6", 
            "binding": "urn:oasis:names:tc:SAML:1.0:profiles:artifact-01", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://jabber.nordu.net/Shibboleth.sso/SAML/Artifact"
          }
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SPSSODescriptor", 
        "extensions": {
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Extensions", 
          "extension_elements": [
            {
              "index": "1", 
              "binding": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol", 
              "__class__": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol&DiscoveryResponse", 
              "location": "https://jabber.nordu.net/Shibboleth.sso/DS/nordu.net"
            }, 
            {
              "attribute_value": [
                {
                  "text": "kalmar", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }, 
                {
                  "text": "sweden", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }
              ], 
              "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&Attribute", 
              "name": "tags"
            }
          ]
        }, 
        "key_descriptor": [
          {
            "use": "signing", 
            "key_info": {
              "key_name": [
                {
                  "text": "jabber.nordu.net", 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyName"
                }
              ], 
              "x509_data": [
                {
                  "x509_subject_name": {
                    "text": "CN=jabber.nordu.net", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509SubjectName"
                  }, 
                  "x509_certificate": {
                    "text": "MIIC9zCCAd+gAwIBAgIJAMdBcIFfKqNcMA0GCSqGSIb3DQEBBQUAMBsxGTAXBgNV\nBAMTEGphYmJlci5ub3JkdS5uZXQwHhcNMTEwNDE1MDkxNDQ2WhcNMjEwNDEyMDkx\nNDQ2WjAbMRkwFwYDVQQDExBqYWJiZXIubm9yZHUubmV0MIIBIjANBgkqhkiG9w0B\nAQEFAAOCAQ8AMIIBCgKCAQEAuf/UhI1cEEWM1EVJNLJLxNQAjgcU1Ed4rWubB9iu\nZPmmpDnXMPJ/PiTAoi58iqzs28M6CN3mVqwP/PlMyt/N1toIu0VSd9R9czXyEmII\nJgBiEJ4CWbLdbhaLoCGeBEyKCob4ZdpHnV/+9o3Vx2kFo6frFg/SY4ryi1hXomcp\nhR5iTpo4H5pYDqFquvlJ0fxPmPBhqZpCeLhJBPGjTrS6rrEnkUYh3iKOywboOMIN\nyVdNhUcV5PPSM3+e0McIquAfRumRacVfhe+qvofEuTlWbTSPQLQymBfBMaDUDYjH\nWK6+jGjLAHB8Y9PPvwM/ecRSb6vckKfpu/Y/+arsn/7ihwIDAQABoz4wPDAbBgNV\nHREEFDASghBqYWJiZXIubm9yZHUubmV0MB0GA1UdDgQWBBTpbrmNDAbzimHpvfgR\nXi9+6vC1GDANBgkqhkiG9w0BAQUFAAOCAQEAFa/NGDqdgxvqkqss0m4SLCa2omxV\nopoYV2zwA7wjPqlPPi4M20i2LysFyqwrPHmOKH0wcAWiB4+d8XN8UmsLrVODmrJN\nBD07pGaDP6jamTtHOr4Enj25pJ/0Fe5hZeLJ3ppFebgq6TfrTd41qIwmC0KMClay\nK0rTtqshk+nKb89Re3xutEU9D7r+EaoHIa9rw1bTz6UmkFZ5ovjfV3htogb8xNt9\n2kQbxgdjl0QkFTf2sURB+4El0oUnXdOZiqQS5hqjEtZDJ6NlDvtW7OtH/SE2PAyn\nzvTzeciRKJ9UNf9ibAJGF7jz/GP5r+yUgizdV0wyikyUa8VNyrSeExBUVg==", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }, 
          {
            "use": "encryption", 
            "key_info": {
              "key_name": [
                {
                  "text": "jabber.nordu.net", 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyName"
                }
              ], 
              "x509_data": [
                {
                  "x509_subject_name": {
                    "text": "CN=jabber.nordu.net", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509SubjectName"
                  }, 
                  "x509_certificate": {
                    "text": "MIIC9zCCAd+gAwIBAgIJAMdBcIFfKqNcMA0GCSqGSIb3DQEBBQUAMBsxGTAXBgNV\nBAMTEGphYmJlci5ub3JkdS5uZXQwHhcNMTEwNDE1MDkxNDQ2WhcNMjEwNDEyMDkx\nNDQ2WjAbMRkwFwYDVQQDExBqYWJiZXIubm9yZHUubmV0MIIBIjANBgkqhkiG9w0B\nAQEFAAOCAQ8AMIIBCgKCAQEAuf/UhI1cEEWM1EVJNLJLxNQAjgcU1Ed4rWubB9iu\nZPmmpDnXMPJ/PiTAoi58iqzs28M6CN3mVqwP/PlMyt/N1toIu0VSd9R9czXyEmII\nJgBiEJ4CWbLdbhaLoCGeBEyKCob4ZdpHnV/+9o3Vx2kFo6frFg/SY4ryi1hXomcp\nhR5iTpo4H5pYDqFquvlJ0fxPmPBhqZpCeLhJBPGjTrS6rrEnkUYh3iKOywboOMIN\nyVdNhUcV5PPSM3+e0McIquAfRumRacVfhe+qvofEuTlWbTSPQLQymBfBMaDUDYjH\nWK6+jGjLAHB8Y9PPvwM/ecRSb6vckKfpu/Y/+arsn/7ihwIDAQABoz4wPDAbBgNV\nHREEFDASghBqYWJiZXIubm9yZHUubmV0MB0GA1UdDgQWBBTpbrmNDAbzimHpvfgR\nXi9+6vC1GDANBgkqhkiG9w0BAQUFAAOCAQEAFa/NGDqdgxvqkqss0m4SLCa2omxV\nopoYV2zwA7wjPqlPPi4M20i2LysFyqwrPHmOKH0wcAWiB4+d8XN8UmsLrVODmrJN\nBD07pGaDP6jamTtHOr4Enj25pJ/0Fe5hZeLJ3ppFebgq6TfrTd41qIwmC0KMClay\nK0rTtqshk+nKb89Re3xutEU9D7r+EaoHIa9rw1bTz6UmkFZ5ovjfV3htogb8xNt9\n2kQbxgdjl0QkFTf2sURB+4El0oUnXdOZiqQS5hqjEtZDJ6NlDvtW7OtH/SE2PAyn\nzvTzeciRKJ9UNf9ibAJGF7jz/GP5r+yUgizdV0wyikyUa8VNyrSeExBUVg==", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ], 
        "manage_name_id_service": [
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:SOAP", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ManageNameIDService", 
            "location": "https://jabber.nordu.net/Shibboleth.sso/NIM/SOAP"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ManageNameIDService", 
            "location": "https://jabber.nordu.net/Shibboleth.sso/NIM/Redirect"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ManageNameIDService", 
            "location": "https://jabber.nordu.net/Shibboleth.sso/NIM/POST"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ManageNameIDService", 
            "location": "https://jabber.nordu.net/Shibboleth.sso/NIM/Artifact"
          }
        ]
      }
    ]
  }, 
  "https://agw-sparknet.utu.fi": {
    "valid_until": "2012-12-19T20:15:01Z", 
    "entity_id": "https://agw-sparknet.utu.fi", 
    "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EntityDescriptor", 
    "organization": {
      "organization_name": [
        {
          "lang": "fi", 
          "text": "Turun yliopisto", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }, 
        {
          "lang": "en", 
          "text": "University of Turku", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }, 
        {
          "lang": "sv", 
          "text": "Abo universitet", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }
      ], 
      "organization_display_name": [
        {
          "lang": "fi", 
          "text": "Turun yliopisto", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }, 
        {
          "lang": "en", 
          "text": "University of Turku", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }, 
        {
          "lang": "sv", 
          "text": "Abo universitet", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }
      ], 
      "organization_url": [
        {
          "lang": "fi", 
          "text": "http://www.utu.fi/", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }, 
        {
          "lang": "en", 
          "text": "http://www.utu.fi/", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }, 
        {
          "lang": "sv", 
          "text": "http://www.utu.fi/", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }
      ], 
      "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Organization"
    }, 
    "contact_person": [
      {
        "given_name": {
          "text": "Mikko", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&GivenName"
        }, 
        "email_address": [
          {
            "text": "hakajasen@utu.fi", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ], 
        "sur_name": {
          "text": "Niemi", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SurName"
        }, 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "contact_type": "technical"
      }, 
      {
        "given_name": {
          "text": "Mikko", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&GivenName"
        }, 
        "email_address": [
          {
            "text": "hakajasen@utu.fi", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ], 
        "sur_name": {
          "text": "Niemi", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SurName"
        }, 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "contact_type": "support"
      }
    ], 
    "spsso_descriptor": [
      {
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "assertion_consumer_service": [
          {
            "is_default": "true", 
            "index": "1", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://agw-common.sparknet.fi/Shibboleth.sso/SAML2/POST"
          }, 
          {
            "is_default": "false", 
            "index": "2", 
            "binding": "urn:oasis:names:tc:SAML:1.0:profiles:browser-post", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://agw-common.sparknet.fi/Shibboleth.sso/SAML/POST"
          }
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SPSSODescriptor", 
        "name_id_format": [
          {
            "text": "urn:mace:shibboleth:1.0:nameIdentifier", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }, 
          {
            "text": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }
        ], 
        "attribute_consuming_service": [
          {
            "index": "1", 
            "service_name": [
              {
                "lang": "fi", 
                "text": "Turun yliopiston SparkNet", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }, 
              {
                "lang": "en", 
                "text": "University of Turku SparkNet", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }
            ], 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AttributeConsumingService", 
            "is_default": "true", 
            "requested_attribute": [
              {
                "friendly_name": "eduPersonAffiliation", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.1"
              }
            ], 
            "service_description": [
              {
                "lang": "fi", 
                "text": "Sparknet, Turun yliopiston langaton verkko", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }, 
              {
                "lang": "en", 
                "text": "Sparknet, Wireless network of University of Turku", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }
            ]
          }
        ], 
        "key_descriptor": [
          {
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIE4zCCA8ugAwIBAgIQbnMIzP8TsRk95w/HSxaw8TANBgkqhkiG9w0BAQUFADA2\nMQswCQYDVQQGEwJOTDEPMA0GA1UEChMGVEVSRU5BMRYwFAYDVQQDEw1URVJFTkEg\nU1NMIENBMB4XDTEwMTEyMzAwMDAwMFoXDTEzMTEyMjIzNTk1OVowgboxCzAJBgNV\nBAYTAkZJMQ4wDAYDVQQREwUyMDUwMDEYMBYGA1UECBMPV2VzdGVybiBGaW5sYW5k\nMQ4wDAYDVQQHEwVUdXJrdTEaMBgGA1UECRMRQXNzaXN0ZW50aW5rYXR1IDUxHDAa\nBgNVBAoTE1VuaXZlcnNpdHkgb2YgVHVya3UxGTAXBgNVBAsTEENvbXB1dGluZyBD\nZW50cmUxHDAaBgNVBAMTE2Fndy1zcGFya25ldC51dHUuZmkwggEiMA0GCSqGSIb3\nDQEBAQUAA4IBDwAwggEKAoIBAQC/DfwsS+l2OcvB8YLJqMKLUrUc9KmEgLuCIBNh\nsy5hZDOnV7vieUzsxibSsz8LO/sqNXZu+oAJvQEbKVzglohKVpvZkXDWB4fJ7/Hk\nAXSSnKFUvA6D7NyITFHus2OuPVtWg7rOH53Hcsj7zDey1tLpt75+r9VYz+rfj7dY\nZhBjQxjnVboDdD0KCw5SuPTYo2L+ZQit7Ede4g9KY970iSjXsPA5pFrjN1pezrse\n7MLBeqfiISwvEsmFvnRImzhnGlc1jkgK1mAxpGGFUOB3wRvlR9uQ1KjlSaFhPfUj\nV09/dG5tdEvc3bUV+3FEM+5Wv/9JMFXmfW/twfGE1cFVL5mRAgMBAAGjggFmMIIB\nYjAfBgNVHSMEGDAWgBQMvZNoDPPeq6NJays3V0fqkOO57TAdBgNVHQ4EFgQUpAIR\n/AL9x2BJgB91p7Z1RDOOGjowDgYDVR0PAQH/BAQDAgWgMAwGA1UdEwEB/wQCMAAw\nHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMBgGA1UdIAQRMA8wDQYLKwYB\nBAGyMQECAh0wOgYDVR0fBDMwMTAvoC2gK4YpaHR0cDovL2NybC50Y3MudGVyZW5h\nLm9yZy9URVJFTkFTU0xDQS5jcmwwbQYIKwYBBQUHAQEEYTBfMDUGCCsGAQUFBzAC\nhilodHRwOi8vY3J0LnRjcy50ZXJlbmEub3JnL1RFUkVOQVNTTENBLmNydDAmBggr\nBgEFBQcwAYYaaHR0cDovL29jc3AudGNzLnRlcmVuYS5vcmcwHgYDVR0RBBcwFYIT\nYWd3LXNwYXJrbmV0LnV0dS5maTANBgkqhkiG9w0BAQUFAAOCAQEAQ09BWmqzKH3P\nywMfrWMAShhiowX3us9JTTJ8HLlApPWjW0feHpzvPCv86J2Ryeg+tRqtsYGAenvL\nFLqYnD65FaKos7/RrwQuxrwsDDbCk0LLVyDhlms7aOSvKRCmK1oyK9MABnraFh8e\nm3ueojjatPYaUG+ivTalv5oWuYi/Ye6GRGBlhyx2u972UqngRYnHAHCYrRzRA/l8\nVRtAw/rJTS3Yj5kDUG3LYeBH5A4myDeIHghg7n0s7A9qDtepxZFYgDzrwUusEo/a\nNbLlYF90/H/wrBP9SogebSqmAAEd7V+vMe2+W7N03f80xajbIli0+P0sEolPPgrW\nDSWPf8vQpQ==", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ]
      }
    ]
  }, 
  "https://web.tut.fi/shibboleth": {
    "valid_until": "2012-12-19T20:15:01Z", 
    "entity_id": "https://web.tut.fi/shibboleth", 
    "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EntityDescriptor", 
    "organization": {
      "organization_name": [
        {
          "lang": "fi", 
          "text": "Tampereen teknillinen yliopisto", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }, 
        {
          "lang": "en", 
          "text": "Tampere University of Technology", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }, 
        {
          "lang": "sv", 
          "text": "Tammerfors tekniska universitet", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }
      ], 
      "organization_display_name": [
        {
          "lang": "fi", 
          "text": "Tampereen teknillinen yliopisto", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }, 
        {
          "lang": "en", 
          "text": "Tampere University of Technology", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }, 
        {
          "lang": "sv", 
          "text": "Tammerfors tekniska universitet", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }
      ], 
      "organization_url": [
        {
          "lang": "fi", 
          "text": "http://www.tut.fi", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }, 
        {
          "lang": "en", 
          "text": "http://www.tut.fi", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }, 
        {
          "lang": "sv", 
          "text": "http://www.tut.fi", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }
      ], 
      "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Organization"
    }, 
    "contact_person": [
      {
        "given_name": {
          "text": "Jussi", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&GivenName"
        }, 
        "email_address": [
          {
            "text": "jussi.tirkkonen@tut.fi", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ], 
        "sur_name": {
          "text": "Tirkkonen", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SurName"
        }, 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "contact_type": "technical"
      }
    ], 
    "spsso_descriptor": [
      {
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "assertion_consumer_service": [
          {
            "is_default": "true", 
            "index": "1", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://web.tut.fi/Shibboleth.sso/SAML2/POST"
          }
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SPSSODescriptor", 
        "name_id_format": [
          {
            "text": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }
        ], 
        "attribute_consuming_service": [
          {
            "index": "1", 
            "service_name": [
              {
                "lang": "fi", 
                "text": "Acrobat Connect Pro -verkkokokouspalvelu", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }, 
              {
                "lang": "en", 
                "text": "TUT Acrobat Connect Pro", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }, 
              {
                "lang": "sv", 
                "text": "TUT Acrobat Connect Pro", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }
            ], 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AttributeConsumingService", 
            "is_default": "true", 
            "requested_attribute": [
              {
                "friendly_name": "cn", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.3"
              }, 
              {
                "friendly_name": "displayName", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.16.840.1.113730.3.1.241"
              }, 
              {
                "friendly_name": "eduPersonAffiliation", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.1"
              }, 
              {
                "friendly_name": "eduPersonPrincipalName", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
              }, 
              {
                "friendly_name": "mail", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:0.9.2342.19200300.100.1.3"
              }, 
              {
                "friendly_name": "schacHomeOrganization", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.25178.1.2.9"
              }, 
              {
                "friendly_name": "sn", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.4"
              }
            ], 
            "service_description": [
              {
                "lang": "fi", 
                "text": "TTY:n verkkokokouspalvelu.", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }, 
              {
                "lang": "en", 
                "text": "TUT web conference service.", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }, 
              {
                "lang": "sv", 
                "text": "TUT-tjansten for e-moten.", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }
            ]
          }
        ], 
        "key_descriptor": [
          {
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIE2TCCA8GgAwIBAgIQAJccxEo2duCHcGqbD4x1ezANBgkqhkiG9w0BAQUFADA2\nMQswCQYDVQQGEwJOTDEPMA0GA1UEChMGVEVSRU5BMRYwFAYDVQQDEw1URVJFTkEg\nU1NMIENBMB4XDTEwMTIxMzAwMDAwMFoXDTEzMTIxMjIzNTk1OVowgbkxCzAJBgNV\nBAYTAkZJMQ4wDAYDVQQREwUzMzcyMDESMBAGA1UECBMJUGlya2FubWFhMRAwDgYD\nVQQHEwdUYW1wZXJlMRwwGgYDVQQJExNLb3JrZWFrb3VsdW5rYXR1IDEwMSkwJwYD\nVQQKEyBUYW1wZXJlIFVuaXZlcnNpdHkgb2YgVGVjaG5vbG9neTEWMBQGA1UECxMN\nVGlldG9oYWxsaW50bzETMBEGA1UEAxMKd2ViLnR1dC5maTCCASIwDQYJKoZIhvcN\nAQEBBQADggEPADCCAQoCggEBAMwuC5ZzOZGbCpzsmKNIBH1rkRQRFRnh1MCO9Yj1\n1SswE4yLjA6dETebXoTMrwJb/v7uDVmv7NY33vUDolPxenXmMcfBqLfQI46MPaiV\n0cKAu0RvPHtpmTghnzFZOg4hGvYIAIT1zPkYywg7U4VFyMtJPnPnlOJeHhbh91vT\nTT37n5Fmh9RWUQJsxzfSQmE3xMVNgnPFBe84Pa+rNTbix24MgmV2hgchSuTFBaEq\nMS3Pba1SJETJ1bZcERyJNLTO8m80BuYZrBYuBjheYfQ23jf1Gy/LLgK9yZJNH9ll\nCnMoQfltT+QkOLy84GHbiEVAXzPfrAmqbZOGcHTt3Q7cAOsCAwEAAaOCAV0wggFZ\nMB8GA1UdIwQYMBaAFAy9k2gM896ro0lrKzdXR+qQ47ntMB0GA1UdDgQWBBRs64Sa\ndKhtvd/JVXh5Bnp6NTaw6DAOBgNVHQ8BAf8EBAMCBaAwDAYDVR0TAQH/BAIwADAd\nBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwGAYDVR0gBBEwDzANBgsrBgEE\nAbIxAQICHTA6BgNVHR8EMzAxMC+gLaArhilodHRwOi8vY3JsLnRjcy50ZXJlbmEu\nb3JnL1RFUkVOQVNTTENBLmNybDBtBggrBgEFBQcBAQRhMF8wNQYIKwYBBQUHMAKG\nKWh0dHA6Ly9jcnQudGNzLnRlcmVuYS5vcmcvVEVSRU5BU1NMQ0EuY3J0MCYGCCsG\nAQUFBzABhhpodHRwOi8vb2NzcC50Y3MudGVyZW5hLm9yZzAVBgNVHREEDjAMggp3\nZWIudHV0LmZpMA0GCSqGSIb3DQEBBQUAA4IBAQBGpKYnuWg/2lN/WYKM/APV44DW\n7Unb8uV40JE2HIpcTXmbgIf/QZJRyou3MxqJS8/f1C4KGDvrWxMqJbWZIO1FGbtL\n4ghjMFfeg68z7R7uj0Gfz4/pj69oSR5duW/9yBdNQ4igO3cAb+RRCRU4iR1s7oZe\nPcv6EAzVSd8GmAVe6EwPpiAA5Zi/61nUCXU2SRfI2E35z7XgGo6z2enHQY8WQvMg\nb+GdlT/1WE0+6q1Z5/AzDXSjx9v2lW+NOmJ0/gSEaIo3DAMaL/K1d0Jv03nNTfBb\n00f/455XQUhcJwtLj063dTVgETHTo+6CZeqBbKQCclY/oOUvTOQdT4v+4E1k", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ]
      }
    ]
  }, 
  "urn:mace:feide.no:services:com.itslearning": {
    "valid_until": "2012-12-19T20:14:03Z", 
    "entity_id": "urn:mace:feide.no:services:com.itslearning", 
    "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EntityDescriptor", 
    "organization": {
      "organization_name": [
        {
          "lang": "en", 
          "text": "itslearning", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }
      ], 
      "organization_display_name": [
        {
          "lang": "en", 
          "text": "itslearning", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }
      ], 
      "organization_url": [
        {
          "lang": "en", 
          "text": "http://www.itslearning.eu/", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }
      ], 
      "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Organization"
    }, 
    "contact_person": [
      {
        "given_name": {
          "text": "itslearning Support", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&GivenName"
        }, 
        "company": {
          "text": "itslearning", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Company"
        }, 
        "email_address": [
          {
            "text": "support@itslearning.com", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "contact_type": "technical"
      }
    ], 
    "spsso_descriptor": [
      {
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "assertion_consumer_service": [
          {
            "index": "0", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://www.itslearning.com/elogin/default.aspx"
          }
        ], 
        "single_logout_service": [
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleLogoutService", 
            "location": "https://www.itslearning.com/elogin/logout.aspx"
          }
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SPSSODescriptor", 
        "attribute_consuming_service": [
          {
            "index": "0", 
            "service_description": [
              {
                "lang": "en", 
                "text": "itslearning is a virtual learning environment specifically designed for schools and universities.", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }, 
              {
                "lang": "no", 
                "text": "itslearning er et virtuelt l\u00e6ringsmilj\u00f8, spesielt utformet for skoler og universiteter.", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }
            ], 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AttributeConsumingService", 
            "requested_attribute": [
              {
                "friendly_name": "eduPersonPrincipalName", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
              }
            ], 
            "service_name": [
              {
                "lang": "en", 
                "text": "itslearning", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }
            ]
          }
        ]
      }
    ]
  }, 
  "http://wayf.ordbogen.com": {
    "valid_until": "2012-12-19T20:17:02Z", 
    "entity_id": "http://wayf.ordbogen.com", 
    "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EntityDescriptor", 
    "spsso_descriptor": [
      {
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "assertion_consumer_service": [
          {
            "index": "0", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://wayf.ordbogen.com/saml2/sp/AssertionConsumerService.php"
          }
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SPSSODescriptor", 
        "name_id_format": [
          {
            "text": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }
        ], 
        "attribute_consuming_service": [
          {
            "index": "0", 
            "service_description": [
              {
                "lang": "en", 
                "text": "to provide an online dictionary in which you look up an unlimited number of words in the dictionaries bought by your educational institution.", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }, 
              {
                "lang": "da", 
                "text": "at levere en online ordbog hvori du kan foretage et ubegr\u00e6nset antal opslag i de ordb\u00f8ger, som din institution har k\u00f8bt adgang til.", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }
            ], 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AttributeConsumingService", 
            "requested_attribute": [
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.25178.1.2.9"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.10"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.10"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.9"
              }
            ], 
            "service_name": [
              {
                "lang": "en", 
                "text": "Ordbogen.com", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }, 
              {
                "lang": "da", 
                "text": "Ordbogen.com", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }
            ]
          }
        ], 
        "key_descriptor": [
          {
            "use": "signing", 
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIEdjCCA16gAwIBAgILAQAAAAABLysKVFswDQYJKoZIhvcNAQEFBQAwYzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExFjAUBgNVBAsTDU9iamVjdFNpZ24gQ0ExITAfBgNVBAMTGEdsb2JhbFNpZ24gT2JqZWN0U2lnbiBDQTAeFw0xMTA0MDYxMzI1NDZaFw0xMzA0MDYxMzI1NDRaMEwxCzAJBgNVBAYTAkRLMQ8wDQYDVQQIEwZPZGVuc2UxFTATBgNVBAoTDE9yZGJvZ2VuIEEvUzEVMBMGA1UEAxMMT3JkYm9nZW4gQS9TMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAovIjWe1fOERH9N7Dk7OP9K1YveGQZipKE+GaOHnCNe33F4a1sXMhT38fEUNWQpRLDBeLsWF2G5FnwrVDGb3qo8dN7e4ycZWbZIBuC/lyq8qRt6iIxNHQ7oad8N2m7CTe3ZNdkPHEY8eaDHUP2AC8c1SXyakv394WKuT2roIZ4OD74pv9CTDGFVNsbgOU1xTM+QIvbRSUDmVGBdkUv5tstC9w7R7UdhrW8R1wYcTwA9UxMNEiCNBvyMTfAcJO32FzDTa5nBopyoAK4jgGEdrz8Oeb17MCb+sStxJiZRTuFCgkvuNkCNXEuBBYiNDAyB8AwsLKMw6IzBPCG88NfcmUZwIDAQABo4IBQDCCATwwHwYDVR0jBBgwFoAU0lvzSyZLpbDnXf1Wf/bxLjhOU6AwTgYIKwYBBQUHAQEEQjBAMD4GCCsGAQUFBzAChjJodHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24ubmV0L2NhY2VydC9PYmplY3RTaWduLmNydDA5BgNVHR8EMjAwMC6gLKAqhihodHRwOi8vY3JsLmdsb2JhbHNpZ24ubmV0L09iamVjdFNpZ24uY3JsMAkGA1UdEwQCMAAwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMEsGA1UdIAREMEIwQAYJKwYBBAGgMgEyMDMwMQYIKwYBBQUHAgEWJWh0dHA6Ly93d3cuZ2xvYmFsc2lnbi5uZXQvcmVwb3NpdG9yeS8wEQYJYIZIAYb4QgEBBAQDAgQQMA0GCSqGSIb3DQEBBQUAA4IBAQA0lPLNM6+JLbeGyjZQ5tU7H4c1hX1WcAAGgRVF1oVtTEH8vA4V+roVB35+8Jk08rzqh+ghIUX99P2keUTOlllYUbxb7DXfsOprD5tDGc/jmMMZrYzL3ibdW0229/eaokXMPI6As7ApvQ7utb+sjftwQoI9BkJlbMRoW//t2GYY3bP7+r7yDUbcOVwNUm3ZoxErIM7SulpTS36uP8jcr0zPOwRAx6atMmtNVfZlt91FR3xzvrnfFLPv5YzZ5euAqFnhxmW97co1IgOElcHazmcj+m/uTaoCjaGhxB6eg7cZePuQW0iX7Ufcb0YIAHczY1d+ZfCe5wTuSYnbdJGwoor7", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }, 
          {
            "use": "encryption", 
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIEdjCCA16gAwIBAgILAQAAAAABLysKVFswDQYJKoZIhvcNAQEFBQAwYzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExFjAUBgNVBAsTDU9iamVjdFNpZ24gQ0ExITAfBgNVBAMTGEdsb2JhbFNpZ24gT2JqZWN0U2lnbiBDQTAeFw0xMTA0MDYxMzI1NDZaFw0xMzA0MDYxMzI1NDRaMEwxCzAJBgNVBAYTAkRLMQ8wDQYDVQQIEwZPZGVuc2UxFTATBgNVBAoTDE9yZGJvZ2VuIEEvUzEVMBMGA1UEAxMMT3JkYm9nZW4gQS9TMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAovIjWe1fOERH9N7Dk7OP9K1YveGQZipKE+GaOHnCNe33F4a1sXMhT38fEUNWQpRLDBeLsWF2G5FnwrVDGb3qo8dN7e4ycZWbZIBuC/lyq8qRt6iIxNHQ7oad8N2m7CTe3ZNdkPHEY8eaDHUP2AC8c1SXyakv394WKuT2roIZ4OD74pv9CTDGFVNsbgOU1xTM+QIvbRSUDmVGBdkUv5tstC9w7R7UdhrW8R1wYcTwA9UxMNEiCNBvyMTfAcJO32FzDTa5nBopyoAK4jgGEdrz8Oeb17MCb+sStxJiZRTuFCgkvuNkCNXEuBBYiNDAyB8AwsLKMw6IzBPCG88NfcmUZwIDAQABo4IBQDCCATwwHwYDVR0jBBgwFoAU0lvzSyZLpbDnXf1Wf/bxLjhOU6AwTgYIKwYBBQUHAQEEQjBAMD4GCCsGAQUFBzAChjJodHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24ubmV0L2NhY2VydC9PYmplY3RTaWduLmNydDA5BgNVHR8EMjAwMC6gLKAqhihodHRwOi8vY3JsLmdsb2JhbHNpZ24ubmV0L09iamVjdFNpZ24uY3JsMAkGA1UdEwQCMAAwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMEsGA1UdIAREMEIwQAYJKwYBBAGgMgEyMDMwMQYIKwYBBQUHAgEWJWh0dHA6Ly93d3cuZ2xvYmFsc2lnbi5uZXQvcmVwb3NpdG9yeS8wEQYJYIZIAYb4QgEBBAQDAgQQMA0GCSqGSIb3DQEBBQUAA4IBAQA0lPLNM6+JLbeGyjZQ5tU7H4c1hX1WcAAGgRVF1oVtTEH8vA4V+roVB35+8Jk08rzqh+ghIUX99P2keUTOlllYUbxb7DXfsOprD5tDGc/jmMMZrYzL3ibdW0229/eaokXMPI6As7ApvQ7utb+sjftwQoI9BkJlbMRoW//t2GYY3bP7+r7yDUbcOVwNUm3ZoxErIM7SulpTS36uP8jcr0zPOwRAx6atMmtNVfZlt91FR3xzvrnfFLPv5YzZ5euAqFnhxmW97co1IgOElcHazmcj+m/uTaoCjaGhxB6eg7cZePuQW0iX7Ufcb0YIAHczY1d+ZfCe5wTuSYnbdJGwoor7", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ]
      }
    ], 
    "cache_duration": "PT345600S"
  }, 
  "https://idp.csc.fi/idp/shibboleth": {
    "valid_until": "2012-12-19T20:15:01Z", 
    "entity_id": "https://idp.csc.fi/idp/shibboleth", 
    "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EntityDescriptor", 
    "idpsso_descriptor": [
      {
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&IDPSSODescriptor", 
        "single_sign_on_service": [
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleSignOnService", 
            "location": "https://idp.csc.fi/idp/profile/SAML2/Redirect/SSO"
          }
        ], 
        "extensions": {
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Extensions", 
          "extension_elements": [
            {
              "information_url": [
                {
                  "lang": "fi", 
                  "text": "http://www.csc.fi/index_html", 
                  "__class__": "urn:oasis:names:tc:SAML:metadata:ui&InformationURL"
                }, 
                {
                  "lang": "en", 
                  "text": "http://www.csc.fi/english", 
                  "__class__": "urn:oasis:names:tc:SAML:metadata:ui&InformationURL"
                }, 
                {
                  "lang": "sv", 
                  "text": "http://www.csc.fi/svenska", 
                  "__class__": "urn:oasis:names:tc:SAML:metadata:ui&InformationURL"
                }
              ], 
              "display_name": [
                {
                  "lang": "fi", 
                  "text": "CSC - Tieteen tietotekniikan keskus Oy", 
                  "__class__": "urn:oasis:names:tc:SAML:metadata:ui&DisplayName"
                }, 
                {
                  "lang": "sv", 
                  "text": "CSC - Tieteen tietotekniikan keskus Oy", 
                  "__class__": "urn:oasis:names:tc:SAML:metadata:ui&DisplayName"
                }, 
                {
                  "lang": "en", 
                  "text": "CSC - IT Center for Science Ltd.", 
                  "__class__": "urn:oasis:names:tc:SAML:metadata:ui&DisplayName"
                }
              ], 
              "__class__": "urn:oasis:names:tc:SAML:metadata:ui&UIInfo", 
              "description": [
                {
                  "lang": "en", 
                  "text": "CSC \u2014 IT Center for Science Ltd is administered by the Ministry of Education, Science and Culture.", 
                  "__class__": "urn:oasis:names:tc:SAML:metadata:ui&Description"
                }, 
                {
                  "lang": "fi", 
                  "text": "CSC on opetus- ja kulttuuriministeri\u00f6n hallinnoima tieteen tietotekniikan keskus.", 
                  "__class__": "urn:oasis:names:tc:SAML:metadata:ui&Description"
                }, 
                {
                  "lang": "sv", 
                  "text": "CSC \u2014 Tieteen tietotekniikan keskus Oy \u00e4r IT-centret f\u00f6r vetenskap.", 
                  "__class__": "urn:oasis:names:tc:SAML:metadata:ui&Description"
                }
              ]
            }, 
            {
              "__class__": "urn:oasis:names:tc:SAML:metadata:ui&DiscoHints", 
              "domain_hint": [
                {
                  "text": "csc.fi", 
                  "__class__": "urn:oasis:names:tc:SAML:metadata:ui&DomainHint"
                }
              ]
            }, 
            {
              "attribute_value": [
                {
                  "text": "kalmar", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }, 
                {
                  "text": "finland", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }
              ], 
              "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&Attribute", 
              "name": "tags"
            }
          ]
        }, 
        "key_descriptor": [
          {
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIEvjCCA6agAwIBAgIRANzJo7X5SEmbvBstb88M+4kwDQYJKoZIhvcNAQEFBQAw\nNjELMAkGA1UEBhMCTkwxDzANBgNVBAoTBlRFUkVOQTEWMBQGA1UEAxMNVEVSRU5B\nIFNTTCBDQTAeFw0xMTEyMjEwMDAwMDBaFw0xMzEyMjAyMzU5NTlaMIGBMQswCQYD\nVQQGEwJGSTEQMA4GA1UECBMHVXVzaW1hYTEOMAwGA1UEBxMFRXNwb28xKTAnBgNV\nBAoTIENTQyAtIElUIENlbnRlciBmb3IgU2NpZW5jZSBMdGQuMRAwDgYDVQQLEwdV\nbmtub3duMRMwEQYDVQQDEwppZHAuY3NjLmZpMIIBIjANBgkqhkiG9w0BAQEFAAOC\nAQ8AMIIBCgKCAQEAt9O61taFpnXBLgpt9TIy9838XN93089o/ATNm9YxJkrX8hqp\nCNHUM3bzsEe/X7hKcT5xjVxTiwacHw8kYP2YgVPz4HDLbL1wakiq2MvbQFmYvcEw\n8YsA3AbZWn/QlrOgbP+e81aaUCWq3emm1QBoqTCidlczNetoCU+LuuUjEvvqWZai\nGSacAZ9qzl7U5MmH7TYt6AovSlVrWZnNagLFaaxQsSt9ccgkVfAXupCqvoSlF2Vb\nuXWuK3GWEbELmR9LrSx5idX3JGnjIVjFOMYceBDsJJHLaicsiBgL3imt9EulnoY+\n5ifuKr5HGFkQzcF1Qsq2y3lLFVv3whLTGio+bwIDAQABo4IBeTCCAXUwHwYDVR0j\nBBgwFoAUDL2TaAzz3qujSWsrN1dH6pDjue0wHQYDVR0OBBYEFHtybSZjYQP+ZNnx\nCQbK8njRX51hMA4GA1UdDwEB/wQEAwIFoDAMBgNVHRMBAf8EAjAAMB0GA1UdJQQW\nMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAYBgNVHSAEETAPMA0GCysGAQQBsjEBAgId\nMDoGA1UdHwQzMDEwL6AtoCuGKWh0dHA6Ly9jcmwudGNzLnRlcmVuYS5vcmcvVEVS\nRU5BU1NMQ0EuY3JsMG0GCCsGAQUFBwEBBGEwXzA1BggrBgEFBQcwAoYpaHR0cDov\nL2NydC50Y3MudGVyZW5hLm9yZy9URVJFTkFTU0xDQS5jcnQwJgYIKwYBBQUHMAGG\nGmh0dHA6Ly9vY3NwLnRjcy50ZXJlbmEub3JnMDEGA1UdEQQqMCiCCmlkcC5jc2Mu\nZmmCDGlkcDAxLmNzYy5maYIMaWRwMDIuY3NjLmZpMA0GCSqGSIb3DQEBBQUAA4IB\nAQBo9n3P845t8Z4ib7SVF/dPa6Sa7zPCWIwFpnKrAgjtsgFQX8usixP7thxgxDfa\nyq91lqm8VBAmIjzMd8NS4TdckKtlmxh6178KR9KIRUyvWsI1L74ANGycs3eF84TQ\nYNFbjK64dwCnMNGfVw1zepuRBVE0BLklgn8wqQf6yKj1HzOB6UT4UUABt71zrdcS\nyv274zsJoe2SU6+POX6wH82lz5Vc9BkxLE8vBSGB78n4BFKSdEPRWIYkeq7Kwk8L\nMwFER9iEtf/HEH+CmxYoqZCr/mm7FduiAyOdQ+AZrQgvFP2c5sqxqhAwQyrW9eU/\nyDPlRNL+S5OBIx61TJQTJ1DZ", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ], 
        "name_id_format": [
          {
            "text": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }
        ]
      }
    ], 
    "organization": {
      "organization_name": [
        {
          "lang": "fi", 
          "text": "CSC - Tieteen tietotekniikan keskus Oy", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }, 
        {
          "lang": "en", 
          "text": "CSC - IT Center for Science Ltd.", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }, 
        {
          "lang": "sv", 
          "text": "CSC - Tieteen tietotekniikan keskus Oy", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }
      ], 
      "organization_display_name": [
        {
          "lang": "fi", 
          "text": "CSC - Tieteen tietotekniikan keskus Oy", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }, 
        {
          "lang": "en", 
          "text": "CSC - IT Center for Science Ltd.", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }, 
        {
          "lang": "sv", 
          "text": "CSC - Tieteen tietotekniikan keskus Oy", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }
      ], 
      "organization_url": [
        {
          "lang": "fi", 
          "text": "http://www.csc.fi", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }, 
        {
          "lang": "en", 
          "text": "http://www.csc.fi", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }, 
        {
          "lang": "sv", 
          "text": "http://www.csc.fi", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }
      ], 
      "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Organization"
    }, 
    "contact_person": [
      {
        "given_name": {
          "text": "Janne", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&GivenName"
        }, 
        "email_address": [
          {
            "text": "haka@csc.fi", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ], 
        "sur_name": {
          "text": "Lauros", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SurName"
        }, 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "contact_type": "technical"
      }, 
      {
        "email_address": [
          {
            "text": "haka@csc.fi", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "contact_type": "support"
      }
    ]
  }, 
  "https://idp.metropolia.fi/idp": {
    "valid_until": "2012-12-19T20:15:01Z", 
    "entity_id": "https://idp.metropolia.fi/idp", 
    "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EntityDescriptor", 
    "idpsso_descriptor": [
      {
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&IDPSSODescriptor", 
        "single_sign_on_service": [
          {
            "binding": "urn:mace:shibboleth:1.0:profiles:AuthnRequest", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleSignOnService", 
            "location": "https://idp.metropolia.fi/idp/profile/Shibboleth/SSO"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleSignOnService", 
            "location": "https://idp.metropolia.fi/idp/profile/SAML2/POST/SSO"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleSignOnService", 
            "location": "https://idp.metropolia.fi/idp/profile/SAML2/Redirect/SSO"
          }
        ], 
        "extensions": {
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Extensions", 
          "extension_elements": [
            {
              "attribute_value": [
                {
                  "text": "kalmar", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }, 
                {
                  "text": "finland", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }
              ], 
              "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&Attribute", 
              "name": "tags"
            }
          ]
        }, 
        "key_descriptor": [
          {
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIECzCCAvOgAwIBAgIRAL+szgnI0qWlv5j0dv0UYtswDQYJKoZIhvcNAQEFBQAwOTELMAkGA1UE\nBhMCRkkxDzANBgNVBAoTBlNvbmVyYTEZMBcGA1UEAxMQU29uZXJhIENsYXNzMiBDQTAeFw0xMTEx\nMjQwNjQwMThaFw0xNDExMjMwNjQwMThaMFExCzAJBgNVBAYTAkZJMSYwJAYDVQQKDB1NZXRyb3Bv\nbGlhIEFtbWF0dGlrb3JrZWFrb3VsdTEaMBgGA1UEAwwRaWRwLm1ldHJvcG9saWEuZmkwggEiMA0G\nCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDS9Nz6Ju8uVYvBqzZq/HSzPL8yZzRRIexBXG7rsZEE\nti0U+ERX/QJ7nDoQCCn4P8PQoGgZvl6A69F4TBxw27KcLEutuZfFAKhvd8P/X3+vbwDMIlJfMi2o\noVWGxcIRfvuLoP5gsTJpmuDQE1xB6ZToA0xs5aIQOJFKzAznWOf8PPrUF7V2SE90xt4gE9OmpnOF\nw1gfp243SRnvxNJwai2+3L+FFAyygiCk4ao9IcdguXxpW42bLghb8GZAsla8ULvrNB+PaAMjYYkd\nEbvcoxbxynSE2LBrRlQ7cn769INlQkv7yVgo12zJ1GHBn2JgSdjiK/mPg68M24S5fAZXZVdBAgMB\nAAGjgfUwgfIwEwYDVR0jBAwwCoAISqCqWITTXjwwGQYDVR0gBBIwEDAOBgwrBgEEAYIPAgMBAQIw\ncgYDVR0fBGswaTBnoGWgY4ZhbGRhcDovLzE5NC4yNTIuMTI0LjI0MTozODkvY249U29uZXJhJTIw\nQ2xhc3MyJTIwQ0Esbz1Tb25lcmEsYz1GST9jZXJ0aWZpY2F0ZXJldm9jYXRpb25saXN0O2JpbmFy\neTAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDgYDVR0PAQH/BAQDAgSwMB0GA1UdDgQW\nBBSetcs1P8mXrxv31HIiIZRlQ5pMizANBgkqhkiG9w0BAQUFAAOCAQEAJXlZQSERzZyIyD5t6zfC\nvelNXend4z9jhUb3ZqFd86xAYNPRj+wNJBCSUJ3+mn1MWW5kV8D28jixtVvtqKZUgSCBBrxRJ5D9\nHl7CRqNPubvcrxkXETZv0uEfnJaEK7wEWR0LP3r5RUjBc9AbSbsHOIX/sBxS/IMjTrb3PAwbAypT\n417lCgBzdpTIiDq+QF4bb4Tt/kjTRqPT21lporYTW+/NWFK02X+rgsABklvOQKSTEGvyDr6dLbSD\ntto9jTy1FzEicXFLvj36B+MB87UChYNTW7IJMJvJZgbuod76mjg9LkY+PHaxcn2kNmUYQKuuio0g\nLQc3QWj/dW5XWHUtjA==", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ], 
        "name_id_format": [
          {
            "text": "urn:mace:shibboleth:1.0:nameIdentifier", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }, 
          {
            "text": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }
        ]
      }
    ], 
    "attribute_authority_descriptor": [
      {
        "attribute_service": [
          {
            "binding": "urn:oasis:names:tc:SAML:1.0:bindings:SOAP-binding", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AttributeService", 
            "location": "https://idp.metropolia.fi/idp/profile/SAML1/SOAP/AttributeQuery"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:SOAP", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AttributeService", 
            "location": "https://idp.metropolia.fi/idp/profile/SAML2/SOAP/AttributeQuery"
          }
        ], 
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AttributeAuthorityDescriptor", 
        "extensions": {
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Extensions"
        }, 
        "key_descriptor": [
          {
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIECzCCAvOgAwIBAgIRAL+szgnI0qWlv5j0dv0UYtswDQYJKoZIhvcNAQEFBQAwOTELMAkGA1UE\nBhMCRkkxDzANBgNVBAoTBlNvbmVyYTEZMBcGA1UEAxMQU29uZXJhIENsYXNzMiBDQTAeFw0xMTEx\nMjQwNjQwMThaFw0xNDExMjMwNjQwMThaMFExCzAJBgNVBAYTAkZJMSYwJAYDVQQKDB1NZXRyb3Bv\nbGlhIEFtbWF0dGlrb3JrZWFrb3VsdTEaMBgGA1UEAwwRaWRwLm1ldHJvcG9saWEuZmkwggEiMA0G\nCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDS9Nz6Ju8uVYvBqzZq/HSzPL8yZzRRIexBXG7rsZEE\nti0U+ERX/QJ7nDoQCCn4P8PQoGgZvl6A69F4TBxw27KcLEutuZfFAKhvd8P/X3+vbwDMIlJfMi2o\noVWGxcIRfvuLoP5gsTJpmuDQE1xB6ZToA0xs5aIQOJFKzAznWOf8PPrUF7V2SE90xt4gE9OmpnOF\nw1gfp243SRnvxNJwai2+3L+FFAyygiCk4ao9IcdguXxpW42bLghb8GZAsla8ULvrNB+PaAMjYYkd\nEbvcoxbxynSE2LBrRlQ7cn769INlQkv7yVgo12zJ1GHBn2JgSdjiK/mPg68M24S5fAZXZVdBAgMB\nAAGjgfUwgfIwEwYDVR0jBAwwCoAISqCqWITTXjwwGQYDVR0gBBIwEDAOBgwrBgEEAYIPAgMBAQIw\ncgYDVR0fBGswaTBnoGWgY4ZhbGRhcDovLzE5NC4yNTIuMTI0LjI0MTozODkvY249U29uZXJhJTIw\nQ2xhc3MyJTIwQ0Esbz1Tb25lcmEsYz1GST9jZXJ0aWZpY2F0ZXJldm9jYXRpb25saXN0O2JpbmFy\neTAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDgYDVR0PAQH/BAQDAgSwMB0GA1UdDgQW\nBBSetcs1P8mXrxv31HIiIZRlQ5pMizANBgkqhkiG9w0BAQUFAAOCAQEAJXlZQSERzZyIyD5t6zfC\nvelNXend4z9jhUb3ZqFd86xAYNPRj+wNJBCSUJ3+mn1MWW5kV8D28jixtVvtqKZUgSCBBrxRJ5D9\nHl7CRqNPubvcrxkXETZv0uEfnJaEK7wEWR0LP3r5RUjBc9AbSbsHOIX/sBxS/IMjTrb3PAwbAypT\n417lCgBzdpTIiDq+QF4bb4Tt/kjTRqPT21lporYTW+/NWFK02X+rgsABklvOQKSTEGvyDr6dLbSD\ntto9jTy1FzEicXFLvj36B+MB87UChYNTW7IJMJvJZgbuod76mjg9LkY+PHaxcn2kNmUYQKuuio0g\nLQc3QWj/dW5XWHUtjA==", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ], 
        "name_id_format": [
          {
            "text": "urn:mace:shibboleth:1.0:nameIdentifier", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }, 
          {
            "text": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }
        ]
      }
    ], 
    "organization": {
      "organization_name": [
        {
          "lang": "fi", 
          "text": "Metropolia-ammattikorkeakoulu", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }, 
        {
          "lang": "en", 
          "text": "Helsinki Metropolia University of Applied Sciences", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }, 
        {
          "lang": "sv", 
          "text": "Metropolia yrkeshogskola", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }
      ], 
      "organization_display_name": [
        {
          "lang": "fi", 
          "text": "Metropolia-ammattikorkeakoulu", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }, 
        {
          "lang": "en", 
          "text": "Helsinki Metropolia University of Applied Sciences", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }, 
        {
          "lang": "sv", 
          "text": "Metropolia yrkeshogskola", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }
      ], 
      "organization_url": [
        {
          "lang": "fi", 
          "text": "http://www.metropolia.fi", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }, 
        {
          "lang": "en", 
          "text": "http://www.metropolia.fi", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }, 
        {
          "lang": "sv", 
          "text": "http://www.metropolia.fi", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }
      ], 
      "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Organization"
    }, 
    "contact_person": [
      {
        "given_name": {
          "text": "Jani", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&GivenName"
        }, 
        "email_address": [
          {
            "text": "jani.kaljunen@metropolia.fi", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ], 
        "sur_name": {
          "text": "Kaljunen", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SurName"
        }, 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "contact_type": "administrative"
      }, 
      {
        "given_name": {
          "text": "Jukka", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&GivenName"
        }, 
        "email_address": [
          {
            "text": "jukka.veikkolainen@metropolia.fi", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ], 
        "sur_name": {
          "text": "Veikkolainen", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SurName"
        }, 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "contact_type": "technical"
      }
    ]
  }, 
  "http://sp.lat.csc.fi": {
    "valid_until": "2012-12-19T20:15:01Z", 
    "entity_id": "http://sp.lat.csc.fi", 
    "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EntityDescriptor", 
    "organization": {
      "organization_name": [
        {
          "lang": "fi", 
          "text": "CSC - Tieteen tietotekniikan keskus Oy", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }, 
        {
          "lang": "en", 
          "text": "CSC - IT Center for Science Ltd.", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }, 
        {
          "lang": "sv", 
          "text": "CSC - Tieteen tietotekniikan keskus Oy", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }
      ], 
      "organization_display_name": [
        {
          "lang": "fi", 
          "text": "CSC - Tieteen tietotekniikan keskus Oy", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }, 
        {
          "lang": "en", 
          "text": "CSC - IT Center for Science Ltd.", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }, 
        {
          "lang": "sv", 
          "text": "CSC - Tieteen tietotekniikan keskus Oy", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }
      ], 
      "organization_url": [
        {
          "lang": "fi", 
          "text": "http://www.csc.fi", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }, 
        {
          "lang": "en", 
          "text": "http://www.csc.fi", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }, 
        {
          "lang": "sv", 
          "text": "http://www.csc.fi", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }
      ], 
      "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Organization"
    }, 
    "contact_person": [
      {
        "given_name": {
          "text": "Tero", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&GivenName"
        }, 
        "email_address": [
          {
            "text": "ling@csc.fi", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ], 
        "sur_name": {
          "text": "Aalto", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SurName"
        }, 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "contact_type": "administrative"
      }, 
      {
        "given_name": {
          "text": "Mikko", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&GivenName"
        }, 
        "email_address": [
          {
            "text": "mikko.jokinen@csc.fi", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ], 
        "sur_name": {
          "text": "Jokinen", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SurName"
        }, 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "contact_type": "technical"
      }, 
      {
        "given_name": {
          "text": "Tero", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&GivenName"
        }, 
        "email_address": [
          {
            "text": "ling@csc.fi", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ], 
        "sur_name": {
          "text": "Aalto", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SurName"
        }, 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "contact_type": "support"
      }
    ], 
    "spsso_descriptor": [
      {
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "assertion_consumer_service": [
          {
            "is_default": "true", 
            "index": "1", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://lat.csc.fi/Shibboleth.sso/SAML2/POST"
          }
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SPSSODescriptor", 
        "extensions": {
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Extensions", 
          "extension_elements": [
            {
              "index": "1", 
              "binding": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol", 
              "__class__": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol&DiscoveryResponse", 
              "location": "https://lat.csc.fi/Shibboleth.sso/DS"
            }, 
            {
              "attribute_value": [
                {
                  "text": "kalmar", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }, 
                {
                  "text": "finland", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }
              ], 
              "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&Attribute", 
              "name": "tags"
            }
          ]
        }, 
        "name_id_format": [
          {
            "text": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }, 
          {
            "text": "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }
        ], 
        "attribute_consuming_service": [
          {
            "index": "1", 
            "service_name": [
              {
                "lang": "fi", 
                "text": "LAT", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }, 
              {
                "lang": "en", 
                "text": "LAT", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }, 
              {
                "lang": "sv", 
                "text": "LAT", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }
            ], 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AttributeConsumingService", 
            "is_default": "true", 
            "requested_attribute": [
              {
                "friendly_name": "cn", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.3"
              }, 
              {
                "friendly_name": "displayName", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.16.840.1.113730.3.1.241"
              }, 
              {
                "friendly_name": "eduPersonPrincipalName", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
              }, 
              {
                "friendly_name": "mail", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:0.9.2342.19200300.100.1.3"
              }
            ], 
            "service_description": [
              {
                "lang": "fi", 
                "text": "Kielitieteen ohjelmia MPI", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }, 
              {
                "lang": "en", 
                "text": "Language archive tools", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }
            ]
          }
        ], 
        "key_descriptor": [
          {
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIEuDCCA6CgAwIBAgIRAJRkURURLhdqLNjrk9ROa4QwDQYJKoZIhvcNAQEFBQAw\nNjELMAkGA1UEBhMCTkwxDzANBgNVBAoTBlRFUkVOQTEWMBQGA1UEAxMNVEVSRU5B\nIFNTTCBDQTAeFw0xMTA1MTgwMDAwMDBaFw0xMzA1MTcyMzU5NTlaMIGXMQswCQYD\nVQQGEwJGSTEOMAwGA1UEERMFMDIxMDExEDAOBgNVBAgTB1V1c2ltYWExDjAMBgNV\nBAcTBUVzcG9vMRYwFAYDVQQJEw1LZWlsYXJhbnRhIDE0MSkwJwYDVQQKEyBDU0Mg\nLSBJVCBDZW50ZXIgZm9yIFNjaWVuY2UgTHRkLjETMBEGA1UEAxMKbGF0LmNzYy5m\naTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMX3OzBEWbhIY+MDtbzF\n7Ys8fDjznPWCT08RkgnTr/lkGl3qUMzx7pjRUtYVi/tdZFxsc3U4NzsfKUW2fYSZ\nIjWL/wZmvXyb/B6YuOTYcPa8R19ocvzU4b1bhA8XPgRKQqDDydJivAkBJEfJ6ZKH\nrtM1Z1u/n9abYwM0KMnqkznF9CtWarR+OdehBpuyKkxC3nJeM+cGVHfGHgrebiZ3\nYGmACWUk/1TEPGfINA3TNya6LSrZAjWlkHt0l6ETMjfsn1qbcx88bTVSq3bMV8ex\nIW2UW4GOENmMbBTEaiMzQmeNkHxQIRUrxNA8+jUhsZGXdwaLmFltqSOJBtgGd6Zf\nKesCAwEAAaOCAV0wggFZMB8GA1UdIwQYMBaAFAy9k2gM896ro0lrKzdXR+qQ47nt\nMB0GA1UdDgQWBBRoExciww04irlvIesUmJQ9EUtNSTAOBgNVHQ8BAf8EBAMCBaAw\nDAYDVR0TAQH/BAIwADAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwGAYD\nVR0gBBEwDzANBgsrBgEEAbIxAQICHTA6BgNVHR8EMzAxMC+gLaArhilodHRwOi8v\nY3JsLnRjcy50ZXJlbmEub3JnL1RFUkVOQVNTTENBLmNybDBtBggrBgEFBQcBAQRh\nMF8wNQYIKwYBBQUHMAKGKWh0dHA6Ly9jcnQudGNzLnRlcmVuYS5vcmcvVEVSRU5B\nU1NMQ0EuY3J0MCYGCCsGAQUFBzABhhpodHRwOi8vb2NzcC50Y3MudGVyZW5hLm9y\nZzAVBgNVHREEDjAMggpsYXQuY3NjLmZpMA0GCSqGSIb3DQEBBQUAA4IBAQBAGJq7\nlQ6NKPiVSlp9N1V6EVDnYlioyqv/pabKKivWlvl+MAAjZlfk8OmdWsBYUgH2aeM5\n1nKz8gFBnwI7up2OjpdrJRGAkyyXbnQt34vT81vEF+otLvAmilNwRPAi29zWnrGl\n37mjTjfziOeHZPLX59q/CGJxibFk1l1G01YzLstT+MYdWI30MhZg//vK96RZaRog\nQ76UgcYknkN+Trpc4n8TExlhXZw881XVdm/hKgaRDnS4obofKFpZyqTtVNekHMr6\n0/tukGQvVEp3KmukbhzJ2Oa4d4Q0sIZctuU8RRh62IqbBKkSAQx/kw9dF43X8rmf\ngIbcJY1SYVwxxDSg", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ]
      }
    ]
  }, 
  "https://beta.lobber.se/shibboleth": {
    "valid_until": "2012-12-16T04:23:08Z", 
    "entity_id": "https://beta.lobber.se/shibboleth", 
    "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EntityDescriptor", 
    "spsso_descriptor": [
      {
        "single_logout_service": [
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:SOAP", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleLogoutService", 
            "location": "https://beta.lobber.se/Shibboleth.sso/SLO/SOAP"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleLogoutService", 
            "location": "https://beta.lobber.se/Shibboleth.sso/SLO/Redirect"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleLogoutService", 
            "location": "https://beta.lobber.se/Shibboleth.sso/SLO/POST"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleLogoutService", 
            "location": "https://beta.lobber.se/Shibboleth.sso/SLO/Artifact"
          }
        ], 
        "attribute_consuming_service": [
          {
            "index": "0", 
            "service_description": [
              {
                "lang": "en", 
                "text": "SUNET Lobber (BETA) - a BitTorrent data distribution service", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }
            ], 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AttributeConsumingService", 
            "requested_attribute": [
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:0.9.2342.19200300.100.1.3"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.42"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.4"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.9"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.7"
              }
            ], 
            "service_name": [
              {
                "lang": "en", 
                "text": "SUNET Lobber (BETA)", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }
            ]
          }
        ], 
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "assertion_consumer_service": [
          {
            "index": "1", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://beta.lobber.se/Shibboleth.sso/SAML2/POST"
          }, 
          {
            "index": "2", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://beta.lobber.se/Shibboleth.sso/SAML2/POST-SimpleSign"
          }, 
          {
            "index": "3", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://beta.lobber.se/Shibboleth.sso/SAML2/Artifact"
          }, 
          {
            "index": "4", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:PAOS", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://beta.lobber.se/Shibboleth.sso/SAML2/ECP"
          }, 
          {
            "index": "5", 
            "binding": "urn:oasis:names:tc:SAML:1.0:profiles:browser-post", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://beta.lobber.se/Shibboleth.sso/SAML/POST"
          }, 
          {
            "index": "6", 
            "binding": "urn:oasis:names:tc:SAML:1.0:profiles:artifact-01", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://beta.lobber.se/Shibboleth.sso/SAML/Artifact"
          }
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SPSSODescriptor", 
        "extensions": {
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Extensions", 
          "extension_elements": [
            {
              "index": "1", 
              "binding": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol", 
              "__class__": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol&DiscoveryResponse", 
              "location": "https://beta.lobber.se/Shibboleth.sso/DS/ds.swamid.se"
            }, 
            {
              "index": "2", 
              "binding": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol", 
              "__class__": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol&DiscoveryResponse", 
              "location": "https://beta.lobber.se/Shibboleth.sso/DS/kalmar2"
            }, 
            {
              "attribute_value": [
                {
                  "text": "kalmar", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }, 
                {
                  "text": "sweden", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }
              ], 
              "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&Attribute", 
              "name": "tags"
            }
          ]
        }, 
        "key_descriptor": [
          {
            "use": "signing", 
            "key_info": {
              "key_name": [
                {
                  "text": "beta.lobber.se", 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyName"
                }, 
                {
                  "text": "https://beta.lobber.se/shibboleth-sp", 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyName"
                }
              ], 
              "x509_data": [
                {
                  "x509_subject_name": {
                    "text": "CN=beta.lobber.se", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509SubjectName"
                  }, 
                  "x509_certificate": {
                    "text": "MIIDFzCCAf+gAwIBAgIJAK3WrSSve3L0MA0GCSqGSIb3DQEBBQUAMBkxFzAVBgNV\nBAMTDmJldGEubG9iYmVyLnNlMB4XDTEwMDQxNjA4MzUyNVoXDTIwMDQxMzA4MzUy\nNVowGTEXMBUGA1UEAxMOYmV0YS5sb2JiZXIuc2UwggEiMA0GCSqGSIb3DQEBAQUA\nA4IBDwAwggEKAoIBAQDUL7NU/brgRsoszEetP0BPY9XcmjSY9BymFpvOn09zLvoY\nJDUgRa5Y54ob3vZZ6dkIBhqZulbTM1/8OMyOFk3zL/SkJJK4Ga7xVelT3JdQGwIU\nTvSuxg2p8CXVijurqVtYp8wWsVyelrpLiQh1X7JSqLlSordJBsFJrKlj7Y8eTqy6\nCuEaWXV4E6pqTmlM2Q+WILSG0G7j8YYw9FVlzTDaF5xM4FhQsYa3DWHNZUZlmB/E\nBBUJmcPpZCDOQP/n5dZnQrDQYSuDudy3UpkuHQHf4B8yiffdOKMFzHcTfQDuMJXw\nh6sA5Xrq1WpsOwn9kgONyDm8ML3IFJC3AYLOLvfdAgMBAAGjYjBgMD8GA1UdEQQ4\nMDaCDmJldGEubG9iYmVyLnNlhiRodHRwczovL2JldGEubG9iYmVyLnNlL3NoaWJi\nb2xldGgtc3AwHQYDVR0OBBYEFEWVLP4kBg/gV79XUV32F6dX7kKBMA0GCSqGSIb3\nDQEBBQUAA4IBAQA666NJBd3xPuNy6PRToyJvGmltOxIsn2HFHANX5xqc7GK9v6vw\nzVhVTpx64sZFC6/B/laF9RNmtr9IxiI2wk43ZkdFtoADGlXMKevQ4+CjdLbqb4VP\nTisAp2vpojnlXtmdj3UCzOmiMjgLlRQY8WN1/vMVBNeYKtJSyXfl4mWVNUTBxnAq\nD46Wa7GYLUVqlWdkWDHBznr4QA4MRxhJDOsm9aVVDq4yAOwCQrHdY+xDokcx4mdN\n5dNwkP7gqpYuryKTfnI32kaRKL+kMXotFg6r+qAaIEo67D3LMnWJE75aZb16HVwz\n/MAyn2Vwd/VAgvtvblNu62vT9+d6mW7zQqTZ", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }, 
          {
            "use": "encryption", 
            "key_info": {
              "key_name": [
                {
                  "text": "beta.lobber.se", 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyName"
                }, 
                {
                  "text": "https://beta.lobber.se/shibboleth-sp", 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyName"
                }
              ], 
              "x509_data": [
                {
                  "x509_subject_name": {
                    "text": "CN=beta.lobber.se", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509SubjectName"
                  }, 
                  "x509_certificate": {
                    "text": "MIIDFzCCAf+gAwIBAgIJAK3WrSSve3L0MA0GCSqGSIb3DQEBBQUAMBkxFzAVBgNV\nBAMTDmJldGEubG9iYmVyLnNlMB4XDTEwMDQxNjA4MzUyNVoXDTIwMDQxMzA4MzUy\nNVowGTEXMBUGA1UEAxMOYmV0YS5sb2JiZXIuc2UwggEiMA0GCSqGSIb3DQEBAQUA\nA4IBDwAwggEKAoIBAQDUL7NU/brgRsoszEetP0BPY9XcmjSY9BymFpvOn09zLvoY\nJDUgRa5Y54ob3vZZ6dkIBhqZulbTM1/8OMyOFk3zL/SkJJK4Ga7xVelT3JdQGwIU\nTvSuxg2p8CXVijurqVtYp8wWsVyelrpLiQh1X7JSqLlSordJBsFJrKlj7Y8eTqy6\nCuEaWXV4E6pqTmlM2Q+WILSG0G7j8YYw9FVlzTDaF5xM4FhQsYa3DWHNZUZlmB/E\nBBUJmcPpZCDOQP/n5dZnQrDQYSuDudy3UpkuHQHf4B8yiffdOKMFzHcTfQDuMJXw\nh6sA5Xrq1WpsOwn9kgONyDm8ML3IFJC3AYLOLvfdAgMBAAGjYjBgMD8GA1UdEQQ4\nMDaCDmJldGEubG9iYmVyLnNlhiRodHRwczovL2JldGEubG9iYmVyLnNlL3NoaWJi\nb2xldGgtc3AwHQYDVR0OBBYEFEWVLP4kBg/gV79XUV32F6dX7kKBMA0GCSqGSIb3\nDQEBBQUAA4IBAQA666NJBd3xPuNy6PRToyJvGmltOxIsn2HFHANX5xqc7GK9v6vw\nzVhVTpx64sZFC6/B/laF9RNmtr9IxiI2wk43ZkdFtoADGlXMKevQ4+CjdLbqb4VP\nTisAp2vpojnlXtmdj3UCzOmiMjgLlRQY8WN1/vMVBNeYKtJSyXfl4mWVNUTBxnAq\nD46Wa7GYLUVqlWdkWDHBznr4QA4MRxhJDOsm9aVVDq4yAOwCQrHdY+xDokcx4mdN\n5dNwkP7gqpYuryKTfnI32kaRKL+kMXotFg6r+qAaIEo67D3LMnWJE75aZb16HVwz\n/MAyn2Vwd/VAgvtvblNu62vT9+d6mW7zQqTZ", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ], 
        "artifact_resolution_service": [
          {
            "index": "1", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:SOAP", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ArtifactResolutionService", 
            "location": "https://beta.lobber.se/Shibboleth.sso/Artifact/SOAP"
          }
        ], 
        "manage_name_id_service": [
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:SOAP", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ManageNameIDService", 
            "location": "https://beta.lobber.se/Shibboleth.sso/NIM/SOAP"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ManageNameIDService", 
            "location": "https://beta.lobber.se/Shibboleth.sso/NIM/Redirect"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ManageNameIDService", 
            "location": "https://beta.lobber.se/Shibboleth.sso/NIM/POST"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ManageNameIDService", 
            "location": "https://beta.lobber.se/Shibboleth.sso/NIM/Artifact"
          }
        ]
      }
    ]
  }, 
  "https://connect-beta.sunet.se/shibboleth": {
    "valid_until": "2012-12-16T04:23:08Z", 
    "entity_id": "https://connect-beta.sunet.se/shibboleth", 
    "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EntityDescriptor", 
    "extensions": {
      "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Extensions", 
      "extension_elements": [
        {
          "attribute": [
            {
              "attribute_value": [
                {
                  "text": "http://www.swamid.se/category/research-and-education", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }, 
                {
                  "text": "http://www.swamid.se/category/nren-service", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }, 
                {
                  "text": "http://www.swamid.se/category/eu-adequate-protection", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }
              ], 
              "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&Attribute", 
              "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
              "name": "http://macedir.org/entity-category"
            }
          ], 
          "__class__": "urn:oasis:names:tc:SAML:metadata:attribute&EntityAttributes"
        }, 
        {
          "attribute_value": [
            {
              "text": "kalmar", 
              "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
              "extension_attributes": {
                "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
              }
            }, 
            {
              "text": "sweden", 
              "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
              "extension_attributes": {
                "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
              }
            }
          ], 
          "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&Attribute", 
          "name": "tags"
        }
      ]
    }, 
    "organization": {
      "organization_name": [
        {
          "lang": "en", 
          "text": "NORDUnet", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }
      ], 
      "organization_display_name": [
        {
          "lang": "en", 
          "text": "NORDUnet A/S", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }
      ], 
      "organization_url": [
        {
          "lang": "en", 
          "text": "http://www.nordu.net", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }
      ], 
      "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Organization"
    }, 
    "spsso_descriptor": [
      {
        "single_logout_service": [
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:SOAP", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleLogoutService", 
            "location": "https://connect-beta.sunet.se/Shibboleth.sso/SLO/SOAP"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleLogoutService", 
            "location": "https://connect-beta.sunet.se/Shibboleth.sso/SLO/Redirect"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleLogoutService", 
            "location": "https://connect-beta.sunet.se/Shibboleth.sso/SLO/POST"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleLogoutService", 
            "location": "https://connect-beta.sunet.se/Shibboleth.sso/SLO/Artifact"
          }
        ], 
        "attribute_consuming_service": [
          {
            "index": "0", 
            "service_description": [
              {
                "lang": "en", 
                "text": "SUNET E-Meeting Service (beta)", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }
            ], 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AttributeConsumingService", 
            "requested_attribute": [
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:0.9.2342.19200300.100.1.3"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.42"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.4"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.9"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.1"
              }
            ], 
            "service_name": [
              {
                "lang": "en", 
                "text": "SUNET E-Meeting Service (beta)", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }
            ]
          }
        ], 
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "assertion_consumer_service": [
          {
            "index": "1", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://connect-beta.sunet.se/Shibboleth.sso/SAML2/POST"
          }, 
          {
            "index": "2", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://connect-beta.sunet.se/Shibboleth.sso/SAML2/POST-SimpleSign"
          }, 
          {
            "index": "3", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://connect-beta.sunet.se/Shibboleth.sso/SAML2/Artifact"
          }, 
          {
            "index": "4", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:PAOS", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://connect-beta.sunet.se/Shibboleth.sso/SAML2/ECP"
          }, 
          {
            "index": "5", 
            "binding": "urn:oasis:names:tc:SAML:1.0:profiles:browser-post", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://connect-beta.sunet.se/Shibboleth.sso/SAML/POST"
          }, 
          {
            "index": "6", 
            "binding": "urn:oasis:names:tc:SAML:1.0:profiles:artifact-01", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://connect-beta.sunet.se/Shibboleth.sso/SAML/Artifact"
          }
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SPSSODescriptor", 
        "extensions": {
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Extensions", 
          "extension_elements": [
            {
              "index": "1", 
              "binding": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol", 
              "__class__": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol&DiscoveryResponse", 
              "location": "https://connect-beta.sunet.se/Shibboleth.sso/DS/ds.swamid.se"
            }, 
            {
              "index": "2", 
              "binding": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol", 
              "__class__": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol&DiscoveryResponse", 
              "location": "https://connect-beta.sunet.se/Shibboleth.sso/DS/ds.sunet.se"
            }, 
            {
              "index": "3", 
              "binding": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol", 
              "__class__": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol&DiscoveryResponse", 
              "location": "https://connect-beta.sunet.se/Shibboleth.sso/DS/kalmar2"
            }, 
            {
              "index": "4", 
              "binding": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol", 
              "__class__": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol&DiscoveryResponse", 
              "location": "https://connect-beta.sunet.se/Shibboleth.sso/DS/nordu.net"
            }
          ]
        }, 
        "key_descriptor": [
          {
            "use": "signing", 
            "key_info": {
              "key_name": [
                {
                  "text": "connect8.sunet.se", 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyName"
                }
              ], 
              "x509_data": [
                {
                  "x509_subject_name": {
                    "text": "CN=connect8.sunet.se", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509SubjectName"
                  }, 
                  "x509_certificate": {
                    "text": "MIIC+jCCAeKgAwIBAgIJALtpdDetd0+aMA0GCSqGSIb3DQEBBQUAMBwxGjAYBgNV\nBAMTEWNvbm5lY3Q4LnN1bmV0LnNlMB4XDTExMDMxODA5MTkxNFoXDTIxMDMxNTA5\nMTkxNFowHDEaMBgGA1UEAxMRY29ubmVjdDguc3VuZXQuc2UwggEiMA0GCSqGSIb3\nDQEBAQUAA4IBDwAwggEKAoIBAQD1d3qbbBDMHcxOLMlEzLthit/PclHFQUivQjdl\ni/iWPBDdTXODRZfYzTcq+B+venAaDJBt99/UF0l+Zept5F/0U8dPmlKXNOHkQtCM\nfP56ssnuMNt56rgUMC7Bkvi0JBsschjzqXzELSn9zw5DO0gj7YU1GGJaYp4abBYg\nLHs403i9Dga6qZvma1nfuBfoSBNcfNPKDfL+LN1KhSyZDrwfupiVXzt4WCm4/B+7\nypEZw66WK5VCXMJJ8nrzbcP0SV+W36qfkz1Vu1799c0msygmb5bfvlZbVvaH5bXR\nP67w5IWiOZNiJ4KP9SsNKT2u2SSJgFwBhs2m+AghWHW6+rcRAgMBAAGjPzA9MBwG\nA1UdEQQVMBOCEWNvbm5lY3Q4LnN1bmV0LnNlMB0GA1UdDgQWBBQnXN19r3XLQq+Z\nDWdMGahYti/oYzANBgkqhkiG9w0BAQUFAAOCAQEAMSB60ydAbZlRUOtKEvqoXu9q\nLQ6RD2PbX8BcB494lEANUftFBUPlH6Bssn+uuu+/OTDe0H4rrehGCzoLjziftfQh\n0/a5kfOp8Ws4CY0xEZdm+q0iIl+JTQQbR4AKsVK+2mGquHakkUnCg6fuS1XTsmex\njDjaYIEYYx7XISnQY/01ZH0oOGCvJAVpW0cEtQzpXmi6a8UOm7xhg0FB0lk4z9v1\n8Yv3mZx1PhYzmXDUVEIfQta/+0SctZ978aj4Y7emDgL1QMdETPyN9OlC3XGNtSYI\nFV4q3nujmHDfDpzbO4vsmaumdoScXaR4CoL/mO9XM7dxx/0k8kMkde1eA1mZWQ==", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }, 
          {
            "use": "encryption", 
            "key_info": {
              "key_name": [
                {
                  "text": "connect8.sunet.se", 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyName"
                }
              ], 
              "x509_data": [
                {
                  "x509_subject_name": {
                    "text": "CN=connect8.sunet.se", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509SubjectName"
                  }, 
                  "x509_certificate": {
                    "text": "MIIC+jCCAeKgAwIBAgIJALtpdDetd0+aMA0GCSqGSIb3DQEBBQUAMBwxGjAYBgNV\nBAMTEWNvbm5lY3Q4LnN1bmV0LnNlMB4XDTExMDMxODA5MTkxNFoXDTIxMDMxNTA5\nMTkxNFowHDEaMBgGA1UEAxMRY29ubmVjdDguc3VuZXQuc2UwggEiMA0GCSqGSIb3\nDQEBAQUAA4IBDwAwggEKAoIBAQD1d3qbbBDMHcxOLMlEzLthit/PclHFQUivQjdl\ni/iWPBDdTXODRZfYzTcq+B+venAaDJBt99/UF0l+Zept5F/0U8dPmlKXNOHkQtCM\nfP56ssnuMNt56rgUMC7Bkvi0JBsschjzqXzELSn9zw5DO0gj7YU1GGJaYp4abBYg\nLHs403i9Dga6qZvma1nfuBfoSBNcfNPKDfL+LN1KhSyZDrwfupiVXzt4WCm4/B+7\nypEZw66WK5VCXMJJ8nrzbcP0SV+W36qfkz1Vu1799c0msygmb5bfvlZbVvaH5bXR\nP67w5IWiOZNiJ4KP9SsNKT2u2SSJgFwBhs2m+AghWHW6+rcRAgMBAAGjPzA9MBwG\nA1UdEQQVMBOCEWNvbm5lY3Q4LnN1bmV0LnNlMB0GA1UdDgQWBBQnXN19r3XLQq+Z\nDWdMGahYti/oYzANBgkqhkiG9w0BAQUFAAOCAQEAMSB60ydAbZlRUOtKEvqoXu9q\nLQ6RD2PbX8BcB494lEANUftFBUPlH6Bssn+uuu+/OTDe0H4rrehGCzoLjziftfQh\n0/a5kfOp8Ws4CY0xEZdm+q0iIl+JTQQbR4AKsVK+2mGquHakkUnCg6fuS1XTsmex\njDjaYIEYYx7XISnQY/01ZH0oOGCvJAVpW0cEtQzpXmi6a8UOm7xhg0FB0lk4z9v1\n8Yv3mZx1PhYzmXDUVEIfQta/+0SctZ978aj4Y7emDgL1QMdETPyN9OlC3XGNtSYI\nFV4q3nujmHDfDpzbO4vsmaumdoScXaR4CoL/mO9XM7dxx/0k8kMkde1eA1mZWQ==", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ], 
        "artifact_resolution_service": [
          {
            "index": "1", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:SOAP", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ArtifactResolutionService", 
            "location": "https://connect-beta.sunet.se/Shibboleth.sso/Artifact/SOAP"
          }
        ], 
        "manage_name_id_service": [
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:SOAP", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ManageNameIDService", 
            "location": "https://connect-beta.sunet.se/Shibboleth.sso/NIM/SOAP"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ManageNameIDService", 
            "location": "https://connect-beta.sunet.se/Shibboleth.sso/NIM/Redirect"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ManageNameIDService", 
            "location": "https://connect-beta.sunet.se/Shibboleth.sso/NIM/POST"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ManageNameIDService", 
            "location": "https://connect-beta.sunet.se/Shibboleth.sso/NIM/Artifact"
          }
        ]
      }
    ], 
    "contact_person": [
      {
        "company": {
          "text": "NORDUnet NOC", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Company"
        }, 
        "email_address": [
          {
            "text": "noc@nordu.net", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "contact_type": "technical"
      }
    ]
  }, 
  "https://filesender.funet.fi": {
    "valid_until": "2012-12-19T20:15:01Z", 
    "entity_id": "https://filesender.funet.fi", 
    "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EntityDescriptor", 
    "organization": {
      "organization_name": [
        {
          "lang": "fi", 
          "text": "CSC - Tieteen tietotekniikan keskus Oy", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }, 
        {
          "lang": "en", 
          "text": "CSC - IT Center for Science Ltd.", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }, 
        {
          "lang": "sv", 
          "text": "CSC - Tieteen tietotekniikan keskus Oy", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }
      ], 
      "organization_display_name": [
        {
          "lang": "fi", 
          "text": "CSC - Tieteen tietotekniikan keskus Oy", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }, 
        {
          "lang": "en", 
          "text": "CSC - IT Center for Science Ltd.", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }, 
        {
          "lang": "sv", 
          "text": "CSC - Tieteen tietotekniikan keskus Oy", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }
      ], 
      "organization_url": [
        {
          "lang": "fi", 
          "text": "http://www.csc.fi", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }, 
        {
          "lang": "en", 
          "text": "http://www.csc.fi", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }, 
        {
          "lang": "sv", 
          "text": "http://www.csc.fi", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }
      ], 
      "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Organization"
    }, 
    "contact_person": [
      {
        "given_name": {
          "text": "Harri", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&GivenName"
        }, 
        "email_address": [
          {
            "text": "harri.kuusisto@csc.fi", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ], 
        "sur_name": {
          "text": "Kuusisto", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SurName"
        }, 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "contact_type": "administrative"
      }, 
      {
        "given_name": {
          "text": "Tomi", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&GivenName"
        }, 
        "email_address": [
          {
            "text": "tomi.salmi@csc.fi", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ], 
        "sur_name": {
          "text": "Salmi", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SurName"
        }, 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "contact_type": "technical"
      }, 
      {
        "given_name": {
          "text": "Tomi", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&GivenName"
        }, 
        "email_address": [
          {
            "text": "tomi.salmi@csc.fi", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ], 
        "sur_name": {
          "text": "Salmi", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SurName"
        }, 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "contact_type": "support"
      }
    ], 
    "spsso_descriptor": [
      {
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "assertion_consumer_service": [
          {
            "is_default": "true", 
            "index": "1", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://filesender.funet.fi/simplesaml/module.php/saml/sp/saml2-acs.php/SP"
          }, 
          {
            "is_default": "false", 
            "index": "2", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://filesender.funet.fi/simplesaml/module.php/saml/sp/saml2-acs.php/SP"
          }
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SPSSODescriptor", 
        "extensions": {
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Extensions", 
          "extension_elements": [
            {
              "index": "1", 
              "binding": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol", 
              "__class__": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol&DiscoveryResponse", 
              "location": "https://filesender.funet.fi/simplesaml/module.php/saml/disco.php"
            }, 
            {
              "display_name": [
                {
                  "lang": "fi", 
                  "text": "Funet FileSender", 
                  "__class__": "urn:oasis:names:tc:SAML:metadata:ui&DisplayName"
                }, 
                {
                  "lang": "sv", 
                  "text": "Funet FileSender", 
                  "__class__": "urn:oasis:names:tc:SAML:metadata:ui&DisplayName"
                }, 
                {
                  "lang": "en", 
                  "text": "Funet FileSender", 
                  "__class__": "urn:oasis:names:tc:SAML:metadata:ui&DisplayName"
                }
              ], 
              "__class__": "urn:oasis:names:tc:SAML:metadata:ui&UIInfo"
            }, 
            {
              "attribute_value": [
                {
                  "text": "kalmar", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }, 
                {
                  "text": "finland", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }
              ], 
              "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&Attribute", 
              "name": "tags"
            }
          ]
        }, 
        "name_id_format": [
          {
            "text": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }
        ], 
        "attribute_consuming_service": [
          {
            "index": "1", 
            "service_name": [
              {
                "lang": "fi", 
                "text": "Funet FileSender", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }, 
              {
                "lang": "en", 
                "text": "Funet FileSender", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }, 
              {
                "lang": "sv", 
                "text": "Funet FileSender", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }
            ], 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AttributeConsumingService", 
            "is_default": "true", 
            "requested_attribute": [
              {
                "friendly_name": "cn", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.3"
              }, 
              {
                "friendly_name": "displayName", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.16.840.1.113730.3.1.241"
              }, 
              {
                "friendly_name": "eduPersonPrincipalName", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
              }, 
              {
                "friendly_name": "mail", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:0.9.2342.19200300.100.1.3"
              }
            ], 
            "service_description": [
              {
                "lang": "fi", 
                "text": "Funet FileSender tarjoaa helpon ja turvallisen tavan jakaa suuria tiedostoja.", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }, 
              {
                "lang": "en", 
                "text": "Funet FileSender offers an easy and a secure way to share large files with anyone.", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }, 
              {
                "lang": "sv", 
                "text": "Funet FileSender erbjuder en latt och saker satt att dela stora datafilar till vem som helst.", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }
            ]
          }
        ], 
        "key_descriptor": [
          {
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIE2TCCA8GgAwIBAgIQX2leAqJlB3Q/3iPF8QljNTANBgkqhkiG9w0BAQUFADA2\nMQswCQYDVQQGEwJOTDEPMA0GA1UEChMGVEVSRU5BMRYwFAYDVQQDEw1URVJFTkEg\nU1NMIENBMB4XDTEyMDYyNjAwMDAwMFoXDTE1MDYyNjIzNTk1OVowgbAxCzAJBgNV\nBAYTAkZJMQ4wDAYDVQQREwUwMjEwMTEQMA4GA1UECBMHdXVzaW1hYTEOMAwGA1UE\nBxMFRXNwb28xFjAUBgNVBAkTDUtlaWxhcmFudGEgMTQxKTAnBgNVBAoTIENTQyAt\nIElUIENlbnRlciBmb3IgU2NpZW5jZSBMdGQuMQ4wDAYDVQQLEwVGVU5FVDEcMBoG\nA1UEAxMTZmlsZXNlbmRlci5mdW5ldC5maTCCASIwDQYJKoZIhvcNAQEBBQADggEP\nADCCAQoCggEBAMZgasarh1nW+r5+zxxElcXiJm7oQVBGDSVwlkZr+7Op8NvdG+Hg\nqC3r64lrmNUgI6LgQ56BH0lDZCdWmH1r4IWmps+VUHEyRb83uDNis+61wnyPW2+k\n0O7JCygTwvltycl4Iw6eaPxERHhgV27r85jMJQbeLMaN+oNZ2HgLEAK8mnksa+IS\nVYULX9ybvh/0YrqfKvhs3bO0fNP9IvUj3HVGCOu5lxHSrZWG5ppmxrVZcRbTYyfz\nPcU5xp0wpvNKju8NQhPlpOhmtvaC8zEDDiRGGG5BTLBc/dMz7gExcjFRh7uUFImx\nkaQBMgbC4Q1PEAfc1HW4dCXH63rTvx7+yNECAwEAAaOCAWYwggFiMB8GA1UdIwQY\nMBaAFAy9k2gM896ro0lrKzdXR+qQ47ntMB0GA1UdDgQWBBS0whoofsD3sLHsJarO\nfwv9F9uGyzAOBgNVHQ8BAf8EBAMCBaAwDAYDVR0TAQH/BAIwADAdBgNVHSUEFjAU\nBggrBgEFBQcDAQYIKwYBBQUHAwIwGAYDVR0gBBEwDzANBgsrBgEEAbIxAQICHTA6\nBgNVHR8EMzAxMC+gLaArhilodHRwOi8vY3JsLnRjcy50ZXJlbmEub3JnL1RFUkVO\nQVNTTENBLmNybDBtBggrBgEFBQcBAQRhMF8wNQYIKwYBBQUHMAKGKWh0dHA6Ly9j\ncnQudGNzLnRlcmVuYS5vcmcvVEVSRU5BU1NMQ0EuY3J0MCYGCCsGAQUFBzABhhpo\ndHRwOi8vb2NzcC50Y3MudGVyZW5hLm9yZzAeBgNVHREEFzAVghNmaWxlc2VuZGVy\nLmZ1bmV0LmZpMA0GCSqGSIb3DQEBBQUAA4IBAQCo97bKpkoqXDVVfg868CNBrSYi\n1bWlUGH732ijBmo3CIDV08G5Q7/0hejeKKTJfw02XNAxHBjatcB9umyuZUKa2Xf/\nFq9C5c4z3aH1DOpUaVDzRr3gKxEloP0iJfp/jR00cs8hNKw0Lzw/dXVIQ+ObT1B7\n4Qm4RJUOIO/yHNqLvs0QRhYCnonyfUN5Hg5RA0hGwBXJzLZpVYG4yNVYEuSS47BA\nNuSoiRuRqUwvjh1crrpK3aEPzrhwALKEQo0tIKOpSHjVUwvGXWtoljY7JJJt94y1\no9pAScnCYOeqNoQ//wrcSVQcwozZLhGlymlLAyDI0rx/hM9v+8PL1E0iFmf/", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ]
      }
    ]
  }, 
  "https://connect.sunet.se/shibboleth": {
    "valid_until": "2012-12-16T04:23:08Z", 
    "entity_id": "https://connect.sunet.se/shibboleth", 
    "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EntityDescriptor", 
    "extensions": {
      "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Extensions", 
      "extension_elements": [
        {
          "attribute": [
            {
              "attribute_value": [
                {
                  "text": "http://www.swamid.se/category/research-and-education", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }, 
                {
                  "text": "http://www.swamid.se/category/nren-service", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }, 
                {
                  "text": "http://www.swamid.se/category/eu-adequate-protection", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }
              ], 
              "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&Attribute", 
              "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
              "name": "http://macedir.org/entity-category"
            }
          ], 
          "__class__": "urn:oasis:names:tc:SAML:metadata:attribute&EntityAttributes"
        }, 
        {
          "attribute_value": [
            {
              "text": "kalmar", 
              "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
              "extension_attributes": {
                "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
              }
            }, 
            {
              "text": "sweden", 
              "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
              "extension_attributes": {
                "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
              }
            }
          ], 
          "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&Attribute", 
          "name": "tags"
        }
      ]
    }, 
    "organization": {
      "organization_name": [
        {
          "lang": "en", 
          "text": "NORDUnet", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }
      ], 
      "organization_display_name": [
        {
          "lang": "en", 
          "text": "NORDUnet A/S", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }
      ], 
      "organization_url": [
        {
          "lang": "en", 
          "text": "http://www.nordu.net", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }
      ], 
      "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Organization"
    }, 
    "spsso_descriptor": [
      {
        "single_logout_service": [
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:SOAP", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleLogoutService", 
            "location": "https://connect.sunet.se/Shibboleth.sso/SLO/SOAP"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleLogoutService", 
            "location": "https://connect.sunet.se/Shibboleth.sso/SLO/Redirect"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleLogoutService", 
            "location": "https://connect.sunet.se/Shibboleth.sso/SLO/POST"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleLogoutService", 
            "location": "https://connect.sunet.se/Shibboleth.sso/SLO/Artifact"
          }
        ], 
        "attribute_consuming_service": [
          {
            "index": "0", 
            "service_description": [
              {
                "lang": "en", 
                "text": "SUNET E-Meeting Service (Adobe Connect Pro)", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }
            ], 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AttributeConsumingService", 
            "requested_attribute": [
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:0.9.2342.19200300.100.1.3"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.42"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.4"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.9"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.1"
              }
            ], 
            "service_name": [
              {
                "lang": "en", 
                "text": "SUNET E-Meeting Service", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }
            ]
          }
        ], 
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "assertion_consumer_service": [
          {
            "index": "1", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://connect.sunet.se/Shibboleth.sso/SAML2/POST"
          }, 
          {
            "index": "2", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://connect.sunet.se/Shibboleth.sso/SAML2/POST-SimpleSign"
          }, 
          {
            "index": "3", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://connect.sunet.se/Shibboleth.sso/SAML2/Artifact"
          }, 
          {
            "index": "4", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:PAOS", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://connect.sunet.se/Shibboleth.sso/SAML2/ECP"
          }, 
          {
            "index": "5", 
            "binding": "urn:oasis:names:tc:SAML:1.0:profiles:browser-post", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://connect.sunet.se/Shibboleth.sso/SAML/POST"
          }, 
          {
            "index": "6", 
            "binding": "urn:oasis:names:tc:SAML:1.0:profiles:artifact-01", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://connect.sunet.se/Shibboleth.sso/SAML/Artifact"
          }
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SPSSODescriptor", 
        "extensions": {
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Extensions", 
          "extension_elements": [
            {
              "index": "1", 
              "binding": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol", 
              "__class__": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol&DiscoveryResponse", 
              "location": "https://connect.sunet.se/Shibboleth.sso/DS/ds.swamid.se"
            }, 
            {
              "index": "2", 
              "binding": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol", 
              "__class__": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol&DiscoveryResponse", 
              "location": "https://connect.sunet.se/Shibboleth.sso/DS/ds.sunet.se"
            }, 
            {
              "index": "3", 
              "binding": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol", 
              "__class__": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol&DiscoveryResponse", 
              "location": "https://connect.sunet.se/Shibboleth.sso/DS/nordu.net"
            }, 
            {
              "index": "4", 
              "binding": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol", 
              "__class__": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol&DiscoveryResponse", 
              "location": "https://connect.sunet.se/Shibboleth.sso/DS/kalmar2"
            }
          ]
        }, 
        "key_descriptor": [
          {
            "use": "signing", 
            "key_info": {
              "key_name": [
                {
                  "text": "connect01.acp.sunet.se", 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyName"
                }, 
                {
                  "text": "https://connect.sunet.se/shibboleth", 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyName"
                }
              ], 
              "x509_data": [
                {
                  "x509_subject_name": {
                    "text": "CN=connect01.acp.sunet.se", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509SubjectName"
                  }, 
                  "x509_certificate": {
                    "text": "MIIDLjCCAhagAwIBAgIJALJTE8wpfDmAMA0GCSqGSIb3DQEBBQUAMCExHzAdBgNV\nBAMTFmNvbm5lY3QwMS5hY3Auc3VuZXQuc2UwHhcNMDkwOTAyMTIwNTIwWhcNMTkw\nODMxMTIwNTIwWjAhMR8wHQYDVQQDExZjb25uZWN0MDEuYWNwLnN1bmV0LnNlMIIB\nIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzaNMBLHGgzRrAHLQDUiM+xu6\nghKwdRqBcg171qVDeA4wSoVJLVeAY2xWKjudYzXtcwqL7qkDcHD3wOd0FLQSFfxE\no67z4chBMNrkK9b9NgdHWp/Nb8gsdYNZt2ZjJVOD/oWTFXRHZDJhqkXFvVjL1gKu\nE3a2vDK6LRqYCLx5cyFleuRoqBvMrDxKLHvmqxo+Qt2e+ntL1sDVyKeMxgZc2s0/\nxGYFFzSVDT08XrWlgpN0AmxhfC0ULDb8YzQiJxsdeZ3C57RnC0InabCCvzPQsy9t\nc1VU/TNXkkXQn3H5aC+LUu8olnYndtFac56k/OaAUPe15/1MQVXvL8vbGG6JkQID\nAQABo2kwZzBGBgNVHREEPzA9ghZjb25uZWN0MDEuYWNwLnN1bmV0LnNlhiNodHRw\nczovL2Nvbm5lY3Quc3VuZXQuc2Uvc2hpYmJvbGV0aDAdBgNVHQ4EFgQUxPAGA++l\ntPOMkUezKJJrwSNAz/0wDQYJKoZIhvcNAQEFBQADggEBADJJgcI6VADyB8749iGB\nUbK97Zav6/YoX3jMH21tpO0+iZyPlfCxlDmNIBSSrHmNIs7g8sBSi+z8ko2IaSKS\nYa0fI0N+cvBoi+3Wfszq0LpUSu/5pMWiw3DacOCNesR76h+FKD/UPgUL+LDw7ebz\nK3aeVvtsIjPijrcCaUKrZg5dv/5CRx/oQLbV20L3xk5UTTO/RNrR1gef37yEowDd\nd8hQaQgw5uujjjdkr/6u03kjO6rEZAySsiBPGcpBDXAbk4lnJVQltP0MBE4pu+es\n0oZu+lC7LltiBjJxdh/7SaqdLbn7G7cApwQKqXHVFITX9ncVMM04FtM9MzMc9d4y\nbUs=", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }, 
          {
            "use": "encryption", 
            "key_info": {
              "key_name": [
                {
                  "text": "connect01.acp.sunet.se", 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyName"
                }, 
                {
                  "text": "https://connect.sunet.se/shibboleth", 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyName"
                }
              ], 
              "x509_data": [
                {
                  "x509_subject_name": {
                    "text": "CN=connect01.acp.sunet.se", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509SubjectName"
                  }, 
                  "x509_certificate": {
                    "text": "MIIDLjCCAhagAwIBAgIJALJTE8wpfDmAMA0GCSqGSIb3DQEBBQUAMCExHzAdBgNV\nBAMTFmNvbm5lY3QwMS5hY3Auc3VuZXQuc2UwHhcNMDkwOTAyMTIwNTIwWhcNMTkw\nODMxMTIwNTIwWjAhMR8wHQYDVQQDExZjb25uZWN0MDEuYWNwLnN1bmV0LnNlMIIB\nIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzaNMBLHGgzRrAHLQDUiM+xu6\nghKwdRqBcg171qVDeA4wSoVJLVeAY2xWKjudYzXtcwqL7qkDcHD3wOd0FLQSFfxE\no67z4chBMNrkK9b9NgdHWp/Nb8gsdYNZt2ZjJVOD/oWTFXRHZDJhqkXFvVjL1gKu\nE3a2vDK6LRqYCLx5cyFleuRoqBvMrDxKLHvmqxo+Qt2e+ntL1sDVyKeMxgZc2s0/\nxGYFFzSVDT08XrWlgpN0AmxhfC0ULDb8YzQiJxsdeZ3C57RnC0InabCCvzPQsy9t\nc1VU/TNXkkXQn3H5aC+LUu8olnYndtFac56k/OaAUPe15/1MQVXvL8vbGG6JkQID\nAQABo2kwZzBGBgNVHREEPzA9ghZjb25uZWN0MDEuYWNwLnN1bmV0LnNlhiNodHRw\nczovL2Nvbm5lY3Quc3VuZXQuc2Uvc2hpYmJvbGV0aDAdBgNVHQ4EFgQUxPAGA++l\ntPOMkUezKJJrwSNAz/0wDQYJKoZIhvcNAQEFBQADggEBADJJgcI6VADyB8749iGB\nUbK97Zav6/YoX3jMH21tpO0+iZyPlfCxlDmNIBSSrHmNIs7g8sBSi+z8ko2IaSKS\nYa0fI0N+cvBoi+3Wfszq0LpUSu/5pMWiw3DacOCNesR76h+FKD/UPgUL+LDw7ebz\nK3aeVvtsIjPijrcCaUKrZg5dv/5CRx/oQLbV20L3xk5UTTO/RNrR1gef37yEowDd\nd8hQaQgw5uujjjdkr/6u03kjO6rEZAySsiBPGcpBDXAbk4lnJVQltP0MBE4pu+es\n0oZu+lC7LltiBjJxdh/7SaqdLbn7G7cApwQKqXHVFITX9ncVMM04FtM9MzMc9d4y\nbUs=", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ], 
        "manage_name_id_service": [
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:SOAP", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ManageNameIDService", 
            "location": "https://connect.sunet.se/Shibboleth.sso/NIM/SOAP"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ManageNameIDService", 
            "location": "https://connect.sunet.se/Shibboleth.sso/NIM/Redirect"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ManageNameIDService", 
            "location": "https://connect.sunet.se/Shibboleth.sso/NIM/POST"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ManageNameIDService", 
            "location": "https://connect.sunet.se/Shibboleth.sso/NIM/Artifact"
          }
        ]
      }
    ], 
    "contact_person": [
      {
        "company": {
          "text": "NORDUnet NOC", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Company"
        }, 
        "email_address": [
          {
            "text": "noc@nordu.net", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "contact_type": "technical"
      }
    ]
  }, 
  "urn:ibistic:prod:dk.ibistic.net": {
    "valid_until": "2012-12-19T20:17:02Z", 
    "entity_id": "urn:ibistic:prod:dk.ibistic.net", 
    "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EntityDescriptor", 
    "spsso_descriptor": [
      {
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "assertion_consumer_service": [
          {
            "index": "0", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://dk.ibistic.net/redirector/saml/post/ac"
          }
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SPSSODescriptor", 
        "name_id_format": [
          {
            "text": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }
        ], 
        "attribute_consuming_service": [
          {
            "index": "0", 
            "service_description": [
              {
                "lang": "en", 
                "text": "to handle and approve supplier invoices in a web-based solution", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }, 
              {
                "lang": "da", 
                "text": "at h\u00e5ndtere og godkende leverand\u00f8rfakturarer i en webbaseret l\u00f8sning", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }
            ], 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AttributeConsumingService", 
            "requested_attribute": [
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.42"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.4"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:0.9.2342.19200300.100.1.3"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.25178.1.2.9"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.10"
              }
            ], 
            "service_name": [
              {
                "lang": "en", 
                "text": "Ibistic", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }, 
              {
                "lang": "da", 
                "text": "Ibistic", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }
            ]
          }
        ], 
        "key_descriptor": [
          {
            "use": "signing", 
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIE3jCCA8agAwIBAgIKVFd/+wAAAAAAVTANBgkqhkiG9w0BAQUFADBoMR0wGwYDVQQKExRJYmlzdGljIFRlY2hub2xvZ2llczEUMBIGA1UECxMLaWJpc3RpYy5uZXQxMTAvBgNVBAMTKEliaXN0aWMgU2VydmljZXMgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTEwOTEyMTI0MjI0WhcNMzYwMjEwMTEyMzUxWjCBkzELMAkGA1UEBhMCREsxHTAbBgNVBAoTFEliaXN0aWMgVGVjaG5vbG9naWVzMRMwEQYDVQQLEwpPcGVyYXRpb25zMSswKQYDVQQDEyJJYmlzdGljIFNzbyAtIFNlY29uZGFyeSBkYXRhY2VudGVyMSMwIQYJKoZIhvcNAQkBFhRpdGFkbWluc0BpYmlzdGljLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALOlseCtQInKCW4gm1g9z/1wWo7eqr3qhYAgRW/YFD05wO+aP2Q82AF5qXIzJnI+bmi6UIK8WGU0MwcpAfwmY7E4G0kiqxvkY8w+a0eS0bB/9BEP0wGNHCABi5F0k5gccq1gAroHO8KHrvxwC2QdF5bpOtmc5yZhn39F6vW1CMa+1e4szXLRfnNEUcAC9BfP8TBZ468/2n8bAgCooXw6NeLTEsLYWF9ZUtd7oQCoM8Vzh9EQYiP/bkNjI3Espr3IqmsjBU92LND2FCZMd0VnP+09WBALPPqecICSxwU/g0pEBD9gJffoaLB4pr9ytHj345dfZA5gZbFJus83D6bhb8sCAwEAAaOCAVwwggFYMA4GA1UdDwEB/wQEAwIE8DATBgNVHSUEDDAKBggrBgEFBQcDAjAdBgNVHQ4EFgQUEA1cOFio+1n2Gl51vXhc6BxHIeowHwYDVR0jBBgwFoAUk5xu2Q3v2+7MptSjR6/WlKEwYAUwgeIGCCsGAQUFBwEBBIHVMIHSMIHPBggrBgEFBQcwAoaBwmxkYXA6Ly8vQ049SWJpc3RpYyUyMFNlcnZpY2VzJTIwQ2VydGlmaWNhdGlvbiUyMEF1dGhvcml0eSxDTj1BSUEsQ049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixEQz1pYmlzdGljLERDPWxvY2FsP2NBQ2VydGlmaWNhdGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQEFBQADggEBAK+rMn969MQZW98WhCuixX80SxDO7eARBJ2IY6aZRQ/seo/GD4qbis23CqZy7BI20nlcgnVEW4mZY+LkeBJ5sHDOTL9R2oo90/LouMsDsvqYk4oL5PtIH1yMTUod6ZUsGCvY6iXs06zY7KXJWPM5PeDg/z07GsmEhWELiQ+OeXG5UFlgzvt0uFuqE3iRpvKP6NztxDPNx4nhFXh2DIVg1f+pMXRRF8jM5mXSXsD144IvpEkgyHL5CkSRcxNNZt3UPAZl54e6cDfWI6aSQdH2v/TcoeeEJcHPBL3PFeQEtypZTHYdhPdhai0fcKsSNcZ4Ed1qAOwORlC0CorwiXeB57A=", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }, 
          {
            "use": "encryption", 
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIE3jCCA8agAwIBAgIKVFd/+wAAAAAAVTANBgkqhkiG9w0BAQUFADBoMR0wGwYDVQQKExRJYmlzdGljIFRlY2hub2xvZ2llczEUMBIGA1UECxMLaWJpc3RpYy5uZXQxMTAvBgNVBAMTKEliaXN0aWMgU2VydmljZXMgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTEwOTEyMTI0MjI0WhcNMzYwMjEwMTEyMzUxWjCBkzELMAkGA1UEBhMCREsxHTAbBgNVBAoTFEliaXN0aWMgVGVjaG5vbG9naWVzMRMwEQYDVQQLEwpPcGVyYXRpb25zMSswKQYDVQQDEyJJYmlzdGljIFNzbyAtIFNlY29uZGFyeSBkYXRhY2VudGVyMSMwIQYJKoZIhvcNAQkBFhRpdGFkbWluc0BpYmlzdGljLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALOlseCtQInKCW4gm1g9z/1wWo7eqr3qhYAgRW/YFD05wO+aP2Q82AF5qXIzJnI+bmi6UIK8WGU0MwcpAfwmY7E4G0kiqxvkY8w+a0eS0bB/9BEP0wGNHCABi5F0k5gccq1gAroHO8KHrvxwC2QdF5bpOtmc5yZhn39F6vW1CMa+1e4szXLRfnNEUcAC9BfP8TBZ468/2n8bAgCooXw6NeLTEsLYWF9ZUtd7oQCoM8Vzh9EQYiP/bkNjI3Espr3IqmsjBU92LND2FCZMd0VnP+09WBALPPqecICSxwU/g0pEBD9gJffoaLB4pr9ytHj345dfZA5gZbFJus83D6bhb8sCAwEAAaOCAVwwggFYMA4GA1UdDwEB/wQEAwIE8DATBgNVHSUEDDAKBggrBgEFBQcDAjAdBgNVHQ4EFgQUEA1cOFio+1n2Gl51vXhc6BxHIeowHwYDVR0jBBgwFoAUk5xu2Q3v2+7MptSjR6/WlKEwYAUwgeIGCCsGAQUFBwEBBIHVMIHSMIHPBggrBgEFBQcwAoaBwmxkYXA6Ly8vQ049SWJpc3RpYyUyMFNlcnZpY2VzJTIwQ2VydGlmaWNhdGlvbiUyMEF1dGhvcml0eSxDTj1BSUEsQ049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixEQz1pYmlzdGljLERDPWxvY2FsP2NBQ2VydGlmaWNhdGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQEFBQADggEBAK+rMn969MQZW98WhCuixX80SxDO7eARBJ2IY6aZRQ/seo/GD4qbis23CqZy7BI20nlcgnVEW4mZY+LkeBJ5sHDOTL9R2oo90/LouMsDsvqYk4oL5PtIH1yMTUod6ZUsGCvY6iXs06zY7KXJWPM5PeDg/z07GsmEhWELiQ+OeXG5UFlgzvt0uFuqE3iRpvKP6NztxDPNx4nhFXh2DIVg1f+pMXRRF8jM5mXSXsD144IvpEkgyHL5CkSRcxNNZt3UPAZl54e6cDfWI6aSQdH2v/TcoeeEJcHPBL3PFeQEtypZTHYdhPdhai0fcKsSNcZ4Ed1qAOwORlC0CorwiXeB57A=", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ]
      }
    ], 
    "cache_duration": "PT345600S"
  }, 
  "https://keybucket.app.nordu.net/saml2/sp/metadata": {
    "valid_until": "2012-12-16T04:23:08Z", 
    "entity_id": "https://keybucket.app.nordu.net/saml2/sp/metadata", 
    "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EntityDescriptor", 
    "organization": {
      "organization_name": [
        {
          "lang": "en", 
          "text": "NORDUNet", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }
      ], 
      "organization_display_name": [
        {
          "lang": "en", 
          "text": "NORDUnet A/S", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }
      ], 
      "organization_url": [
        {
          "lang": "en", 
          "text": "http://www.nordu.net", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }
      ], 
      "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Organization"
    }, 
    "contact_person": [
      {
        "contact_type": "technical", 
        "company": {
          "text": "NORDUnet", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Company"
        }, 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "sur_name": {
          "text": "Johansson", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SurName"
        }, 
        "given_name": {
          "text": "Leif", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&GivenName"
        }, 
        "email_address": [
          {
            "text": "leifj@nordu.net", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ]
      }, 
      {
        "contact_type": "technical", 
        "company": {
          "text": "NORDUnet", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Company"
        }, 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "sur_name": {
          "text": "Berggren", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SurName"
        }, 
        "given_name": {
          "text": "Johan", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&GivenName"
        }, 
        "email_address": [
          {
            "text": "jbn@nordu.net", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ]
      }
    ], 
    "spsso_descriptor": [
      {
        "single_logout_service": [
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleLogoutService", 
            "location": "https://keybucket.app.nordu.net/saml2/sp/ls/"
          }
        ], 
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "assertion_consumer_service": [
          {
            "index": "1", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://keybucket.app.nordu.net/saml2/sp/acs/"
          }
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SPSSODescriptor", 
        "key_descriptor": [
          {
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIEujCCA6KgAwIBAgIQLINqZJFs8l1wYd2J2IBMTjANBgkqhkiG9w0BAQUFADA2\nMQswCQYDVQQGEwJOTDEPMA0GA1UEChMGVEVSRU5BMRYwFAYDVQQDEw1URVJFTkEg\nU1NMIENBMB4XDTEyMDIyOTAwMDAwMFoXDTE1MDIyODIzNTk1OVowgZUxCzAJBgNV\nBAYTAkRLMQowCAYDVQQREwEuMQowCAYDVQQIEwEuMQswCQYDVQQHEwIuLjEZMBcG\nA1UECRMQREsgMjk3MCBIb3JzaG9sbTEVMBMGA1UECRMMQWdlcm4gQWxsZSAzMRUw\nEwYDVQQKEwxOT1JEVW5ldCBBL1MxGDAWBgNVBAMUDyouYXBwLm5vcmR1Lm5ldDCC\nASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJkBbj0ZJsjuirO6tN9rbRhE\n5PfQKfjrwMf5lp1a05DHlJcxsv2JZGPszkOA260D8gouWfjk3DJQIIJJgELfn5yP\nL4zwKArBDpsttTXW+DFmhfECbkemWV571ErDHMVC9JUD39uLhE1bAoYFxAeJGr14\nmg/N5YdnsuSTGOfVfC+XuhA3CgylcGBIWoXHPbPlUJk3VWVeNnYjO+nLlKPjhSSq\nmRVhmVhEwREiRPgbKyMEEoFpdmSzuNWcBMtVKt4FTLa0cjx3/rIn77imztcXRDSN\nT6GwXaG5pjy+7E602epC4t5hbj6pxzrC7mpyIQXdYjKboPgaKQ+E7bv+OqJNG3sC\nAwEAAaOCAWIwggFeMB8GA1UdIwQYMBaAFAy9k2gM896ro0lrKzdXR+qQ47ntMB0G\nA1UdDgQWBBT0F6Szj83YxTlMGIIIf3I9jdTedjAOBgNVHQ8BAf8EBAMCBaAwDAYD\nVR0TAQH/BAIwADAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwGAYDVR0g\nBBEwDzANBgsrBgEEAbIxAQICHTA6BgNVHR8EMzAxMC+gLaArhilodHRwOi8vY3Js\nLnRjcy50ZXJlbmEub3JnL1RFUkVOQVNTTENBLmNybDBtBggrBgEFBQcBAQRhMF8w\nNQYIKwYBBQUHMAKGKWh0dHA6Ly9jcnQudGNzLnRlcmVuYS5vcmcvVEVSRU5BU1NM\nQ0EuY3J0MCYGCCsGAQUFBzABhhpodHRwOi8vb2NzcC50Y3MudGVyZW5hLm9yZzAa\nBgNVHREEEzARgg8qLmFwcC5ub3JkdS5uZXQwDQYJKoZIhvcNAQEFBQADggEBADMQ\nbc0dPVC1SlyOxDf90hN9sDKw92YdVtsUNFfs9MYivZK7KI5+qEQStpAvXkrBUNfd\ngM9wqL9ea9BDDmBcn5lYyjPBgGJBeLLkcyBbZ56JbcBAxIncKKFw6r5M3j7tMcth\nf06K4cm7ngUg80ZEYK00ioAyFle56qPfZ5UM25QFzV38DGvusLl5H1bTtpz1ijh7\nkO/ehJVo4K64KVCbjOr1bavp665TtcIQX2qoPsnTZY30gQ/X/K2UJQSUE5Qc+o19\nBkvvVT5jNYdeLZHXbC6X4kXYNhFKZaz9nURgfaFQIeIEu/zmsIM8tcwLjZyF1veH\nwXXiBDXS3PNHXQnnpys=", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ], 
        "want_assertions_signed": "true", 
        "authn_requests_signed": "false", 
        "attribute_consuming_service": [
          {
            "index": "1", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AttributeConsumingService", 
            "requested_attribute": [
              {
                "is_required": "true", 
                "friendly_name": "eduPersonPrincipalName", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
              }, 
              {
                "is_required": "true", 
                "friendly_name": "displayName", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.16.840.1.113730.3.1.241"
              }
            ], 
            "service_name": [
              {
                "lang": "en", 
                "text": "The KeyBucket", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }
            ]
          }
        ]
      }
    ]
  }, 
  "https://idp.nordu.net/idp/shibboleth": {
    "valid_until": "2012-12-16T04:23:08Z", 
    "entity_id": "https://idp.nordu.net/idp/shibboleth", 
    "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EntityDescriptor", 
    "idpsso_descriptor": [
      {
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&IDPSSODescriptor", 
        "single_sign_on_service": [
          {
            "binding": "urn:mace:shibboleth:1.0:profiles:AuthnRequest", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleSignOnService", 
            "location": "https://idp.nordu.net/idp/profile/Shibboleth/SSO"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleSignOnService", 
            "location": "https://idp.nordu.net/idp/profile/SAML2/POST/SSO"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleSignOnService", 
            "location": "https://idp.nordu.net/idp/profile/SAML2/POST-SimpleSign/SSO"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleSignOnService", 
            "location": "https://idp.nordu.net/idp/profile/SAML2/Redirect/SSO"
          }
        ], 
        "extensions": {
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Extensions", 
          "extension_elements": [
            {
              "attribute_value": [
                {
                  "text": "kalmar", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }, 
                {
                  "text": "sweden", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }
              ], 
              "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&Attribute", 
              "name": "tags"
            }
          ]
        }, 
        "key_descriptor": [
          {
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIDHzCCAgegAwIBAgIUbYzFMX2BKRKmZwRSWg0HZ3/MQQwwDQYJKoZIhvcNAQEF\nBQAwGDEWMBQGA1UEAxMNaWRwLm5vcmR1Lm5ldDAeFw0wOTA5MDMxOTI4NDlaFw0y\nOTA5MDMxOTI4NDlaMBgxFjAUBgNVBAMTDWlkcC5ub3JkdS5uZXQwggEiMA0GCSqG\nSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCSypIpdblxznunPXiwKCqwOYmj99u5S9f7\nRTR+s8EDs01uwJ8buJs0MId+s96mD8MIkobE4iwn/B6xlafbMr3/BF+XxxH8Q5WX\nBf3aQV3ohBqur6+mRQ2C+EenzPMGHmV/FCz0cbmTsIAQHZ9Vy16H+x5uWOBVd44i\nCMLM+fgjKyYcpcEUJP9Jkn/+d36L3mdXbyqAQS2UPN+S1g37xrgR2kWW+s1lMEiR\nM/f5L+PuA3l5DxIBmK0tFo+ZPLxbr6OBWOdH6EUbfdkvfciFCVNbWBGRW5MC2aru\nATCdtf/Vev3OngUYBGSR/94eTgMcs3Oww/ppxRS6dzntGnnCT1sPAgMBAAGjYTBf\nMD4GA1UdEQQ3MDWCDWlkcC5ub3JkdS5uZXSGJGh0dHBzOi8vaWRwLm5vcmR1Lm5l\ndC9pZHAvc2hpYmJvbGV0aDAdBgNVHQ4EFgQUwPXuksUpm5OdopeWHdoRcs6wCu0w\nDQYJKoZIhvcNAQEFBQADggEBAHiPOKmhiLnx8ecuQHmwmh4DUZvarhZXNtgxyasU\nbZAfPoZn8YiELiqYQoA/j+hoAfWcCEafMgjm8nkQO9aad1cwpGY66SIRKPAKBgsW\nnOugnrREWwYl1tXG3VWYzpgygycziYzkmwc4ysHQATKjCYdulA1tZ09YiAnZOIzY\nQ93/gA7X177nVKnAbmSkY1Nap4/rbkHIvQqk8RPSYs5AwasThkEFVk4OQpPtoTOn\naOBLkJxpXY7rZDixrz59ny629qmOOakSCsuVkNwDPmbLQy9dKmHXTcge2xP0mDK7\nJiNCTXH29oP8kWBEBVaDxrDIrfDv53VjURS+KXqpBLjsuVE=", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ], 
        "artifact_resolution_service": [
          {
            "index": "1", 
            "binding": "urn:oasis:names:tc:SAML:1.0:bindings:SOAP-binding", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ArtifactResolutionService", 
            "location": "https://idp.nordu.net:8443/idp/profile/SAML1/SOAP/ArtifactResolution"
          }, 
          {
            "index": "2", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:SOAP", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ArtifactResolutionService", 
            "location": "https://idp.nordu.net:8443/idp/profile/SAML2/SOAP/ArtifactResolution"
          }
        ], 
        "name_id_format": [
          {
            "text": "urn:mace:shibboleth:1.0:nameIdentifier", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }, 
          {
            "text": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }
        ]
      }
    ], 
    "attribute_authority_descriptor": [
      {
        "attribute_service": [
          {
            "binding": "urn:oasis:names:tc:SAML:1.0:bindings:SOAP-binding", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AttributeService", 
            "location": "https://idp.nordu.net:8443/idp/profile/SAML1/SOAP/AttributeQuery"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:SOAP", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AttributeService", 
            "location": "https://idp.nordu.net:8443/idp/profile/SAML2/SOAP/AttributeQuery"
          }
        ], 
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AttributeAuthorityDescriptor", 
        "extensions": {
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Extensions"
        }, 
        "key_descriptor": [
          {
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIDHzCCAgegAwIBAgIUbYzFMX2BKRKmZwRSWg0HZ3/MQQwwDQYJKoZIhvcNAQEF\nBQAwGDEWMBQGA1UEAxMNaWRwLm5vcmR1Lm5ldDAeFw0wOTA5MDMxOTI4NDlaFw0y\nOTA5MDMxOTI4NDlaMBgxFjAUBgNVBAMTDWlkcC5ub3JkdS5uZXQwggEiMA0GCSqG\nSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCSypIpdblxznunPXiwKCqwOYmj99u5S9f7\nRTR+s8EDs01uwJ8buJs0MId+s96mD8MIkobE4iwn/B6xlafbMr3/BF+XxxH8Q5WX\nBf3aQV3ohBqur6+mRQ2C+EenzPMGHmV/FCz0cbmTsIAQHZ9Vy16H+x5uWOBVd44i\nCMLM+fgjKyYcpcEUJP9Jkn/+d36L3mdXbyqAQS2UPN+S1g37xrgR2kWW+s1lMEiR\nM/f5L+PuA3l5DxIBmK0tFo+ZPLxbr6OBWOdH6EUbfdkvfciFCVNbWBGRW5MC2aru\nATCdtf/Vev3OngUYBGSR/94eTgMcs3Oww/ppxRS6dzntGnnCT1sPAgMBAAGjYTBf\nMD4GA1UdEQQ3MDWCDWlkcC5ub3JkdS5uZXSGJGh0dHBzOi8vaWRwLm5vcmR1Lm5l\ndC9pZHAvc2hpYmJvbGV0aDAdBgNVHQ4EFgQUwPXuksUpm5OdopeWHdoRcs6wCu0w\nDQYJKoZIhvcNAQEFBQADggEBAHiPOKmhiLnx8ecuQHmwmh4DUZvarhZXNtgxyasU\nbZAfPoZn8YiELiqYQoA/j+hoAfWcCEafMgjm8nkQO9aad1cwpGY66SIRKPAKBgsW\nnOugnrREWwYl1tXG3VWYzpgygycziYzkmwc4ysHQATKjCYdulA1tZ09YiAnZOIzY\nQ93/gA7X177nVKnAbmSkY1Nap4/rbkHIvQqk8RPSYs5AwasThkEFVk4OQpPtoTOn\naOBLkJxpXY7rZDixrz59ny629qmOOakSCsuVkNwDPmbLQy9dKmHXTcge2xP0mDK7\nJiNCTXH29oP8kWBEBVaDxrDIrfDv53VjURS+KXqpBLjsuVE=", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ], 
        "name_id_format": [
          {
            "text": "urn:mace:shibboleth:1.0:nameIdentifier", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }, 
          {
            "text": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }
        ]
      }
    ], 
    "organization": {
      "organization_name": [
        {
          "lang": "en", 
          "text": "NORDUnet", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }
      ], 
      "organization_display_name": [
        {
          "lang": "en", 
          "text": "NORDUnet", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }
      ], 
      "organization_url": [
        {
          "lang": "en", 
          "text": "http://www.nordu.net", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }
      ], 
      "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Organization"
    }, 
    "contact_person": [
      {
        "company": {
          "text": "NORDUnet NOC", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Company"
        }, 
        "email_address": [
          {
            "text": "noc@nordu.net", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "contact_type": "technical"
      }
    ]
  }, 
  "https://wayf.wayf.dk": {
    "valid_until": "2012-12-19T20:17:02Z", 
    "entity_id": "https://wayf.wayf.dk", 
    "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EntityDescriptor", 
    "idpsso_descriptor": [
      {
        "single_logout_service": [
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleLogoutService", 
            "location": "https://wayf.wayf.dk/saml2/idp/SingleLogoutService.php"
          }
        ], 
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&IDPSSODescriptor", 
        "single_sign_on_service": [
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleSignOnService", 
            "location": "https://wayf.wayf.dk/saml2/idp/SSOService.php"
          }
        ], 
        "extensions": {
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Extensions", 
          "extension_elements": [
            {
              "attribute_value": [
                {
                  "text": "kalmar", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }, 
                {
                  "text": "denmark", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }, 
                {
                  "text": "iceland", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }
              ], 
              "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&Attribute", 
              "name": "tags"
            }
          ]
        }, 
        "key_descriptor": [
          {
            "use": "signing", 
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIE3TCCA8WgAwIBAgISESFgDbqp6YXwPvILGKAnrUDtMA0GCSqGSIb3DQEBBQUAMFcxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMS0wKwYDVQQDEyRHbG9iYWxTaWduIERvbWFpbiBWYWxpZGF0aW9uIENBIC0gRzIwHhcNMTIwMTA0MDkzNTU0WhcNMTcwMTAzMDkzNTU0WjBHMQswCQYDVQQGEwJESzEhMB8GA1UECxMYRG9tYWluIENvbnRyb2wgVmFsaWRhdGVkMRUwEwYDVQQDEwx3YXlmLndheWYuZGswggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDAosqmcujXhA49vHQLLTKZxFTz3guMRnwHvUxz5vvuMPYVTGl+fXPdq9ULhkNc1jlCr4+pFOwLdy9zkuAn8dK7grQEaU58K0uF4MTyKixFnPvU3806roL8PnrmUQ2t8y76U9jzsk/B3Ggi5pVqhOktHpZyzz1yBpE14R+/DPzHrpKIFJY4N2uzoBrcEAsJY6aTUfIaB/NEpe4BY8sDZ3CTuU3tWUfhdlZESYsmngdnHD6k0HUKti9F43UM6JyN6fz7T70JlHAcTHzYKhjtPLcWG8lWFqNtry7fCYC5SlKn4zmyifoASxRoH3EuxtE/Fmmt+M6I83kg3H0R1b8PHimfAgMBAAGjggGxMIIBrTAOBgNVHQ8BAf8EBAMCBaAwTAYDVR0gBEUwQzBBBgkrBgEEAaAyAQowNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wFwYDVR0RBBAwDoIMd2F5Zi53YXlmLmRrMAkGA1UdEwQCMAAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMD8GA1UdHwQ4MDYwNKAyoDCGLmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3MvZ3Nkb21haW52YWxnMi5jcmwwgYgGCCsGAQUFBwEBBHwwejBBBggrBgEFBQcwAoY1aHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvZ3Nkb21haW52YWxnMi5jcnQwNQYIKwYBBQUHMAGGKWh0dHA6Ly9vY3NwMi5nbG9iYWxzaWduLmNvbS9nc2RvbWFpbnZhbGcyMB0GA1UdDgQWBBS44PHFNUdj1NTiqkjShHfvW50SIzAfBgNVHSMEGDAWgBSWrfqwW7mDZCp2whyKadpC3P79KDANBgkqhkiG9w0BAQUFAAOCAQEAjqwtcRjT+gYKMhgwpJ4MNpL6W80efrcMDdWnZUJzN081ht0dcQqvdAVjkWylEQbbS1LXc9OZecRJGR1vxBzS7bq0lRauPuYodzOsDzP4cEW/W+PvWIEIpm5yIBZ31P7VnRpaRwmeff8OlhDOvM4+wdovRvIpLgyeyW05R2i4DenI8juCaWXNG+CATj35gW3uh/LD9DBzpZDoQ41/5yJPZUuiHfZtnW0M7oVnhidn5sT319Xiag3Jlqe7dx1D+b0oZVDTbwrECOdROTcbOkbGsr4VleBcTtL5RoF4cDokYB6LpIDmSMiBV6DztPcrPC/ERS/tEBMbfMWVAus4f0SvdQ==", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }, 
          {
            "use": "encryption", 
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIE3TCCA8WgAwIBAgISESFgDbqp6YXwPvILGKAnrUDtMA0GCSqGSIb3DQEBBQUAMFcxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMS0wKwYDVQQDEyRHbG9iYWxTaWduIERvbWFpbiBWYWxpZGF0aW9uIENBIC0gRzIwHhcNMTIwMTA0MDkzNTU0WhcNMTcwMTAzMDkzNTU0WjBHMQswCQYDVQQGEwJESzEhMB8GA1UECxMYRG9tYWluIENvbnRyb2wgVmFsaWRhdGVkMRUwEwYDVQQDEwx3YXlmLndheWYuZGswggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDAosqmcujXhA49vHQLLTKZxFTz3guMRnwHvUxz5vvuMPYVTGl+fXPdq9ULhkNc1jlCr4+pFOwLdy9zkuAn8dK7grQEaU58K0uF4MTyKixFnPvU3806roL8PnrmUQ2t8y76U9jzsk/B3Ggi5pVqhOktHpZyzz1yBpE14R+/DPzHrpKIFJY4N2uzoBrcEAsJY6aTUfIaB/NEpe4BY8sDZ3CTuU3tWUfhdlZESYsmngdnHD6k0HUKti9F43UM6JyN6fz7T70JlHAcTHzYKhjtPLcWG8lWFqNtry7fCYC5SlKn4zmyifoASxRoH3EuxtE/Fmmt+M6I83kg3H0R1b8PHimfAgMBAAGjggGxMIIBrTAOBgNVHQ8BAf8EBAMCBaAwTAYDVR0gBEUwQzBBBgkrBgEEAaAyAQowNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wFwYDVR0RBBAwDoIMd2F5Zi53YXlmLmRrMAkGA1UdEwQCMAAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMD8GA1UdHwQ4MDYwNKAyoDCGLmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3MvZ3Nkb21haW52YWxnMi5jcmwwgYgGCCsGAQUFBwEBBHwwejBBBggrBgEFBQcwAoY1aHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvZ3Nkb21haW52YWxnMi5jcnQwNQYIKwYBBQUHMAGGKWh0dHA6Ly9vY3NwMi5nbG9iYWxzaWduLmNvbS9nc2RvbWFpbnZhbGcyMB0GA1UdDgQWBBS44PHFNUdj1NTiqkjShHfvW50SIzAfBgNVHSMEGDAWgBSWrfqwW7mDZCp2whyKadpC3P79KDANBgkqhkiG9w0BAQUFAAOCAQEAjqwtcRjT+gYKMhgwpJ4MNpL6W80efrcMDdWnZUJzN081ht0dcQqvdAVjkWylEQbbS1LXc9OZecRJGR1vxBzS7bq0lRauPuYodzOsDzP4cEW/W+PvWIEIpm5yIBZ31P7VnRpaRwmeff8OlhDOvM4+wdovRvIpLgyeyW05R2i4DenI8juCaWXNG+CATj35gW3uh/LD9DBzpZDoQ41/5yJPZUuiHfZtnW0M7oVnhidn5sT319Xiag3Jlqe7dx1D+b0oZVDTbwrECOdROTcbOkbGsr4VleBcTtL5RoF4cDokYB6LpIDmSMiBV6DztPcrPC/ERS/tEBMbfMWVAus4f0SvdQ==", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ], 
        "name_id_format": [
          {
            "text": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }
        ]
      }
    ], 
    "cache_duration": "PT345600S", 
    "organization": {
      "organization_name": [
        {
          "lang": "en", 
          "text": "WAYF - Where are you from", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }, 
        {
          "lang": "da", 
          "text": "WAYF - Where are you from", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }
      ], 
      "organization_display_name": [
        {
          "lang": "en", 
          "text": "WAYF - Where are you from", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }, 
        {
          "lang": "da", 
          "text": "WAYF - Where are you from", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }
      ], 
      "organization_url": [
        {
          "lang": "da", 
          "text": "http://wayf.dk/index.php/da", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }, 
        {
          "lang": "en", 
          "text": "http://wayf.dk/index.php/en", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }
      ], 
      "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Organization"
    }
  }, 
  "https://idp.it.helsinki.fi/shibboleth": {
    "valid_until": "2012-12-19T20:15:01Z", 
    "entity_id": "https://idp.it.helsinki.fi/shibboleth", 
    "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EntityDescriptor", 
    "idpsso_descriptor": [
      {
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&IDPSSODescriptor", 
        "single_sign_on_service": [
          {
            "binding": "urn:mace:shibboleth:1.0:profiles:AuthnRequest", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleSignOnService", 
            "location": "https://idp.it.helsinki.fi/idp/profile/Shibboleth/SSO"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleSignOnService", 
            "location": "https://idp.it.helsinki.fi/idp/profile/SAML2/POST/SSO"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleSignOnService", 
            "location": "https://idp.it.helsinki.fi/idp/profile/SAML2/Redirect/SSO"
          }
        ], 
        "extensions": {
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Extensions", 
          "extension_elements": [
            {
              "attribute_value": [
                {
                  "text": "kalmar", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }, 
                {
                  "text": "finland", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }
              ], 
              "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&Attribute", 
              "name": "tags"
            }
          ]
        }, 
        "key_descriptor": [
          {
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIE4DCCA8igAwIBAgIQZn39PmRSCZ62SwsmIa4aojANBgkqhkiG9w0BAQUFADA2\nMQswCQYDVQQGEwJOTDEPMA0GA1UEChMGVEVSRU5BMRYwFAYDVQQDEw1URVJFTkEg\nU1NMIENBMB4XDTExMDQyNzAwMDAwMFoXDTEzMDQyNjIzNTk1OVowgbgxCzAJBgNV\nBAYTAkZJMQ4wDAYDVQQREwUwMDAxNDEQMA4GA1UECBMHVXVzaW1hYTERMA8GA1UE\nBxMISGVsc2lua2kxIjAgBgNVBAkTGVBMIDI2IChUZW9sbGlzdXVza2F0dSAyMykx\nHzAdBgNVBAoTFlVuaXZlcnNpdHkgb2YgSGVsc2lua2kxEjAQBgNVBAsTCUlUIENl\nbnRlcjEbMBkGA1UEAxMSaWRwLml0LmhlbHNpbmtpLmZpMIIBIjANBgkqhkiG9w0B\nAQEFAAOCAQ8AMIIBCgKCAQEAyK5KTNz4ELhqZ3LR9cMf/OM/MIdw+oNblBoizLVV\n03ikG2b0XFnYu8aDJYBo993D8c+hhNE/63owt3BaPuRufU1qmJIOW+7UQAjFj/AC\n01BvW8fmbR4SFZZuyCFzbs0oPZ5spYhjMIqMm0xYEWEQ1wdrf27KCJrI4+YZgKR4\nqhTnm+wg7Gp++EBchCKIssZSP0HFu9pWyaiaWpWj+rO3hSIr0lQPIdkXeaG1EEe2\nqLU9rB5jdA4mAufE98j3sbbbE74HrYhPLEnO8qOPs+Dd8gKYBa07/YBzjAKsSyTn\nEo/PcOg8lqFXLomZ/ZtedKF+vmvaMWOxBA5SXJjTXX3GtwIDAQABo4IBZTCCAWEw\nHwYDVR0jBBgwFoAUDL2TaAzz3qujSWsrN1dH6pDjue0wHQYDVR0OBBYEFBkdk1+u\nunMB8VAFivm0U4Is4evWMA4GA1UdDwEB/wQEAwIFoDAMBgNVHRMBAf8EAjAAMB0G\nA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAYBgNVHSAEETAPMA0GCysGAQQB\nsjEBAgIdMDoGA1UdHwQzMDEwL6AtoCuGKWh0dHA6Ly9jcmwudGNzLnRlcmVuYS5v\ncmcvVEVSRU5BU1NMQ0EuY3JsMG0GCCsGAQUFBwEBBGEwXzA1BggrBgEFBQcwAoYp\naHR0cDovL2NydC50Y3MudGVyZW5hLm9yZy9URVJFTkFTU0xDQS5jcnQwJgYIKwYB\nBQUHMAGGGmh0dHA6Ly9vY3NwLnRjcy50ZXJlbmEub3JnMB0GA1UdEQQWMBSCEmlk\ncC5pdC5oZWxzaW5raS5maTANBgkqhkiG9w0BAQUFAAOCAQEAhKsDvGEQEWrPjPKz\nCNuiAlgRd3TQcbxqY0oDPAeUdBhUw/idEQOek5Uz07Y8ZUsyH05s17wuCXyn19a7\nKPgUsgNlvy5o5+DGv4PpjzUvjHaokawQFsycLW0AG2UC78UPLGAtk0hh4wRtrwLY\nEDcBP3LwtCoYqfrVqy537g0W68NlNv2MSjtFDq2rOvxO+B67TBmkTHx/v848epUA\nW6BwdDSP8schHGwDP1DLvFoFlZ/T7vaIg/460ioTZ6XBKYYVXiCCX2qjrZy6ayMd\namwGEOJi/gst4Ol+x3mwFw6dZATmLJ/WTYEqS1O2RzzxHOukzhl4B9W23LpssqSk\nmdOXEA==", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ], 
        "name_id_format": [
          {
            "text": "urn:mace:shibboleth:1.0:nameIdentifier", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }, 
          {
            "text": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }
        ]
      }
    ], 
    "attribute_authority_descriptor": [
      {
        "attribute_service": [
          {
            "binding": "urn:oasis:names:tc:SAML:1.0:bindings:SOAP-binding", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AttributeService", 
            "location": "https://idp.it.helsinki.fi:8443/idp/profile/SAML1/SOAP/AttributeQuery"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:SOAP", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AttributeService", 
            "location": "https://idp.it.helsinki.fi:8443/idp/profile/SAML2/SOAP/AttributeQuery"
          }
        ], 
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AttributeAuthorityDescriptor", 
        "extensions": {
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Extensions"
        }, 
        "key_descriptor": [
          {
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIE4DCCA8igAwIBAgIQZn39PmRSCZ62SwsmIa4aojANBgkqhkiG9w0BAQUFADA2\nMQswCQYDVQQGEwJOTDEPMA0GA1UEChMGVEVSRU5BMRYwFAYDVQQDEw1URVJFTkEg\nU1NMIENBMB4XDTExMDQyNzAwMDAwMFoXDTEzMDQyNjIzNTk1OVowgbgxCzAJBgNV\nBAYTAkZJMQ4wDAYDVQQREwUwMDAxNDEQMA4GA1UECBMHVXVzaW1hYTERMA8GA1UE\nBxMISGVsc2lua2kxIjAgBgNVBAkTGVBMIDI2IChUZW9sbGlzdXVza2F0dSAyMykx\nHzAdBgNVBAoTFlVuaXZlcnNpdHkgb2YgSGVsc2lua2kxEjAQBgNVBAsTCUlUIENl\nbnRlcjEbMBkGA1UEAxMSaWRwLml0LmhlbHNpbmtpLmZpMIIBIjANBgkqhkiG9w0B\nAQEFAAOCAQ8AMIIBCgKCAQEAyK5KTNz4ELhqZ3LR9cMf/OM/MIdw+oNblBoizLVV\n03ikG2b0XFnYu8aDJYBo993D8c+hhNE/63owt3BaPuRufU1qmJIOW+7UQAjFj/AC\n01BvW8fmbR4SFZZuyCFzbs0oPZ5spYhjMIqMm0xYEWEQ1wdrf27KCJrI4+YZgKR4\nqhTnm+wg7Gp++EBchCKIssZSP0HFu9pWyaiaWpWj+rO3hSIr0lQPIdkXeaG1EEe2\nqLU9rB5jdA4mAufE98j3sbbbE74HrYhPLEnO8qOPs+Dd8gKYBa07/YBzjAKsSyTn\nEo/PcOg8lqFXLomZ/ZtedKF+vmvaMWOxBA5SXJjTXX3GtwIDAQABo4IBZTCCAWEw\nHwYDVR0jBBgwFoAUDL2TaAzz3qujSWsrN1dH6pDjue0wHQYDVR0OBBYEFBkdk1+u\nunMB8VAFivm0U4Is4evWMA4GA1UdDwEB/wQEAwIFoDAMBgNVHRMBAf8EAjAAMB0G\nA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAYBgNVHSAEETAPMA0GCysGAQQB\nsjEBAgIdMDoGA1UdHwQzMDEwL6AtoCuGKWh0dHA6Ly9jcmwudGNzLnRlcmVuYS5v\ncmcvVEVSRU5BU1NMQ0EuY3JsMG0GCCsGAQUFBwEBBGEwXzA1BggrBgEFBQcwAoYp\naHR0cDovL2NydC50Y3MudGVyZW5hLm9yZy9URVJFTkFTU0xDQS5jcnQwJgYIKwYB\nBQUHMAGGGmh0dHA6Ly9vY3NwLnRjcy50ZXJlbmEub3JnMB0GA1UdEQQWMBSCEmlk\ncC5pdC5oZWxzaW5raS5maTANBgkqhkiG9w0BAQUFAAOCAQEAhKsDvGEQEWrPjPKz\nCNuiAlgRd3TQcbxqY0oDPAeUdBhUw/idEQOek5Uz07Y8ZUsyH05s17wuCXyn19a7\nKPgUsgNlvy5o5+DGv4PpjzUvjHaokawQFsycLW0AG2UC78UPLGAtk0hh4wRtrwLY\nEDcBP3LwtCoYqfrVqy537g0W68NlNv2MSjtFDq2rOvxO+B67TBmkTHx/v848epUA\nW6BwdDSP8schHGwDP1DLvFoFlZ/T7vaIg/460ioTZ6XBKYYVXiCCX2qjrZy6ayMd\namwGEOJi/gst4Ol+x3mwFw6dZATmLJ/WTYEqS1O2RzzxHOukzhl4B9W23LpssqSk\nmdOXEA==", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ], 
        "name_id_format": [
          {
            "text": "urn:mace:shibboleth:1.0:nameIdentifier", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }, 
          {
            "text": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }
        ]
      }
    ], 
    "organization": {
      "organization_name": [
        {
          "lang": "fi", 
          "text": "Helsingin yliopisto", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }, 
        {
          "lang": "en", 
          "text": "University of Helsinki", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }, 
        {
          "lang": "sv", 
          "text": "Helsingfors universitet", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }
      ], 
      "organization_display_name": [
        {
          "lang": "fi", 
          "text": "Helsingin yliopisto", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }, 
        {
          "lang": "en", 
          "text": "University of Helsinki", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }, 
        {
          "lang": "sv", 
          "text": "Helsingfors universitet", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }
      ], 
      "organization_url": [
        {
          "lang": "fi", 
          "text": "http://www.helsinki.fi/yliopisto/", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }, 
        {
          "lang": "en", 
          "text": "http://www.helsinki.fi/yliopisto/", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }, 
        {
          "lang": "sv", 
          "text": "http://www.helsinki.fi/yliopisto/", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }
      ], 
      "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Organization"
    }, 
    "contact_person": [
      {
        "given_name": {
          "text": "Olli", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&GivenName"
        }, 
        "email_address": [
          {
            "text": "haka-hy@helsinki.fi", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ], 
        "sur_name": {
          "text": "Saikko", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SurName"
        }, 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "contact_type": "technical"
      }, 
      {
        "given_name": {
          "text": "Aarno", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&GivenName"
        }, 
        "email_address": [
          {
            "text": "haka-hy@helsinki.fi", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ], 
        "sur_name": {
          "text": "Sandvik", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SurName"
        }, 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "contact_type": "technical"
      }
    ]
  }, 
  "http://www.ordbogen.com": {
    "valid_until": "2012-12-19T20:17:02Z", 
    "entity_id": "http://www.ordbogen.com", 
    "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EntityDescriptor", 
    "cache_duration": "PT345600S", 
    "contact_person": [
      {
        "email_address": [
          {
            "text": "maw@ordbogen.com", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ], 
        "sur_name": {
          "text": "Administrator", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SurName"
        }, 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "contact_type": "technical"
      }
    ], 
    "spsso_descriptor": [
      {
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "assertion_consumer_service": [
          {
            "index": "0", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://www.ordbogen.com//singlesignon/simplesamlphp/saml2/sp/AssertionConsumerService.php"
          }
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SPSSODescriptor", 
        "name_id_format": [
          {
            "text": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }
        ], 
        "attribute_consuming_service": [
          {
            "index": "0", 
            "service_description": [
              {
                "lang": "en", 
                "text": "to provide an online dictionary in which you can look up an unlimited number of words in the dictionaries bought by your educational institution", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }, 
              {
                "lang": "da", 
                "text": "at levere en online ordbog hvori du kan foretage et ubegr\u00e6nset antal opslag i de ordb\u00f8ger som din institution har k\u00f8bt adgang til", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }
            ], 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AttributeConsumingService", 
            "requested_attribute": [
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.25178.1.2.9"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.10"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.10"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.9"
              }
            ], 
            "service_name": [
              {
                "lang": "en", 
                "text": "Ordbogen.com", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }, 
              {
                "lang": "da", 
                "text": "Ordbogen.com", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }
            ]
          }
        ], 
        "key_descriptor": [
          {
            "use": "signing", 
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIEdjCCA16gAwIBAgILAQAAAAABLysKVFswDQYJKoZIhvcNAQEFBQAwYzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExFjAUBgNVBAsTDU9iamVjdFNpZ24gQ0ExITAfBgNVBAMTGEdsb2JhbFNpZ24gT2JqZWN0U2lnbiBDQTAeFw0xMTA0MDYxMzI1NDZaFw0xMzA0MDYxMzI1NDRaMEwxCzAJBgNVBAYTAkRLMQ8wDQYDVQQIEwZPZGVuc2UxFTATBgNVBAoTDE9yZGJvZ2VuIEEvUzEVMBMGA1UEAxMMT3JkYm9nZW4gQS9TMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAovIjWe1fOERH9N7Dk7OP9K1YveGQZipKE+GaOHnCNe33F4a1sXMhT38fEUNWQpRLDBeLsWF2G5FnwrVDGb3qo8dN7e4ycZWbZIBuC/lyq8qRt6iIxNHQ7oad8N2m7CTe3ZNdkPHEY8eaDHUP2AC8c1SXyakv394WKuT2roIZ4OD74pv9CTDGFVNsbgOU1xTM+QIvbRSUDmVGBdkUv5tstC9w7R7UdhrW8R1wYcTwA9UxMNEiCNBvyMTfAcJO32FzDTa5nBopyoAK4jgGEdrz8Oeb17MCb+sStxJiZRTuFCgkvuNkCNXEuBBYiNDAyB8AwsLKMw6IzBPCG88NfcmUZwIDAQABo4IBQDCCATwwHwYDVR0jBBgwFoAU0lvzSyZLpbDnXf1Wf/bxLjhOU6AwTgYIKwYBBQUHAQEEQjBAMD4GCCsGAQUFBzAChjJodHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24ubmV0L2NhY2VydC9PYmplY3RTaWduLmNydDA5BgNVHR8EMjAwMC6gLKAqhihodHRwOi8vY3JsLmdsb2JhbHNpZ24ubmV0L09iamVjdFNpZ24uY3JsMAkGA1UdEwQCMAAwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMEsGA1UdIAREMEIwQAYJKwYBBAGgMgEyMDMwMQYIKwYBBQUHAgEWJWh0dHA6Ly93d3cuZ2xvYmFsc2lnbi5uZXQvcmVwb3NpdG9yeS8wEQYJYIZIAYb4QgEBBAQDAgQQMA0GCSqGSIb3DQEBBQUAA4IBAQA0lPLNM6+JLbeGyjZQ5tU7H4c1hX1WcAAGgRVF1oVtTEH8vA4V+roVB35+8Jk08rzqh+ghIUX99P2keUTOlllYUbxb7DXfsOprD5tDGc/jmMMZrYzL3ibdW0229/eaokXMPI6As7ApvQ7utb+sjftwQoI9BkJlbMRoW//t2GYY3bP7+r7yDUbcOVwNUm3ZoxErIM7SulpTS36uP8jcr0zPOwRAx6atMmtNVfZlt91FR3xzvrnfFLPv5YzZ5euAqFnhxmW97co1IgOElcHazmcj+m/uTaoCjaGhxB6eg7cZePuQW0iX7Ufcb0YIAHczY1d+ZfCe5wTuSYnbdJGwoor7", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }, 
          {
            "use": "encryption", 
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIEdjCCA16gAwIBAgILAQAAAAABLysKVFswDQYJKoZIhvcNAQEFBQAwYzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExFjAUBgNVBAsTDU9iamVjdFNpZ24gQ0ExITAfBgNVBAMTGEdsb2JhbFNpZ24gT2JqZWN0U2lnbiBDQTAeFw0xMTA0MDYxMzI1NDZaFw0xMzA0MDYxMzI1NDRaMEwxCzAJBgNVBAYTAkRLMQ8wDQYDVQQIEwZPZGVuc2UxFTATBgNVBAoTDE9yZGJvZ2VuIEEvUzEVMBMGA1UEAxMMT3JkYm9nZW4gQS9TMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAovIjWe1fOERH9N7Dk7OP9K1YveGQZipKE+GaOHnCNe33F4a1sXMhT38fEUNWQpRLDBeLsWF2G5FnwrVDGb3qo8dN7e4ycZWbZIBuC/lyq8qRt6iIxNHQ7oad8N2m7CTe3ZNdkPHEY8eaDHUP2AC8c1SXyakv394WKuT2roIZ4OD74pv9CTDGFVNsbgOU1xTM+QIvbRSUDmVGBdkUv5tstC9w7R7UdhrW8R1wYcTwA9UxMNEiCNBvyMTfAcJO32FzDTa5nBopyoAK4jgGEdrz8Oeb17MCb+sStxJiZRTuFCgkvuNkCNXEuBBYiNDAyB8AwsLKMw6IzBPCG88NfcmUZwIDAQABo4IBQDCCATwwHwYDVR0jBBgwFoAU0lvzSyZLpbDnXf1Wf/bxLjhOU6AwTgYIKwYBBQUHAQEEQjBAMD4GCCsGAQUFBzAChjJodHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24ubmV0L2NhY2VydC9PYmplY3RTaWduLmNydDA5BgNVHR8EMjAwMC6gLKAqhihodHRwOi8vY3JsLmdsb2JhbHNpZ24ubmV0L09iamVjdFNpZ24uY3JsMAkGA1UdEwQCMAAwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMEsGA1UdIAREMEIwQAYJKwYBBAGgMgEyMDMwMQYIKwYBBQUHAgEWJWh0dHA6Ly93d3cuZ2xvYmFsc2lnbi5uZXQvcmVwb3NpdG9yeS8wEQYJYIZIAYb4QgEBBAQDAgQQMA0GCSqGSIb3DQEBBQUAA4IBAQA0lPLNM6+JLbeGyjZQ5tU7H4c1hX1WcAAGgRVF1oVtTEH8vA4V+roVB35+8Jk08rzqh+ghIUX99P2keUTOlllYUbxb7DXfsOprD5tDGc/jmMMZrYzL3ibdW0229/eaokXMPI6As7ApvQ7utb+sjftwQoI9BkJlbMRoW//t2GYY3bP7+r7yDUbcOVwNUm3ZoxErIM7SulpTS36uP8jcr0zPOwRAx6atMmtNVfZlt91FR3xzvrnfFLPv5YzZ5euAqFnhxmW97co1IgOElcHazmcj+m/uTaoCjaGhxB6eg7cZePuQW0iX7Ufcb0YIAHczY1d+ZfCe5wTuSYnbdJGwoor7", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ]
      }
    ]
  }, 
  "urn:ibistic:prod:services.ibistic.net": {
    "valid_until": "2012-12-19T20:17:02Z", 
    "entity_id": "urn:ibistic:prod:services.ibistic.net", 
    "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EntityDescriptor", 
    "spsso_descriptor": [
      {
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "assertion_consumer_service": [
          {
            "index": "0", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://services.ibistic.net/redirector/saml/post/ac"
          }
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SPSSODescriptor", 
        "name_id_format": [
          {
            "text": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }
        ], 
        "attribute_consuming_service": [
          {
            "index": "0", 
            "service_description": [
              {
                "lang": "en", 
                "text": "to handle and approve supplier invoices in a web-based solution", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }, 
              {
                "lang": "da", 
                "text": "at h\u00e5ndtere og godkende leverand\u00f8rfakturarer i en webbaseret l\u00f8sning", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }
            ], 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AttributeConsumingService", 
            "requested_attribute": [
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.42"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.4"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:0.9.2342.19200300.100.1.3"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.25178.1.2.9"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.10"
              }
            ], 
            "service_name": [
              {
                "lang": "en", 
                "text": "Ibistic Services", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }, 
              {
                "lang": "da", 
                "text": "Ibistic Services", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }
            ]
          }
        ], 
        "key_descriptor": [
          {
            "use": "signing", 
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIHPDCCBiSgAwIBAgIQBqroOeZGXLtbM/pxpybmVDANBgkqhkiG9w0BAQUFADBpMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSgwJgYDVQQDEx9EaWdpQ2VydCBIaWdoIEFzc3VyYW5jZSBFViBDQS0xMB4XDTExMDIwNzAwMDAwMFoXDTEzMDQyNTIzNTk1OVowgeIxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRMwEQYLKwYBBAGCNzwCAQMTAkRLMREwDwYDVQQFEwgyNzc2ODM5MzELMAkGA1UEBhMCREsxFDASBgNVBAgTC0hvdmVkc3RhZGVuMRcwFQYDVQQHEw5Lb25nZW5zIEx5bmdieTEpMCcGA1UEChMgSUJJU1RJQyBURUNITk9MT0dJRVMgREVOTUFSSyBBL1MxEzARBgNVBAsTCk9wZXJhdGlvbnMxHTAbBgNVBAMTFHNlcnZpY2VzLmliaXN0aWMubmV0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArewM8dSQqpWoBWgFQa4P5vQ53fWsYLyJNkPsVmOf3YBE4XjCHhm0jgJkSE4vgcLmolaPHxkxYwyfRif11bpkcxtWN2QQwqNJjZcgfin8kYiImRu1Y+dDW/BQUsmkUgNgo+ualWDtP8Rx0BTm81BzJYDUUPzeyGhwDKY2urHpJFCp83eChopbCb7L7ITjKoQNv6Ak+1vkrWhugJBUyS+1o7fnWYbXSmQCBztlZ2rzcXojYiI5vP0OQ6wrJ7sWXCusdvDNpXzK/CdmzTNLjKEl3Ofmd+tQC001NH62DvvukyirESjc4AvlCaymEXVLJL8LrsBFdzxGTjPjBJz2kcbLGwIDAQABo4IDZDCCA2AwHwYDVR0jBBgwFoAUTFjLJfBBT1L0KMiBQ5umqKDmkuUwHQYDVR0OBBYEFO3n6sj7ezQ9K5XEsjB3hZnMpHu3MB8GA1UdEQQYMBaCFHNlcnZpY2VzLmliaXN0aWMubmV0MIGBBggrBgEFBQcBAQR1MHMwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBLBggrBgEFBQcwAoY/aHR0cDovL3d3dy5kaWdpY2VydC5jb20vQ0FDZXJ0cy9EaWdpQ2VydEhpZ2hBc3N1cmFuY2VFVkNBLTEuY3J0MAwGA1UdEwEB/wQCMAAwYQYDVR0fBFowWDAqoCigJoYkaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL2V2MjAwOWEuY3JsMCqgKKAmhiRodHRwOi8vY3JsNC5kaWdpY2VydC5jb20vZXYyMDA5YS5jcmwwggHEBgNVHSAEggG7MIIBtzCCAbMGCWCGSAGG/WwCATCCAaQwOgYIKwYBBQUHAgEWLmh0dHA6Ly93d3cuZGlnaWNlcnQuY29tL3NzbC1jcHMtcmVwb3NpdG9yeS5odG0wggFkBggrBgEFBQcCAjCCAVYeggFSAEEAbgB5ACAAdQBzAGUAIABvAGYAIAB0AGgAaQBzACAAQwBlAHIAdABpAGYAaQBjAGEAdABlACAAYwBvAG4AcwB0AGkAdAB1AHQAZQBzACAAYQBjAGMAZQBwAHQAYQBuAGMAZQAgAG8AZgAgAHQAaABlACAARABpAGcAaQBDAGUAcgB0ACAAQwBQAC8AQwBQAFMAIABhAG4AZAAgAHQAaABlACAAUgBlAGwAeQBpAG4AZwAgAFAAYQByAHQAeQAgAEEAZwByAGUAZQBtAGUAbgB0ACAAdwBoAGkAYwBoACAAbABpAG0AaQB0ACAAbABpAGEAYgBpAGwAaQB0AHkAIABhAG4AZAAgAGEAcgBlACAAaQBuAGMAbwByAHAAbwByAGEAdABlAGQAIABoAGUAcgBlAGkAbgAgAGIAeQAgAHIAZQBmAGUAcgBlAG4AYwBlAC4wHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMBEGCWCGSAGG+EIBAQQEAwIGwDAOBgNVHQ8BAf8EBAMCBaAwDQYJKoZIhvcNAQEFBQADggEBAHddJRU33qaEDpYuogJ3H4bMQ+LhMwaCKxpH0W/BPbplL9hPzPByJqaM216LH4npiTsnWVrzQ7SWVl6J6yVHgLLctekigjBjz0JNk6UB3skVZsfMhK1GyD6r4SspuPY7RU6ejEbm/1rlB4haDvr0Yd56zRSKP/OUf8P0wTqPOk4V55OUH0vMmnDH7VlaswRtZZBeai3q/3BeZiuQEvrs6ZZBo6UbVWUzRbxvlRAAkRm+cKR6RA0FHIzmjKD36SLQhyMAgE9PFPLwu52LgsYR9Fq0qzHxTQ5rLN7OWz7RSonda1UPkjp5qGdit3M4a/T6t9hLFXcmA6kmL8hq13l0tUw=", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }, 
          {
            "use": "encryption", 
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIHPDCCBiSgAwIBAgIQBqroOeZGXLtbM/pxpybmVDANBgkqhkiG9w0BAQUFADBpMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSgwJgYDVQQDEx9EaWdpQ2VydCBIaWdoIEFzc3VyYW5jZSBFViBDQS0xMB4XDTExMDIwNzAwMDAwMFoXDTEzMDQyNTIzNTk1OVowgeIxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRMwEQYLKwYBBAGCNzwCAQMTAkRLMREwDwYDVQQFEwgyNzc2ODM5MzELMAkGA1UEBhMCREsxFDASBgNVBAgTC0hvdmVkc3RhZGVuMRcwFQYDVQQHEw5Lb25nZW5zIEx5bmdieTEpMCcGA1UEChMgSUJJU1RJQyBURUNITk9MT0dJRVMgREVOTUFSSyBBL1MxEzARBgNVBAsTCk9wZXJhdGlvbnMxHTAbBgNVBAMTFHNlcnZpY2VzLmliaXN0aWMubmV0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArewM8dSQqpWoBWgFQa4P5vQ53fWsYLyJNkPsVmOf3YBE4XjCHhm0jgJkSE4vgcLmolaPHxkxYwyfRif11bpkcxtWN2QQwqNJjZcgfin8kYiImRu1Y+dDW/BQUsmkUgNgo+ualWDtP8Rx0BTm81BzJYDUUPzeyGhwDKY2urHpJFCp83eChopbCb7L7ITjKoQNv6Ak+1vkrWhugJBUyS+1o7fnWYbXSmQCBztlZ2rzcXojYiI5vP0OQ6wrJ7sWXCusdvDNpXzK/CdmzTNLjKEl3Ofmd+tQC001NH62DvvukyirESjc4AvlCaymEXVLJL8LrsBFdzxGTjPjBJz2kcbLGwIDAQABo4IDZDCCA2AwHwYDVR0jBBgwFoAUTFjLJfBBT1L0KMiBQ5umqKDmkuUwHQYDVR0OBBYEFO3n6sj7ezQ9K5XEsjB3hZnMpHu3MB8GA1UdEQQYMBaCFHNlcnZpY2VzLmliaXN0aWMubmV0MIGBBggrBgEFBQcBAQR1MHMwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBLBggrBgEFBQcwAoY/aHR0cDovL3d3dy5kaWdpY2VydC5jb20vQ0FDZXJ0cy9EaWdpQ2VydEhpZ2hBc3N1cmFuY2VFVkNBLTEuY3J0MAwGA1UdEwEB/wQCMAAwYQYDVR0fBFowWDAqoCigJoYkaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL2V2MjAwOWEuY3JsMCqgKKAmhiRodHRwOi8vY3JsNC5kaWdpY2VydC5jb20vZXYyMDA5YS5jcmwwggHEBgNVHSAEggG7MIIBtzCCAbMGCWCGSAGG/WwCATCCAaQwOgYIKwYBBQUHAgEWLmh0dHA6Ly93d3cuZGlnaWNlcnQuY29tL3NzbC1jcHMtcmVwb3NpdG9yeS5odG0wggFkBggrBgEFBQcCAjCCAVYeggFSAEEAbgB5ACAAdQBzAGUAIABvAGYAIAB0AGgAaQBzACAAQwBlAHIAdABpAGYAaQBjAGEAdABlACAAYwBvAG4AcwB0AGkAdAB1AHQAZQBzACAAYQBjAGMAZQBwAHQAYQBuAGMAZQAgAG8AZgAgAHQAaABlACAARABpAGcAaQBDAGUAcgB0ACAAQwBQAC8AQwBQAFMAIABhAG4AZAAgAHQAaABlACAAUgBlAGwAeQBpAG4AZwAgAFAAYQByAHQAeQAgAEEAZwByAGUAZQBtAGUAbgB0ACAAdwBoAGkAYwBoACAAbABpAG0AaQB0ACAAbABpAGEAYgBpAGwAaQB0AHkAIABhAG4AZAAgAGEAcgBlACAAaQBuAGMAbwByAHAAbwByAGEAdABlAGQAIABoAGUAcgBlAGkAbgAgAGIAeQAgAHIAZQBmAGUAcgBlAG4AYwBlAC4wHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMBEGCWCGSAGG+EIBAQQEAwIGwDAOBgNVHQ8BAf8EBAMCBaAwDQYJKoZIhvcNAQEFBQADggEBAHddJRU33qaEDpYuogJ3H4bMQ+LhMwaCKxpH0W/BPbplL9hPzPByJqaM216LH4npiTsnWVrzQ7SWVl6J6yVHgLLctekigjBjz0JNk6UB3skVZsfMhK1GyD6r4SspuPY7RU6ejEbm/1rlB4haDvr0Yd56zRSKP/OUf8P0wTqPOk4V55OUH0vMmnDH7VlaswRtZZBeai3q/3BeZiuQEvrs6ZZBo6UbVWUzRbxvlRAAkRm+cKR6RA0FHIzmjKD36SLQhyMAgE9PFPLwu52LgsYR9Fq0qzHxTQ5rLN7OWz7RSonda1UPkjp5qGdit3M4a/T6t9hLFXcmA6kmL8hq13l0tUw=", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ]
      }
    ], 
    "cache_duration": "PT345600S"
  }, 
  "https://idp.abo.fi/idp/shibboleth": {
    "valid_until": "2012-12-19T20:15:01Z", 
    "entity_id": "https://idp.abo.fi/idp/shibboleth", 
    "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EntityDescriptor", 
    "idpsso_descriptor": [
      {
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&IDPSSODescriptor", 
        "single_sign_on_service": [
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleSignOnService", 
            "location": "https://idp.abo.fi/idp/profile/SAML2/Redirect/SSO"
          }
        ], 
        "extensions": {
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Extensions", 
          "extension_elements": [
            {
              "attribute_value": [
                {
                  "text": "kalmar", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }, 
                {
                  "text": "finland", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }
              ], 
              "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&Attribute", 
              "name": "tags"
            }
          ]
        }, 
        "key_descriptor": [
          {
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIE0zCCA7ugAwIBAgIQEHWkYlOQvbuzDURupLTuqDANBgkqhkiG9w0BAQUFADA2\nMQswCQYDVQQGEwJOTDEPMA0GA1UEChMGVEVSRU5BMRYwFAYDVQQDEw1URVJFTkEg\nU1NMIENBMB4XDTEwMDQyNzAwMDAwMFoXDTEzMDQyNjIzNTk1OVowgbMxCzAJBgNV\nBAYTAkZJMQ4wDAYDVQQREwUyMDUwMDEYMBYGA1UECBMPV2VzdGVybiBGaW5sYW5k\nMQ4wDAYDVQQHEwVUdXJrdTEZMBcGA1UECRMQVmFucmlraW5rYXR1IDMgQjEfMB0G\nA1UEChMWQWJvIEFrYWRlbWkgVW5pdmVyc2l0eTEZMBcGA1UECxMQQ29tcHV0aW5n\nIENlbnRyZTETMBEGA1UEAxMKaWRwLmFiby5maTCCASIwDQYJKoZIhvcNAQEBBQAD\nggEPADCCAQoCggEBAO5UWgT90vXzUDlkapH5CVGFvoVgNDWxVr7WhrH+z2moP5h1\nwkK/Dnr0CKsglVyNkHycNkLmNH/9CVynp6LNsl+CEli5BmskLGNAvc+Q9bQwV52O\nJZQnXeCDDYSwSgDiIgrrml8niocBehGJEORCKW51UErjEf6U//1VfW1vG2r3Bydj\nqM7pqs2GZx9p/US7F6lds8La1Vf/jp1ErW6Gg1TzHYkx56EYNpqjo2Uin2vHowhi\ndM37grjJQJ+q2qb7JsS4t074EwEQA0fF4wKaYv6coSZyOpPXuuDLDlp3/dfY+beq\nR2oRml3HMvPnSp8+x/4y3/zEkcXcksmlwVCGLBUCAwEAAaOCAV0wggFZMB8GA1Ud\nIwQYMBaAFAy9k2gM896ro0lrKzdXR+qQ47ntMB0GA1UdDgQWBBT6OoUGpLGH7zyi\nXK+pmGrcVKeRnDAOBgNVHQ8BAf8EBAMCBaAwDAYDVR0TAQH/BAIwADAdBgNVHSUE\nFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwGAYDVR0gBBEwDzANBgsrBgEEAbIxAQIC\nHTA6BgNVHR8EMzAxMC+gLaArhilodHRwOi8vY3JsLnRjcy50ZXJlbmEub3JnL1RF\nUkVOQVNTTENBLmNybDBtBggrBgEFBQcBAQRhMF8wNQYIKwYBBQUHMAKGKWh0dHA6\nLy9jcnQudGNzLnRlcmVuYS5vcmcvVEVSRU5BU1NMQ0EuY3J0MCYGCCsGAQUFBzAB\nhhpodHRwOi8vb2NzcC50Y3MudGVyZW5hLm9yZzAVBgNVHREEDjAMggppZHAuYWJv\nLmZpMA0GCSqGSIb3DQEBBQUAA4IBAQBgW2khV9OYQg+E+6dyRWCa5mHp2YExMMLK\n2wSUlgYhglyqHVu1Lu6K58Lm6taKQI0r5+TisO8dUJDh3YwAa8EaUU4NGcfNjf0Y\nFgxaXpOcPvCafcJKOF+CnOFr8efQLCWFbqxZ7q5IUi5wD1kNcbHnwd7hs/ziLPcC\nEik6jao8iEFjp8+F64vFURqoPwl7PM4+KGuUPIWTcYt54hxaE8MwwJkH6Om/La6i\ncrcRaMgj+lqqWg8H8tJzrc3UvSL3vhbhIUcWYUjAtSvuS2sFtWeQFO5G0ETuNNUJ\nc1VLPrddhPOAvbbcdQPiNR6q6I7LkgyAl6KhRBYcWYd7oszFtuik", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ], 
        "name_id_format": [
          {
            "text": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }
        ]
      }
    ], 
    "organization": {
      "organization_name": [
        {
          "lang": "fi", 
          "text": "Abo Akademi", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }, 
        {
          "lang": "en", 
          "text": "Abo Akademi University", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }, 
        {
          "lang": "sv", 
          "text": "Abo Akademi", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }
      ], 
      "organization_display_name": [
        {
          "lang": "fi", 
          "text": "Abo Akademi", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }, 
        {
          "lang": "en", 
          "text": "Abo Akademi University", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }, 
        {
          "lang": "sv", 
          "text": "Abo Akademi", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }
      ], 
      "organization_url": [
        {
          "lang": "fi", 
          "text": "http://www.abo.fi", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }, 
        {
          "lang": "en", 
          "text": "http://www.abo.fi", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }, 
        {
          "lang": "sv", 
          "text": "http://www.abo.fi", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }
      ], 
      "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Organization"
    }, 
    "contact_person": [
      {
        "given_name": {
          "text": "Barbro", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&GivenName"
        }, 
        "email_address": [
          {
            "text": "haka@abo.fi", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ], 
        "sur_name": {
          "text": "Sjoblom", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SurName"
        }, 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "contact_type": "administrative"
      }, 
      {
        "given_name": {
          "text": "Dennis", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&GivenName"
        }, 
        "email_address": [
          {
            "text": "haka@abo.fi", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ], 
        "sur_name": {
          "text": "Holtlund", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SurName"
        }, 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "contact_type": "technical"
      }, 
      {
        "given_name": {
          "text": "Barbro", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&GivenName"
        }, 
        "email_address": [
          {
            "text": "haka@abo.fi", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ], 
        "sur_name": {
          "text": "Sjoblom", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SurName"
        }, 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "contact_type": "technical"
      }, 
      {
        "given_name": {
          "text": "Barbro", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&GivenName"
        }, 
        "email_address": [
          {
            "text": "haka@abo.fi", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ], 
        "sur_name": {
          "text": "Sjoblom", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SurName"
        }, 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "contact_type": "support"
      }
    ]
  }, 
  "https://idp.shh.fi/idp/shibboleth": {
    "valid_until": "2012-12-19T20:15:01Z", 
    "entity_id": "https://idp.shh.fi/idp/shibboleth", 
    "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EntityDescriptor", 
    "idpsso_descriptor": [
      {
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&IDPSSODescriptor", 
        "single_sign_on_service": [
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleSignOnService", 
            "location": "https://idp.shh.fi/idp/profile/SAML2/Redirect/SSO"
          }
        ], 
        "extensions": {
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Extensions", 
          "extension_elements": [
            {
              "attribute_value": [
                {
                  "text": "kalmar", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }, 
                {
                  "text": "finland", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }
              ], 
              "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&Attribute", 
              "name": "tags"
            }
          ]
        }, 
        "key_descriptor": [
          {
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIEzTCCA7WgAwIBAgIQK949tWfXb8PXIyPj420VwjANBgkqhkiG9w0BAQUFADA2\nMQswCQYDVQQGEwJOTDEPMA0GA1UEChMGVEVSRU5BMRYwFAYDVQQDEw1URVJFTkEg\nU1NMIENBMB4XDTEwMTExNTAwMDAwMFoXDTEzMTExNDIzNTk1OVowga0xCzAJBgNV\nBAYTAkZJMQ4wDAYDVQQREwUwMDEwMTEPMA0GA1UECBMGTnlsYW5kMRQwEgYDVQQH\nEwtIZWxzaW5nZm9yczEYMBYGA1UECRMPQXJrYWRpYWdhdGFuIDIyMSowKAYDVQQK\nEyFIQU5LRU4gLSBTdmVuc2thIGhhbmRlbHNob2dza29sYW4xDDAKBgNVBAsTA1NE\nQzETMBEGA1UEAxMKaWRwLnNoaC5maTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC\nAQoCggEBAM2k+mkqzcw+iee9ADHbh3ESyUovAphz6JrMWlsuqV4Fe8paTwZvmH7w\ncbcqcB6pHPPP5ZeGg2MJ5ySsXGCZt1y54s1x7eXlC/gW0idpi1g4b405HK72VzRU\n0nM9lmN8MXDWNp0PL+2WlcYqEkFG66eoij/uvAZ6R/rlv9Yqp+5YODT7rnK+8+Ad\nAiI/HHhvRWnpZ3JmKEUFRQMGEBdCfl5uVLteTwgXJE2RwXsZM8ssdWueVnz+7soo\nK0cRcGlZBTV4i/sxrN/RYcY8ml3YIMEa+Y/M2f7zaNYmlZ0Z7r4y4YS8lxL2kDM8\nX+bX/I1KxrhMPqa3LHyaylBIHwnhCUECAwEAAaOCAV0wggFZMB8GA1UdIwQYMBaA\nFAy9k2gM896ro0lrKzdXR+qQ47ntMB0GA1UdDgQWBBT4iC98qz60jdzy0FsZMKM5\nD5JpSTAOBgNVHQ8BAf8EBAMCBaAwDAYDVR0TAQH/BAIwADAdBgNVHSUEFjAUBggr\nBgEFBQcDAQYIKwYBBQUHAwIwGAYDVR0gBBEwDzANBgsrBgEEAbIxAQICHTA6BgNV\nHR8EMzAxMC+gLaArhilodHRwOi8vY3JsLnRjcy50ZXJlbmEub3JnL1RFUkVOQVNT\nTENBLmNybDBtBggrBgEFBQcBAQRhMF8wNQYIKwYBBQUHMAKGKWh0dHA6Ly9jcnQu\ndGNzLnRlcmVuYS5vcmcvVEVSRU5BU1NMQ0EuY3J0MCYGCCsGAQUFBzABhhpodHRw\nOi8vb2NzcC50Y3MudGVyZW5hLm9yZzAVBgNVHREEDjAMggppZHAuc2hoLmZpMA0G\nCSqGSIb3DQEBBQUAA4IBAQBiii+RMMzxCzPzM72PA2pqUMfwferGXdl+XeH0tkPy\nCd8Ggdj1AXtAevhXNJ62GvULS2m/SQ8hsbulCIqzOYejjCBz2IszmMUbCp2GYEEq\ny1Ck2hM/ChctgGpvMonmgn5mxUnecFH7IapTh7zozifejpMEN0/MM0B7LGs7eTJI\nDHUtc3gzsgtW+kmogclxEEhyxzzdY3RDFKnBuX2HGUNJEI35KVIfYyHgV+32jzW4\n2mxQfWAhJ+al0Ooi00F0heVlhP5sS2bNDkAQLltfNDBRllBTJ+hyoR0JRC3kpEXV\n34aXbnif5+6RosrbfiWc0Sa1n7sgtKgwL+PkxGwYVvvx", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ], 
        "name_id_format": [
          {
            "text": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }
        ]
      }
    ], 
    "organization": {
      "organization_name": [
        {
          "lang": "fi", 
          "text": "Hanken Svenska handelshogskolan", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }, 
        {
          "lang": "en", 
          "text": "Hanken School of Economics", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }, 
        {
          "lang": "sv", 
          "text": "Hanken Svenska handelshogskolan", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }
      ], 
      "organization_display_name": [
        {
          "lang": "fi", 
          "text": "Hanken Svenska handelshogskolan", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }, 
        {
          "lang": "en", 
          "text": "Hanken School of Economics", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }, 
        {
          "lang": "sv", 
          "text": "Hanken Svenska handelshogskolan", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }
      ], 
      "organization_url": [
        {
          "lang": "fi", 
          "text": "http://www.hanken.fi", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }, 
        {
          "lang": "en", 
          "text": "http://www.hanken.fi", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }, 
        {
          "lang": "sv", 
          "text": "http://www.hanken.fi", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }
      ], 
      "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Organization"
    }, 
    "contact_person": [
      {
        "given_name": {
          "text": "Kuno", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&GivenName"
        }, 
        "email_address": [
          {
            "text": "shibboservice@hanken.fi", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ], 
        "sur_name": {
          "text": "Ohrman", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SurName"
        }, 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "contact_type": "administrative"
      }, 
      {
        "given_name": {
          "text": "Johan", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&GivenName"
        }, 
        "email_address": [
          {
            "text": "shibboservice@hanken.fi", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ], 
        "sur_name": {
          "text": "Isaksson", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SurName"
        }, 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "contact_type": "technical"
      }, 
      {
        "given_name": {
          "text": "Hanken", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&GivenName"
        }, 
        "email_address": [
          {
            "text": "help@hanken.fi", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ], 
        "sur_name": {
          "text": "Helpdesk", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SurName"
        }, 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "contact_type": "support"
      }
    ]
  }, 
  "https://moodle.helsinki.fi/shibboleth": {
    "valid_until": "2012-12-19T20:15:01Z", 
    "entity_id": "https://moodle.helsinki.fi/shibboleth", 
    "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EntityDescriptor", 
    "organization": {
      "organization_name": [
        {
          "lang": "fi", 
          "text": "Helsingin yliopisto", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }, 
        {
          "lang": "en", 
          "text": "University of Helsinki", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }, 
        {
          "lang": "sv", 
          "text": "Helsingfors universitet", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }
      ], 
      "organization_display_name": [
        {
          "lang": "fi", 
          "text": "Helsingin yliopisto", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }, 
        {
          "lang": "en", 
          "text": "University of Helsinki", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }, 
        {
          "lang": "sv", 
          "text": "Helsingfors universitet", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }
      ], 
      "organization_url": [
        {
          "lang": "fi", 
          "text": "http://www.helsinki.fi/yliopisto/", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }, 
        {
          "lang": "en", 
          "text": "http://www.helsinki.fi/yliopisto/", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }, 
        {
          "lang": "sv", 
          "text": "http://www.helsinki.fi/yliopisto/", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }
      ], 
      "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Organization"
    }, 
    "contact_person": [
      {
        "given_name": {
          "text": "Heiko", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&GivenName"
        }, 
        "email_address": [
          {
            "text": "heiko.schach@helsinki.fi", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ], 
        "sur_name": {
          "text": "Schach", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SurName"
        }, 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "contact_type": "administrative"
      }, 
      {
        "given_name": {
          "text": "Olli", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&GivenName"
        }, 
        "email_address": [
          {
            "text": "haka-hy@helsinki.fi", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ], 
        "sur_name": {
          "text": "Saikko", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SurName"
        }, 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "contact_type": "technical"
      }, 
      {
        "given_name": {
          "text": "Aarno", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&GivenName"
        }, 
        "email_address": [
          {
            "text": "haka-hy@helsinki.fi", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ], 
        "sur_name": {
          "text": "Sandvik", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SurName"
        }, 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "contact_type": "technical"
      }
    ], 
    "spsso_descriptor": [
      {
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "assertion_consumer_service": [
          {
            "is_default": "true", 
            "index": "1", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://moodle.helsinki.fi/Shibboleth.sso/SAML2/POST"
          }, 
          {
            "is_default": "false", 
            "index": "2", 
            "binding": "urn:oasis:names:tc:SAML:1.0:profiles:browser-post", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://moodle.helsinki.fi/Shibboleth.sso/SAML/POST"
          }
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SPSSODescriptor", 
        "extensions": {
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Extensions", 
          "extension_elements": [
            {
              "index": "1", 
              "binding": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol", 
              "__class__": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol&DiscoveryResponse", 
              "location": "https://moodle.helsinki.fi/Shibboleth.sso/HAKALogin"
            }, 
            {
              "attribute_value": [
                {
                  "text": "kalmar", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }, 
                {
                  "text": "finland", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }
              ], 
              "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&Attribute", 
              "name": "tags"
            }
          ]
        }, 
        "name_id_format": [
          {
            "text": "urn:mace:shibboleth:1.0:nameIdentifier", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }, 
          {
            "text": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }
        ], 
        "attribute_consuming_service": [
          {
            "index": "1", 
            "service_name": [
              {
                "lang": "fi", 
                "text": "Helsingin yliopiston Moodle", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }, 
              {
                "lang": "en", 
                "text": "Helsinki University's Moodle", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }
            ], 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AttributeConsumingService", 
            "is_default": "true", 
            "requested_attribute": [
              {
                "friendly_name": "cn", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.3"
              }, 
              {
                "friendly_name": "displayName", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.16.840.1.113730.3.1.241"
              }, 
              {
                "friendly_name": "eduPersonPrincipalName", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
              }, 
              {
                "friendly_name": "mail", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:0.9.2342.19200300.100.1.3"
              }, 
              {
                "friendly_name": "schacPersonalUniqueCode", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.25178.1.2.14"
              }, 
              {
                "friendly_name": "sn", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.4"
              }
            ], 
            "service_description": [
              {
                "lang": "fi", 
                "text": "Helsingin yliopiston Moodle-oppimisalusta.", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }, 
              {
                "lang": "en", 
                "text": "University of Helsinki's Moodle learning management system.", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }
            ]
          }
        ], 
        "key_descriptor": [
          {
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIEMjCCAxqgAwIBAgIQb6ERXxpBr1wj7QJL1uUSrzANBgkqhkiG9w0BAQUFADA5\nMQswCQYDVQQGEwJGSTEPMA0GA1UEChMGU29uZXJhMRkwFwYDVQQDExBTb25lcmEg\nQ2xhc3MyIENBMB4XDTA5MDUyOTEyMDkxNloXDTExMDUyOTEyMDkxNlowgYgxCzAJ\nBgNVBAYTAkZJMRAwDgYDVQQIEwdVdXNpbWFhMREwDwYDVQQHEwhIZWxzaW5raTEf\nMB0GA1UEChMWVW5pdmVyc2l0eSBvZiBIZWxzaW5raTEWMBQGA1UECxMNSVQgRGVw\nYXJ0bWVudDEbMBkGA1UEAxMSbW9vZGxlLmhlbHNpbmtpLmZpMIIBIjANBgkqhkiG\n9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmOryQRNC8eih0bzShoavhAniRXeQNOPUXgNQ\nDf1e9OHAKe7yfJy3uRs+P9DQ6uBB+uRW4nEVL5/iVxOolMm8UX2vE9HlRGBylXQO\nt7W2zmSN7GcgPX40McZA3CIByg/wyRjZ/CSM2kowaUlX6m7MIDvaks5dY9jfEYQ4\nIarokwEGhV51qeU3bOQw790QhdTpf9nPC1sSpj0LISjR/uuRPgG9ZB2Vf5D2uAVc\nh60KiqROyqbNNHLFm7PjiMtobINgJy0yUpop4StiEMoP8VVcIKU1Ig4G3uo9bXug\nUdrUTXrQMYXa3psO6TsgyjzQfJkAZCV7hJVxujc9lb3nOELg3wIDAQABo4HlMIHi\nMBMGA1UdIwQMMAqACEqgqliE0148MBkGA1UdIAQSMBAwDgYMKwYBBAGCDwIDAQEC\nMHIGA1UdHwRrMGkwZ6BloGOGYWxkYXA6Ly8xOTQuMjUyLjEyNC4yNDE6Mzg5L2Nu\nPVNvbmVyYSUyMENsYXNzMiUyMENBLG89U29uZXJhLGM9Rkk/Y2VydGlmaWNhdGVy\nZXZvY2F0aW9ubGlzdDtiaW5hcnkwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUF\nBwMCMB0GA1UdDgQWBBTvFlhigSEeZTzx/wuEW9BtEUhooTANBgkqhkiG9w0BAQUF\nAAOCAQEAORCb2tsrCK1HxtpFJjaappUFF60qwhVfCbDhitAxVBv3QujonxvNYEuD\nfawKUU4+z6TDe4ddilrErHEFFzSkkeqk3Yw2dyVUD8PpHNaH7hMiPY1A+D9bSOr6\nWhEXPp7F3Cfl7LFWHo461B9juza/Q3p6dNYoil9hfCfo4SvrW49xljsD+E4hKdHD\nAK7B+7VrvQ4yDoNERJ2Jnp34wUGj7VaNb4dwWW23mhkFLfkZC03v0K17QX+lgErk\n1+Ve7tz+Ew8PD/pcxCgTG889iQl0+LREQuqPbplvx/xEQFR5oHwfO9h6AlYmmROw\nvyAaHRvOgS1o4x1UPp8JoqYpWm/T9Q==", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ]
      }
    ]
  }, 
  "urn:mace:feide.no:services:com.itslearning.test": {
    "valid_until": "2012-12-19T20:14:03Z", 
    "entity_id": "urn:mace:feide.no:services:com.itslearning.test", 
    "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EntityDescriptor", 
    "spsso_descriptor": [
      {
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "assertion_consumer_service": [
          {
            "index": "0", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://test.itslearning.com/elogin/default.aspx"
          }
        ], 
        "single_logout_service": [
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleLogoutService", 
            "location": "https://test.itslearning.com/elogin/logout.aspx"
          }
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SPSSODescriptor", 
        "attribute_consuming_service": [
          {
            "index": "0", 
            "service_description": [
              {
                "lang": "en", 
                "text": "itslearning is a virtual learning environment specifically designed for schools and universities.", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }, 
              {
                "lang": "no", 
                "text": "itslearning er et virtuelt l\u00e6ringsmilj\u00f8, spesielt utformet for skoler og universiteter.", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }
            ], 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AttributeConsumingService", 
            "requested_attribute": [
              {
                "friendly_name": "eduPersonPrincipalName", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
              }
            ], 
            "service_name": [
              {
                "lang": "en", 
                "text": "itslearning", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }
            ]
          }
        ]
      }
    ]
  }, 
  "https://mailfilter.nordu.net/shibboleth": {
    "valid_until": "2012-12-16T04:23:08Z", 
    "organization": {
      "organization_name": [
        {
          "lang": "en", 
          "text": "NORDUnet", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }
      ], 
      "organization_display_name": [
        {
          "lang": "en", 
          "text": "NORDUnet A/S", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }
      ], 
      "organization_url": [
        {
          "lang": "en", 
          "text": "http://www.nordu.net", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }
      ], 
      "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Organization"
    }, 
    "entity_id": "https://mailfilter.nordu.net/shibboleth", 
    "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EntityDescriptor", 
    "spsso_descriptor": [
      {
        "single_logout_service": [
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:SOAP", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleLogoutService", 
            "location": "https://mailfilter.nordu.net/Shibboleth.sso/SLO/SOAP"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleLogoutService", 
            "location": "https://mailfilter.nordu.net/Shibboleth.sso/SLO/Redirect"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleLogoutService", 
            "location": "https://mailfilter.nordu.net/Shibboleth.sso/SLO/POST"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleLogoutService", 
            "location": "https://mailfilter.nordu.net/Shibboleth.sso/SLO/Artifact"
          }
        ], 
        "attribute_consuming_service": [
          {
            "index": "0", 
            "service_description": [
              {
                "lang": "en", 
                "text": "SUNET Mailfilter Service", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }
            ], 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AttributeConsumingService", 
            "requested_attribute": [
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:0.9.2342.19200300.100.1.3"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.42"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
              }
            ], 
            "service_name": [
              {
                "lang": "en", 
                "text": "SUNET Mailfilter Service", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }
            ]
          }
        ], 
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "assertion_consumer_service": [
          {
            "index": "1", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://mailfilter.nordu.net/Shibboleth.sso/SAML2/POST"
          }, 
          {
            "index": "2", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://mailfilter.nordu.net/Shibboleth.sso/SAML2/POST-SimpleSign"
          }, 
          {
            "index": "3", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://mailfilter.nordu.net/Shibboleth.sso/SAML2/Artifact"
          }, 
          {
            "index": "4", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:PAOS", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://mailfilter.nordu.net/Shibboleth.sso/SAML2/ECP"
          }, 
          {
            "index": "5", 
            "binding": "urn:oasis:names:tc:SAML:1.0:profiles:browser-post", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://mailfilter.nordu.net/Shibboleth.sso/SAML/POST"
          }, 
          {
            "index": "6", 
            "binding": "urn:oasis:names:tc:SAML:1.0:profiles:artifact-01", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://mailfilter.nordu.net/Shibboleth.sso/SAML/Artifact"
          }
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SPSSODescriptor", 
        "extensions": {
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Extensions", 
          "extension_elements": [
            {
              "index": "1", 
              "binding": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol", 
              "__class__": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol&DiscoveryResponse", 
              "location": "https://mailfilter.nordu.net/Shibboleth.sso/DS/ds.sunet.se"
            }, 
            {
              "index": "2", 
              "binding": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol", 
              "__class__": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol&DiscoveryResponse", 
              "location": "https://mailfilter.nordu.net/Shibboleth.sso/DS/ds.swamid.se"
            }, 
            {
              "attribute_value": [
                {
                  "text": "kalmar", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }, 
                {
                  "text": "sweden", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }
              ], 
              "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&Attribute", 
              "name": "tags"
            }
          ]
        }, 
        "key_descriptor": [
          {
            "use": "signing", 
            "key_info": {
              "key_name": [
                {
                  "text": "mailfilter.sunet.se", 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyName"
                }
              ], 
              "x509_data": [
                {
                  "x509_subject_name": {
                    "text": "CN=mailfilter.sunet.se", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509SubjectName"
                  }, 
                  "x509_certificate": {
                    "text": "MIIDADCCAeigAwIBAgIJAJ5oV5rQ7B3hMA0GCSqGSIb3DQEBBQUAMB4xHDAaBgNV\nBAMTE21haWxmaWx0ZXIuc3VuZXQuc2UwHhcNMTAwODI2MTk0NDIyWhcNMjAwODIz\nMTk0NDIyWjAeMRwwGgYDVQQDExNtYWlsZmlsdGVyLnN1bmV0LnNlMIIBIjANBgkq\nhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuwGz7eWqtVCW3Be28I+IPpODVQDPQIwi\nchEFFSJdlkF7c9XN806yVAaGvsOrnNaFUTM5h/Gc4Hak1A0puoLI1aMkyeA0sMWb\nMi6owbVDrjXGoD4gAoC9AIhqfj0NtE8zGlbGsL0dezM68NJwIt2C30U1rzOfUS53\nrngSTvleQK0lnd8I2Sys+msN6kP+4N64A3IBg6A2AVZtaadB6fJIoxQrQOhU3N1U\nAfaK8TcLaclVC5PfiwuJuiSLM0RgMy68B0Fht0V6lUpdiBoF5nU4sKAVYjZz+ZHo\npi6sntIe+FchSvmDXf7zqqLS/NQiM+bD65T/nvazAbtBIbKmWb817wIDAQABo0Ew\nPzAeBgNVHREEFzAVghNtYWlsZmlsdGVyLnN1bmV0LnNlMB0GA1UdDgQWBBQ+3/bs\nSg4SKO4FCGqYge9BF2au7TANBgkqhkiG9w0BAQUFAAOCAQEAVxV3i2vePzZeSjyy\n/i7KiU62byrG6YVBpUnmuofRuNtrC0pvnEMlGYI93pqOuQOe0sw5CEweIIyeTfQ2\n7AlQPA3kiIyvG1mubSJH421oJWXt1GJD/RRH56uJtGUzOykEC350lwcQ3chnQauO\nTJuwybaXhBX3CiHaq2aUt4rLRCiY4q3i2n0x/K5h3YajaI1I/6kSmA/2i6N7kUM3\nywk5dDSfqTd62MTtqC8hJXQj0pQlQ/9GBeoyE83uTSrPR+Fo3bcGPu6WPs3FeQY5\nEeerFHSYV6H0U7y47ZJcBMX2n4xZXMZbTYTlX1AHOYiU3y7I/ZCvSuZScFBK5Lk/\nKHCx/w==", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }, 
          {
            "use": "encryption", 
            "key_info": {
              "key_name": [
                {
                  "text": "mailfilter.sunet.se", 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyName"
                }
              ], 
              "x509_data": [
                {
                  "x509_subject_name": {
                    "text": "CN=mailfilter.sunet.se", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509SubjectName"
                  }, 
                  "x509_certificate": {
                    "text": "MIIDADCCAeigAwIBAgIJAJ5oV5rQ7B3hMA0GCSqGSIb3DQEBBQUAMB4xHDAaBgNV\nBAMTE21haWxmaWx0ZXIuc3VuZXQuc2UwHhcNMTAwODI2MTk0NDIyWhcNMjAwODIz\nMTk0NDIyWjAeMRwwGgYDVQQDExNtYWlsZmlsdGVyLnN1bmV0LnNlMIIBIjANBgkq\nhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuwGz7eWqtVCW3Be28I+IPpODVQDPQIwi\nchEFFSJdlkF7c9XN806yVAaGvsOrnNaFUTM5h/Gc4Hak1A0puoLI1aMkyeA0sMWb\nMi6owbVDrjXGoD4gAoC9AIhqfj0NtE8zGlbGsL0dezM68NJwIt2C30U1rzOfUS53\nrngSTvleQK0lnd8I2Sys+msN6kP+4N64A3IBg6A2AVZtaadB6fJIoxQrQOhU3N1U\nAfaK8TcLaclVC5PfiwuJuiSLM0RgMy68B0Fht0V6lUpdiBoF5nU4sKAVYjZz+ZHo\npi6sntIe+FchSvmDXf7zqqLS/NQiM+bD65T/nvazAbtBIbKmWb817wIDAQABo0Ew\nPzAeBgNVHREEFzAVghNtYWlsZmlsdGVyLnN1bmV0LnNlMB0GA1UdDgQWBBQ+3/bs\nSg4SKO4FCGqYge9BF2au7TANBgkqhkiG9w0BAQUFAAOCAQEAVxV3i2vePzZeSjyy\n/i7KiU62byrG6YVBpUnmuofRuNtrC0pvnEMlGYI93pqOuQOe0sw5CEweIIyeTfQ2\n7AlQPA3kiIyvG1mubSJH421oJWXt1GJD/RRH56uJtGUzOykEC350lwcQ3chnQauO\nTJuwybaXhBX3CiHaq2aUt4rLRCiY4q3i2n0x/K5h3YajaI1I/6kSmA/2i6N7kUM3\nywk5dDSfqTd62MTtqC8hJXQj0pQlQ/9GBeoyE83uTSrPR+Fo3bcGPu6WPs3FeQY5\nEeerFHSYV6H0U7y47ZJcBMX2n4xZXMZbTYTlX1AHOYiU3y7I/ZCvSuZScFBK5Lk/\nKHCx/w==", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ], 
        "artifact_resolution_service": [
          {
            "index": "1", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:SOAP", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ArtifactResolutionService", 
            "location": "https://mailfilter.nordu.net/Shibboleth.sso/Artifact/SOAP"
          }
        ], 
        "manage_name_id_service": [
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:SOAP", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ManageNameIDService", 
            "location": "https://mailfilter.nordu.net/Shibboleth.sso/NIM/SOAP"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ManageNameIDService", 
            "location": "https://mailfilter.nordu.net/Shibboleth.sso/NIM/Redirect"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ManageNameIDService", 
            "location": "https://mailfilter.nordu.net/Shibboleth.sso/NIM/POST"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ManageNameIDService", 
            "location": "https://mailfilter.nordu.net/Shibboleth.sso/NIM/Artifact"
          }
        ]
      }
    ]
  }, 
  "https://weblicht.sfs.uni-tuebingen.de": {
    "valid_until": "2012-12-19T20:15:01Z", 
    "entity_id": "https://weblicht.sfs.uni-tuebingen.de", 
    "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EntityDescriptor", 
    "organization": {
      "organization_name": [
        {
          "lang": "fi", 
          "text": "CLARIN Service Provider Federation/MPI", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }, 
        {
          "lang": "en", 
          "text": "CLARIN Service Provider Federation/MPI", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }, 
        {
          "lang": "sv", 
          "text": "CLARIN Service Provider Federation/MPI", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }
      ], 
      "organization_display_name": [
        {
          "lang": "fi", 
          "text": "CLARIN Service Provider Federation/MPI", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }, 
        {
          "lang": "en", 
          "text": "CLARIN Service Provider Federation/MPI", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }, 
        {
          "lang": "sv", 
          "text": "CLARIN Service Provider Federation/MPI", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }
      ], 
      "organization_url": [
        {
          "lang": "fi", 
          "text": "http://www.clarin.eu", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }, 
        {
          "lang": "en", 
          "text": "http://www.clarin.eu", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }, 
        {
          "lang": "sv", 
          "text": "http://www.clarin.eu", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }
      ], 
      "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Organization"
    }, 
    "contact_person": [
      {
        "given_name": {
          "text": "Thomas", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&GivenName"
        }, 
        "email_address": [
          {
            "text": "thomas.zastrow@uni-tuebingen.de", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ], 
        "sur_name": {
          "text": "Zastrow", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SurName"
        }, 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "contact_type": "technical"
      }, 
      {
        "given_name": {
          "text": "Thomas", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&GivenName"
        }, 
        "email_address": [
          {
            "text": "thomas.zastrow@uni-tuebingen.de", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ], 
        "sur_name": {
          "text": "Zastrow", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SurName"
        }, 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "contact_type": "support"
      }
    ], 
    "spsso_descriptor": [
      {
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "assertion_consumer_service": [
          {
            "is_default": "true", 
            "index": "1", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://weblicht.sfs.uni-tuebingen.de/Shibboleth.sso/SAML2/POST"
          }
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SPSSODescriptor", 
        "extensions": {
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Extensions", 
          "extension_elements": [
            {
              "index": "1", 
              "binding": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol", 
              "__class__": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol&DiscoveryResponse", 
              "location": "https://weblicht.sfs.uni-tuebingen.de/Shibboleth.sso/Login"
            }, 
            {
              "display_name": [
                {
                  "lang": "fi", 
                  "text": "weblicht", 
                  "__class__": "urn:oasis:names:tc:SAML:metadata:ui&DisplayName"
                }
              ], 
              "__class__": "urn:oasis:names:tc:SAML:metadata:ui&UIInfo"
            }, 
            {
              "attribute_value": [
                {
                  "text": "kalmar", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }, 
                {
                  "text": "finland", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }
              ], 
              "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&Attribute", 
              "name": "tags"
            }
          ]
        }, 
        "name_id_format": [
          {
            "text": "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }
        ], 
        "attribute_consuming_service": [
          {
            "index": "1", 
            "service_name": [
              {
                "lang": "fi", 
                "text": "WebLicht", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }, 
              {
                "lang": "en", 
                "text": "WebLicht", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }, 
              {
                "lang": "sv", 
                "text": "WebLicht", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }
            ], 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AttributeConsumingService", 
            "is_default": "true", 
            "requested_attribute": [
              {
                "friendly_name": "schacHomeOrganizationType", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.25178.1.2.10"
              }
            ], 
            "service_description": [
              {
                "lang": "fi", 
                "text": "Web-based linguistic chaining tool.", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }, 
              {
                "lang": "en", 
                "text": "Web-based linguistic chaining tool.", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }, 
              {
                "lang": "sv", 
                "text": "Web-based linguistic chaining tool.", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }
            ]
          }
        ], 
        "key_descriptor": [
          {
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIFpzCCBI+gAwIBAgIED+vXfzANBgkqhkiG9w0BAQUFADB3MQswCQYDVQQGEwJE\nRTEfMB0GA1UEChMWVW5pdmVyc2l0YWV0IFR1ZWJpbmdlbjEcMBoGA1UEAxMTR2xv\nYmFsLVVOSVRVRS1DQSAwMTEpMCcGCSqGSIb3DQEJARYadW5pdHVlLWNhQHVuaS10\ndWViaW5nZW4uZGUwHhcNMTAwNDE5MTMyNjA3WhcNMTUwNDE4MTMyNjA3WjCByzEL\nMAkGA1UEBhMCREUxHzAdBgNVBAoTFlVuaXZlcnNpdGFldCBUdWViaW5nZW4xKDAm\nBgNVBAsTH1NlbWluYXIgZnVlciBTcHJhY2h3aXNzZW5zY2hhZnQxDjAMBgNVBAsT\nBURTUElOMREwDwYDVQQLEwhXZWJMaWNodDEmMCQGA1UEAxMdd2VibGljaHQuc2Zz\nLnVuaS10dWViaW5nZW4uZGUxJjAkBgkqhkiG9w0BCQEWF2VoQHNmcy51bmktdHVl\nYmluZ2VuLmRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnJJ+lISL\nliCGHMdtC5EKdkSPkZIEfGf6u0I2YT+u/bX37XL4yOvmMxJxRLQM4oEvnE67n8k8\n4qe06B8xErFh3KqgC5Q5keUlQmXJu4wvABnk9AuxlwJKuGXI3PetBYfhid10A7Iu\n3Ki0s3j7+7yYTG6xXJt4qrE7rV/v79zBQcoKOwu1AMdfV9q8GRShEXCQ82P4IITT\nQ4z513p1e0mscDdBIunH6aThNCJA9rUBwEVX90HX5KHaOPSksHISylhjl/++XJFy\n/0wBpiZ4+7pN2S/go9J8A153NZSPhF2M5deyWgjT/K2LSudLnegIlRFTq1Kv89eE\nbF/ZaHuNvakbqQIDAQABo4IB5DCCAeAwCQYDVR0TBAIwADALBgNVHQ8EBAMCBeAw\nHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMB0GA1UdDgQWBBRmWkIAb3Vr\nzkTtELxvwSx4nngcUDAfBgNVHSMEGDAWgBSwwbtoNX/i1kGcGnGv4PxBNM3DqDAi\nBgNVHREEGzAZgRdlaEBzZnMudW5pLXR1ZWJpbmdlbi5kZTCBkwYDVR0fBIGLMIGI\nMEKgQKA+hjxodHRwOi8vY2RwMS5wY2EuZGZuLmRlL2NsYXNzaWMtdW5pdHVlLWNh\nL3B1Yi9jcmwvZ19jYWNybC5jcmwwQqBAoD6GPGh0dHA6Ly9jZHAyLnBjYS5kZm4u\nZGUvY2xhc3NpYy11bml0dWUtY2EvcHViL2NybC9nX2NhY3JsLmNybDCBrAYIKwYB\nBQUHAQEEgZ8wgZwwTAYIKwYBBQUHMAKGQGh0dHA6Ly9jZHAxLnBjYS5kZm4uZGUv\nY2xhc3NpYy11bml0dWUtY2EvcHViL2NhY2VydC9nX2NhY2VydC5jcnQwTAYIKwYB\nBQUHMAKGQGh0dHA6Ly9jZHAyLnBjYS5kZm4uZGUvY2xhc3NpYy11bml0dWUtY2Ev\ncHViL2NhY2VydC9nX2NhY2VydC5jcnQwDQYJKoZIhvcNAQEFBQADggEBAGxJyokA\nuUwUFzvszzutQNicSlWWHmrB6g63cRkbgBMsNGFwIyhrizCJtPYTDAbJ1lG2PrYj\nYpbhHR4892JIAm1IkyR4sJvAKXgnzNHtTy1ZTmlP7BjekPb6pcSRWAra84A+bOWY\n+Q3KRITfEcUfsFw/PWYO8qwDurTWGBK3ReWkwLJ9y89XZDXQZt4A9RQnnBvnC7RU\nkLkAmxRV27neEuG8eh0tuFXStHuLbClnNnHaAt1c8m2awjWCWShG5cTR99muSJTc\nNGifdwt0qWax50ASplgOtT/GZAw2E7HEEgbDA+6JcKpVlh+UMnk2JN+nkkKUjgnD\nwN2yHSwHNNMiiGY=", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ]
      }
    ]
  }, 
  "https://rr.funet.fi/attribute-test": {
    "valid_until": "2012-12-19T20:15:01Z", 
    "entity_id": "https://rr.funet.fi/attribute-test", 
    "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EntityDescriptor", 
    "organization": {
      "organization_name": [
        {
          "lang": "fi", 
          "text": "CSC - Tieteen tietotekniikan keskus Oy", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }, 
        {
          "lang": "en", 
          "text": "CSC - IT Center for Science Ltd.", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }, 
        {
          "lang": "sv", 
          "text": "CSC - Tieteen tietotekniikan keskus Oy", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }
      ], 
      "organization_display_name": [
        {
          "lang": "fi", 
          "text": "CSC - Tieteen tietotekniikan keskus Oy", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }, 
        {
          "lang": "en", 
          "text": "CSC - IT Center for Science Ltd.", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }, 
        {
          "lang": "sv", 
          "text": "CSC - Tieteen tietotekniikan keskus Oy", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }
      ], 
      "organization_url": [
        {
          "lang": "fi", 
          "text": "http://www.csc.fi", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }, 
        {
          "lang": "en", 
          "text": "http://www.csc.fi", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }, 
        {
          "lang": "sv", 
          "text": "http://www.csc.fi", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }
      ], 
      "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Organization"
    }, 
    "contact_person": [
      {
        "given_name": {
          "text": "Timo", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&GivenName"
        }, 
        "email_address": [
          {
            "text": "haka@csc.fi", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ], 
        "sur_name": {
          "text": "Mustonen", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SurName"
        }, 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "contact_type": "technical"
      }, 
      {
        "given_name": {
          "text": "Timo", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&GivenName"
        }, 
        "email_address": [
          {
            "text": "haka@csc.fi", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ], 
        "sur_name": {
          "text": "Mustonen", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SurName"
        }, 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "contact_type": "support"
      }
    ], 
    "spsso_descriptor": [
      {
        "single_logout_service": [
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleLogoutService", 
            "location": "https://rr.funet.fi/attribute-test/Shibboleth.sso/SLO/Redirect"
          }
        ], 
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "assertion_consumer_service": [
          {
            "is_default": "true", 
            "index": "1", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://rr.funet.fi/attribute-test/Shibboleth.sso/SAML2/POST"
          }
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SPSSODescriptor", 
        "extensions": {
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Extensions", 
          "extension_elements": [
            {
              "index": "1", 
              "binding": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol", 
              "__class__": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol&DiscoveryResponse", 
              "location": "https://rr.funet.fi/attribute-test/Shibboleth.sso/Login"
            }, 
            {
              "privacy_statement_url": [
                {
                  "lang": "fi", 
                  "text": "http://www.csc.fi/hallinto/haka/luottamusverkosto/palvelut/attributetest/", 
                  "__class__": "urn:oasis:names:tc:SAML:metadata:ui&PrivacyStatementURL"
                }, 
                {
                  "lang": "en", 
                  "text": "http://www.csc.fi/hallinto/haka/luottamusverkosto/palvelut/attributetest/", 
                  "__class__": "urn:oasis:names:tc:SAML:metadata:ui&PrivacyStatementURL"
                }
              ], 
              "display_name": [
                {
                  "lang": "fi", 
                  "text": "Haka attribuuttitestipalvelu", 
                  "__class__": "urn:oasis:names:tc:SAML:metadata:ui&DisplayName"
                }, 
                {
                  "lang": "en", 
                  "text": "Haka Attribute Test Service", 
                  "__class__": "urn:oasis:names:tc:SAML:metadata:ui&DisplayName"
                }
              ], 
              "__class__": "urn:oasis:names:tc:SAML:metadata:ui&UIInfo", 
              "description": [
                {
                  "lang": "fi", 
                  "text": "Palvelua vasten voi testata IdP-palvelimen luovuttamia attribuutteja.", 
                  "__class__": "urn:oasis:names:tc:SAML:metadata:ui&Description"
                }, 
                {
                  "lang": "en", 
                  "text": "Attributes released by IdP-server can be tested against this SP.", 
                  "__class__": "urn:oasis:names:tc:SAML:metadata:ui&Description"
                }
              ]
            }, 
            {
              "attribute_value": [
                {
                  "text": "kalmar", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }, 
                {
                  "text": "finland", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }
              ], 
              "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&Attribute", 
              "name": "tags"
            }
          ]
        }, 
        "name_id_format": [
          {
            "text": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }
        ], 
        "attribute_consuming_service": [
          {
            "index": "1", 
            "service_name": [
              {
                "lang": "fi", 
                "text": "Haka attribuuttitestipalvelu", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }, 
              {
                "lang": "en", 
                "text": "Haka Attribute Test Service", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }
            ], 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AttributeConsumingService", 
            "is_default": "true", 
            "requested_attribute": [
              {
                "friendly_name": "businessCategory", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.15"
              }, 
              {
                "friendly_name": "businessCode", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.2.246.10"
              }, 
              {
                "friendly_name": "cn", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.3"
              }, 
              {
                "friendly_name": "CountryOfResidence", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.25178.1.2.11"
              }, 
              {
                "friendly_name": "description", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.13"
              }, 
              {
                "friendly_name": "displayName", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.16.840.1.113730.3.1.241"
              }, 
              {
                "friendly_name": "eduCourseMember", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.6.1.2"
              }, 
              {
                "friendly_name": "eduCourseOffering", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.6.1.1"
              }, 
              {
                "friendly_name": "eduPersonAffiliation", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.1"
              }, 
              {
                "friendly_name": "eduPersonEntitlement", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.7"
              }, 
              {
                "friendly_name": "eduPersonOrgDN", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.3"
              }, 
              {
                "friendly_name": "eduPersonOrgUnitDN", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.4"
              }, 
              {
                "friendly_name": "eduPersonPrimaryAffiliation", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.5"
              }, 
              {
                "friendly_name": "eduPersonPrimaryOrgUnitDN", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.8"
              }, 
              {
                "friendly_name": "eduPersonPrincipalName", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
              }, 
              {
                "friendly_name": "eduPersonScopedAffiliation", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.9"
              }, 
              {
                "friendly_name": "eduPersonTargetedID", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.10"
              }, 
              {
                "friendly_name": "electronicIdentificationNumber", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.2.246.22"
              }, 
              {
                "friendly_name": "employeeNumber", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.16.840.1.113730.3.1.3"
              }, 
              {
                "friendly_name": "facsimileTelephoneNumber", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.23"
              }, 
              {
                "friendly_name": "funetEduPersonCreditUnits", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.16161.1.1.18"
              }, 
              {
                "friendly_name": "funetEduPersonECTS", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.16161.1.1.19"
              }, 
              {
                "friendly_name": "funetEduPersonEPPNTimeStamp", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.16161.1.1.24"
              }, 
              {
                "friendly_name": "funetEduPersonHomeCity", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.16161.1.1.23"
              }, 
              {
                "friendly_name": "funetEduPersonPrimaryStudyStart", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.16161.1.1.15"
              }, 
              {
                "friendly_name": "funetEduPersonProgram", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.16161.1.1.12"
              }, 
              {
                "friendly_name": "funetEduPersonSpecialisation", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.16161.1.1.13"
              }, 
              {
                "friendly_name": "funetEduPersonStudentCategory", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.16161.1.1.20"
              }, 
              {
                "friendly_name": "funetEduPersonStudentStatus", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.16161.1.1.21"
              }, 
              {
                "friendly_name": "funetEduPersonStudentUnion", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.16161.1.1.22"
              }, 
              {
                "friendly_name": "funetEduPersonStudyStart", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.16161.1.1.14"
              }, 
              {
                "friendly_name": "funetEduPersonStudyToEnd", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.16161.1.1.16"
              }, 
              {
                "friendly_name": "funetEduPersonTargetDegree", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.16161.1.1.11"
              }, 
              {
                "friendly_name": "givenName", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.42"
              }, 
              {
                "friendly_name": "homePhone", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:0.9.2342.19200300.100.1.20"
              }, 
              {
                "friendly_name": "homePostalAddress", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:0.9.2342.19200300.100.1.39"
              }, 
              {
                "friendly_name": "initials", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.43"
              }, 
              {
                "friendly_name": "jpegPhoto", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:0.9.2342.19200300.100.1.60"
              }, 
              {
                "friendly_name": "l", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.7"
              }, 
              {
                "friendly_name": "labeledURI", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.250.1.57"
              }, 
              {
                "friendly_name": "mail", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:0.9.2342.19200300.100.1.3"
              }, 
              {
                "friendly_name": "mobile", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:0.9.2342.19200300.100.1.41"
              }, 
              {
                "friendly_name": "nationalIdentificationNumber", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.2.246.21"
              }, 
              {
                "friendly_name": "Nickname", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.2"
              }, 
              {
                "friendly_name": "o", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.10"
              }, 
              {
                "friendly_name": "ou", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.11"
              }, 
              {
                "friendly_name": "postalAddress", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.16"
              }, 
              {
                "friendly_name": "postalCode", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.17"
              }, 
              {
                "friendly_name": "postOfficeBox", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.18"
              }, 
              {
                "friendly_name": "preferredLanguage", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.16.840.1.113730.3.1.39"
              }, 
              {
                "friendly_name": "schacCountryOfCitizenship", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.25178.1.2.5"
              }, 
              {
                "friendly_name": "schacDateOfBirth", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.25178.1.2.3"
              }, 
              {
                "friendly_name": "schacGender", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.25178.1.2.2"
              }, 
              {
                "friendly_name": "schacHomeOrganization", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.25178.1.2.9"
              }, 
              {
                "friendly_name": "schacHomeOrganizationType", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.25178.1.2.10"
              }, 
              {
                "friendly_name": "schacMotherTongue", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.25178.1.2.1"
              }, 
              {
                "friendly_name": "schacPersonalUniqueCode", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.25178.1.2.14"
              }, 
              {
                "friendly_name": "schacPersonalUniqueID", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.25178.1.2.15"
              }, 
              {
                "friendly_name": "schacPlaceOfBirth", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.25178.1.2.4"
              }, 
              {
                "friendly_name": "seeAlso", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.34"
              }, 
              {
                "friendly_name": "sn", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.4"
              }, 
              {
                "friendly_name": "street", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.9"
              }, 
              {
                "friendly_name": "telephoneNumber", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.20"
              }, 
              {
                "friendly_name": "title", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.12"
              }, 
              {
                "friendly_name": "uid", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:0.9.2342.19200300.100.1.1"
              }, 
              {
                "friendly_name": "userCertificate", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.36"
              }, 
              {
                "friendly_name": "userPresenceID", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.25178.1.2.12"
              }, 
              {
                "friendly_name": "userStatus", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.25178.1.2.19"
              }
            ], 
            "service_description": [
              {
                "lang": "fi", 
                "text": "Palvelua vasten voi testata IdP-palvelimen luovuttamia attribuutteja.", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }, 
              {
                "lang": "en", 
                "text": "Attributes released by IdP-server can be tested against this SP.", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }
            ]
          }
        ], 
        "key_descriptor": [
          {
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIEzDCCA7SgAwIBAgIRANkuMGk/HlexnQRYLfLoQaEwDQYJKoZIhvcNAQEFBQAw\nNjELMAkGA1UEBhMCTkwxDzANBgNVBAoTBlRFUkVOQTEWMBQGA1UEAxMNVEVSRU5B\nIFNTTCBDQTAeFw0xMjAyMjgwMDAwMDBaFw0xNDAyMjcyMzU5NTlaMIGqMQswCQYD\nVQQGEwJGSTEOMAwGA1UEERMFMDIxMDExEDAOBgNVBAgTB1V1c2ltYWExDjAMBgNV\nBAcTBUVzcG9vMRYwFAYDVQQJEw1LZWlsYXJhbnRhIDE0MSkwJwYDVQQKEyBDU0Mg\nLSBJVCBDZW50ZXIgZm9yIFNjaWVuY2UgTHRkLjEQMA4GA1UECxMHVW5rbm93bjEU\nMBIGA1UEAxMLcnIuZnVuZXQuZmkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\nAoIBAQDM5bZnIo6ilf+77pDys40qwpu1U6ym22WZvnxCmAoZ+dDOuBcVdoVagVTp\nMqJ0jc/c/7+grSHG+II+2MftSD78sa0fTWWLCqxdH8GKSfai5FeGbP/YoI14W7OL\n/Bxy7mAKluwkxtx+X5226Q7UeKHaBaF2i+An5i269HYzTO3XIt/eNHMKynsRQgje\n6pNj8PyDnIWm3DENXJi2yVK8AmVvWpEyx0RptMIazFCJa+MvypCYS4Y4D4wKEs5m\n3LWcsqM95zDsyiytv/fAYeRAVpWdTvhOPLW+3Q13/ek6/9Te03YAkzuAaLYvFxwu\nVd2BLs7FAiyR3HDk0Ykl5TyimkaBAgMBAAGjggFeMIIBWjAfBgNVHSMEGDAWgBQM\nvZNoDPPeq6NJays3V0fqkOO57TAdBgNVHQ4EFgQUOaXmVjDtx1G/7svHBNhFLrT5\n5rowDgYDVR0PAQH/BAQDAgWgMAwGA1UdEwEB/wQCMAAwHQYDVR0lBBYwFAYIKwYB\nBQUHAwEGCCsGAQUFBwMCMBgGA1UdIAQRMA8wDQYLKwYBBAGyMQECAh0wOgYDVR0f\nBDMwMTAvoC2gK4YpaHR0cDovL2NybC50Y3MudGVyZW5hLm9yZy9URVJFTkFTU0xD\nQS5jcmwwbQYIKwYBBQUHAQEEYTBfMDUGCCsGAQUFBzAChilodHRwOi8vY3J0LnRj\ncy50ZXJlbmEub3JnL1RFUkVOQVNTTENBLmNydDAmBggrBgEFBQcwAYYaaHR0cDov\nL29jc3AudGNzLnRlcmVuYS5vcmcwFgYDVR0RBA8wDYILcnIuZnVuZXQuZmkwDQYJ\nKoZIhvcNAQEFBQADggEBADH55FfR7I+1zt41DTwz2Ig9w6S6l0pFL889eFl772qV\n/vepbU245oc+FuHxwp1Be1EeEo5Pb1Op+imx/tnXdJZyQ8T19cttw6k0faIIOPk0\n4LDPpPHeNd5UIiegJxuXLwGrs3s8OHrICSzD6UUTGuKQ2ch7Isl65oumZ5BYtmXc\nBipmtjTfM/pv+j2iTDMRfjzTjKSlDdDOaRbCQeLDtIgJkXvwSb/OTPOWHzbLLiPE\nrpMTlKYf36DnHsyERNItnzU02J686VAecWTuNgUwHHI3LzZCWVncQm+I6veK43Ct\nPahX4Y7zrHlQEDDBvQM0uwFM4Dgy07Qk3EwVXCs+46U=", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ]
      }
    ]
  }, 
  "https://sp.catalog.clarin.eu": {
    "valid_until": "2012-12-19T20:15:01Z", 
    "entity_id": "https://sp.catalog.clarin.eu", 
    "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EntityDescriptor", 
    "organization": {
      "organization_name": [
        {
          "lang": "fi", 
          "text": "CLARIN Service Provider Federation/MPI", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }, 
        {
          "lang": "en", 
          "text": "CLARIN Service Provider Federation/MPI", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }, 
        {
          "lang": "sv", 
          "text": "CLARIN Service Provider Federation/MPI", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }
      ], 
      "organization_display_name": [
        {
          "lang": "fi", 
          "text": "CLARIN Service Provider Federation/MPI", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }, 
        {
          "lang": "en", 
          "text": "CLARIN Service Provider Federation/MPI", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }, 
        {
          "lang": "sv", 
          "text": "CLARIN Service Provider Federation/MPI", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }
      ], 
      "organization_url": [
        {
          "lang": "fi", 
          "text": "http://www.clarin.eu", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }, 
        {
          "lang": "en", 
          "text": "http://www.clarin.eu", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }, 
        {
          "lang": "sv", 
          "text": "http://www.clarin.eu", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }
      ], 
      "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Organization"
    }, 
    "contact_person": [
      {
        "given_name": {
          "text": "Tobias", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&GivenName"
        }, 
        "email_address": [
          {
            "text": "tobias.vanvalkenhoef@mpi.nl", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ], 
        "sur_name": {
          "text": "Vanvalkenhoef", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SurName"
        }, 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "contact_type": "technical"
      }
    ], 
    "spsso_descriptor": [
      {
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "assertion_consumer_service": [
          {
            "is_default": "true", 
            "index": "1", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://catalog.clarin.eu/Shibboleth.sso/SAML2/POST"
          }, 
          {
            "is_default": "false", 
            "index": "2", 
            "binding": "urn:oasis:names:tc:SAML:1.0:profiles:browser-post", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://catalog.clarin.eu/Shibboleth.sso/SAML/POST"
          }
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SPSSODescriptor", 
        "name_id_format": [
          {
            "text": "urn:mace:shibboleth:1.0:nameIdentifier", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }, 
          {
            "text": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }
        ], 
        "attribute_consuming_service": [
          {
            "index": "1", 
            "service_name": [
              {
                "lang": "fi", 
                "text": "Catalog Clarin", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }, 
              {
                "lang": "en", 
                "text": "Catalog Clarin", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }, 
              {
                "lang": "sv", 
                "text": "Catalog Clarin", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }
            ], 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AttributeConsumingService", 
            "is_default": "true", 
            "requested_attribute": [
              {
                "friendly_name": "eduPersonPrincipalName", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
              }
            ], 
            "service_description": [
              {
                "lang": "fi", 
                "text": "Catalog Clarin", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }, 
              {
                "lang": "en", 
                "text": "CMDI Component Registry - web application for managing, creating and editing metadata components.", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }
            ]
          }
        ], 
        "key_descriptor": [
          {
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIE3DCCA8SgAwIBAgIED+aV9jANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJE\nRTEgMB4GA1UEChMXTWF4LVBsYW5jay1HZXNlbGxzY2hhZnQxDzANBgNVBAMTBk1Q\nRyBDQTEcMBoGCSqGSIb3DQEJARYNbXBnLWNhQG1wZy5kZTAeFw0xMDA0MTUxMzQ1\nMTFaFw0xNTA0MTQxMzQ1MTFaMH8xCzAJBgNVBAYTAk5MMSAwHgYDVQQKExdNYXgt\nUGxhbmNrLUdlc2VsbHNjaGFmdDEyMDAGA1UECxMpTWF4LVBsYW5jay1JbnN0aXR1\ndCBmdWVyIFBzeWNob2xpbmd1aXN0aWsxGjAYBgNVBAMTEWNhdGFsb2cuY2xhcmlu\nLmV1MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0SxoF+pHBBTzECbn\nIK3k+WuiRpZCv/ECHgUqSq5mw+5x1ZOrP3qW1c/BL+mh8rPM3twPw1zh7faycCzb\nWg6xjkzbvfnidFq394JdJ8OYHHd4629vF/QQlDiPU/WXNL1PWqh+JNoVbBeZI8Uz\n+xglMyPaLn2rOTcVm5fqk6Do8DrubkZ7fxZ/4CkzJ8rTlFNOCcN8x5G2rWtcJYHa\nxS0ZBhmMt1AmqzWh7ZJCvgS9Wma4ZOhuh3xZSlaEB8o3HWAYprR6g7L+HFvmKdfK\n8oGbBViHUqsslr80Mtli15ZzxkkBH95fzYPdJTCAMccaqLhvQfjuChy7FsDYI5cV\nfvhaJQIDAQABo4IBfzCCAXswCQYDVR0TBAIwADALBgNVHQ8EBAMCBPAwEwYDVR0l\nBAwwCgYIKwYBBQUHAwEwHQYDVR0OBBYEFPV/s0egKEIbVq/6uW/GqGNX3RInMB8G\nA1UdIwQYMBaAFALWHm4Jq79YZacKPEgzYdHOfcNbMHcGA1UdHwRwMG4wNaAzoDGG\nL2h0dHA6Ly9jZHAxLnBjYS5kZm4uZGUvbXBnLWNhL3B1Yi9jcmwvY2FjcmwuY3Js\nMDWgM6Axhi9odHRwOi8vY2RwMi5wY2EuZGZuLmRlL21wZy1jYS9wdWIvY3JsL2Nh\nY3JsLmNybDCBkgYIKwYBBQUHAQEEgYUwgYIwPwYIKwYBBQUHMAKGM2h0dHA6Ly9j\nZHAxLnBjYS5kZm4uZGUvbXBnLWNhL3B1Yi9jYWNlcnQvY2FjZXJ0LmNydDA/Bggr\nBgEFBQcwAoYzaHR0cDovL2NkcDIucGNhLmRmbi5kZS9tcGctY2EvcHViL2NhY2Vy\ndC9jYWNlcnQuY3J0MA0GCSqGSIb3DQEBBQUAA4IBAQCyMBGsYojEQdaSJnym2OQQ\ns6fNqdPrhNcEN8KweZh9HyOgNpTEJPJpfwb4XR3pzfSRyPotr2GL80NVXTDA+YQs\nfPO0WLU0KduZtyfl1QGnYZcIpBAN53M+EvMk0Q9ruOP3FZazLPscULJnqW8Ks8/v\nijthUt3XZFCR66qbNf7HeyS7zzYYMkyRDJN9PixRyiEAWHifqXJQzNI9dlqcy+Aq\nnnDbttGYLUyhuuT+CqcBRWJButW9x4BFUDNHrgfcPWwFhUGx3hqI2U6zqrTgesWg\nhSpV3QIescvTSt7Z39lTi6xXr6rXJMxwwpfBn292RbTvgwtTd+yxU0eOLu+3J8tI", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ]
      }
    ]
  }, 
  "https://www.diva-portal.org/shibboleth": {
    "valid_until": "2012-12-16T04:23:08Z", 
    "entity_id": "https://www.diva-portal.org/shibboleth", 
    "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EntityDescriptor", 
    "spsso_descriptor": [
      {
        "single_logout_service": [
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:SOAP", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleLogoutService", 
            "location": "https://www.diva-portal.org/Shibboleth.sso/SLO/SOAP"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleLogoutService", 
            "location": "https://www.diva-portal.org/Shibboleth.sso/SLO/Redirect"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleLogoutService", 
            "location": "https://www.diva-portal.org/Shibboleth.sso/SLO/POST"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleLogoutService", 
            "location": "https://www.diva-portal.org/Shibboleth.sso/SLO/Artifact"
          }
        ], 
        "attribute_consuming_service": [
          {
            "index": "0", 
            "service_description": [
              {
                "lang": "en", 
                "text": "DiVA \u2013 Academic Archive Online - is a system for electronic publishing and for registering publications produced by researchers, teachers and students. Uppsala University Library develops and maintains DiVA.", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }
            ], 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AttributeConsumingService", 
            "requested_attribute": [
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:0.9.2342.19200300.100.1.3"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.42"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.4"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.9"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.1"
              }
            ], 
            "service_name": [
              {
                "lang": "en", 
                "text": "DiVA", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }
            ]
          }
        ], 
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "assertion_consumer_service": [
          {
            "index": "1", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://www.diva-portal.org/Shibboleth.sso/SAML2/POST"
          }, 
          {
            "index": "2", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://www.diva-portal.org/Shibboleth.sso/SAML2/POST-SimpleSign"
          }, 
          {
            "index": "3", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://www.diva-portal.org/Shibboleth.sso/SAML2/Artifact"
          }, 
          {
            "index": "4", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:PAOS", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://www.diva-portal.org/Shibboleth.sso/SAML2/ECP"
          }, 
          {
            "index": "5", 
            "binding": "urn:oasis:names:tc:SAML:1.0:profiles:browser-post", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://www.diva-portal.org/Shibboleth.sso/SAML/POST"
          }, 
          {
            "index": "6", 
            "binding": "urn:oasis:names:tc:SAML:1.0:profiles:artifact-01", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://www.diva-portal.org/Shibboleth.sso/SAML/Artifact"
          }
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SPSSODescriptor", 
        "key_descriptor": [
          {
            "use": "signing", 
            "key_info": {
              "key_name": [
                {
                  "text": "www.diva-portal.org", 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyName"
                }
              ], 
              "x509_data": [
                {
                  "x509_subject_name": {
                    "text": "CN=www.diva-portal.org", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509SubjectName"
                  }, 
                  "x509_certificate": {
                    "text": "MIIDADCCAeigAwIBAgIJALws/Gp4u0qUMA0GCSqGSIb3DQEBBQUAMB4xHDAaBgNV\nBAMTE3d3dy5kaXZhLXBvcnRhbC5vcmcwHhcNMTAwMTI2MTMzMDA0WhcNMjAwMTI0\nMTMzMDA0WjAeMRwwGgYDVQQDExN3d3cuZGl2YS1wb3J0YWwub3JnMIIBIjANBgkq\nhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxiqePLbYzwDdJ7db9++auHZNsjAhXhpm\nAIfDlpu0ZJ6PdxsRtwT5aQzjTkvBce7JYezri6Z8u/un+yPqA/NjAOgJvygIxfCI\nXGMMiw8FA+RX/UNtJBWTr/eJOFRLbQ3xhnmkv3qS1jODtGFrc/ycf+V9GeP2f6GV\nKT1zRoQvoXEurU/LketNnoVr6cIu+dWQXLldJbsvFepw1dIuKlWs3PauFVgiw7cV\n1wioFKcPfYUt7hg5ZpUlK2I8AszgwRQZAACqS8zNc54Q97RbgptL+ua21v4R703H\ndxtuRAWUrDe7uU4HTZucYKqomZI3pS5UbdHxDIupOl6Alot9lfTN/wIDAQABo0Ew\nPzAeBgNVHREEFzAVghN3d3cuZGl2YS1wb3J0YWwub3JnMB0GA1UdDgQWBBQyrnjR\nZLYO63h6dvCxoMPSvgG8FDANBgkqhkiG9w0BAQUFAAOCAQEAbUAQQ0OV0npudm5T\nRjcc/INAcF5fJ2sDejOMWa3unB5XbWHUbPmBmN0vCchVs97QUWVIsHTm6wAjdi0N\nIjW6umykM+aJ0jCRHNwD7wbwet55rHU+pxK3YxRRN5D3JdjN+ttswwNPv83r85o0\ndIEDJtDobA2HT+i6/A2uK2JR7DzpWw2RcG+iCrNmMI9L2YXIs+p5CjS32Pdmn77B\n2C9DSmBXboPTPxfmIOo1S6B4ZEtJ7W2s425lx38v4oEo+TspFAqzTDs8+fTw9/aa\nJ1z0kVcxmvNLpIVh3rlkUQvNycE22FMDlp6sDtIn/KaODR5hKSGHT2Cdk4tpktkh\nH5e8OA==", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }, 
          {
            "use": "encryption", 
            "key_info": {
              "key_name": [
                {
                  "text": "www.diva-portal.org", 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyName"
                }
              ], 
              "x509_data": [
                {
                  "x509_subject_name": {
                    "text": "CN=www.diva-portal.org", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509SubjectName"
                  }, 
                  "x509_certificate": {
                    "text": "MIIDADCCAeigAwIBAgIJALws/Gp4u0qUMA0GCSqGSIb3DQEBBQUAMB4xHDAaBgNV\nBAMTE3d3dy5kaXZhLXBvcnRhbC5vcmcwHhcNMTAwMTI2MTMzMDA0WhcNMjAwMTI0\nMTMzMDA0WjAeMRwwGgYDVQQDExN3d3cuZGl2YS1wb3J0YWwub3JnMIIBIjANBgkq\nhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxiqePLbYzwDdJ7db9++auHZNsjAhXhpm\nAIfDlpu0ZJ6PdxsRtwT5aQzjTkvBce7JYezri6Z8u/un+yPqA/NjAOgJvygIxfCI\nXGMMiw8FA+RX/UNtJBWTr/eJOFRLbQ3xhnmkv3qS1jODtGFrc/ycf+V9GeP2f6GV\nKT1zRoQvoXEurU/LketNnoVr6cIu+dWQXLldJbsvFepw1dIuKlWs3PauFVgiw7cV\n1wioFKcPfYUt7hg5ZpUlK2I8AszgwRQZAACqS8zNc54Q97RbgptL+ua21v4R703H\ndxtuRAWUrDe7uU4HTZucYKqomZI3pS5UbdHxDIupOl6Alot9lfTN/wIDAQABo0Ew\nPzAeBgNVHREEFzAVghN3d3cuZGl2YS1wb3J0YWwub3JnMB0GA1UdDgQWBBQyrnjR\nZLYO63h6dvCxoMPSvgG8FDANBgkqhkiG9w0BAQUFAAOCAQEAbUAQQ0OV0npudm5T\nRjcc/INAcF5fJ2sDejOMWa3unB5XbWHUbPmBmN0vCchVs97QUWVIsHTm6wAjdi0N\nIjW6umykM+aJ0jCRHNwD7wbwet55rHU+pxK3YxRRN5D3JdjN+ttswwNPv83r85o0\ndIEDJtDobA2HT+i6/A2uK2JR7DzpWw2RcG+iCrNmMI9L2YXIs+p5CjS32Pdmn77B\n2C9DSmBXboPTPxfmIOo1S6B4ZEtJ7W2s425lx38v4oEo+TspFAqzTDs8+fTw9/aa\nJ1z0kVcxmvNLpIVh3rlkUQvNycE22FMDlp6sDtIn/KaODR5hKSGHT2Cdk4tpktkh\nH5e8OA==", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ], 
        "manage_name_id_service": [
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:SOAP", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ManageNameIDService", 
            "location": "https://www.diva-portal.org/Shibboleth.sso/NIM/SOAP"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ManageNameIDService", 
            "location": "https://www.diva-portal.org/Shibboleth.sso/NIM/Redirect"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ManageNameIDService", 
            "location": "https://www.diva-portal.org/Shibboleth.sso/NIM/POST"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ManageNameIDService", 
            "location": "https://www.diva-portal.org/Shibboleth.sso/NIM/Artifact"
          }
        ]
      }
    ]
  }, 
  "http://fse.eduuni.fi/adfs/services/trust": {
    "valid_until": "2012-12-19T20:15:01Z", 
    "entity_id": "http://fse.eduuni.fi/adfs/services/trust", 
    "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EntityDescriptor", 
    "organization": {
      "organization_name": [
        {
          "lang": "fi", 
          "text": "CSC - Tieteen tietotekniikan keskus Oy", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }, 
        {
          "lang": "en", 
          "text": "CSC - IT Center for Science Ltd.", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }, 
        {
          "lang": "sv", 
          "text": "CSC - Tieteen tietotekniikan keskus Oy", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }
      ], 
      "organization_display_name": [
        {
          "lang": "fi", 
          "text": "CSC - Tieteen tietotekniikan keskus Oy", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }, 
        {
          "lang": "en", 
          "text": "CSC - IT Center for Science Ltd.", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }, 
        {
          "lang": "sv", 
          "text": "CSC - Tieteen tietotekniikan keskus Oy", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }
      ], 
      "organization_url": [
        {
          "lang": "fi", 
          "text": "http://www.csc.fi", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }, 
        {
          "lang": "en", 
          "text": "http://www.csc.fi", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }, 
        {
          "lang": "sv", 
          "text": "http://www.csc.fi", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }
      ], 
      "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Organization"
    }, 
    "contact_person": [
      {
        "given_name": {
          "text": "Sami", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&GivenName"
        }, 
        "email_address": [
          {
            "text": "asiakaspalvelu@eduuni.fi", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ], 
        "sur_name": {
          "text": "Saarikoski", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SurName"
        }, 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "contact_type": "technical"
      }, 
      {
        "given_name": {
          "text": "Toni", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&GivenName"
        }, 
        "email_address": [
          {
            "text": "asiakaspalvelu@eduuni.fi", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ], 
        "sur_name": {
          "text": "Sormunen", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SurName"
        }, 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "contact_type": "support"
      }
    ], 
    "spsso_descriptor": [
      {
        "single_logout_service": [
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleLogoutService", 
            "location": "https://fse.eduuni.fi/adfs/ls/"
          }
        ], 
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "assertion_consumer_service": [
          {
            "is_default": "true", 
            "index": "1", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://fse.eduuni.fi/adfs/ls/"
          }
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SPSSODescriptor", 
        "name_id_format": [
          {
            "text": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }
        ], 
        "attribute_consuming_service": [
          {
            "index": "1", 
            "service_name": [
              {
                "lang": "fi", 
                "text": "Eduuni-tyotilat", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }, 
              {
                "lang": "en", 
                "text": "Eduuni-workspaces", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }
            ], 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AttributeConsumingService", 
            "is_default": "true", 
            "requested_attribute": [
              {
                "friendly_name": "displayName", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.16.840.1.113730.3.1.241"
              }, 
              {
                "friendly_name": "eduPersonAffiliation", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.1"
              }, 
              {
                "friendly_name": "eduPersonPrincipalName", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
              }, 
              {
                "friendly_name": "eduPersonScopedAffiliation", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.9"
              }, 
              {
                "friendly_name": "schacHomeOrganization", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.25178.1.2.9"
              }, 
              {
                "friendly_name": "schacHomeOrganizationType", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.25178.1.2.10"
              }, 
              {
                "friendly_name": "sn", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.4"
              }
            ], 
            "service_description": [
              {
                "lang": "fi", 
                "text": "Eduuni-tyotilat on opetus- ja kulttuuriministerion toimialan yhteinen sahkoisen tyoskentelyn ja verkostoitumisen alusta.", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }, 
              {
                "lang": "en", 
                "text": "Eduuni-workspaces is a shared platform for collaboration and networking in the branch of the Ministry of Education and Culture.", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }
            ]
          }
        ], 
        "key_descriptor": [
          {
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIGBjCCBO6gAwIBAgIEC+0xjzANBgkqhkiG9w0BAQUFADCBhTELMAkGA1UEBhMC\nRkkxEDAOBgNVBAgTB0ZpbmxhbmQxITAfBgNVBAoTGFZhZXN0b3Jla2lzdGVyaWtl\nc2t1cyBDQTEaMBgGA1UECxMRUGFsdmVsdXZhcm1lbnRlZXQxJTAjBgNVBAMTHFZS\nSyBDQSBmb3IgU2VydmljZSBQcm92aWRlcnMwHhcNMTEwOTA1MDgwMDAwWhcNMTMw\nOTA1MjA1OTAwWjB0MQswCQYDVQQGEwJGSTEQMA4GA1UECBMHVXVzaW1hYTERMA8G\nA1UEBxMISGVsc2lua2kxKDAmBgNVBAoMH09wZXR1cy0gamEga3VsdHR1dXJpbWlu\naXN0ZXJpw7YxFjAUBgNVBAMTDWZzZS5lZHV1bmkuZmkwggEiMA0GCSqGSIb3DQEB\nAQUAA4IBDwAwggEKAoIBAQC6uO2/A1TiGW1n/NHldRDLISVw5u/cjM0D+x237es/\nxkJBM+tyyBGO7Ta8gIIBRezYkzUDpDYhKOdtkpzFUpYL9zTXWwaD3Qay323TTuFF\nU8qIs7sg980aaJ287gnnxe6PkhP2s1mYRhgBgP7pCSTEw4YFArn7zyaTwqaD8QUY\nT2k07/IrP2tK0tF9quxtdVAf6LmUaVo0+vsXvDxH5APGFU/81hi1RQNbIAtDXZgN\ndrnlHcP3yuUlrJTGuLAV7dyiHd2OLXOt/Dx6eUfI1/Y5tYQw8kUqdlOPcOmiWVBT\nefuqutqFLwXq6RV9xZnbFkmdAiJeK246xkz7/TJ9hdQrAgMBAAGjggKMMIICiDAM\nBgNVHRMBAf8EAjAAMIHVBgNVHSAEgc0wgcowCAYGBACPegEDMIG9BgkqgXaEBQEK\nBAEwga8wgYQGCCsGAQUFBwICMHgadlZhcm1lbm5lcG9saXRpaWtrYSBvbiBzYWF0\nYXZpbGxhIC0gQ2VydGlmaWthdCBwb2xpY3kgZmlubnMgLSBDZXJ0aWZpY2F0ZSBw\nb2xpY3kgaXMgYXZhaWxhYmxlIGh0dHA6Ly93d3cuZmluZWlkLmZpL2NwczMwJgYI\nKwYBBQUHAgEWGmh0dHA6Ly93d3cuZmluZWlkLmZpL2NwczMvMD8GCCsGAQUFBwEB\nBDMwMTAvBggrBgEFBQcwAoYjaHR0cDovL3Byb3h5LmZpbmVpZC5maS9jYS92cmtz\ncC5jcnQwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEF\nBQcDAjAfBgNVHSMEGDAWgBQYNf0kF+5fwkVxbmsZvebuAfU68jCB7wYDVR0fBIHn\nMIHkMCugKaAnhiVodHRwOi8vcHJveHkuZmluZWlkLmZpL2NybC92cmtzcGMuY3Js\nMIG0oIGxoIGuhoGrbGRhcDovL2xkYXAuZmluZWlkLmZpOjM4OS9jbiUzZFZSSyUy\nMENBJTIwZm9yJTIwU2VydmljZSUyMFByb3ZpZGVycyxvdSUzZFBhbHZlbHV2YXJt\nZW50ZWV0LG8lM2RWYWVzdG9yZWtpc3RlcmlrZXNrdXMlMjBDQSxkbWROYW1lJTNk\nRklORUlELGMlM2RGST9jZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0MB0GA1UdDgQW\nBBSjFTaTWYoUyyp3jwXkzrGD3xcFVTANBgkqhkiG9w0BAQUFAAOCAQEAY9eZv6EX\nQMUT/uRKWbahBYiNHVrFNAN1QJiui+URiil/H/glQ7r+os3z2EZBle56f0gVplkh\nKi8l/xge9S6IZz7y1wbZi0euvIgJ4W3EsbC2uWZn4elOr+D7j+4fep+46Ko7ROBn\neryGe01KBXZWJBkFaqzoJCL8BF2vbtsYMqJaVtzDXdv101CxbeZ4bPeJa3XsQ/6k\nrQ5gBxGmQsJJfMf50HRu/k2kwpvyEryKtk50Xmm89V2CjWoPylxOyWv1a+BAPQpe\n7h6IenpuNGUJJ4eUN/O2CLOsH446n97IHtrM/pzz38dQEFjfY9G+oEA+s/mJRRQa\nNUEsJ2eMhHrNWw==", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ]
      }
    ]
  }, 
  "https://idp.ids-mannheim.de/shibboleth": {
    "valid_until": "2012-12-19T20:15:01Z", 
    "entity_id": "https://idp.ids-mannheim.de/shibboleth", 
    "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EntityDescriptor", 
    "organization": {
      "organization_name": [
        {
          "lang": "fi", 
          "text": "CLARIN Service Provider Federation/MPI", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }, 
        {
          "lang": "en", 
          "text": "CLARIN Service Provider Federation/MPI", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }, 
        {
          "lang": "sv", 
          "text": "CLARIN Service Provider Federation/MPI", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }
      ], 
      "organization_display_name": [
        {
          "lang": "fi", 
          "text": "CLARIN Service Provider Federation/MPI", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }, 
        {
          "lang": "en", 
          "text": "CLARIN Service Provider Federation/MPI", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }, 
        {
          "lang": "sv", 
          "text": "CLARIN Service Provider Federation/MPI", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }
      ], 
      "organization_url": [
        {
          "lang": "fi", 
          "text": "http://www.clarin.eu", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }, 
        {
          "lang": "en", 
          "text": "http://www.clarin.eu", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }, 
        {
          "lang": "sv", 
          "text": "http://www.clarin.eu", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }
      ], 
      "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Organization"
    }, 
    "contact_person": [
      {
        "given_name": {
          "text": "Oliver", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&GivenName"
        }, 
        "email_address": [
          {
            "text": "schonefeld@ids-mannheim.de", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ], 
        "sur_name": {
          "text": "Schonefeld", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SurName"
        }, 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "contact_type": "technical"
      }
    ], 
    "spsso_descriptor": [
      {
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "assertion_consumer_service": [
          {
            "is_default": "true", 
            "index": "1", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://idp.ids-mannheim.de/Shibboleth.sso/SAML2/POST"
          }, 
          {
            "is_default": "false", 
            "index": "2", 
            "binding": "urn:oasis:names:tc:SAML:1.0:profiles:browser-post", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://idp.ids-mannheim.de/Shibboleth.sso/SAML/POST"
          }
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SPSSODescriptor", 
        "extensions": {
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Extensions", 
          "extension_elements": [
            {
              "index": "1", 
              "binding": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol", 
              "__class__": "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol&DiscoveryResponse", 
              "location": "https://idp.ids-mannheim.de/Shibboleth.sso/Login"
            }, 
            {
              "attribute_value": [
                {
                  "text": "kalmar", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }, 
                {
                  "text": "finland", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }
              ], 
              "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&Attribute", 
              "name": "tags"
            }
          ]
        }, 
        "name_id_format": [
          {
            "text": "urn:mace:shibboleth:1.0:nameIdentifier", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }, 
          {
            "text": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }
        ], 
        "attribute_consuming_service": [
          {
            "index": "1", 
            "service_name": [
              {
                "lang": "fi", 
                "text": "Institut f\u00fcr Deutsche Sprache - Test SP", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }, 
              {
                "lang": "en", 
                "text": "Institut f\u00fcr Deutsche Sprache - Test SP", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }
            ], 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AttributeConsumingService", 
            "is_default": "true", 
            "requested_attribute": [
              {
                "friendly_name": "eduPersonPrincipalName", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
              }, 
              {
                "friendly_name": "mail", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:0.9.2342.19200300.100.1.3"
              }, 
              {
                "friendly_name": "o", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:2.5.4.10"
              }
            ], 
            "service_description": [
              {
                "lang": "en", 
                "text": "Interface to the Corpus Search, Management and Analysis System COSMAS-II, which offers various possibilities to access the German Reference Corpus DeReKo and other corpora hosted at the IDS. For Humanities and Social Sciences researchers.", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }
            ]
          }
        ], 
        "key_descriptor": [
          {
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIE4zCCA8ugAwIBAgIEDyTTjjANBgkqhkiG9w0BAQUFADBVMQswCQYDVQQGEwJE\nRTETMBEGA1UEChMKREZOLVZlcmVpbjEQMA4GA1UECxMHREZOLVBLSTEfMB0GA1UE\nAxMWREZOLVZlcmVpbiBDQSBTZXJ2aWNlczAeFw0wOTExMTkxNDI4MTVaFw0xNDEx\nMTgxNDI4MTVaMFIxCzAJBgNVBAYTAkRFMRMwEQYDVQQKEwpERk4tVmVyZWluMRAw\nDgYDVQQLEwdERk4tUEtJMRwwGgYDVQQDExNpZHAuaWRzLW1hbm5oZWltLmRlMIIB\nIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt7L/7N+17/v7lajOiMdvThxk\nNoiCwy2RDzaDi7IEvJtXmT1CkKXVg84uxCneoixdPwO9EZAyphOGfXyvIWiWOEkB\n8135pYTbKNYPuG0+fIYXPvHE1+oFMca3K21GgssvoOZYJfi/wrORLx77iQXRgGYF\nmRllzaspZriQNbIvCwVsKsoL8zt9TeVa0Ltv6A7dRg/36u8XppG4glE4xuuXQgNI\nmj0qpJ9pV76bgzPKUNm2/aXDiyqoI4qvp2h4vM2sFv2MAguPkHI7PPcVXn1L2q3h\nWpylL+gjjNfZm1TdDww+r1HFdeQDORmjSh+Cd4bbdEeA2bWH3NHjSR6xWwCj/wID\nAQABo4IBvDCCAbgwCQYDVR0TBAIwADALBgNVHQ8EBAMCBeAwHQYDVR0lBBYwFAYI\nKwYBBQUHAwIGCCsGAQUFBwMBMB0GA1UdDgQWBBSg5wzZdnXH5hJRlkFfkCXU0cFr\n4TAfBgNVHSMEGDAWgBQdqfGGJnZNz139UKNu6/G8InVt6zCBkQYDVR0fBIGJMIGG\nMEGgP6A9hjtodHRwOi8vY2RwMS5wY2EuZGZuLmRlL2dsb2JhbC1zZXJ2aWNlcy1j\nYS9wdWIvY3JsL2NhY3JsLmNybDBBoD+gPYY7aHR0cDovL2NkcDIucGNhLmRmbi5k\nZS9nbG9iYWwtc2VydmljZXMtY2EvcHViL2NybC9jYWNybC5jcmwwgaoGCCsGAQUF\nBwEBBIGdMIGaMEsGCCsGAQUFBzAChj9odHRwOi8vY2RwMS5wY2EuZGZuLmRlL2ds\nb2JhbC1zZXJ2aWNlcy1jYS9wdWIvY2FjZXJ0L2NhY2VydC5jcnQwSwYIKwYBBQUH\nMAKGP2h0dHA6Ly9jZHAyLnBjYS5kZm4uZGUvZ2xvYmFsLXNlcnZpY2VzLWNhL3B1\nYi9jYWNlcnQvY2FjZXJ0LmNydDANBgkqhkiG9w0BAQUFAAOCAQEAB1uluFS88lYI\nQPiuEvlALX1GYfNZTNCJogeflb5E59zdd49Y7L5zs9IXbYLUMqSQrbLyv4i4nK4e\nbApMu6sgKRf6qPW/MZUAmW0VXjce+W3elGohc4D0MSVHXZQN48Y3S0Jktc5CVC46\nHzxN+4WnjMpVFIB8d5PoL8Nck6vuKvM/IzQbUKym9VC29qwxUIyzG7/f6OuzwXtJ\nxPmwm/Z3/0myg08CF/awdegYuOaq2NBWi7ZvJefTvunuzhwv8LcNPon2mFomUq+E\nVVbh+FSPaIx4RWUSCYsAX8B5Yx9FCb0PJ8HnemcVzgyA8x4Qh5JYbdo0FiNI04LE\n99YJ9IIzYQ==", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ]
      }
    ]
  }, 
  "https://terena.org/sp": {
    "valid_until": "2012-12-19T20:17:02Z", 
    "entity_id": "https://terena.org/sp", 
    "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EntityDescriptor", 
    "spsso_descriptor": [
      {
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "assertion_consumer_service": [
          {
            "index": "1", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://login.terena.org/wayf/module.php/saml/sp/saml1-acs.php/default-sp"
          }, 
          {
            "index": "0", 
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AssertionConsumerService", 
            "location": "https://login.terena.org/wayf/module.php/saml/sp/saml2-acs.php/default-sp"
          }
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SPSSODescriptor", 
        "name_id_format": [
          {
            "text": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }
        ], 
        "attribute_consuming_service": [
          {
            "index": "0", 
            "service_description": [
              {
                "lang": "en", 
                "text": "to be a Service Provider Proxy for all TERENA Federated Services", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }, 
              {
                "lang": "da", 
                "text": "at fungere som tjenesteudbyder-proxy for alle TERENAs f\u00f8dererede tjenester", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceDescription"
              }
            ], 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AttributeConsumingService", 
            "requested_attribute": [
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:0.9.2342.19200300.100.1.3"
              }, 
              {
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&RequestedAttribute", 
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", 
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.7"
              }
            ], 
            "service_name": [
              {
                "lang": "en", 
                "text": "TERENA Service Provider Proxy", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }, 
              {
                "lang": "da", 
                "text": "TERENA Service Provider Proxy", 
                "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ServiceName"
              }
            ]
          }
        ], 
        "key_descriptor": [
          {
            "use": "signing", 
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIEkjCCA3qgAwIBAgIJAL90CxMEVb/kMA0GCSqGSIb3DQEBBQUAMIGMMQswCQYDVQQGEwJOTDELMAkGA1UECBMCTkgxEjAQBgNVBAcTCUFtc3RlcmRhbTEPMA0GA1UEChMGVEVSRU5BMQwwCgYDVQQLEwNJVFMxHjAcBgNVBAMTFWh0dHBzOi8vdGVyZW5hLm9yZy9zcDEdMBsGCSqGSIb3DQEJARYOYWFpQHRlcmVuYS5vcmcwHhcNMTEwMTEyMTUyNjM4WhcNMjEwMTExMTUyNjM4WjCBjDELMAkGA1UEBhMCTkwxCzAJBgNVBAgTAk5IMRIwEAYDVQQHEwlBbXN0ZXJkYW0xDzANBgNVBAoTBlRFUkVOQTEMMAoGA1UECxMDSVRTMR4wHAYDVQQDExVodHRwczovL3RlcmVuYS5vcmcvc3AxHTAbBgkqhkiG9w0BCQEWDmFhaUB0ZXJlbmEub3JnMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwTxx8JBWSpBJiZgdvGOJDXLwaE29Opx1CBbIrYHm47Oy4btsf0BzCmfdSPDlydDm6//355hsQU8BgIh/waEwFZZCg/XyzrJEXCDTZBm1H210aT7FNp356azqKOO1bYWcku0xpFOWWf3jCIkjtOiTkbl12Tw7Y+zJRhV2+jleC5td3JxZ6k1qotgN+1cGwZ2Tv2HhSNeMC4QsGOyBqeP+7B1CLFqFZSiLWGVqcZi0fGkXf+SrTSEH/kLzdciEg2EePyQPcLCKNz9RiIhSmsLE/Rr1ksOvZGmyWFe7YsPyJOLsNyYcZTufDVwpl9fDuJdYy2GdMT1kSNNOpZXZ7QcgYwIDAQABo4H0MIHxMB0GA1UdDgQWBBQ6tVqjpKC8+30XF/qWlaZ3fUKTvDCBwQYDVR0jBIG5MIG2gBQ6tVqjpKC8+30XF/qWlaZ3fUKTvKGBkqSBjzCBjDELMAkGA1UEBhMCTkwxCzAJBgNVBAgTAk5IMRIwEAYDVQQHEwlBbXN0ZXJkYW0xDzANBgNVBAoTBlRFUkVOQTEMMAoGA1UECxMDSVRTMR4wHAYDVQQDExVodHRwczovL3RlcmVuYS5vcmcvc3AxHTAbBgkqhkiG9w0BCQEWDmFhaUB0ZXJlbmEub3JnggkAv3QLEwRVv+QwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQUFAAOCAQEAn+06i7zZE7MjuB68gCaNvnCkrgfumi4PWiP6kaE6+LU2MTbxdFyoSAoKh6Ft9TDi+8ANAsn5jRQ5xLUE4YoVbub/KufMwdlX0zO9i+Q//npDTFESnWsiMi7DHg/av1LtzrYYZvE2E1e5c/7wo/axx8Bk7qsE9YXFRs372vDkDwOGSkLbRtgwdCUX47CE/fXvccPDHH217XMed2cVOGFjQgidsFZlJbSfSvQjWYw5LIE0wo9RtsEu5I3WAIar8Wr6/nhVOgIBUStpcw94GwlPxLywfij5CJ9HT+sN2SOj4YmKPBtcwHI75uNZp7XRy85jRjrvhahg5baIQ0u3aL8aMA==", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }, 
          {
            "use": "encryption", 
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIEkjCCA3qgAwIBAgIJAL90CxMEVb/kMA0GCSqGSIb3DQEBBQUAMIGMMQswCQYDVQQGEwJOTDELMAkGA1UECBMCTkgxEjAQBgNVBAcTCUFtc3RlcmRhbTEPMA0GA1UEChMGVEVSRU5BMQwwCgYDVQQLEwNJVFMxHjAcBgNVBAMTFWh0dHBzOi8vdGVyZW5hLm9yZy9zcDEdMBsGCSqGSIb3DQEJARYOYWFpQHRlcmVuYS5vcmcwHhcNMTEwMTEyMTUyNjM4WhcNMjEwMTExMTUyNjM4WjCBjDELMAkGA1UEBhMCTkwxCzAJBgNVBAgTAk5IMRIwEAYDVQQHEwlBbXN0ZXJkYW0xDzANBgNVBAoTBlRFUkVOQTEMMAoGA1UECxMDSVRTMR4wHAYDVQQDExVodHRwczovL3RlcmVuYS5vcmcvc3AxHTAbBgkqhkiG9w0BCQEWDmFhaUB0ZXJlbmEub3JnMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwTxx8JBWSpBJiZgdvGOJDXLwaE29Opx1CBbIrYHm47Oy4btsf0BzCmfdSPDlydDm6//355hsQU8BgIh/waEwFZZCg/XyzrJEXCDTZBm1H210aT7FNp356azqKOO1bYWcku0xpFOWWf3jCIkjtOiTkbl12Tw7Y+zJRhV2+jleC5td3JxZ6k1qotgN+1cGwZ2Tv2HhSNeMC4QsGOyBqeP+7B1CLFqFZSiLWGVqcZi0fGkXf+SrTSEH/kLzdciEg2EePyQPcLCKNz9RiIhSmsLE/Rr1ksOvZGmyWFe7YsPyJOLsNyYcZTufDVwpl9fDuJdYy2GdMT1kSNNOpZXZ7QcgYwIDAQABo4H0MIHxMB0GA1UdDgQWBBQ6tVqjpKC8+30XF/qWlaZ3fUKTvDCBwQYDVR0jBIG5MIG2gBQ6tVqjpKC8+30XF/qWlaZ3fUKTvKGBkqSBjzCBjDELMAkGA1UEBhMCTkwxCzAJBgNVBAgTAk5IMRIwEAYDVQQHEwlBbXN0ZXJkYW0xDzANBgNVBAoTBlRFUkVOQTEMMAoGA1UECxMDSVRTMR4wHAYDVQQDExVodHRwczovL3RlcmVuYS5vcmcvc3AxHTAbBgkqhkiG9w0BCQEWDmFhaUB0ZXJlbmEub3JnggkAv3QLEwRVv+QwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQUFAAOCAQEAn+06i7zZE7MjuB68gCaNvnCkrgfumi4PWiP6kaE6+LU2MTbxdFyoSAoKh6Ft9TDi+8ANAsn5jRQ5xLUE4YoVbub/KufMwdlX0zO9i+Q//npDTFESnWsiMi7DHg/av1LtzrYYZvE2E1e5c/7wo/axx8Bk7qsE9YXFRs372vDkDwOGSkLbRtgwdCUX47CE/fXvccPDHH217XMed2cVOGFjQgidsFZlJbSfSvQjWYw5LIE0wo9RtsEu5I3WAIar8Wr6/nhVOgIBUStpcw94GwlPxLywfij5CJ9HT+sN2SOj4YmKPBtcwHI75uNZp7XRy85jRjrvhahg5baIQ0u3aL8aMA==", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ]
      }
    ], 
    "cache_duration": "PT345600S"
  }, 
  "https://tullbommen.arcada.fi/simplesaml/": {
    "valid_until": "2012-12-19T20:15:01Z", 
    "entity_id": "https://tullbommen.arcada.fi/simplesaml/", 
    "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EntityDescriptor", 
    "idpsso_descriptor": [
      {
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&IDPSSODescriptor", 
        "single_sign_on_service": [
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleSignOnService", 
            "location": "https://tullbommen.arcada.fi/simplesaml/saml2/idp/SSOService.php"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleSignOnService", 
            "location": "https://tullbommen.arcada.fi/simplesaml/saml2/idp/SSOService.php"
          }
        ], 
        "extensions": {
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Extensions", 
          "extension_elements": [
            {
              "attribute_value": [
                {
                  "text": "kalmar", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }, 
                {
                  "text": "finland", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }
              ], 
              "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&Attribute", 
              "name": "tags"
            }
          ]
        }, 
        "key_descriptor": [
          {
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIELTCCAxWgAwIBAgIQavqUF8l15ouY6e+Gm1RlcjANBgkqhkiG9w0BAQUFADA5\nMQswCQYDVQQGEwJGSTEPMA0GA1UEChMGU29uZXJhMRkwFwYDVQQDExBTb25lcmEg\nQ2xhc3MyIENBMB4XDTA5MTIwMzIxMDMyNVoXDTEwMTIwMzIxMDMyNVowdzEaMBgG\nA1UEChMRU3RpZnRlbHNlbiBBcmNhZGExFTATBgNVBAsTDElULWNlbnRyYWxlbjEd\nMBsGA1UEAxMUdHVsbGJvbW1lbi5hcmNhZGEuZmkxIzAhBgkqhkiG9w0BCQEWFGhv\nc3RtYXN0ZXJAYXJjYWRhLmZpMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC\nAQEA1Af5oqZO2J/9MkGva6UNwDBpkdPf+OZAScaLOp0vXQmz2fnn8tHTZ73Bf4Vw\nm7252Fx4gGSYNU4wRTiTuo3jzaZc7PKA1iJOQVf2Glq5ys2Z7muupuHX3hSKi150\n65Z0d2wazfRjnUgx3TBLkyJ7ZvtjlZ6SVJ1S0wbBY6hnJ1iErJOw8UlrySSOXIq2\nsEPkSt8nl0Eo4P1V6VkGFU2oS3vd/FWmey1NnC3jSdDtoqb+SxFzOZi1+ykmyPv2\nkjnV4vtFnQ+04WM64xtXFsCFvGMFNSDSGbtcDr83Pq+C8iIseMBWiiKETh4hq/3T\nG8YM/aDmgpGi5dmXSuDh9odZ/wIDAQABo4HyMIHvMBMGA1UdIwQMMAqACEqgqliE\n0148MBkGA1UdIAQSMBAwDgYMKwYBBAGCDwIDAQECMHIGA1UdHwRrMGkwZ6BloGOG\nYWxkYXA6Ly8xOTQuMjUyLjEyNC4yNDE6Mzg5L2NuPVNvbmVyYSUyMENsYXNzMiUy\nMENBLG89U29uZXJhLGM9Rkk/Y2VydGlmaWNhdGVyZXZvY2F0aW9ubGlzdDtiaW5h\ncnkwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAsGA1UdDwQEAwIF4DAd\nBgNVHQ4EFgQUYw143pn/Vha8iT1GD6cNUD36ZxYwDQYJKoZIhvcNAQEFBQADggEB\nAHPPpWkAatTuwIYfA3eF4lV1wUx9VCcYgeu5n/yzu6p9lEGtnT9Oyf2isD9Ll6fP\nEAF86nLA0sUUY8VwmKmz4NJFyVo/jegOGVXIb/wre0hapJR73OHI4APb8IkoYUPD\nLDmh6ukYvLM5TwhpDmDaFY4hrcxu5GDq4DG9cE0X8Utbx8xZdQA9i6OjYvTKWd40\nCMpKUKb8ZGmXsx5pVDJzu5gWxXaAIX36lmg8e/kAWdOMD7e+yiQr9YDfajpWKwzv\neIG1Ef6b4TSUvypncJLKqfKO4nQrq2rS1HNMUE+Ipfhd4pnjXk5MsX/UHvheW4F0\n8Wo8LAnlYbl+MJgiAFzNJJw=", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }, 
          {
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIE5jCCA86gAwIBAgIQa3vG7hzvE9YGrscDYuR+kDANBgkqhkiG9w0BAQUFADA2\nMQswCQYDVQQGEwJOTDEPMA0GA1UEChMGVEVSRU5BMRYwFAYDVQQDEw1URVJFTkEg\nU1NMIENBMB4XDTEwMTExMTAwMDAwMFoXDTEzMTExMDIzNTk1OVowgbwxCzAJBgNV\nBAYTAkZJMQ4wDAYDVQQREwUwMDU1MDEPMA0GA1UECBMGTnlsYW5kMRQwEgYDVQQH\nEwtIZWxzaW5nZm9yczEkMCIGA1UECRMbSmFuLU1hZ251cyBKYW5zc29ucyBQbGF0\ncyAxMRowGAYDVQQKExFTdGlmdGVsc2VuIEFyY2FkYTEVMBMGA1UECxMMSVQtY2Vu\ndHJhbGVuMR0wGwYDVQQDExR0dWxsYm9tbWVuLmFyY2FkYS5maTCCASIwDQYJKoZI\nhvcNAQEBBQADggEPADCCAQoCggEBANQH+aKmTtif/TJBr2ulDcAwaZHT3/jmQEnG\nizqdL10Js9n55/LR02e9wX+FcJu9udhceIBkmDVOMEU4k7qN482mXOzygNYiTkFX\n9hpaucrNme5rrqbh194UiotedOuWdHdsGs30Y51IMd0wS5Mie2b7Y5WeklSdUtMG\nwWOoZydYhKyTsPFJa8kkjlyKtrBD5ErfJ5dBKOD9VelZBhVNqEt73fxVpnstTZwt\n40nQ7aKm/ksRczmYtfspJsj79pI51eL7RZ0PtOFjOuMbVxbAhbxjBTUg0hm7XA6/\nNz6vgvIiLHjAVooihE4eIav90xvGDP2g5oKRouXZl0rg4faHWf8CAwEAAaOCAWcw\nggFjMB8GA1UdIwQYMBaAFAy9k2gM896ro0lrKzdXR+qQ47ntMB0GA1UdDgQWBBRj\nDXjemf9WFryJPUYPpw1QPfpnFjAOBgNVHQ8BAf8EBAMCBaAwDAYDVR0TAQH/BAIw\nADAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwGAYDVR0gBBEwDzANBgsr\nBgEEAbIxAQICHTA6BgNVHR8EMzAxMC+gLaArhilodHRwOi8vY3JsLnRjcy50ZXJl\nbmEub3JnL1RFUkVOQVNTTENBLmNybDBtBggrBgEFBQcBAQRhMF8wNQYIKwYBBQUH\nMAKGKWh0dHA6Ly9jcnQudGNzLnRlcmVuYS5vcmcvVEVSRU5BU1NMQ0EuY3J0MCYG\nCCsGAQUFBzABhhpodHRwOi8vb2NzcC50Y3MudGVyZW5hLm9yZzAfBgNVHREEGDAW\nghR0dWxsYm9tbWVuLmFyY2FkYS5maTANBgkqhkiG9w0BAQUFAAOCAQEAW0MOCRCS\n3BfMa0MKrfWtgWIbtQT9LxpIKEx9AE4C9cmBws8TLrwzXHVwnt7uTS5JMxSm2d35\nJSowjUXv+shLSw3d5DWxK/19Rl9mELZm5FyYOau0nGzMp53oA8n0snbgsnCAjYCI\nB394SK5MjW/MdE68L/5ZCm7ediMFdbEwabzTMCixHPaM9PYW6dGzujI4yQhAb+Eh\nvl55iqhWUxcWYGhm03x0VRPN6w7ICRoYCpM+SoemdR5EfXk0gB5tu2qLCKoH36+z\n+EC4Jn8FfKOqAY6L4xsGIJqlrQv8ObOz6q010EpbrXvBapKHiDVTcM9tc2Jg9MQ+\nzQgT271kaFblsw==", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ], 
        "name_id_format": [
          {
            "text": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }
        ]
      }
    ], 
    "organization": {
      "organization_name": [
        {
          "lang": "fi", 
          "text": "Arcada", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }, 
        {
          "lang": "en", 
          "text": "Arcada", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }, 
        {
          "lang": "sv", 
          "text": "Arcada", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }
      ], 
      "organization_display_name": [
        {
          "lang": "fi", 
          "text": "Arcada", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }, 
        {
          "lang": "en", 
          "text": "Arcada", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }, 
        {
          "lang": "sv", 
          "text": "Arcada", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }
      ], 
      "organization_url": [
        {
          "lang": "fi", 
          "text": "http://www.arcada.fi/", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }, 
        {
          "lang": "en", 
          "text": "http://www.arcada.fi/", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }, 
        {
          "lang": "sv", 
          "text": "http://www.arcada.fi/", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }
      ], 
      "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Organization"
    }, 
    "contact_person": [
      {
        "given_name": {
          "text": "Fredrik", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&GivenName"
        }, 
        "email_address": [
          {
            "text": "haka.admin@arcada.fi", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ], 
        "sur_name": {
          "text": "Finnberg", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SurName"
        }, 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "contact_type": "administrative"
      }, 
      {
        "given_name": {
          "text": "David", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&GivenName"
        }, 
        "email_address": [
          {
            "text": "haka@arcada.fi", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ], 
        "sur_name": {
          "text": "Sjoberg", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SurName"
        }, 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "contact_type": "administrative"
      }, 
      {
        "given_name": {
          "text": "Harald", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&GivenName"
        }, 
        "email_address": [
          {
            "text": "haka.technical@arcada.fi", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ], 
        "sur_name": {
          "text": "Hannelius", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SurName"
        }, 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "contact_type": "technical"
      }
    ]
  }, 
  "https://idp.tut.fi/shibboleth2": {
    "valid_until": "2012-12-19T20:15:01Z", 
    "entity_id": "https://idp.tut.fi/shibboleth2", 
    "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EntityDescriptor", 
    "idpsso_descriptor": [
      {
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&IDPSSODescriptor", 
        "single_sign_on_service": [
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleSignOnService", 
            "location": "https://idp.tut.fi/idp/profile/SAML2/Redirect/SSO"
          }, 
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SingleSignOnService", 
            "location": "https://idp.tut.fi/idp/profile/SAML2/POST/SSO"
          }
        ], 
        "extensions": {
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Extensions", 
          "extension_elements": [
            {
              "attribute_value": [
                {
                  "text": "kalmar", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }, 
                {
                  "text": "finland", 
                  "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&AttributeValue", 
                  "extension_attributes": {
                    "{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"
                  }
                }
              ], 
              "__class__": "urn:oasis:names:tc:SAML:2.0:assertion&Attribute", 
              "name": "tags"
            }
          ]
        }, 
        "key_descriptor": [
          {
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIEfjCCA2agAwIBAgIQWIB+VOhffDPHGuGeMVopmDANBgkqhkiG9w0BAQUFADA2\nMQswCQYDVQQGEwJOTDEPMA0GA1UEChMGVEVSRU5BMRYwFAYDVQQDEw1URVJFTkEg\nU1NMIENBMB4XDTExMTIwMTAwMDAwMFoXDTE0MTExODIzNTk1OVowXzELMAkGA1UE\nBhMCRkkxEDAOBgNVBAcTB1RhbXBlcmUxKTAnBgNVBAoTIFRhbXBlcmUgVW5pdmVy\nc2l0eSBvZiBUZWNobm9sb2d5MRMwEQYDVQQDEwppZHAudHV0LmZpMIIBIjANBgkq\nhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAstTbaAoJW/l2/SKvotrG1LClmBc18T11\nUdssfGkl8uc2DbiOhjiRtq8LQr2GrGrAOi3EQHSV6DK4CQecTKwXggdnFf79daBv\nBuCHTphd9096vo/pTi/DhFvY0bME1wO7SB0L8IzABCsnTkl/wGcQMxpBi4x49+7i\n/MkARsi8BbWhpdKhGEOVJTCmG1qGf6I+JDm8F99kWvFJXm81fx2NkFvSuSFrn2QL\n996U5WucBSLxsg8Se3Dbel6tP8egaXZSnbgxZoI3V9fT47YIXa2eA0cXKCc52I3T\nxQj4lx8EMpcdRMZkbs7Hmo1Wpnz6t0Js/nSOWWX1IfIOty7EKhQCcQIDAQABo4IB\nXTCCAVkwHwYDVR0jBBgwFoAUDL2TaAzz3qujSWsrN1dH6pDjue0wHQYDVR0OBBYE\nFLu8aVDgy1EMaH1Nqow2ZuJML2bsMA4GA1UdDwEB/wQEAwIFoDAMBgNVHRMBAf8E\nAjAAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAYBgNVHSAEETAPMA0G\nCysGAQQBsjEBAgIdMDoGA1UdHwQzMDEwL6AtoCuGKWh0dHA6Ly9jcmwudGNzLnRl\ncmVuYS5vcmcvVEVSRU5BU1NMQ0EuY3JsMG0GCCsGAQUFBwEBBGEwXzA1BggrBgEF\nBQcwAoYpaHR0cDovL2NydC50Y3MudGVyZW5hLm9yZy9URVJFTkFTU0xDQS5jcnQw\nJgYIKwYBBQUHMAGGGmh0dHA6Ly9vY3NwLnRjcy50ZXJlbmEub3JnMBUGA1UdEQQO\nMAyCCmlkcC50dXQuZmkwDQYJKoZIhvcNAQEFBQADggEBAJ8TRQUIymqyAB63Zv9f\nZBESdccwCknUEkv42cV9SKSuWaSWzVEfZgbr1dvBWEv/C7jRZJ9JIpcvP3Ow2e6b\naZPGFii79Dzxsi1wvt9pATsXeJI6uqgt4kcIh0kKOzwXs0k//R/Q4Q9gjhQbgbz6\nVJS/b8TpL1JFNTSSAaY3lBMRitQoI5bJaQ+g8lzztHVlp2i03doy51u3MIrRgMeR\nLuh8iZo7fcSQCO57okd/cCEl/dZ4UfDk6FGyd1069r6mCnOXIvGfSaFL3zHZMjsx\nA53q7i0tenMvCIqhv/Ti7MWJ4CTrV5BAfjQrlJF8eAUnr+98iqxEsRNiZ5pd+fqw\nFZ4=", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ], 
        "name_id_format": [
          {
            "text": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }, 
          {
            "text": "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }
        ]
      }
    ], 
    "attribute_authority_descriptor": [
      {
        "attribute_service": [
          {
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:SOAP", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AttributeService", 
            "location": "https://idp.tut.fi:8443/idp/profile/SAML2/SOAP/AttributeQuery"
          }
        ], 
        "protocol_support_enumeration": [
          "urn:oasis:names:tc:SAML:2.0:protocol"
        ], 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&AttributeAuthorityDescriptor", 
        "extensions": {
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Extensions"
        }, 
        "key_descriptor": [
          {
            "key_info": {
              "x509_data": [
                {
                  "x509_certificate": {
                    "text": "MIIEfjCCA2agAwIBAgIQWIB+VOhffDPHGuGeMVopmDANBgkqhkiG9w0BAQUFADA2\nMQswCQYDVQQGEwJOTDEPMA0GA1UEChMGVEVSRU5BMRYwFAYDVQQDEw1URVJFTkEg\nU1NMIENBMB4XDTExMTIwMTAwMDAwMFoXDTE0MTExODIzNTk1OVowXzELMAkGA1UE\nBhMCRkkxEDAOBgNVBAcTB1RhbXBlcmUxKTAnBgNVBAoTIFRhbXBlcmUgVW5pdmVy\nc2l0eSBvZiBUZWNobm9sb2d5MRMwEQYDVQQDEwppZHAudHV0LmZpMIIBIjANBgkq\nhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAstTbaAoJW/l2/SKvotrG1LClmBc18T11\nUdssfGkl8uc2DbiOhjiRtq8LQr2GrGrAOi3EQHSV6DK4CQecTKwXggdnFf79daBv\nBuCHTphd9096vo/pTi/DhFvY0bME1wO7SB0L8IzABCsnTkl/wGcQMxpBi4x49+7i\n/MkARsi8BbWhpdKhGEOVJTCmG1qGf6I+JDm8F99kWvFJXm81fx2NkFvSuSFrn2QL\n996U5WucBSLxsg8Se3Dbel6tP8egaXZSnbgxZoI3V9fT47YIXa2eA0cXKCc52I3T\nxQj4lx8EMpcdRMZkbs7Hmo1Wpnz6t0Js/nSOWWX1IfIOty7EKhQCcQIDAQABo4IB\nXTCCAVkwHwYDVR0jBBgwFoAUDL2TaAzz3qujSWsrN1dH6pDjue0wHQYDVR0OBBYE\nFLu8aVDgy1EMaH1Nqow2ZuJML2bsMA4GA1UdDwEB/wQEAwIFoDAMBgNVHRMBAf8E\nAjAAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAYBgNVHSAEETAPMA0G\nCysGAQQBsjEBAgIdMDoGA1UdHwQzMDEwL6AtoCuGKWh0dHA6Ly9jcmwudGNzLnRl\ncmVuYS5vcmcvVEVSRU5BU1NMQ0EuY3JsMG0GCCsGAQUFBwEBBGEwXzA1BggrBgEF\nBQcwAoYpaHR0cDovL2NydC50Y3MudGVyZW5hLm9yZy9URVJFTkFTU0xDQS5jcnQw\nJgYIKwYBBQUHMAGGGmh0dHA6Ly9vY3NwLnRjcy50ZXJlbmEub3JnMBUGA1UdEQQO\nMAyCCmlkcC50dXQuZmkwDQYJKoZIhvcNAQEFBQADggEBAJ8TRQUIymqyAB63Zv9f\nZBESdccwCknUEkv42cV9SKSuWaSWzVEfZgbr1dvBWEv/C7jRZJ9JIpcvP3Ow2e6b\naZPGFii79Dzxsi1wvt9pATsXeJI6uqgt4kcIh0kKOzwXs0k//R/Q4Q9gjhQbgbz6\nVJS/b8TpL1JFNTSSAaY3lBMRitQoI5bJaQ+g8lzztHVlp2i03doy51u3MIrRgMeR\nLuh8iZo7fcSQCO57okd/cCEl/dZ4UfDk6FGyd1069r6mCnOXIvGfSaFL3zHZMjsx\nA53q7i0tenMvCIqhv/Ti7MWJ4CTrV5BAfjQrlJF8eAUnr+98iqxEsRNiZ5pd+fqw\nFZ4=", 
                    "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Certificate"
                  }, 
                  "__class__": "http://www.w3.org/2000/09/xmldsig#&X509Data"
                }
              ], 
              "__class__": "http://www.w3.org/2000/09/xmldsig#&KeyInfo"
            }, 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&KeyDescriptor"
          }
        ], 
        "name_id_format": [
          {
            "text": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }, 
          {
            "text": "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&NameIDFormat"
          }
        ]
      }
    ], 
    "organization": {
      "organization_name": [
        {
          "lang": "fi", 
          "text": "Tampereen teknillinen yliopisto", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }, 
        {
          "lang": "en", 
          "text": "Tampere University of Technology", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }, 
        {
          "lang": "sv", 
          "text": "Tammerfors tekniska universitet", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationName"
        }
      ], 
      "organization_display_name": [
        {
          "lang": "fi", 
          "text": "Tampereen teknillinen yliopisto", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }, 
        {
          "lang": "en", 
          "text": "Tampere University of Technology", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }, 
        {
          "lang": "sv", 
          "text": "Tammerfors tekniska universitet", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationDisplayName"
        }
      ], 
      "organization_url": [
        {
          "lang": "fi", 
          "text": "http://www.tut.fi", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }, 
        {
          "lang": "en", 
          "text": "http://www.tut.fi", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }, 
        {
          "lang": "sv", 
          "text": "http://www.tut.fi", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&OrganizationURL"
        }
      ], 
      "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&Organization"
    }, 
    "contact_person": [
      {
        "given_name": {
          "text": "Teemu", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&GivenName"
        }, 
        "email_address": [
          {
            "text": "idp-support@tut.fi", 
            "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&EmailAddress"
          }
        ], 
        "sur_name": {
          "text": "Turpeinen", 
          "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&SurName"
        }, 
        "__class__": "urn:oasis:names:tc:SAML:2.0:metadata&ContactPerson", 
        "contact_type": "technical"
      }
    ]
  }
}
