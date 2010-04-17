#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 

from saml2 import metadata
from saml2.assertion import Policy
from saml2.attribute_converter import ac_factory, AttributeConverter

class MissingValue(Exception):
    pass
    
def entity_id2url(meta, entity_id):
    """ Grab the first endpoint if there are more than one, 
        raises IndexError if the function returns an empty list.
     
    :param meta: MetaData instance
    :param entity_id: The entity id of the entity for which an
        endpoint is sought
    :return: An endpoint (URL)
    """
    return meta.single_sign_on_services(entity_id)[0]
    
class Config(dict):
    def _sp_check(self, config, metadat=None):
        """ Verify that the SP configuration part is correct.
        
        """
        if metadat:
            if "idp" not in config or len(config["idp"]) == 0:
                eids = [e for e, d in metadat.entity.items() if "idp_sso" in d]
                config["idp"] = {}
                for eid in eids:
                    try:
                        config["idp"][eid] = entity_id2url(metadat, eid)
                    except (IndexError, KeyError):
                        if not config["idp"][eid]:
                            raise MissingValue
            else:
                for eid, url in config["idp"].items():
                    if not url:
                        config["idp"][eid] = entity_id2url(metadat, eid)
        else:
            assert "idp" in config
            assert len(config["idp"]) > 0
        
        assert "url" in config
        assert "name" in config
            
    def _idp_aa_check(self, config):
        assert "url" in config
        if "assertions" in config:
            config["policy"] = Policy(config["assertions"])
            del config["assertions"]
        elif "policy" in config:
            config["policy"] = Policy(config["policy"])
                
    def load_metadata(self, metadata_conf, xmlsec_binary, acs):
        """ Loads metadata into an internal structure """
        metad = metadata.MetaData(xmlsec_binary, acs)
        if "local" in metadata_conf:
            for mdfile in metadata_conf["local"]:
                metad.import_metadata(open(mdfile).read(), mdfile)
        if "remote" in metadata_conf:
            for spec in metadata_conf["remote"]:
                try:
                    cert = spec["cert"]
                except KeyError:
                    cert = None
                metad.import_external_metadata(spec["url"], cert)
        return metad
                
    def load_file(self, config_file):
        return self.load(eval(open(config_file).read()))
        
    def load(self, config):
    
        # check for those that have to be there
        assert "xmlsec_binary" in config
        assert "service" in config
        assert "entityid" in config
        
        if "key_file" in config:
            # If you have a key file you have to have a cert file
            assert "cert_file" in config
        else:
            config["key_file"] = None
            
        if "attribute_map_dir" in config:
            config["attrconverters"] = ac_factory(
                                                config["attribute_map_dir"])
        else:
            config["attrconverters"] = [AttributeConverter()]

        if "metadata" in config:
            config["metadata"] = self.load_metadata(config["metadata"],
                                                    config["xmlsec_binary"],
                                                    config["attrconverters"])
                    
        if "sp" in config["service"]:
            #print config["service"]["sp"]
            if "metadata" in config:
                self._sp_check(config["service"]["sp"], config["metadata"])
            else:
                self._sp_check(config["service"]["sp"])
        if "idp" in config["service"]:
            self._idp_aa_check(config["service"]["idp"])
        if "aa" in config["service"]:
            self._idp_aa_check(config["service"]["aa"])
                            
        for key, val in config.items():
            self[key] = val
        
        return self
    
    def xmlsec(self):
        return self["xmlsec_binary"]
        
    def services(self):
        return self["service"].keys()
        
    def idp_policy(self):
        try:
            return self["service"]["idp"]["policy"]
        except KeyError:
            return Policy()
        
    def aa_policy(self):
        try:
            return self["service"]["aa"]["policy"]
        except KeyError:
            return Policy()
            
    def aa_url(self):
        return self["service"]["aa"]["url"]

    def idp_url(self):
        return self["service"]["idp"]["url"]
        
    def vo_conf(self, name):
        return self["virtual_organization"][name]

    def attribute_converters(self):
        return self["attrconverters"]

