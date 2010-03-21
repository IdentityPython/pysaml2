#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 

from saml2 import metadata, utils
import re

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

def do_assertions(assertions):
    """ This is only for IdPs or AAs, and it's about limiting what
    is returned to the SP. 
    In the configuration file, restrictions on which values that 
    can be returned are specified with the help of regular expressions.
    This function goes through and pre-compile the regular expressions.
    
    :param assertions:
    :return: The assertion with the string specification replaced with
        a compiled regular expression.
    """
    for _, spec in assertions.items():
        if spec == None:
            continue
            
        try:
            restr = spec["attribute_restrictions"]
        except KeyError:
            continue
            
        if restr == None:
            continue
            
        for key, values in restr.items():
            if not values:
                spec["attribute_restrictions"][key] = None
                continue
                
            rev = []
            for value in values:
                rev.append(re.compile(value))
            spec["attribute_restrictions"][key] = rev
    
    return assertions
    
class Config(dict):
    def sp_check(self, config, metadata=None):
        """ config["idp"] is a dictionary with entity_ids as keys and
        urls as values
        """
        if metadata:
            if "idp" not in config or len(config["idp"]) == 0:
                eids = [e for e, d in metadata.entity.items() if "idp_sso" in d]
                config["idp"] = {}
                for eid in eids:
                    try:
                        config["idp"][eid] = entity_id2url(metadata, eid)
                    except IndexError, KeyError:
                        if not config["idp"][eid]:
                            raise MissingValue
            else:
                for eid, url in config["idp"].items():
                    if not url:
                        config["idp"][eid] = entity_id2url(metadata, eid)
        else:
            assert "idp" in config
            assert len(config["idp"]) > 0
        
        assert "url" in config
        assert "name" in config
            
    def idp_check(self, config):
        assert "url" in config
        if "assertions" in config:
            config["assertions"] = do_assertions(config["assertions"])
        
    def aa_check(self, config):
        assert "url" in config
        if "assertions" in config:
            config["assertions"] = do_assertions(config["assertions"])
        
    def load_metadata(self, metadata_conf):
        """ Loads metadata into an internal structure """
        metad = metadata.MetaData()
        if "local" in metadata_conf:
            for mdfile in metadata_conf["local"]:
                metad.import_metadata(open(mdfile).read(), 
                                        "local:%s" % mdfile)
        if "remote" in metadata_conf:
            for _, val in metadata_conf["remote"].items():
                metad.import_external_metadata(val["url"], val["cert"])
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
            
        if "metadata" in config:
            config["metadata"] = self.load_metadata(config["metadata"])
            
        if "attribute_maps" in config:
            (forward, backward) = utils.parse_attribute_map(config[
                                                            "attribute_maps"])
            config["am_forward"] = forward
            config["am_backward"] = backward
        else:
            config["am_forward"] = None
            config["am_backward"] = None
        
        if "sp" in config["service"]:
            #print config["service"]["sp"]
            if "metadata" in config:
                self.sp_check(config["service"]["sp"], config["metadata"])
            else:
                self.sp_check(config["service"]["sp"])
        if "idp" in config["service"]:
            self.idp_check(config["service"]["idp"])
        if "aa" in config["service"]:
            self.aa_check(config["service"]["aa"])
                            
        for key, val in config.items():
            self[key] = val
        
        return self