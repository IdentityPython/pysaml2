#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 

from saml2 import metadata
import re

def entity_id2url(md, entity_id):
    try:
        # grab the first one
        return md.single_sign_on_services(entity_id)[0]
    except Exception:
        print "idp_entity_id",entity_id
        print ("idps in metadata",
            [e for e,d in md.entity.items() if "idp_sso" in d])
        print "metadata entities", md.entity.keys()
        for ent, dic in md.entity.items():
            print ent, dic.keys()
        return None

def do_assertions(assertions):
    for id, spec in assertions.items():
        try:
            restr = spec["attribute_restrictions"]
        except:
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
    def sp_check(self, config, md=None):
        assert "idp" in config
        assert len(config["idp"]) > 0

        if md:
            
            if len(config["idp"]) == 0:
                eids = [e for e,d in md.entity.items() if "idp_sso" in d]
                for eid in eids:
                    config["idp"][eid] = entity_id2url(md, eid)
            else:
                for eid, url in config["idp"].items():
                    if not url:
                        config["idp"][eid] = entity_id2url(md, eid)
        
        assert "url" in config
            
    def idp_check(self, config):
        assert "url" in config
        if "assertions" in config:
            config["assertions"] = do_assertions(config["assertions"])
        
    def aa_check(self, config):
        assert "url" in config
        if "assertions" in config:
            config["assertions"] = do_assertions(config["assertions"])
        
    def load_metadata(self, metadata_conf):
        """ """
        md = metadata.MetaData()
        if "local" in metadata_conf:
            for mdfile in metadata_conf["local"]:
                md.import_metadata(open(mdfile).read())
        if "remote" in metadata_conf:
            for key,val in metadata_conf["remote"].items():
                md.import_external_metadata(val["url"],val["cert"])
        return md
                
    def load_file(self, config_file):
        self.load(eval(open(config_file).read()))
        
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
            
        if "sp" in config["service"]:
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