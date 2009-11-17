#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 

from saml2 import metadata

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

class Config(dict):
    def sp_check(self, config):
        assert "idp" in config
        
        if "metadata" in config:
            md = config["metadata"]
            
            if "entity_id" in config["idp"]:
                if not "url" in config["idp"]:
                    config["idp"]["url"] = []
                urls = config["idp"]["url"]
                for eid in config["idp"]["entity_id"]:
                    url = entity_id2url(md, eid)
                    if url:
                        if url not in urls:
                            urls.append(url)
                
        assert "sp" in config["service"]
        assert "url" in config["service"]["sp"]
            
    def idp_check(self, config):
        pass
        
    def aa_check(self, config):
        pass
        
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
            self.sp_check(config)
        if "idp" in config["service"]:
            self.idp_check(config)
        if "aa" in config["service"]:
            self.aa_check(config)
                    
        
        for key, val in config.items():
            self[key] = val