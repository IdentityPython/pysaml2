import ConfigParser, os

from zope.interface import implements

#from repoze.who.interfaces import IChallenger, IIdentifier, IAuthenticator
from repoze.who.interfaces import IMetadataProvider

class INIMetadataProvider(object):
    
    implements(IMetadataProvider)
    
    def __init__(self, ini_file, key_attribute):

        self.users = ConfigParser.ConfigParser()
        self.users.readfp(open(ini_file))
        self.key_attribute = key_attribute
        
    def add_metadata(self, environ, identity):
        logger = environ.get('repoze.who.logger','')

        key = identity.get('repoze.who.userid')
        #logger and logger.info("Identity: %s (before)" % (identity.items(),))
        try:
            if self.key_attribute:
                for sec in self.users.sections():
                    if self.users.has_option(sec,self.key_attribute):
                        if key in self.users.get(sec, self.key_attribute):
                            identity["user"] = dict(self.users.items(sec))
                            break
            else:
                identity["user"] = dict(self.users.items(key))
            #logger and logger.info("Identity: %s (after)" % (identity.items(),))
        except ValueError:
            pass
        
def make_plugin(ini_file, key_attribute=""):
    return INIMetadataProvider(ini_file, key_attribute)
