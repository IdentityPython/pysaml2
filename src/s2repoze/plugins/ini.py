import ConfigParser, os

from zope.interface import implements

from repoze.who.interfaces import IChallenger, IIdentifier, IAuthenticator
from repoze.who.interfaces import IMetadataProvider

class INIMetadataProvider(object):
    
    implements(IMetadataProvider)
    
    def __init__(self, ini_file):

        self.users = ConfigParser.ConfigParser()
        self.users.readfp(open(ini_file))
        
#    def authenticate(self, environ, identity):
#        try:
#            username = identity['login']
#            password = identity['password']
#        except KeyError:
#            return None
#        
#        success = User.authenticate(username, password)
#        
#        return success

    def add_metadata(self, environ, identity):
        logger = environ.get('repoze.who.logger','')

        username = identity.get('repoze.who.userid')
        logger and logger.info("Identity: %s (before)" % (identity.items(),))
        try:
            identity["user"] = self.users.items(username)
            logger and logger.info("Identity: %s (after)" % (identity.items(),))
        except ValueError:
            pass
        
def make_plugin(ini_file):
    return INIMetadataProvider(ini_file)
