from paste.request import construct_url

import re 

class my_challenge_decider:
    def __init__(self,path_login=""):
        self.path_login = path_login
    def __call__(self, environ, status, headers):
        if status.startswith('401 '):
            return True
        else:
            # logout : need to "forget" => require a peculiar challenge
            if environ.has_key('rwpc.logout'):
                return True

            # If the user is already authent, whatever happens(except logout), 
            #   don't make a challenge
            if environ.has_key('repoze.who.identity'): 
                return False

            uri = environ.get('REQUEST_URI', None)
            if uri is None:
                uri = construct_url(environ)

            # require a challenge for login
            for regex in self.path_login:
                if regex.match(uri) != None:
                    return True

        return False



def make_plugin(path_login = None):
    if path_login is None:
        raise ValueError(
            'must include path_login in configuration')

# make regexp out of string passed via the config file
    list_login = []
    for a in path_login.splitlines():
        u = a.lstrip()
        if u != '':
            list_login.append(re.compile(u))

    plugin = my_challenge_decider(list_login)

    return plugin

