from saml2.samlp import NewID
from saml2.saml import NameID, NAMEID_FORMAT_TRANSIENT
from saml2.client import Saml2Client
from saml2.server import Server

__author__ = 'rolandh'

def test_basic():
    sp = Saml2Client(config_file="servera_conf")
    idp = Server(config_file="idp_all_conf")

    # -------- @SP ------------
    binding, destination = sp.pick_binding("manage_name_id_service",
                                           entity_id=idp.config.entityid)

    nameid = NameID(format=NAMEID_FORMAT_TRANSIENT, text="foobar")
    newid = NewID(text="Barfoo")

    mid = sp.create_manage_name_id_request(destination, name_id=nameid,
                                           new_id=newid)

    print mid
    rargs = sp.apply_binding(binding, "%s" % mid, destination, "")

    # --------- @IDP --------------

    _req = idp.parse_manage_name_id_request(rargs["data"], binding)

    print _req.message

    assert mid.id == _req.message.id
