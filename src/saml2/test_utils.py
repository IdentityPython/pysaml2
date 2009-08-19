#!/usr/bin/env python

import string
import time
from saml2 import utils

def test_id():
    oid = utils.create_id()
    print oid
    assert len(oid) == 40
    for c in oid:
        assert c in string.lowercase
        
def test_get_date_and_time_now():
    dt = utils.get_date_and_time()
    # Should return something similar to 2009-07-09T10:24:28Z
    print dt
    assert isinstance(dt,basestring)
    assert len(dt) == 20

def test_get_date_and_time_old():
    t = time.struct_time((2009, 7, 9, 10, 39, 36, 3, 190,0))
    dt = utils.get_date_and_time(time.mktime(t))
    print dt
    assert isinstance(dt,basestring)
    assert len(dt) == 20
    assert dt == "2009-07-09T09:39:36Z"
    
def test_lib_init():
    utils.lib_init()