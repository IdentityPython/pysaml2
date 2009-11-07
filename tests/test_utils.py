#!/usr/bin/env python
# -*- coding: utf-8 -*-

from saml2.utils import deflate_and_base64_encode
from saml2.utils import decode_base64_and_inflate
import zlib
import base64
import gzip
from saml2.sigver import make_temp

def test_encode_decode():
    package = "1234567890abcdefghijklmnopqrstuvxyzåäö"

    intermediate = deflate_and_base64_encode(package)
    res = decode_base64_and_inflate(intermediate)
    assert package == res
    
