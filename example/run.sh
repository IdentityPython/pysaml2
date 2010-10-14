#!/bin/sh

# run.sh
# pysaml2
#
# Created by Roland Hedberg on 3/25/10.
# Copyright 2010 Umeå Universitet. All rights reserved.

../tools/make_metadata.py sp/sp.conf idp/idp.conf > metadata.xml
cd sp
./sp.py sp.conf &

cd ../idp
./idp.py idp.conf &

cd ..

