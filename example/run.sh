#!/bin/sh

# Created by Roland Hedberg on 3/25/10.
# Copyright 2010 Umeå Universitet. All rights reserved.

cd sp
../../tools/make_metadata.py sp_conf > sp.xml

cd ../idp
../../tools/make_metadata.py idp_conf > idp.xml

cd ../sp
./sp.py sp_conf &

cd ../idp
./idp.py idp_conf &

cd ..

