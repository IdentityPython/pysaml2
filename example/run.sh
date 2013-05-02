#!/bin/sh

cd sp
../../tools/make_metadata.py sp_conf > sp.xml

cd ../idp2
../../tools/make_metadata.py idp_conf > idp.xml

cd ../sp
./sp.py sp_conf &

cd ../idp2
./idp.py idp_conf &

cd ..

