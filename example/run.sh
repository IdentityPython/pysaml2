#!/bin/sh

cd sp-wsgi
if [ ! -f conf.py ] ; then
    cp conf.py.example conf.py
fi
../../tools/make_metadata.py conf > sp.xml

cd ../idp2
if [ ! -f idp_conf.py ] ; then
    cp idp_conf.py.example conf.py
fi
../../tools/make_metadata.py idp_conf > idp.xml

cd ../sp-wsgi
./sp.py sp_conf &

cd ../idp2
./idp.py idp_conf &

cd ..

