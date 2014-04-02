#!/bin/sh
rm -f ./code/*
sphinx-apidoc -F -o ../doc/code ../src
make clean
make html
