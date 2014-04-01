#!/bin/sh

startme() {
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
    ./sp.py conf &

    cd ../idp2
    ./idp.py idp_conf &

    cd ..
}

stopme() {
    pkill -f "sp.py"
    pkill -f "idp.py"
}

case "$1" in
    start)   startme ;;
    stop)    stopme ;;
    restart) stopme; startme ;;
    *) echo "usage: $0 start|stop|restart" >&2
       exit 1
       ;;
esac