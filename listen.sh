#!/bin/sh

sc_args=
if [ "$1" = -v ]; then
    sc_args=-v
    shift
fi

echo "Listening on port 4080"
exec socat $sc_args TCP-LISTEN:4080,fork EXEC:"./httpd $*"
