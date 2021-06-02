#!/bin/sh

exec /usr/local/snort/bin/snort -c /etc/snort/etc/snort.lua "$@"