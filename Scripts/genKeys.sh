#!/bin/bash
# Thanks to https://gist.github.com/rozifus

openssl req -new -x509 -keyout cert.pem -out cert.pem -days 365 -nodes