#!/bin/sh
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes -keyout test.key -out test.crt -subj "/CN=localhost" 
# -addext "subjectAltName=DNS:example.com,DNS:example.net,IP:10.0.0.1"

