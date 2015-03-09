#!/bin/bash

openssl req -nodes -new -x509 -keyout key.pem -out cert.pem -days 1000
