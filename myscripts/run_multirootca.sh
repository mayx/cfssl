#!/bin/sh
ENABLEHTPASSWD=1 ../bin/multirootca \
            -l default \
            -roots ../myconfig/multirootca_config.ini \
	    -tls-cert ../myconfig/tls-cert.pem \
	    -tls-key ../myconfig/tls-key.pem
