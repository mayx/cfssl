ENABLEHTPASSWD=1 ../bin/multirootca \
            -l default \
            -roots multirootca_config.ini \
	    -tls-cert tls-cert.pem \
	    -tls-key tls-key.pem
