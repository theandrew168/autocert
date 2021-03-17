from autocert import autocert, wsgi
import socket
import waitress

import logging
logging.basicConfig(level=logging.INFO)

# open a socket on port 443
s443 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s443.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s443.bind(('0.0.0.0', 8443))
s443.listen()

# setup automatic cert issuance and renewal
s443_tls = autocert.manage(s443, 'example.org', accept_tos=True)

# serve your app with TLS!
waitress.serve(wsgi.hello_world_app, sockets=[s443_tls], url_scheme='https')
