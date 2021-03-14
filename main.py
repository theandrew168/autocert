from autocert import autocert
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
s443_tls = autocert.do(s443, 'example.org', accept_tos=True)

# example WSGI app (could be Flask, Django, etc)
def my_wsgi_app(environ, start_response):
    status = '200 OK'
    response_headers = [('Content-Type', 'text/plain')]
    start_response(status, response_headers)
    return [b'Hello world from simple WSGI app\n']

# serve your app with TLS!
waitress.serve(my_wsgi_app, sockets=[s443_tls], url_scheme='https')
