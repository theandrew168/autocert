from autocert import autocert
import socket
import waitress

# open a socket on port 443
s443 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s443.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s443.bind(('0.0.0.0', 443))
s443.listen()

# setup automatic cert issuance and renewal
s443_tls = autocert.do(s443, 'example.org', 'www.example.org', accept_tos=True)

# serve your app with TLS!
waitress.serve(my_wsgi_app, sockets=[s443_tls], url_scheme='https')
