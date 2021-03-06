from autocert import autocert, wsgi
import os
import socket
import waitress

# make sure systemd PID matches
if os.environ['LISTEN_PID'] != str(os.getpid()):
    raise SystemExit('Mismatched LISTEN_PID')

# expecting 1 port here: 443
if os.environ['LISTEN_FDS'] != '1':
    raise SystemExit('Expected 1 socket fd for port 443')

# create socket from the fd opened by systemd
s443 = socket.fromfd(3, socket.AF_INET, socket.SOCK_STREAM)

# setup automatic cert issuance and renewal
s443_tls = autocert.manage(s443, 'example.org', 'www.example.org', accept_tos=True)

# serve your app with TLS!
waitress.serve(wsgi.hello_world_app, sockets=[s443_tls], url_scheme='https')
