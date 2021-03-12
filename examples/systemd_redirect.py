from autocert import autocert, wsgi
import os
import socket
import threading
import waitress

# make sure systemd PID matches
if os.environ['LISTEN_PID'] != os.getpid():
    raise SystemExit('Mismatched LISTEN_PID')

# expecting 2 ports here: 80, 443
if os.environ['LISTEN_FDS'] != 2:
    raise SystemExit('Expected 2 socket fds for ports 80 and 443')

# create sockets from the fds opened by systemd
s80 = socket.fromfd(3, socket.AF_INET, socket.SOCK_STREAM)
s443 = socket.fromfd(4, socket.AF_INET, socket.SOCK_STREAM)

# start autocert's wsgi.redirect_app in a background thread
t = threading.Thread(
    target=waitress.serve,
    args=(wsgi.redirect_app,),
    kwargs={'sockets': [s80]},
    daemon=True,
)
t.start()

# setup automatic cert issuance and renewal
s443_tls = autocert.do(s443, 'example.org', 'www.example.org', accept_tos=True)

# serve your app with TLS!
waitress.serve(my_wsgi_app, sockets=[s443_tls], url_scheme='https')
