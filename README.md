# autocert
Automatic TLS cert issuance and renewal for Python web apps

## Overview
Autocert is a package for automatically obtaining and renewing TLS certificates from [Let's Encrypt](https://letsencrypt.org/) using the [ACME](https://en.wikipedia.org/wiki/Automated_Certificate_Management_Environment) protocol.
It is based on the API and design of the [Go](https://golang.org/) package with the same name: [autocert](https://pkg.go.dev/golang.org/x/crypto/acme/autocert).
To work its magic, autocert only requires two TCP sockets: one listening on port 80 and another listening on port 443.
These can come directly from an application or from a management system such as [systemd](https://www.freedesktop.org/software/systemd/man/systemd.socket.html).

## Install
If you are unfamiliar with [virtual environments](https://docs.python.org/3/library/venv.html), I suggest taking a brief moment to learn about them and set one up.
The Python docs provide a great [tutorial](https://docs.python.org/3/tutorial/venv.html) for getting started with virtual environments and packages.

Autocert can be installed via pip:
```
pip install autocert
```

## Examples
These example utilize the [waitress](https://docs.pylonsproject.org/projects/waitress/en/stable/) WSGI server but you can follow your own preference.
However, whichever server you choose must be able to accept pre-listening sockets.

### basic
Here is a basic example of autocert usage (requires root):
```python
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
```

### systemd
Here is an example of using autocert with systemd sockets:
```python
from autocert import autocert
import os
import socket
import waitress

# make sure systemd PID matches
if os.environ['LISTEN_PID'] != os.getpid():
    raise SystemExit('Mismatched LISTEN_PID')

# expecting 1 port here: 80
if os.environ['LISTEN_FDS'] != 1:
    raise SystemExit('Expected 1 socket fd for port 443')

# create socket from the fd opened by systemd
s443 = socket.fromfd(3, socket.AF_INET, socket.SOCK_STREAM)

# setup automatic cert issuance and renewal
s443_tls = autocert.do(s443, 'example.org', 'www.example.org', accept_tos=True)

# serve your app with TLS!
waitress.serve(my_wsgi_app, sockets=[s443_tls], url_scheme='https')
```

### systemd w/ redirect
Here is an example of using autocert with systemd sockets and an HTTP->HTTPS redirect:
```python
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
```
