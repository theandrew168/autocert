# autocert
Automatic TLS cert acquisition and renewal for Python web apps

## Overview
Autocert is a package for automatically obtaining and renewing TLS certificates from [Let's Encrypt](https://letsencrypt.org/) using the [ACME](https://en.wikipedia.org/wiki/Automated_Certificate_Management_Environment) protocol.
It is based on the API and design of the [Go](https://golang.org/) package with the same name: [autocert](https://pkg.go.dev/golang.org/x/crypto/acme/autocert).
To work its magic, autocert only requires two TCP sockets: one listening on port 80 and another listening on port 443.
These can come directly from an application with the ability to listen on privileged ports or from a management system such as [systemd](https://www.freedesktop.org/software/systemd/man/systemd.socket.html).

## Install
If you are unfamiliar with [virtual environments](https://docs.python.org/3/library/venv.html), I suggest taking a brief moment to learn about them and set one up.
The Python docs provide a great [tutorial](https://docs.python.org/3/tutorial/venv.html) for getting started with virtual environments and packages.

Autocert can be installed via pip:
```
pip install autocert
```

## Examples
### basic
Here is a basic example of autocert usage (requires root):
```python
import autocert
import socket

s80 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s80.bind(('0.0.0.0', 80))
s80.listen()

s443 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s443.bind(('0.0.0.0', 443))
s443.listen()

# tls_s443 can now be used for serving HTTPS web traffic
tls_s443 = autocert.do(s80, s443, 'example.org', 'www.example.org')

# waitress example
import waitress
waitress.serve(my_wsgi_app, sockets=[tls_s443], url_scheme='https')
```

### systemd
Here is an example of using autocert with systemd sockets:
```python
import autocert
import os
import socket

if os.environ['LISTEN_PID'] != os.getpid():
    raise SystemExit('Mismatched LISTEN_PID')

if os.enivron['LISTEN_FDS'] != 2:
    raise SystemExit('Expected 2 socket fds for ports 80 and 443')

s80 = socket.fromfd(3, socket.AF_INET, socket.SOCK_STREAM)
s443 = socket.fromfd(4, socket.AF_INET, socket.SOCK_STREAM)

# tls_s443 can now be used for serving HTTPS web traffic
tls_s443 = autocert.do(s80, s443, 'example.org', 'www.example.org')

# waitress example
import waitress
waitress.serve(my_wsgi_app, sockets=[tls_s443], url_scheme='https')
```
