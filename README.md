# autocert
Automatic TLS cert issuance and renewal for Python web apps

## Overview
Autocert is a package for automatically obtaining and renewing TLS certificates from [Let's Encrypt](https://letsencrypt.org/) using the [ACME](https://en.wikipedia.org/wiki/Automated_Certificate_Management_Environment) protocol.
It is based on the API and design of the [Go](https://golang.org/) package with the same name: [autocert](https://pkg.go.dev/golang.org/x/crypto/acme/autocert).
To work its magic, autocert only requires a single TCP socket listening on your desired HTTPS port (usually 443).
This can come directly from an application or from a management system such as [systemd](https://www.freedesktop.org/software/systemd/man/systemd.socket.html).

## Motivation
I often find myself with the need to host simple Python web apps as demos for friends / clients.
In these situations, I want the demo to be properly secured via [HTTPS](https://en.wikipedia.org/wiki/HTTPS) but I don't want to worry about the extra infrastructure that comes with setting up a reverse proxy ([NGINX](http://nginx.org/), [Caddy](https://caddyserver.com/), etc).
This library allows you to add an auto-renewing TLS certificate from [Let's Encrypt](https://letsencrypt.org/) to your website with a single line of code.

There is quite a bit of dogma surrounding the hosting of Python-based web applications.
Most folks believe that utilizing a [reverse proxy](https://en.wikipedia.org/wiki/Reverse_proxy) is a hard requirement for achieving a secure, fast, and reliable deployment.
However, I really like the simplicity of hosting a [Flask](https://flask.palletsprojects.com/en/1.1.x/) or [Django](https://www.djangoproject.com/) app by combining a pure-Python [WSGI server](https://www.python.org/dev/peps/pep-3333/) (such as [Waitress](https://docs.pylonsproject.org/projects/waitress/en/stable/)) with this project.
It might not be the best deployment option for a high-traffic, business-critical applications but it can easily support a few hundred requests per second on a small [Digital Ocean](https://www.digitalocean.com/) droplet.

## Install
If you are unfamiliar with [virtual environments](https://docs.python.org/3/library/venv.html), I suggest taking a brief moment to learn about them and set one up.
The Python docs provide a great [tutorial](https://docs.python.org/3/tutorial/venv.html) for getting started with virtual environments and packages.

Autocert can be installed via pip:
```
pip install autocert
```

## Examples
These examples utilize the [Waitress](https://docs.pylonsproject.org/projects/waitress/en/stable/) WSGI server but you can follow your own preference.
However, whichever server you choose must be able to accept pre-listening sockets (you'll see what I mean).
More examples can be found in the [examples directory](https://github.com/theandrew168/autocert/tree/main/examples).

Waitress can be installed via pip:
```
pip install waitress
```

### basic
Here is a basic example of autocert usage (requires root):
```python
from autocert import autocert, wsgi
import socket
import waitress

# open a socket on port 443
s443 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s443.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s443.bind(('0.0.0.0', 443))
s443.listen()

# setup automatic cert issuance and renewal
s443_tls = autocert.manage(s443, 'example.org', 'www.example.org', accept_tos=True)

# serve your app with TLS!
waitress.serve(wsgi.hello_world_app, sockets=[s443_tls], url_scheme='https')
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
s443_tls = autocert.manage(s443, 'example.org', 'www.example.org', accept_tos=True)

# serve your app with TLS!
waitress.serve(wsgi.hello_world_app, sockets=[s443_tls], url_scheme='https')
```

## Testing
Autocert is tested using [pytest](). Unit tests can be executed without anything special but the integration tests expect a locally-running ACME server. Running [pebble]() in a container is a great way to accomplish this!

To run the tests, first install pytest:
```
pip install pytest
```

Then, unit tests can be ran via:
```
pytest tests/unit/
```

The integration tests need that local ACME server so let's start it up and set some necessary vars:
```
docker run -p 14000:14000 --detach letsencrypt/pebble
```

Now the integration tests can be ran:
```
pytest tests/integration/
```
