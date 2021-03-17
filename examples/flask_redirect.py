from autocert import autocert, wsgi
from flask import Flask
import socket
import threading
import waitress

# create a minimal Flask application
app = Flask(__name__)

@app.route('/')
def hello_world():
    return 'Hello world from flask!'

# open a socket on port 80
s80 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s80.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s80.bind(('0.0.0.0', 80))
s80.listen()

# open a socket on port 443
s443 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s443.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s443.bind(('0.0.0.0', 443))
s443.listen()

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
waitress.serve(app, sockets=[s443_tls], url_scheme='https')
