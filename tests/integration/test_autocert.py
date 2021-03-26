import time
from wsgiref.simple_server import make_server

import requests

from autocert import autocert
from autocert.wsgi import BackgroundWSGIServer, hello_world_app


def test_autocert():
    domains = ['autocert.example.org', 'www.autocert.example.org']

    # start WSGI server
    with make_server('127.0.0.1', 0, hello_world_app, server_class=BackgroundWSGIServer) as httpd:
        host, port = httpd.server_address
        url = 'https://{}:{}'.format(host, port)

        # wrap the socket w/ autocert
        httpd.socket = autocert.manage(httpd.socket, *domains, accept_tos=True)

#        # requests gives bad cert error
#        # try a few times til cert goes green
#        for _ in range(3):
#            try:
#                resp = requests.get(url)
#            except requests.exceptions.SSLError:
#                time.sleep(1)
#        else:
#            assert False
