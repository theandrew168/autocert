import threading
from wsgiref.simple_server import make_server, WSGIServer

import requests

from autocert.wsgi import hello_world_app, redirect_app
from autocert.wsgi import reconstruct_https_url


class BackgroundWSGIServer(WSGIServer):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.thread = None

    def __enter__(self):
        super().__enter__()
        self.thread = threading.Thread(target=self.serve_forever)
        self.thread.start()
        return self

    def __exit__(self, *args):
        super().__exit__(*args)
        self.shutdown()
        self.thread.join()


def test_hello_world_app():
    with make_server('127.0.0.1', 0, hello_world_app, server_class=BackgroundWSGIServer) as httpd:
        host, port = httpd.server_address
        url = 'http://{}:{}'.format(host, port)

        resp = requests.get(url)
        assert resp.status_code == 200
        assert 'autocert' in resp.text


def test_redirect_app():
    with make_server('127.0.0.1', 0, redirect_app, server_class=BackgroundWSGIServer) as httpd:
        host, port = httpd.server_address
        url = 'http://{}:{}'.format(host, port)

        resp = requests.get(url, allow_redirects=False)
        assert resp.status_code == 301
        location = resp.headers['Location']
        assert location == 'https://{}:{}/'.format(host, port)


def test_reconstruct_https_url_basic():
    environ = {
        'HTTP_HOST': 'example.org',
        'PATH_INFO': '/',
    }

    url = reconstruct_https_url(environ)
    assert url == 'https://example.org/'


def test_reconstruct_https_url_path():
    environ = {
        'HTTP_HOST': 'example.org',
        'PATH_INFO': '/hello/world',
    }

    url = reconstruct_https_url(environ)
    assert url == 'https://example.org/hello/world'


def test_reconstruct_https_url_query():
    environ = {
        'HTTP_HOST': 'example.org',
        'PATH_INFO': '/hello/world',
        'QUERY_STRING': 'foo=bar&baz=42',
    }

    url = reconstruct_https_url(environ)
    assert url == 'https://example.org/hello/world?foo=bar&baz=42'


def test_reconstruct_https_url_no_http_host():
    environ = {
        'SERVER_NAME': 'example.org',
        'SERVER_PORT': '443',
        'PATH_INFO': '/hello/world',
        'QUERY_STRING': 'foo=bar&baz=42',
    }

    url = reconstruct_https_url(environ)
    assert url == 'https://example.org/hello/world?foo=bar&baz=42'


def test_reconstruct_https_url_no_http_host_8443():
    environ = {
        'SERVER_NAME': 'example.org',
        'SERVER_PORT': '8443',
        'PATH_INFO': '/hello/world',
        'QUERY_STRING': 'foo=bar&baz=42',
    }

    url = reconstruct_https_url(environ)
    assert url == 'https://example.org:8443/hello/world?foo=bar&baz=42'
