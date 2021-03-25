from autocert.wsgi import hello_world_app, redirect_app
from autocert.wsgi import reconstruct_https_url


def test_reconstruct_https_url_basic():
    environ = {
        'HTTP_HOST': 'example.org',
    }

    url = reconstruct_https_url(environ)
    assert url == 'https://example.org'


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
