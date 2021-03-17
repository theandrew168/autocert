from urllib.parse import quote


def hello_world_app(environ, start_response):
    status = '200 OK'
    response_headers = [('Content-Type', 'text/plain')]
    start_response(status, response_headers)
    return [b'Hello world from autocert!\n']


def redirect_app(environ, start_response):
    status = '301 Moved Permanently'
    response_headers = [('Location', reconstruct_https_url(environ))]
    start_response(status, response_headers)
    return [b'']


# https://www.python.org/dev/peps/pep-3333/#url-reconstruction
def reconstruct_https_url(environ):
    url = 'https://'

    if environ.get('HTTP_HOST'):
        url += environ['HTTP_HOST']
    else:
        url += environ['SERVER_NAME']

        if environ['wsgi.url_scheme'] == 'https':
            if environ['SERVER_PORT'] != '443':
               url += ':' + environ['SERVER_PORT']
        else:
            if environ['SERVER_PORT'] != '80':
               url += ':' + environ['SERVER_PORT']

    url += quote(environ.get('SCRIPT_NAME', ''))
    url += quote(environ.get('PATH_INFO', ''))
    if environ.get('QUERY_STRING'):
        url += '?' + environ['QUERY_STRING']

    return url
