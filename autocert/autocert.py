import os
import socket
import ssl
import tempfile
import threading
import time

from autocert import acme


class ACMEClient:

    def do_tls_alpn_01_challenge(self, domain, challenge):

        # create an SSLContext and add our cert
        ctx = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
        ctx.set_ciphers('ECDHE+AESGCM')
        ctx.set_alpn_protocols(['acme-tls/1'])
        ctx.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        ctx.load_verify_locations(cadata=cert)
        print(ctx.cert_store_stats())


def do(s443, *domains, accept_tos=False):
    # ensure args are valid
    if not accept_tos:
        raise AutocertError("CA's Terms of Service must be accepted")
    if not isinstance(s443, socket.socket):
        raise AutocertError('Socket s443 must be a socket')
#    if s443.getsockname()[1] != 443:
#        raise AutocertError('Socket s443 must be listening on port 443')

    from pprint import pprint
    client = acme.ACMEClient(accept_tos=True)

    order = client.create_order(domains)
    pprint(order)

    auth_urls = order['authorizations']
    for auth_url in auth_urls:
        auth = client.get_authorization(auth_url)
        pprint(auth)

        # pull out the domain and TLS-ALPN-01 challenge
        domain = auth['identifier']['value']
        challenge = [c for c in auth['challenges'] if c['type'] == 'tls-alpn-01'][0]

        key, cert = acme.generate_tls_alpn_01_key_cert(challenge, domain, client.jwk)

        # TODO: make these better somehow
        fd, key_path = tempfile.mkstemp()
        os.write(fd, key)
        os.close(fd)

        fd, cert_path = tempfile.mkstemp()
        os.write(fd, cert)
        os.close(fd)

        def load_cert(sslsocket, sni_name, sslcontext):
            print('got request for: {}'.format(sni_name))

        # create ssl context w/ ALPN chain
        ctx = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
        ctx.set_ciphers('ECDHE+AESGCM')
        ctx.set_alpn_protocols(['acme-tls/1'])
        ctx.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        ctx.sni_callback = load_cert
        ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)

        # start the SSL server
        s443_tls = ctx.wrap_socket(s443, server_side=True)
        def accept_loop():
            print('started sock_tls accept loop')
            while True:
                try:
                    conn, addr = s443_tls.accept()
                    #conn_tls = ctx.wrap_socket(conn, server_side=True)
                    print('***********************')
                    print('got conn from: {}'.format(addr))
                    print('***********************')
                    conn.recv(1)
                    conn.close()
                except Exception as e:
                    print(e)

        t = threading.Thread(target=accept_loop, daemon=True)
        t.start()

        # tell ACME server to check
        client.verify_challenge(challenge)

        # wait til not pending
        while auth['status'] == 'pending':
            time.sleep(5)
            auth = client.get_authorization(auth_url)
            pprint(auth)

        # TODO: create CSR
        # TODO: finalize order
        # TODO: update context with valid chain
        # TODO: schedule renew

        # return the SSL-wrapped socket
        return s443_tls
