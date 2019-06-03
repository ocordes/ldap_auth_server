# import socket programming library

import os, sys
import socket, time
import configparser

# import thread module
from _thread import *
import threading


# Imports from pyasn1
from pyasn1.type import tag, namedtype, namedval, univ, constraint

from ldap.protocol import *
from ldap.ldap_objects import LDAP_Server
from pyasn1.codec.ber import encoder, decoder

from ldap.auth_provider import htpasswd_auth_provider, \
                                sasl_auth_provider, \
                                pam_auth_provider, \
                                unix_auth_provider, \
                                test_auth_provider, \
                                yes_auth_provider, \
                                auth_provider


print_lock = threading.Lock()


ini_filename = 'ldap_auth.ini'

def search_ini_file():
    dirs = ['.', '/etc']

    for i in dirs:
        fname = os.path.join(i, ini_filename)

        if os.access(fname, os.R_OK):
            return fname

    print('Cannot find any ini-file!')
    return None


def create_auth_provider():
    fname = search_ini_file()
    if fname is None:
        # this is the simplest ...
        return pam_auth_provider()

    config = configparser.ConfigParser()
    if len(config.read(fname)) == 0:
        return pam_auth_provider()

    default_config = config['DEFAULT']
    provider = str(default_config.get('provider', 'pam')).upper()
    realm = default_config.get('realm', None)


    if provider == 'PAM':
        print('Using PAM authentication provider...')
        auth_provider = pam_auth_provider(realm=realm)
    elif provider == 'HTPASSWD':
        print('Using htpasswd authentication provider...')
        if provider in config:
            htpasswd = config[provider].get('htpasswd', 'htpasswd')
        else:
            print('HTPASSWD section not found!')
            htpasswd = 'htpasswd'
        auth_provider = htpasswd_auth_provider(htpasswd, realm=realm)
    elif provider == 'TEST':
        print('Using test authentication provider...')
        if provider in config:
            credentials = config[provider].get('credentials', 'test:test')
        else:
            print('TEST section not found!')
            credentials = 'test:test'
        auth_provider = test_auth_provider(credentials, realm=realm)
    elif provider == 'SASL':
        print('Using sasl authentication provider...')
        if provider in config:
            binary = config[provider].get('binary', '/bin/ls')
        else:
            print('SASL section not found!')
            binary = '/bin/ls'
        auth_provider = sasl_auth_provider(binary)
    else:
        auth_provider = auth_provider


    return auth_provider


# thread fuction

def threaded(connection, auth_provider):
    ldap_server = LDAP_Server(connection, auth_provider)

    ldap_server.run()
    print_lock.release()
    # connection closed
    print('Closing the connection!')
    connection.close()



def Main():
    host = ""


    auth_provider = create_auth_provider()

    # reverse a port on your computer
    # in our case it is 12345 but it
    # can be anything
    port = 389
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    nr_bind = 10
    while True:
        try:
            s.bind((host, port))
            break
        except:
            nr_bind -= 1
            if nr_bind == 0:
                sys.exit(0)
            else:
                print('Bind failed! Nr of tries: %i' %nr_bind)
                time.sleep(1)

    print("socket binded to post", port)

    # put the socket into listening mode
    s.listen(5)
    print("socket is listening")

    # a forever loop until client wants to exit
    try:
        while True:

            # establish connection with client
            c, addr = s.accept()

            # lock acquired by client
            print_lock.acquire()
            print('Connected to :', addr[0], ':', addr[1])

            # Start a new thread and return its identifier
            start_new_thread(threaded, (c,auth_provider))
    except:
        pass
    s.close()


if __name__ == '__main__':
    Main()
