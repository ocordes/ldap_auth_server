#!/usr/bin/env python3

"""
server.py

written by: Oliver Cordes 2019-06-03
changed by: Oliver Cordes 2020-03-25

"""


__version__ = '0.2'
__author__ = 'Oliver Cordes'

import os, sys
import socket, time
import configparser

# import thread module
from _thread import *
import threading


# load all ldap thinggies
from ldap.rfc4511 import *
from ldap.ldap_objects import LDAP_Server

from ldap.auth_provider import htpasswd_auth_provider, \
                                sasl_auth_provider, \
                                krb5_auth_provider, \
                                pam_auth_provider, \
                                unix_auth_provider, \
                                test_auth_provider, \
                                yes_auth_provider, \
                                auth_provider


import ldap.logger as log
from ldap.whitelists import WhiteLists


logger = log.logger(log.LOGGER_FILE) # logs into a file



print_lock = threading.Lock()


ini_filename = 'ldap_auth.ini'
debug = False
database = None
timeout = 5


def search_ini_file():
    dirs = ['.', '/etc']

    for i in dirs:
        fname = os.path.join(i, ini_filename)

        if os.access(fname, os.R_OK):
            return fname

    logger.write('Cannot find any ini-file!')
    return None


def create_auth_provider():
    global debug, database, logger, timeout

    fname = search_ini_file()
    if fname is None:
        # this is the simplest ...
        return pam_auth_provider(logger=logger)

    config = configparser.ConfigParser()
    if len(config.read(fname)) == 0:
        return pam_auth_provider(logger=logger)

    default_config = config['DEFAULT']

    logfile = default_config.get('logfile', None)
    if logfile is not None:
       logger.write('Switching to file \'%s\' ... ' % logfile )
       logger = log.logger(log.LOGGER_FILE, logfilename=logfile)

    provider = str(default_config.get('provider', 'pam')).upper()
    realm = default_config.get('realm', None)

    debug = default_config.getint('debug', 0) == 1
    database = default_config.get('fake_database', None)

    whitelists = default_config.get('whitelists', None)

    whitelist = WhiteLists(whitelists,logger=logger)

    # read guest configs
    guest_accounts = default_config.get('guest_accounts', None)

    # read local htpasswd
    extra_htpasswd = default_config.get('extra_htpasswd', None)

    if 'SERVER' in config:
        server_config = config['SERVER']
        timeout = server_config.get('timeout', timeout)
        logger.write('Set server timeout: {}s'.format(timeout))

    if provider == 'PAM':
        logger.write('Using PAM authentication provider...')
        auth_provider = pam_auth_provider(realm=realm,
                                          logger=logger,
                                          whitelist=whitelist,
                                          guest_accounts=guest_accounts,
                                          extra_htpasswd=extra_htpasswd,
                                          extra_realm=realm
                                          )
    elif provider == 'HTPASSWD':
        print('Using htpasswd authentication provider...')
        if provider in config:
            htpasswd = config[provider].get('htpasswd', 'htpasswd')
        else:
            logger.write('HTPASSWD section not found!')
            htpasswd = 'htpasswd'
        auth_provider = htpasswd_auth_provider(htpasswd, realm=realm, logger=logger, whitelist=whitelist, guest_accounts=guest_accounts)
    elif provider == 'TEST':
        logger.write('Using test authentication provider...')
        if provider in config:
            credentials = config[provider].get('credentials', 'test:test')
        else:
            logger.write('TEST section not found!')
            credentials = 'test:test'
        auth_provider = test_auth_provider(credentials,
                                            realm=realm,
                                            logger=logger,
                                            whitelist=whitelist,
                                            guest_accounts=guest_accounts,
                                            extra_htpasswd=extra_htpasswd,
                                            extra_realm=realm
                                           )
    elif provider == 'SASL':
        logger.write('Using sasl authentication provider...')
        if provider in config:
            binary = config[provider].get('binary', '/bin/ls')
        else:
            logger.write('SASL section not found!')
            binary = '/bin/ls'
        auth_provider = sasl_auth_provider(binary,
                                           logger=logger,
                                           whitelist=whitelist,
                                           guest_accounts=guest_accounts,
                                           extra_htpasswd=extra_htpasswd,
                                           extra_realm=realm
                                          )
    elif provider == 'KRB5':
        logger.write('Using krb5 authentication provider...')
        if provider in config:
            service = config[provider].get('service', None)
        else:
            logger.write('KRB5 section not found!')
            service = None
        auth_provider = krb5_auth_provider(service,
                                            logger=logger,
                                            whitelist=whitelist,
                                            guest_accounts=guest_accounts,
                                            extra_htpasswd=extra_htpasswd,
                                            extra_realm=realm
                                           )
    else:
        auth_provider = auth_provider


    return auth_provider


# thread fuction

def threaded(connection, auth_provider):
    ldap_server = LDAP_Server(connection, auth_provider,
                                database=database, logger=logger,
                                debug=debug,
                                timeout=float(timeout))

    ldap_server.run()

    # connection closed
    logger.writeid(connection.fileno(), 'Closing the connection!')
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
                logger.write('Bind failed! Nr of tries: %i' %nr_bind)
                time.sleep(1)

    logger.write('Socket binded to port', port)

    # put the socket into listening mode
    s.listen(5)
    logger.write('Socket is listening')

    # a forever loop until client wants to exit
    try:
        while True:

            # establish connection with client
            c, addr = s.accept()

            logger.writeid(c.fileno(), 'Connected to :', addr[0], ':', addr[1])

            # Start a new thread and return its identifier
            start_new_thread(threaded, (c,auth_provider))
    except:
        pass
    s.close()


if __name__ == '__main__':
    Main()
