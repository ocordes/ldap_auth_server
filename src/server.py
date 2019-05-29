# import socket programming library

import os, sys
import socket, time

# import thread module
from _thread import *
import threading


# Imports from pyasn1
from pyasn1.type import tag, namedtype, namedval, univ, constraint

from ldap.protocol import *
from ldap.ldap_objects import LDAP_Server
from pyasn1.codec.ber import encoder, decoder



print_lock = threading.Lock()

# https://tools.ietf.org/html/rfc4511



# thread fuction

def threaded(c):
    ldap_server = LDAP_Server(c)

    ldap_server.run()
    print_lock.release()
    # connection closed
    print('Closing the connection!')
    c.close()



def Main():
    host = ""

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
            start_new_thread(threaded, (c,))
    except:
        pass
    s.close()


if __name__ == '__main__':
    Main()
