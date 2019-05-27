# import socket programming library
import socket

import sys, os, time

# import thread module
from _thread import *
import threading


# Imports from pyasn1
from pyasn1.type import tag, namedtype, namedval, univ, constraint

from ldap.protocol import *
from pyasn1.codec.ber import encoder, decoder


print_lock = threading.Lock()

# https://tools.ietf.org/html/rfc4511

def decode_data(data):
    try:
        x, _ = decoder.decode(data, LDAPMessage())
    except:
        x = None

    return x


def print_decoded_data(data):
    x = decode_data(data)
    if x is not None:
        print(x.prettyPrint())
    else:
        print('NONE (Error)')


def receive_from(connection):
    buffer = b""

    # we set a 2 second timeout; depending on your
    # target, this may need to be adjusted
    connection.settimeout(0.05)

    try:
        # keep reading into the buffer until
        # there's no more data or we timeout
        count = 0
        while True:
            count += 1
            data = connection.recv(4096)

            if not data:
                break

            buffer += data

    except:
        pass

    return buffer

# thread fuction
def threaded(c):
    proxy_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_server_address = ('ldap.astro.uni-bonn.de', 389)

    proxy_sock.connect(proxy_server_address)


    while True:


        # data received from client
        in_data = receive_from(c)
        if not in_data:
            print('Bye')

            # lock released on exit
            print_lock.release()
            break


        proxy_sock.send(in_data)
        print('IN:    ', in_data)
        #print('INh:   ', ' '.join([ '%02x' % i for i in data]))
        #print('INd:   ', ' '.join([ '%03i' % i for i in data]))
        print_decoded_data(in_data)
        sys.stdout.flush()


        out_data = receive_from(proxy_sock)
        c.send(out_data)

        print('OUT:   ', out_data)
        #if len(data) < 50:
        #    print('OUTh:  ', ' '.join([ '%02x' % i for i in data]))
        #    print('OUTd:  ', ' '.join([ '%03i' % i for i in data]))
        print_decoded_data(out_data)
        sys.stdout.flush()

        if ( len(in_data) == 0 ) and ( len(out_data) == 0):
            break

    # connection closed
    print('Closing the connections!')
    proxy_sock.close()
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
            #start_new_thread(threaded, (c,))
            threaded(c)
    except:
        pass
    s.close()


if __name__ == '__main__':
    Main()
