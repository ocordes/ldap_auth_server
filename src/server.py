# import socket programming library
import socket

# import thread module
from _thread import *
import threading


# Imports from pyasn1
from pyasn1.type import tag, namedtype, namedval, univ, constraint




print_lock = threading.Lock()

# https://tools.ietf.org/html/rfc4511



# thread fuction
def threaded(c):
    while True:

        # data received from client
        data = c.recv(1024)
        if not data:
            print('Bye')

            # lock released on exit
            print_lock.release()
            break

        # reverse the given string from client
        #data = data[::-1]

        # send back reversed string to client
        #c.send(data)
        print(data)


        s = b'0\x1c\x02\x01\x01a\x170\x15\n\x01\x00\x04\x05Hallo\x04\x07Success\xa3\x00'
        #s = b'0\x1c\x02\x01\x02a\x170\x15\n\x01\x00\x04\x05Hallo\x04\x07Success\xa3\x00'


        #s = b'0\x1c\x02\x01\x01a\x170\x15\n\x01\x01\x04\x05Hallo\x04\x07Success\xa3\x00'
        s = b'0\x1c\x02\x01\x02a\x170\x15\n\x01\x01\x04\x05Hallo\x04\x07Success\xa3\x00'
        s = b'0\x1c\x02\x01\x02a\x170\x15\n\x011\x04\x05Hallo\x04\x07Success\xa3\x00'
        c.send(s)
        #c.send(s)

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
    s.bind((host, port))
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
