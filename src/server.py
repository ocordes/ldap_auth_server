# import socket programming library
import socket

# import thread module
from _thread import *
import threading


# Imports from pyasn1
from pyasn1.type import tag, namedtype, namedval, univ, constraint
from pyasn1.codec.ber import encoder, decoder


print_lock = threading.Lock()

# https://tools.ietf.org/html/rfc4511

class SaslCredentials(univ.Sequence):
    """
    SaslCredentials ::= SEQUENCE {
             mechanism               LDAPString,
             credentials             OCTET STRING OPTIONAL }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('mechanism', univ.OctetString()),
        namedtype.OptionalNamedType('credentials', univ.OctetString()),
    )





class AuthenticationChoice(univ.Choice):
    """
    AuthenticationChoice ::= CHOICE {
             simple                  [0] OCTET STRING,
                                     -- 1 and 2 reserved
             sasl                    [3] SaslCredentials,
             ...  }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('simple', univ.OctetString()),
        namedtype.NamedType('sasl', SaslCredentials()),
    )


class BindRequest(univ.Sequence):
    """
    BindRequest ::= [APPLICATION 0] SEQUENCE {
             version                 INTEGER (1 ..  127),
             name                    LDAPDN,
             authentication          AuthenticationChoice }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', univ.Integer()),
        namedtype.NamedType('name', univ.OctetString()),
        namedtype.NamedType('authentication', univ.Integer()),
        #namestype.DefaultedNamedType('authentication', AuthenticationChoice())
        #namedtype.OptionalNamedType('controls', univ.Integer() ),
    )


class LDAPOp(univ.Choice):
    """
    protocolOp      CHOICE {
         bindRequest           BindRequest,
         bindResponse          BindResponse,
         unbindRequest         UnbindRequest,
         searchRequest         SearchRequest,
         searchResEntry        SearchResultEntry,
         searchResDone         SearchResultDone,
         searchResRef          SearchResultReference,
         modifyRequest         ModifyRequest,
         modifyResponse        ModifyResponse,
         addRequest            AddRequest,
         addResponse           AddResponse,
         delRequest            DelRequest,
         delResponse           DelResponse,
         modDNRequest          ModifyDNRequest,
         modDNResponse         ModifyDNResponse,
         compareRequest        CompareRequest,
         compareResponse       CompareResponse,
         abandonRequest        AbandonRequest,
         extendedReq           ExtendedRequest,
         extendedResp          ExtendedResponse,
         ...,
         intermediateResponse  IntermediateResponse },
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('bindRequest', BindRequest().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
    )


class LDAPMessage(univ.Sequence):
    """
    LDAPMessage ::= SEQUENCE {
             messageID       MessageID,
             protocolOp      CHOICE {
                  bindRequest           BindRequest,
                  bindResponse          BindResponse,
                  unbindRequest         UnbindRequest,
                  searchRequest         SearchRequest,
                  searchResEntry        SearchResultEntry,
                  searchResDone         SearchResultDone,
                  searchResRef          SearchResultReference,
                  modifyRequest         ModifyRequest,
                  modifyResponse        ModifyResponse,
                  addRequest            AddRequest,
                  addResponse           AddResponse,
                  delRequest            DelRequest,
                  delResponse           DelResponse,
                  modDNRequest          ModifyDNRequest,
                  modDNResponse         ModifyDNResponse,
                  compareRequest        CompareRequest,
                  compareResponse       CompareResponse,
                  abandonRequest        AbandonRequest,
                  extendedReq           ExtendedRequest,
                  extendedResp          ExtendedResponse,
                  ...,
                  intermediateResponse  IntermediateResponse },
             controls       [0] Controls OPTIONAL }

        MessageID ::= INTEGER (0 ..  maxInt)

        maxInt INTEGER ::= 2147483647 -- (2^^31 - 1) --
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('messageID', univ.Integer() ),
        namedtype.NamedType('protocolOp', LDAPOp())
        #namedtype.OptionalNamedType('controls', univ.Integer() ),
    )



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
        d = decoder.decode(data, asn1Spec=LDAPMessage())

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
