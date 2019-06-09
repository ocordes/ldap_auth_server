
import os, sys

from asn1_coding import Decoder
from rfc4511 import *

from asn1_debug import *


if __name__ == '__main__':
    print('Testings')


    data = b'0>\x02\x01\x19c9\x04\x11dc=UNI-BONN,dc=DE\n\x01\x02\n\x01\x00\x02\x02\x03\xe8\x02\x01\x00\x01\x01\x00\xa0\x12\x87\x0bobjectClass\x87\x03uid0\x00'

    print(' '.join([str(i) for i in data]))


    lm = LDAPMessage()


    decoder = Decoder()

    debug_on()
    x, sub = decoder.decode(data, schema=LDAPMessage())

    print(x.prettyPrint())


    print(x['messageID'])
    print(x['protocolOp'])

    #
    # filter1 = Filter()
    # filter1['present'] = 'uid'
    # filter2 = Filter()
    # filter2['present'] = 'objectClass'

    # afilter = Filter()
    # #afilter['and'].extend([filter1])
    # #afilter['and'].extend([filter1, filter2])
    #
    # Aand = And()
    # Aand.setComponentByPosition(0, filter1)
    # afilter['and'] = Aand

    #
    # print(lm)
    # print(' '.join(['%i' % i for i in lm]))
    # print(' '.join(['%x' % i for i in lm]))


    #x, sub = decoder.decode(data, asn1spec=SearchRequest())
    #x, sub = decoder.decode(data, SearchRequest())

    #print('Output')
    #print(x.prettyPrint())
    #print(sub)
