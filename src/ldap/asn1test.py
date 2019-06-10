
import os, sys

from asn1_coding import decode, encode
from rfc4511 import *

from asn1_debug import *


if __name__ == '__main__':
    print('Testings')


    data = b'0>\x02\x01\x19c9\x04\x11dc=UNI-BONN,dc=DE\n\x01\x02\n\x01\x00\x02\x02\x03\xe8\x02\x01\x00\x01\x01\x00\xa0\x12\x87\x0bobjectClass\x87\x03uid0\x00'

    print(' '.join([str(i) for i in data]))


    lm = LDAPMessage()


    debug_on()
    x, sub = decode(data, schema=LDAPMessage())

    print(x.prettyPrint())


    print(x['messageID'])
    op_x = x['protocolOp']
    print(op_x)
    print(op_x.getName())
    print(op_x['baseObject'])

    filter = op_x['filter']
    print(filter.__class__)
    print(filter.getName()) # 'and'
    filters = filter.get_value()
    print(filters)
    for f in filters:
        print(f.getName())
        print(f.get_value())

    print('Encoding...')

    filter1 = Filter()
    filter1['present'] = 'objectClass'

    filter2 = Filter()
    filter2['present'] = 'uid'


    filter = Filter()
    filter['and'] = [filter1, filter2]

    print(filter.prettyPrint())


    searchrequest = SearchRequest()
    searchrequest['baseObject'] = 'dc=UNI-BONN,dc=DE'
    searchrequest['scope'] = 'wholeSubtree'
    searchrequest['derefAliases'] = 'neverDerefAliases'
    searchrequest['sizeLimit'] = 1000
    searchrequest['timeLimit'] = 0
    searchrequest['typesOnly'] = False
    searchrequest['filter'] = filter
    searchrequest['attributes'] = None

    print(searchrequest.prettyPrint())


    lm = LDAPMessage()
    lm['messageID'] = 25
    lm['protocolOp'] = searchrequest

    data_new = encode(lm)
    print(data_new)
    print(' '.join([str(i) for i in data_new]))

    data = b'0>\x02\x01\x19c9\x04\x11dc=UNI-BONN,dc=DE\n\x01\x02\n\x01\x00\x02\x02\x03\xe8\x02\x01\x00\x01\x01\x00\xa0\x12\x87\x0bobjectClass\x87\x03uid0\x00'
    print(data)
    print(' '.join([str(i) for i in data]))

    print('Success:', data == data_new)

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
