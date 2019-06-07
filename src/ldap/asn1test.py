
import os, sys

# Imports from pyasn1
from pyasn1.type import tag, namedtype, namedval, univ, constraint
from pyasn1.codec.ber import encoder, decoder
#from pyasn1.codec.der import encoder, decoder


from pyasn1 import debug
#debug.setLogger(debug.Debug('all'))


from rfc4511 import *


if __name__ == '__main__':
    print('Testings')


    data = b'0>\x02\x01\x19c9\x04\x11dc=UNI-BONN,dc=DE\n\x01\x02\n\x01\x00\x02\x02\x03\xe8\x02\x01\x00\x01\x01\x00\xa0\x12\x87\x0bobjectClass\x87\x03uid0\x00'

    print(' '.join([str(i) for i in data]))


    filter1 = Filter()
    filter1['present'] = 'uid'
    filter2 = Filter()
    filter2['present'] = 'objectClass'

    # afilter = Filter()
    # #afilter['and'].extend([filter1])
    # #afilter['and'].extend([filter1, filter2])
    #
    # Aand = And()
    # Aand.setComponentByPosition(0, filter1)
    # afilter['and'] = Aand
    #
    # searchrequest = SearchRequest()
    # searchrequest['baseObject'] = 'dc=UNI-BONN,dc=DE'
    # searchrequest['scope'] = 'wholeSubtree'
    # searchrequest['derefAliases'] = 'neverDerefAliases'
    # searchrequest['sizeLimit'] = 1000
    # searchrequest['timeLimit'] = 0
    # searchrequest['typesOnly'] = False
    # #searchrequest['filter'] = afilter
    # searchrequest['filter'] = afilter
    #
    # lm = encoder.encode(searchrequest)
    #
    # print(lm)
    # print(' '.join(['%i' % i for i in lm]))
    # print(' '.join(['%x' % i for i in lm]))

    debug.setLogger(debug.Debug('all'))
    #x, sub = decoder.decode(data, asn1spec=SearchRequest())
    x, sub = decoder.decode(data, SearchRequest())

    print('Output')
    print(x.prettyPrint())
    print(sub)
