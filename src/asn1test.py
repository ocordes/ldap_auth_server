
import os, sys

from ldap.asn1_coding import decode, encode
from ldap.rfc4511 import *

from ldap.asn1_debug import *


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
    op_x = op_x[op_x.getName()]
    print(op_x['baseObject'])

    filter = op_x['filter']
    print(filter.__class__)
    print(filter.getName()) # 'and'
    filters = filter['and']
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


    data = b"0\x82\x02x\x02\x01\x02d\x82\x02q\x04,uid=omc,ou=People,dc=astro,dc=uni-bonn,dc=de0\x82\x02?0n\x04\x0bobjectClass1_\x04\x16inetLocalMailRecipient\x04\x0cposixAccount\x04\rinetOrgPerson\x04\x14organizationalPerson\x04\x06person\x04\nhostObject0\x19\x04\nloginShell1\x0b\x04\t/bin/bash0\x12\x04\tgidNumber1\x05\x04\x031000\x15\x04\x02cn1\x0f\x04\rOliver Cordes0\x0e\x04\x02sn1\x08\x04\x06Cordes0\x15\x04\tgivenName1\x08\x04\x06Oliver0\x1e\x04\x10mailLocalAddress1\n\x04\x08omcordes0\x18\x04\x0cemployeeType1\x08\x04\x06Intern0\x13\x04\tuidNumber1\x06\x04\x0419990'\x04\x04host1\x1f\x04\x07desktop\x04\x05ebhis\x04\x06portal\x04\x05theli0\x1d\x04\rhomeDirectory1\x0c\x04\n/users/omc08\x04\x0cuserPassword1(\x04&{SSHA}/W0okeqgj7NbCkymTDzm9FyO9IFSeEho00\x04\x04mail1(\x04\x15omc@astro.uni-bonn.de\x04\x0focordes@gmx.net0#\x04\x10departmentNumber1\x0f\x04\x01F\x04\x01M\x04\x01N\x04\x01R\x04\x01T0*\x04\x12mailRoutingAddress1\x14\x04\x12ocordes@freenet.de0\x0c\x04\x03uid1\x05\x04\x03omc0\x0c\x02\x01\x02e\x07\n\x01\x00\x04\x00\x04\x00"



    x, sub = decode(data, schema=LDAPMessage())

    print(x.prettyPrint())


    search_result_entry = SearchResultEntry()
    search_result_entry['object'] = 'omc'

    attr1 = PartialAttribute()
    attr1['type'] = 'objectClass'
    attr1['vals'] = ['hallo', 'berta']

    attr2 = PartialAttribute()
    attr2['type'] = 'email'
    attr2['vals'] = ['mail@mail.mail', 'email@email.email']

    print(attr1.prettyPrint())
    print(attr2.prettyPrint())

    search_result_entry['attributes'] = []
    print('append')
    print(search_result_entry['attributes'])
    search_result_entry['attributes'].append(attr1)
    search_result_entry['attributes'].append(attr2)

    print(search_result_entry.prettyPrint())

    l = LDAPMessage()
    l['messageID'] = 2
    l['protocolOp'] = search_result_entry
    data = encode(l)
    print(data)

    x, sub = decode(data, schema=LDAPMessage())

    print(x.prettyPrint())
