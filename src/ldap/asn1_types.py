"""

ldap/asn1_types.py

writtem by: Oliver Cordes 2019-06-08
changed by: Oliver Cordes 2019-06-08

"""

from asn1_tags import Tag, tagClassUniversal, tagClassApplication, \
                            tagClassContext, tagClassPrivate, \
                            tagFormatSimple, tagFormatConstructed


"""
all based on this arcticle:

https://en.wikipedia.org/wiki/X.690
"""

SPACES = '  '

#------------------------------------------------------------------------------

def bytes2integer(s):
    base = 1
    integer = 0

    pos = len(s)-1
    for i in range(len(s)):
        integer += s[pos]*base
        pos -= 1
        base *= 256

    return integer

#------------------------------------------------------------------------------

class NamedValues(object):
    def __init__(self, *args):
        self._namedtypes = tuple(args)

        print(self._namedtypes)


    def getobjfromtag(self, tag):
        for i in self._namedtypes:
            print(tag,i._schema.tag)
            if tag == i._schema.tag:
                return i._schema

        return None


    def __getitem__(self, ind):
        print('getitem', ind, len(self._namedtypes))
        if ind >= len(self._namedtypes):
            return None
        else:
            return self._namedtypes[ind]._schema


class NamedType(object):
    def __init__(self, name, schema):
        self._name   = name
        self._schema = schema
        self._optional = False


class OptionalNamedType(NamedType):
    def __init__(self, name, schema):
        NamedType.__init__(self, name, schema)
        self._optional = True


class ValueMap(object):
    def __init__(self, *args):
        values = list(args)
        self._map = {}
        self._map.update(values)

        values = [ (j,i) for i,j in values]

        self._revmap = {}
        self._revmap.update(values)

    def get(self, name):
        return self._revmap.get(name, name)


#-----------------------------------------------------------------------------



class asn1base(object):
    tag = Tag(0,0,0)

    namedValues = NamedValues()

    def __init__(self, tag=None, schema=None):
        if tag is not None:
            self.tag = tag

        self._schema = schema


    def update_payload(self, payload):
        self._payload = payload

        # do nothing


    def prettyPrint(self, indent=0):
        return '{}asn1base:\n{} {} payload={}\n'.format(SPACES*indent,
                                            SPACES*(indent+1),
                                            self.tag,
                                            self._payload)


    def getobjfromtag(self, tag):
        if self.namedValues is None:
            raise ValueError('namedValues are not set for \'{}\''.format(self.__class__))
        return self.namedValues.getobjfromtag(tag)


    @staticmethod
    def split_decode(substrate):
        print('Tag coded:', substrate[0])
        tag = Tag.decode(substrate[0])
        print('Tag decoded:', tag)
        l1 = substrate[1]
        payload_start = 2

        if l1 > 127:
            octed_length = l1 & 127
            payload_start += octed_length
            base = 1
            length = bytes2integer(substrate[2:2+octed_length])
        else:
            length = l1

        # split the string
        payload = substrate[payload_start:payload_start+length]
        substrate = substrate[payload_start+length:]

        return substrate, tag, payload


    """
    objfromtag

    returns a canonical obj from list if tag matches

    """
    @staticmethod
    def objfromtag(tag):
        l = [Boolean, Integer, OctetString, Enumerated, Sequence, Set]

        for i in l:
            if tag == i.tag:
                return i

        return asn1base


    @staticmethod
    def decode(substrate, schema=None):

        print('decode: schema=',schema)
        print(' '.join(['%i' % i for i in substrate]))
        substrate, tag, payload = asn1base.split_decode(substrate)
        print(' '.join(['%i' % i for i in substrate]))
        print(' '.join(['%i' % i for i in payload]))
        print(tag)

        if schema is None:
            obj_type = asn1base.objfromtag(tag)
            obj = obj_type(tag)
        else:
            if isinstance(schema, Choice):
                print(schema.__class__)
                obj = schema.getobjfromtag(tag)
                if obj is None:
                    raise TypeError('Decoded {} is not in \'{}\''.format(tag, schema.__class__))
            else:
                if tag == schema.tag:
                    obj = schema
                else:
                    raise TypeError('Decoded {} is not {} in schema!'.format(tag, schema.tag))

        obj.update_payload(payload)

        print(obj.__class__)

        return obj, substrate


class Boolean(asn1base):
    tag = Tag(0, 0, 1)

    def update_payload(self, payload):
        asn1base.update_payload(self, payload)
        self._value = payload[0] != 0


    def prettyPrint(self, indent=0):
        return '{}{}:\n{}{}\n'.format(SPACES*indent,
                                            self.__class__.__name__,
                                            SPACES*(indent+1), self._value)



class Integer(asn1base):
    tag = Tag(0, 0, 2)

    def update_payload(self, payload):
        asn1base.update_payload(self, payload)
        self._value = bytes2integer(payload)


    def set(self, val):
        self._value = val


    def prettyPrint(self, indent=0):
        return '{}{}:\n{}{}\n'.format(SPACES*indent,
                                            self.__class__.__name__,
                                            SPACES*(indent+1), self._value)



class OctetString(asn1base):
    tag = Tag(0, 0, 4)

    def update_payload(self, payload):
        asn1base.update_payload(self, payload)
        self._value = payload.decode('utf-8')


    def prettyPrint(self, indent=0):
        return '{}{}:\n{}{}\n'.format(SPACES*indent,
                                        self.__class__.__name__,
                                        SPACES*(indent+1), self._value)



class Enumerated(asn1base):
    tag = Tag(0, 0, 10)

    valuemap = None

    def update_payload(self, payload):
        asn1base.update_payload(self, payload)

        self._value = bytes2integer(payload)


    def _valuetoname(self):
        if self.valuemap is None:
            return self._value
        else:
            return self.valuemap.get(self._value)


    def prettyPrint(self, indent=0):
        return '{}{}:\n{}{}\n'.format(SPACES*indent,
                                        self.__class__.__name__,
                                        SPACES*(indent+1), self._valuetoname())



class Sequence(asn1base):
    tag = Tag(0, tagFormatConstructed, 16)


    def update_payload(self, payload):
        asn1base.update_payload(self, payload)

        self._values = []

        # extract the next objects
        print('update_payload sequence')

        ind = 0
        while len(payload) > 9:
            print(payload)
            schema = self.namedValues[ind]
            obj, payload = asn1base.decode(payload, schema)
            print('rest=', payload)
            self._values.append(obj)
            ind += 1
        print('Done.')


    def prettyPrint(self, indent=0):
        subitems = ''
        for i in self._values:
            subitems += i.prettyPrint(indent+1)
        return '{}{}:\n{}'.format(SPACES*indent, self.__class__.__name__, subitems)



class Set(asn1base):
    tag = Tag(0, tagFormatConstructed, 17)

    def update_payload(self, payload):
        asn1base.update_payload(self, payload)

        self._values = []

        # extract the next objects
        print('update_payload set')

        ind = 0
        while len(payload) > 9:
            print(payload)
            schema = self.namedValues[ind]
            obj, payload = asn1base.decode(payload, schema)
            print('rest=', payload)
            self._values.append(obj)
            ind += 1
        print('Done.')


    def prettyPrint(self, indent=0):
        subitems = ''
        for i in self._values:
            subitems += i.prettyPrint(indent+1)
        return '{}{}:\n{}'.format(SPACES*indent, self.__class__.__name__, subitems)

        

class Choice(asn1base):
    tag = None



if __name__ == '__main__':
    pass
