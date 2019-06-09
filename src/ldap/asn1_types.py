"""

ldap/asn1_types.py

writtem by: Oliver Cordes 2019-06-08
changed by: Oliver Cordes 2019-06-08

"""

import copy

from asn1_tags import Tag, tagClassUniversal, tagClassApplication, \
                            tagClassContext, tagClassPrivate, \
                            tagFormatSimple, tagFormatConstructed


from asn1_debug import *

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

        #debug(self._namedtypes)


    def getobjfromtag(self, tag):
        #debug('NamedValues.getobjfromtag:', tag)
        #debug('  len', len(self._namedtypes))
        for i in self._namedtypes:
            if tag == i._schema.tag:
                return i._schema
        return None


    def getnametypefromtag(self, tag):
        for i in self._namedtypes:
            if tag == i._schema.tag:
                return i
        return None


    def __getitem__(self, ind):
        #debug('getitem', ind, len(self._namedtypes))
        if ind >= len(self._namedtypes):
            return None
        else:
            return self._namedtypes[ind]._schema


    def getname(self, ind):
        if ind >= len(self._namedtypes):
            return None
        else:
            return self._namedtypes[ind]._name


    def getid(self, name):
        nr = 0
        for i in self._namedtypes:
            if i._name == name:
                return nr
            nr += 1

        return -1


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
    #def __init__(self, tag=None,  **kwargs):
        if tag is not None:
            self.tag = tag

        self._schema = schema
        self._name = None


    def setName(self, name):
        #debug('setName:', name)
        self._name = name


    def getName(self):
        if self._name is None:
            return self.__class__.__name__
        else:
            return self._name


    def get_value(self):
        return self.__str__()


    def set_value(self, value):
        pass


    def update_payload(self, payload):
        self._payload = payload

        # do nothing


    def prettyPrint(self, indent=0):
        return '{}asn1base:\n{} {} payload={}\n'.format(SPACES*indent,
                                            SPACES*(indent+1),
                                            self.tag,
                                            self._payload)


    def getobjfromtag(self, tag):
        #debug('getobjfromtag: ', tag)
        #debug('namedValues', self.namedValues)
        if self.namedValues is None:
            raise ValueError('namedValues are not set for \'{}\''.format(self.__class__))
        return self.namedValues.getnametypefromtag(tag)


    @staticmethod
    def split_decode(substrate):
        #print('Tag coded:', substrate[0])
        tag = Tag.decode(substrate[0])
        #print('Tag decoded:', tag)
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
    def decode(substrate, schema=None, name=None):
        if schema is not None:
            debug('decode called with schema: {} name={}'.format(schema.__class__.__name__, name))
        debug('substrate =', octed2string(substrate))

        substrate, tag, payload = asn1base.split_decode(substrate)

        debug('remaining substrate =', octed2string(substrate))
        debug('payload =', octed2string(payload))
        debug('tag =', tag )

        if schema is None:
            obj_type = asn1base.objfromtag(tag)
            obj = obj_type(tag)
        else:
            if isinstance(schema, Choice):
                schema = copy.copy(schema)
                debug('decode: choice object detected')
                named_obj = schema.getobjfromtag(tag)
                if named_obj is None:
                    raise TypeError('Decoded {} is not in \'{}\''.format(tag, schema.__class__))

                obj = copy.copy(named_obj._schema)
                obj.setName(named_obj._name)

                # now put the decoded object into the choice object
                schema.set_value(obj)
                schema.setName(name)
                obj = schema
            else:
                if tag == schema.tag:
                    obj = copy.copy(schema)
                    obj.setName(name)
                else:
                    raise TypeError('Decoded {} is not {} in schema!'.format(tag, schema.tag))

        debug('object detected: ', obj.__class__.__name__)

        obj.update_payload(payload)
        debug(' value =', obj)

        debug('decode done.')
        return obj, substrate



class Boolean(asn1base):
    tag = Tag(0, 0, 1)

    def update_payload(self, payload):
        asn1base.update_payload(self, payload)
        self._value = payload[0] != 0


    def __str__(self):
        return str(self._value)


    def get_value(self):
        return self._value


    def set_value(self, value):
        self._value = value


    def prettyPrint(self, indent=0):
        return '{}{}:\n{}{}\n'.format(SPACES*indent,
                                            self.getName(),
                                            SPACES*(indent+1), self._value)



class Integer(asn1base):
    tag = Tag(0, 0, 2)

    def update_payload(self, payload):
        asn1base.update_payload(self, payload)
        self._value = bytes2integer(payload)


    def set(self, val):
        self._value = val


    def __str__(self):
        return str(self._value)


    def get_value(self):
        return self._value


    def set_value(self, value):
        self._value = value


    def prettyPrint(self, indent=0):
        return '{}{}:\n{}{}\n'.format(SPACES*indent,
                                            self.getName(),
                                            SPACES*(indent+1), self._value)




class OctetString(asn1base):
    tag = Tag(0, 0, 4)

    def update_payload(self, payload):
        asn1base.update_payload(self, payload)
        self._value = payload.decode('utf-8')


    def __str__(self):
        return '\'{}\''.format(self._value)


    def get_value(self):
        return self._value


    def set_value(self, value):
        self._value = value


    def prettyPrint(self, indent=0):
        return '{}{}:\n{}{}\n'.format(SPACES*indent,
                                        self.getName(),
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


    def __str__(self):
        return 'Enumerated({}=={})'.format(self._value, self._valuetoname())


    def get_value(self):
        return self._value


    def set_value(self, value):
        self._value = value


    def prettyPrint(self, indent=0):
        return '{}{}:\n{}{}\n'.format(SPACES*indent,
                                        self.getName(),
                                        SPACES*(indent+1), self._valuetoname())


class SequenceAndSet(asn1base):
    def __getitem__(self, val):
        if isinstance(val, int):
            id = val
        else:
            id = self.namedValues.getid(val)
            if id == -1:
                raise AttributeError('\'{}\' is not in Sequence'.format(val))

        obj = self._values[id]
        if isinstance(obj, Choice):
            return obj._value
        else:
            return obj.get_value()


    def prettyPrint(self, indent=0):
        subitems = ''
        for i in self._values:
            subitems += i.prettyPrint(indent+1)
        return '{}{}:\n{}'.format(SPACES*indent,
                                    self.getName(),
                                    subitems)



class Sequence(SequenceAndSet):
    tag = Tag(0, tagFormatConstructed, 16)


    def update_payload(self, payload):
        asn1base.update_payload(self, payload)

        self._values = []

        # extract the next objects
        debug('update_paylaod: sequence')

        ind = 0
        while len(payload) > 0:
            schema = self.namedValues[ind]
            obj, payload = asn1base.decode(payload, schema, self.namedValues.getname(ind))
            self._values.append(obj)
            ind += 1
        debug('update_payload_done: sequence')



    def __str__(self):
        return 'Sequence({} entries)'.format(len(self._values))



class Set(SequenceAndSet):
    tag = Tag(0, tagFormatConstructed, 17)
    components = None

    def update_payload(self, payload):
        asn1base.update_payload(self, payload)

        self._values = []

        # extract the next objects
        debug('update_payload: set')

        ind = 0
        while len(payload) > 0:
            obj, payload = asn1base.decode(payload, self.components._schema, self.components._name)
            self._values.append(obj)
            #debug('set update_payload: ' , obj.prettyPrint())
            ind += 1
        debug('update_payload_done: set')


    def __str__(self):
        return 'Set({} entries)'.format(len(self._values))


    def get_value(self):
        return [i.get_value() for i in self._values]



class Choice(asn1base):
    tag = None


    def set_value(self, val):
        self._value = val


    #def get_value(self):
    #    return self._value.get_value()


    def update_payload(self, payload):
        self._value.update_payload(payload)


    def prettyPrint(self, indent=0):
        return '{}{}:\n{}'.format(SPACES*indent,
                                    self.getName(),
                                    self._value.prettyPrint(indent=indent+1))


    def __str__(self):
        return 'Choice({})'.format(self._value.getName())



if __name__ == '__main__':
    pass
