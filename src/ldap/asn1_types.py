"""

ldap/asn1_types.py

writtem by: Oliver Cordes 2019-06-08
changed by: Oliver Cordes 2019-06-10

"""

import copy

from ldap.asn1_tags import Tag, tagClassUniversal, tagClassApplication, \
                            tagClassContext, tagClassPrivate, \
                            tagFormatSimple, tagFormatConstructed


from ldap.asn1_debug import *

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


def lengthtobytes(length):
    bstr = length.to_bytes(30, 'big').lstrip(b'\x00')
    if len(bstr) == 1:
        return bstr
    elif len(bstr) == 0:
        return b'\x00'
    else:
        lengthid = (128 + len(bstr)).to_bytes(1, 'big')
        return lengthid + bstr


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


    def getname(self, id):
        return self._revmap.get(id, id)


    def getid(self, name):
        return self._map.get(name, name)


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
        self._value = None


    def setName(self, name):
        #debug('setName:', name)
        self._name = name


    def getName(self):
        if self._name is None:
            return self.__class__.__name__
        else:
            return self._name


    def getTreeName(self):
        # use definetly the original one
        return asn1base.getName(self)


    def get_value(self):
        return self.__str__()


    def set_value(self, value):
        raise NotImplementedError


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
        l = [Null, Boolean, Integer, OctetString, Enumerated, Sequence, Set, SequenceOf, Choice, ]

        for i in l:
            if tag == i.tag:
                return i

        return asn1base


    @staticmethod
    def decode(substrate, schema=None, name=None):
        if schema is not None:
            debug('decode called with schema: {} name={}'.format(schema.__class__.__name__, name))
        else:
            debug('decode called with None schema!')
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
                debug('is_choice:', obj.__class__)
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


    def encodepayload(self, payload):
        length = lengthtobytes(len(payload))
        return self.tag.encode2byte() + length + payload


    def encode(self):
        raise NotImplementedError



class Null(asn1base):
    tag = Tag(0, 0, 5)

    def __str__(self):
        return 'Null'


    def get_value(self):
        return None


    def set_value(self, value):
        pass


    def prettyPrint(self, indent=0):
        return '{}{}:\n{}{}\n'.format(SPACES*indent,
                                        self.getTreeName(),
                                        SPACES*(indent+1), 'Null')

    def encode(self):
        return self.encodepayload(b'')



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
                                            self.getTreeName(),
                                            SPACES*(indent+1), self._value)

    def encode(self):
        return self.encodepayload(int(self._value).to_bytes(1, 'big'))



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
        debug('intger.set_value({}) {}'.format(value, value.__class__))
        self._value = value



    def prettyPrint(self, indent=0):
        return '{}{}:\n{}{}\n'.format(SPACES*indent,
                                            self.getTreeName(),
                                            SPACES*(indent+1), self._value)


    def encode(self):
        if self._value == 0:
            bstr = b'\x00'
        else:
            bstr = self._value.to_bytes(10, 'big').lstrip(b'\x00')

        return self.encodepayload(bstr)



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
                                        self.getTreeName(),
                                        SPACES*(indent+1), self._value)

    def encode(self):
        return self.encodepayload(bytearray(self._value, 'utf-8'))



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
            return self.valuemap.getname(self._value)


    def __str__(self):
        return 'Enumerated({}=={})'.format(self._value, self._valuetoname())


    def get_value(self):
        return self._value


    def set_value(self, value):
        if isinstance(value, int):
            self._value = value
        elif isinstance(value, str):
            if self.valuemap is None:
                raise ValueError('Cannot map strings to int without valuemap!')
            self._value = self.valuemap.getid(value)


    def prettyPrint(self, indent=0):
        return '{}{}:\n{}{}\n'.format(SPACES*indent,
                                        self.getTreeName(),
                                        SPACES*(indent+1), self._valuetoname())


    def encode(self):
        return self.encodepayload(int(self._value).to_bytes(1, 'big'))



class SequenceAndSet(asn1base):
    def __getitem__(self, val):
        if isinstance(val, int):
            id = val
        else:
            id = self.namedValues.getid(val)
            if id == -1:
                raise AttributeError('\'{}\' is not in Sequence'.format(val))

        obj = self._value[id]
        debug('__getitem__=', obj.__class__)

        return obj.get_value()

        #if isinstance(obj, Choice):
        #    return obj
        #else:
        #    return obj.get_value()


    def prettyPrint(self, indent=0):
        if self._value is None:
            raise ValueError('{} is not initialised'.format(self.__class__.__name__))
        subitems = ''
        for i in self._value:
            if i is not None:
                subitems += i.prettyPrint(indent+1)
        return '{}{}:\n{}'.format(SPACES*indent,
                                    self.getTreeName(),
                                    subitems)


    def encode(self):
        subitems = b''
        for i in self._value:
            if i is not None:
                subitems += i.encode()
        return self.encodepayload(subitems)



class Sequence(SequenceAndSet):
    tag = Tag(0, tagFormatConstructed, 16)


    def _initvalues(self, empty=False):
        if self._value is None:
            # create the list of possible entries
            self._value = []
            debug('_initvalues({}):'.format(empty))
            debug('len(namedValues)={}'.format(len(self.namedValues._namedtypes)))
            for i in self.namedValues._namedtypes:
                if i._optional or empty:
                    obj = None
                else:
                    obj = copy.copy(i._schema)
                    obj.setName(i._name)
                self._value.append(obj)


    def update_payload(self, payload):
        asn1base.update_payload(self, payload)

        self._initvalues(empty=True)

        # extract the next objects
        debug('update_paylaod: sequence({})'.format(self.__class__.__name__))

        id = 0
        while len(payload) > 0:
            schema = self.namedValues[id]
            obj, payload = asn1base.decode(payload, schema, self.namedValues.getname(id))
            debug('add sequcence: obj=', obj.__class__)
            debug('_value={} id={} len={}'.format(self._value, id, len(self._value)))
            self._value[id] = obj
            id += 1
        debug('update_payload_done: sequence')



    def __setitem__(self, ind, val):
        debug('sequence[{}] = {}'.format(ind,val))
        self._initvalues()
        # sets now the value
        id = self.namedValues.getid(ind)
        if id == -1:
            raise AttributeError('{} is not in namedtype definitions!'.format(ind))
        if self._value[id] is None:
            # optional entry
            self._value[id] = copy.copy(self.namedValue[id])
            self._value[id].setName(self.namedValue.getname(id))
        # finally sets the value!
        self._value[id].set_value(val)
        debug('squence[] done')


    def __str__(self):
        return 'Sequence({} entries)'.format(len(self._value))



class Set(SequenceAndSet):
    tag = Tag(0, tagFormatConstructed, 17)
    components = None


    def update_payload(self, payload):
        asn1base.update_payload(self, payload)

        self._value = []

        # extract the next objects
        debug('update_payload: set({})'.format(self.__class__.__name__))

        ind = 0
        while len(payload) > 0:
            if isinstance(self.components, NamedType) == False:
                raise TypeError('components of {} has the wrong type!'.format(self.__class__.__name__))
            obj, payload = asn1base.decode(payload, self.components._schema, self.components._name)
            #obj, payload = asn1base.decode(payload, self.components._schema, 'blubber')
            self._value.append(obj)
            #debug('set update_payload: ' , obj.prettyPrint())
            debug('add set: obj=', obj.__class__)
            ind += 1
        debug('update_payload_done: set')


    def __str__(self):
        return 'Set({} entries)'.format(len(self._value))


    def get_value(self):
        return [i.get_value() for i in self._value]


    def set_value(self, val):
        if isinstance(val, (list,tuple)):
            if self._value is None:
                self._value = []
            for i in val:
                self._value.append(i)
        else:
            if val is None:
                self._value = []
            else:
                raise AttributeError('Set needs a list or tuple with values!')


    def prettyPrint(self, indent=0):
        if self._value is None:
            raise ValueError('{} is not initialised'.format(self.__class__.__name__))
        subitems = ''
        for i in self._value:
            if i is not None:
                if isinstance(i, (Null, Boolean, Integer, OctetString)):
                    subitems += '{}{}\n'.format(SPACES*(indent+1),i.get_value())
                else:
                    subitems += i.prettyPrint(indent+1)
        return '{}{}:\n{}'.format(SPACES*indent,
                                    self.getTreeName(),
                                    subitems)


class SequenceOf(Set):
    tag = Tag(0, tagFormatConstructed, 16)


class Choice(asn1base):
    tag = None


    def getName(self):
        debug('Choice.getName =', self._value.getName())
        return self._value.getName()


    def set_value(self, val):
        self._value = val


    def get_value(self):
        #return self._value.get_value()
        debug('Choice.get_value()')
        return self
        #return self._value


    def update_payload(self, payload):
        self._value.update_payload(payload)


    def prettyPrint(self, indent=0):
        return '{}{}:\n{}'.format(SPACES*indent,
                                    self.getTreeName(),
                                    self._value.prettyPrint(indent=indent+1))


    def __setitem__(self, ind, val):
        # get the schema
        debug('choice[{}] = {}'.format(ind,val))
        id = self.namedValues.getid(ind)
        if id == -1:
            raise AttributeError('{} is not in namedtype definitions!'.format(ind))
        obj = copy.copy(self.namedValues[id])
        name = self.namedValues.getname(id)
        obj.setName(name)
        obj.set_value(val)
        self._value = obj
        debug('choice[] done')


    def __getitem__(self, ind):
        debug('Choice[{}] start'.format(ind))
        if isinstance(ind, str):
            if ind == self._value.getName():
                debug('Choice[] value=', self._value)
                if isinstance(self._value, (Boolean, Integer, OctetString, Enumerated)):
                    return self._value.get_value()
                else:
                    return self._value
            else:
                raise AttributeError('{} is not equal with the choosen type!'.format(ind))
        else:
            raise TypeError('type of ind is not supported for choice[]')

    def __str__(self):
        return 'Choice({})'.format(self._value.getName())


    def encode(self):
        return self._value.encode()



if __name__ == '__main__':
    pass
