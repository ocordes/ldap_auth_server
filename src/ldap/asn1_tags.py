"""

ldap/asn1_tags.py

writtem by: Oliver Cordes 2019-06-08
changed by: Oliver Cordes 2019-06-08

"""

"""
all based on this arcticle:

https://en.wikipedia.org/wiki/X.690
"""

# tag constants
tagClassUniversal = 0
tagClassApplication = 64
tagClassContext = 128
tagClassPrivate = 192
tagFormatSimple = 0
tagFormatConstructed = 32



class Tag(object):
    def __init__(self, tagClass, tagFormat, tagId):
        self._tagClass = tagClass
        self._tagFormat = tagFormat
        self._tagId = tagId


    def __str__(self):
        return 'Tag={}-{}-{}'.format(self._tagClass, self._tagFormat, self._tagId)


    def __eq__(self, val):
        if val is None:
            return False

        return ((self._tagClass == val._tagClass) and
            (self._tagFormat == val._tagFormat) and
            (self._tagId==val._tagId))


    def encode(self):
        return self._tagClass+self._tagFormat+self._tagId


    @staticmethod
    def decode(substrate_byte):
        tagClass = substrate_byte & 192
        tagFormat = substrate_byte & 32
        tagId = substrate_byte & 31

        return Tag(tagClass, tagFormat, tagId)



if __name__ == '__main__':
    print('Test cases')

    tag = Tag(tagClassApplication, tagFormatConstructed, 3)

    print(tag)

    tag2 = Tag.decode(48)
    print(tag2)

    tag2 = Tag.decode(99)
    print(tag2)

    print(tag==tag2)

    print(Tag.decode(4))
