"""

ldap/asn1_debug.py

written by: Oliver Cordes 2019-06-09
changed by: Oliver Cordes 2019-06-09

"""


output_func = print
is_debug    = False

def debug(*vars):
    if is_debug:
        s = ' '.join([str(i) for i in vars])
        output_func(s)


def debug_on():
    global is_debug
    is_debug = True


def debug_off():
    global is_debug
    is_debug = False


def set_outputfunc(func):
    global output_func
    output_func = func


def octed2string(s):
    return ' '.join(['%i' %i for i in s])


def octed2hexstring(s):
    return ' '.join(['%x' %i for i in s])
