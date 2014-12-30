import gmpy2
from gmpy2 import mpz
import struct
from binascii import unhexlify


BITLEN = 2048

def icbrt (a1, a2):
    z = gmpy2.iroot(mpz(a1), 3)
    return z[0]

def forge_prefix(s, w, N):
    zd = BITLEN - w
    repas = s
    repa = (repas >> zd)
    cmax = N
    cmin = 0
    s = 0
    while True:

        c = (cmax + cmin + 1) / 2
        a1 = repas + c
        s = icbrt(a1, BITLEN)
        a2 = ((s * s * s) >> zd)
        if a2 == repa:
            break
        if c == cmax or c == cmin:
            print( " *** Error: The value cannot be found ***")
            return 0
        if a2 > repa:
            cmax = c
        else:
            cmin = c


    for d in range(zd / 3, 0, -1):
        mask = ((1 << d) - 1)
        s1 = s & (~mask)
        a2 = ((s1 * s1 * s1) >> zd)
        if a2 == repa:
            return s1
    return s

def long_to_bytes (val, endianness='big'):
    """
    Use :ref:`string formatting` and :func:`~binascii.unhexlify` to
    convert ``val``, a :func:`long`, to a byte :func:`str`.

    :param long val: The value to pack

    :param str endianness: The endianness of the result. ``'big'`` for
      big-endian, ``'little'`` for little-endian.

    If you want byte- and word-ordering to differ, you're on your own.

    Using :ref:`string formatting` lets us use Python's C innards.
    """

    # one (1) hex digit per four (4) bits
    width = val.bit_length()

    # unhexlify wants an even multiple of eight (8) bits, but we don't
    # want more digits than we need (hence the ternary-ish 'or')
    width += 8 - ((width % 8) or 8)

    # format width specifier: four (4) bits per hex digit
    fmt = '%%0%dx' % (width // 4)

    # prepend zero (0) to the width, to zero-pad the output
    s = unhexlify(fmt % val)

    if endianness == 'little':
        # see http://stackoverflow.com/a/931095/309233
        s = s[::-1]

    return s

def createsig():
    # modulus of of amazon certificate
    modulus = 0x00c88adfc863913d4e7a63680297db526bd5dfec3d62cba01b358691d5bf3c2599a7c036f70e3044bd04c8a0b4aabd6a1dab829a787c060fd58f0ecdbdda9ca7b08b1e8a3e1dc28e73c8b7d6f66ee39d260e0b7b4773d200c14a9167a5f5697008ea44cae2ecba0cc3ccf7678011ec871b0228db3ca64f4abc70cb954f5fe1816e4b1b7929b6625ba070d2d2e7df5fc30b6e412c9ee77a14fac94ef71d234ad30c29558830b690ca89601e5ad11eee1b087203a9e66d1a9bd5cc2bc060583f362cf854f7bf780abc6ed08fd393da72c7f07948c438421293da5ab261c976da5bfd1a86470eb4b8e4dc09f692124c64090bea03d62f8a5650d90e88cd6f7859
    # PKCS#1 v1.5 fixed prefix
    prefix = 0x0001FFFFFFFFFFFFFFFF000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000

    #load the hash from created file
    f = open("hash.abc", "rb")
    block = f.read(32)
    hash = struct.unpack('>4Q', block)
    hash0 = int(hash[0])<<192
    hash1 = int(hash[1])<<128
    hash2 = int(hash[2])<<64
    hash3 = int(hash[3])
    hash5 = hash0 + hash1 + hash2 + hash3
    # get hash to right position
    hash = hash5 << 1704

    #create forged prefix
    prefix = forge_prefix(prefix+hash, 86*8, modulus)

    # write signature to file
    pref = int(prefix)
    file = open("signature.abc","wb")
    file.write(long_to_bytes(pref, "big"))

createsig()

