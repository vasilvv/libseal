#!/usr/bin/python

from itertools import product
import random
import sys

# Generate addition tests.  Those tests are trying to ensure that
# carry-in/carry-out logic is always correct, hence they are using boundary
# values of the word size
def gen_add_data():
    basis = [0, 1, 2 ** 64 - 2, 2 ** 64 - 1]
    args = [a + (b << 64) + (c << 128) + (d << 192) for (a, b, c, d) in product(basis, basis, basis, basis)]

    for a, b in product(args, args):
        print "------"
        print "%064x" % a
        print "%064x" % b
        print "%064x" % ((a + b) % (2**256))
        print "%064x" % ((a + b + 1) % (2**256))
    print "EOF"

def gen_mul_data():
    random.seed(123456)  # Make tests determininistic
    for power in range(6, 14):
        maxval = 2 ** (2**power)
        fmt = "%0" + str(2 ** power / 4) + "x"
        fmt2 = "%0" + str(2 ** (power + 1) / 4) + "x"
        for i in xrange(1000):
            a = random.randint(0, maxval)
            b = random.randint(0, maxval)
            print "------"
            print fmt % a
            print fmt % b
            print fmt2 % (a * b)
    print "EOF"

def gen_divmod_data():
    random.seed(654321)  # Make tests determininistic
    for power_numer in range(6, 14):
        maxval_numer = 2 ** (2**power_numer)
        for power_denom in range(6, 14):
            maxval_denom = 2 ** (2**power_denom)
            fmt = "%0" + str(2 ** max(power_numer, power_denom) / 4) + "x"
            for i in xrange(5):
                a = random.randint(0, maxval_numer)
                b = random.randint(0, maxval_denom)
                print "------"
                print fmt % a
                print fmt % b
                print fmt % (a / b)
                print fmt % (a % b)
    print "EOF"

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print "Usage: test_gen.py [test type]"
    if sys.argv[1] == 'add':
        gen_add_data()
    elif sys.argv[1] == 'mul':
        gen_mul_data()
    elif sys.argv[1] == 'divmod':
        gen_divmod_data()
    else:
        print "Unknwon test type: %s" % sys.argv[1]
