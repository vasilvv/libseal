#!/usr/bin/python

from itertools import product
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
    print "EOF"

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print "Usage: test_gen.py [test type]"
    if sys.argv[1] == 'add':
        gen_add_data()
    else:
        print "Unknwon test type: %s" % sys.argv[1]
