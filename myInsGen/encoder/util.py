import sys
import re

from global_init import *

make_numeric_decimal_pattern = re.compile(r'^[-]?[0-9]+$')
make_numeric_hex_pattern = re.compile(r'^0[xX][0-9A-Fa-f]+$')
make_numeric_binary_pattern = re.compile(r'^0b[01_]+$')

make_numeric_old_binary_pattern = re.compile(
    r"B['](?P<bits>[01_]+)")  # leading "B'"
make_numeric_old_decimal_pattern = re.compile(
    r'^0m[0-9]+$')  # only base 10 numbers


#stderr = sys.stderr.write
stderr = logger.error


def numeric(s):
    if make_numeric_decimal_pattern.match(s):
        return True
    if make_numeric_hex_pattern.match(s):
        return True
    if make_numeric_binary_pattern.match(s):
        return True
    return False

def decimal_to_binary(i):
    "Take a decimal integer, and return a list of bits MSB to LSB"
    if i == 0:
        return ['0']
    rev_out = []
    while i > 0:
        bit = i & 1
        # print hex(i),ig, bit
        rev_out.append(str(bit))
        i = i >> 1
    # print str(rev_out)
    rev_out.reverse()
    return rev_out

def hex_to_binary(x):
   "Take a hex number, no 0x prefix required, and return a list of bits MSB to LSB"
   i = int(x,16)
   return decimal_to_binary(i)

def posix_slashes(s):
    """convert to posix slashes. Do not flip slashes immediately before spaces
    @type s: string  or list of strings
    @param s: path name(s)

    @rtype: string or list of strings
    @return: string(s) with forward slashes
    """
    if isinstance(s, list):
        return list(map(posix_slashes, s))
    # t = re.sub(r'\\','/',s,0) # replace all
    last = len(s)-1
    t = []
    for i, a in enumerate(s):
        x = a
        if a == '\\':
            if i == last:
                x = '/'
            elif s[i+1] != ' ':
                x = '/'
        t.append(x)
    return ''.join(t)


def is_stringish(x):
    if isinstance(x, bytes) or isinstance(x, str):
        return True
    return False


def no_underscores(s):
    v = s.replace('_', '')  # remove underscores
    return v


def make_binary(bits):
    "return a string of 1s and 0s. Could return letter strings as well"
    # binary numbers must preserve the number of bits. If we are
    # doing a conversion, then we just go with the number of bits we get.

    if make_numeric_binary_pattern.match(bits):
        # strip off the 0b prefix
        bits = re.sub('_', '', bits)
        return bits[2:]
    # this might return fewer than the expected number of binary bits.
    # for example, if you are in a 4 bit field and use a 5, you will
    # only get 3 bits out. Because this routine is not cognizant of
    # the field width.

    if numeric(bits):
        v = make_numeric(bits)
        d = decimal_to_binary(v)  # a list of bits
        return ''.join(d)
    bits = re.sub('_', '', bits)
    return bits

def make_numeric(s, restriction_pattern=None):
    global make_numeric_old_decimal_pattern
    global make_numeric_hex_pattern
    global make_numeric_binary_pattern
    global make_numeric_old_binary_pattern

    if type(s) == int:
        die("Converting integer to integer")
    elif make_numeric_hex_pattern.match(s):
        out = int(s, 16)
    elif make_numeric_binary_pattern.match(s):
        # I thought that I could leave the '0b' prefix. Python >= 2.6
        # handles '0b' just fine but Python 2.5 cannot.  As of
        # 2012-06-20 the pin team currently still relies upon python
        # 2.5.
        just_bits = s.replace('0b', '')
        just_bits = just_bits.replace('_', '')
        out = int(just_bits, 2)
        #msgb("MAKE BINARY NUMERIC", "%s -> %d" % (s,out))
    elif make_numeric_old_decimal_pattern.match(s):
        sys.stderr.write("0m should not occur. Rewrite files!")
        sys.exit(1)
    elif make_numeric_old_binary_pattern.match(s):
        sys.stderr.write("B' binary specifer should not occur. Rewrite files!")
        sys.exit(1)
    else:
        out = int(s)
    return out


def no_comments(line):
    comment_pattern = re.compile(r'[#].*$')
    oline = comment_pattern.sub('', line)
    oline = oline.strip()
    return oline


def process_continuations(lines):
    continuation_pattern = re.compile(r'\\$')
    olines = []
    while len(lines) != 0:
        line = no_comments(lines[0])
        line = line.strip()
        lines.pop(0)
        if line == '':
            continue
        if continuation_pattern.search(line):
            # combine this line with the next line if the next line exists
            line = continuation_pattern.sub('', line)
            if len(lines) >= 1:
                combined_lines = [line + lines[0]]
                lines.pop(0)
                lines = combined_lines + lines
                continue
        olines.append(line)
    del lines
    return olines


def die(s):
    stderr(s)
    sys.exit(-1)
