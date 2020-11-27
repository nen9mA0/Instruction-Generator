import re
import slash_expand

comment_pattern = re.compile(r'#.*$')
leading_whitespace_pattern = re.compile(r'^\s+')


def parse_state_bits(lines):
    d = []
    state_input_pattern = re.compile(r'(?P<key>[^\s]+)\s+(?P<value>.*)')
    while len(lines) > 0:
        line = lines.pop(0)
        line = comment_pattern.sub("",line)
        line = leading_whitespace_pattern.sub("",line)
        if line == '':
            continue
        line = slash_expand.expand_all_slashes(line)
        p = state_input_pattern.search(line)
        if p:
            #_vmsgb(p.group('key'), p.group('value'))
            #d[p.group('key')] = p.group('value')
            s = r'\b' + p.group('key') + r'\b'
            pattern = re.compile(s) 
            d.append( (pattern, p.group('value')) )
        else:
            print("Bad state line: %s"  % line)
            exit()
    return d

def ReadState(filename):
    lines = open(filename, 'r').readlines()
    state_bits = parse_state_bits(lines)
    return state_bits

if __name__ == "__main__":
    state_bits = ReadState("../../all-datafiles/all-state.txt")
    pass