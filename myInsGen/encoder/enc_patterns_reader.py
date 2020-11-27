import state_bits_reader
import fields_reader
import actions
import slash_expand

from patterns import *
from util import *

from global_init import *
from pattern_class import *


def parse_encode_lines(lines, state_bits):
    """
    Returns a tuple of two dictionaries: (1) a dictionary of
    sequencer_t's and (2) a dictionary of nonterminal_t's
    """
    nts = {} # nonterminals_t's
    ntlufs = {} # nonterminals_t's
    seqs = {} # sequencer_t's 
    i = 0
    while len(lines) > 0:
        line = lines.pop(0)
        line = comment_pattern.sub("",line)
        line = leading_whitespace_pattern.sub("",line)
        if line == '':
            continue
        line = slash_expand.expand_all_slashes(line)

        c =  curly_pattern.search(line)
        if c:
            line = re.sub("{", " { ", line)
            line = re.sub("}", " } ", line)

        sequence = sequence_pattern.match(line)
        if sequence:
            seq = sequencer_t(sequence.group('seqname'))
            seqs[seq.name] = seq
            #msg("SEQ MATCH %s" % seq.name)
            nt = None
            continue

        p =  ntluf_pattern.match(line)
        if p:
            nt_name =  p.group('ntname')
            ret_type = p.group('rettype')
            # create a new nonterminal to use
            nt = nonterminal_t(nt_name, ret_type)
            ntlufs[nt_name] = nt
            seq = None
            continue

        m = nt_pattern.match(line)
        if m:
            nt_name =  m.group('ntname')
            if nt_name in nts:
                nt = nts[nt_name]
            else:
                nt = nonterminal_t(nt_name)
                nts[nt_name] = nt
            seq = None
            continue
        a = arrow_pattern.match(line)
        if a:
            conds = a.group('cond').split()
            actns = a.group('action').split()
            #msg("ARROW" + str(conds) + "=>" + str(actions))
            conditions = conditions_t()
            for c in conds:
                conditions.and_cond(c)
            rule = rule_t(conditions, actns, nt_name)
            if seq:
                seq.add(rule)
            else:
                # we do not need the rules otherwise->error/nothing in the 
                # new encoding structure (hash tables). 
                # instead we are holding this info in a matching attribute
                if rule.conditions.and_conditions[0].is_otherwise():
                    if rule.actions[0].is_nothing():
                        nt.otherwise = [actions.gen_return_action('1')] 
                    elif rule.actions[0].is_error():
                        nt.otherwise = [actions.gen_return_action('0')]
                    else:
                        nt.otherwise = [ actions.action_t(x) for x in actns]
                        # in case we have valid action for the otherwise
                        # rule we should finish it with returnning 1
                        # which is "not an error"
                        nt.otherwise.append(actions.gen_return_action('1'))
                else:
                    nt.add(rule)
        else:
            for nt in line.split():
                seq.add(nt)
    return (seqs,nts,ntlufs)

def expand_state_bits(lines, state_bits):
    new_lines = []
    # n^2 algorithm
    for line in lines:
        new_line = line
        for k,v in state_bits:
            new_line = k.sub(v,new_line)
        new_lines.append(new_line)
    return new_lines

def ReadEncPattern(filename, state_bits):
    lines = open(filename, 'r').readlines()
    lines = expand_state_bits(lines, state_bits)
    return parse_encode_lines(lines, state_bits)


if __name__ == "__main__":
    operand = fields_reader.ReadFields(all_field)
    storage_fields = operand.operand_fields
    state_bits = state_bits_reader.ReadState(all_state_file)
    (seqs,nts,ntlufs) = ReadEncPattern(all_enc_pattern, state_bits)

