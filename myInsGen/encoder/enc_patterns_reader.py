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

def parse_decode_lines(lines):
    """ Read the flat decoder files (not the ISA file).
    
    Return a tuple:
        ( dict of nonterminals, dict of nonterminal lookup functions )
        
        This parses the so-called flat format with the vertical
        bar used for all the non-instruction tables.

        For decode the semantics are:
            preconditions | dec-actions
        However for encode, the semantics change to:
            enc-actions  | conditions

        And we must take some of the "enc-actions"  and add them to the preconditions.
        These include the actions associated with: MODE,SMODE,EOSZ,EASZ
    """
    nts = {}
    ntlufs = {}

    while len(lines) > 0:
        line = lines.pop(0)
        #msge("LINEOUT:" + line)
        line = comment_pattern.sub("",line)
        line = leading_whitespace_pattern.sub("",line)
        line = line.rstrip()
        if line == '':
            continue
        line = slash_expand.expand_all_slashes(line)

        p =  ntluf_pattern.match(line)
        if p:
            nt_name = p.group('ntname')
            ret_type = p.group('rettype')
            # create a new nonterminal to use
            nt = nonterminal_t(nt_name, ret_type)
            ntlufs[nt_name] = nt
            continue
        
        p = nt_pattern.match(line)
        if p:
            nt_name =  p.group('ntname')
            # create a new nonterminal to use
            nt = nonterminal_t(nt_name)
            nts[nt_name] = nt
            continue
        
        p = decode_rule_pattern.match(line)
        if p:
            conds = p.group('cond').split() # rhs, from an encode perspective (decode operands)
            actions = p.group('action').split() # lhs, from a encode perspective (decode patterns)
            rule = parse_decode_rule(conds,actions,line,nt.name)
            if rule:
                nt.add(rule)
            if nt.multiple_otherwise_rules():
                die("Multiple otherwise rules in %s -- noninvertible" % (nt_name))
            continue
        
        die("Unhandled line: %s" % line)
        
    return  (nts, ntlufs)

def parse_decode_rule(conds, actions, line, nt_name):
    # conds   -- rhs, from an encode perspective (decode operands)
    # actions -- lhs, from an encode perspective (decode patterns)

    # move some special actions to the conditions
    new_actions = []
    for a in actions: # decode patterns
        logger.debug("parse_decode_rule actions %s" %str(a))
        q = lhs_pattern.match(a)
        if q:
            lhs_a = q.group('name')
            if lhs_a in gs.storage_fields and gs.storage_fields[lhs_a].encoder_input == True:
                logger.debug("CVT TO ENCODER CONDITION %s" %lhs_a)
                conds.append(a)
                continue
        opcap = lhs_capture_pattern_end.match(a)
        if opcap:
            synth_cap = "%s=%s" % (opcap.group('name'), opcap.group('bits'))
            conds.append( synth_cap )
            logger.debug("SYNTH CONDITION FOR " + a + " --> " + synth_cap )
            new_actions.append(a)
            continue
        logger.debug("NEWACTION " + a)
        new_actions.append(a)
    del actions

    # Move some special encode conditions to the encode
    # actions if they are not encoder inputs. This solves
    # a problem with encoding IMM0SIGNED on SIMMz()
    # nonterminals.
    new_conds = []
    for c in conds: # were decode operands (rhs)
        logger.debug("parse_decode_rule conditions %s" %str(c))
        if c.find('=') == -1:
            trimmed_cond = c
        else:
            ep = equals_pattern.match(c) # catches  "=", but not "!="
            if ep:
                trimmed_cond = ep.group('lhs')
            else:
                die("Bad condition: %s" % c)
        logger.debug("TESTING COND %s --> %s" % (c, trimmed_cond))
        keep_in_conds = True
        try:
            if gs.storage_fields[trimmed_cond].encoder_input == False:
                logger.debug("DROPPING COND", c)
                keep_in_conds = False # 2007-08-01
        except:
            pass
        
        # if we have the constraint: OUTREG=some_nt() and it is not the 
        # single constraint we want to move 
        # the nt: some_nt() to the actions side.
        # e.g. the constraint: MODE=3 OUTREG=GPRv_64() -> nothing
        #      becomes:        MODE=3 -> GPRv_64()
        if trimmed_cond == 'OUTREG':
            nt = nt_name_pattern.match(c.split('=')[1])
            if nt and len(conds) > 1:
                c = "%s(OUTREG)" % nt.group('ntname')
                keep_in_conds = False
                
        if keep_in_conds:
            new_conds.append(c)
        else:
            logger.debug("COND->ACTION " +  c) # FIXME: REMOVEME
            new_actions.append(c)
    conds = new_conds

    # signal it is okay if there is no action
    if len(new_actions) == 0:
        new_actions.append('nothing')

    if len(conds) == 0:
        conds = ['otherwise']

    if len(conds) > 0:
        conditions = conditions_t()
        for c in conds:
            #msge("COND " +  c) # FIXME: REMOVEME
            xr = xed_reg_pattern.match(c) # FIXME: not general enough
            if xr:
                conditions.and_cond("OUTREG=%s" % (xr.group('regname')))
            else:
                conditions.and_cond(c)
        # only add a rule if we have conditions for it!    
        rule = rule_t(conditions, new_actions, nt_name)
        return rule
    else:
        logger.debug("DROP DECODE LINE (NO eCONDS) %s\nin NT: %s" %(line,nt_name))
    return None

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

def ReadEncDecPattern(filename, state_bits):
    lines = open(filename, "r").readlines()
    lines = expand_state_bits(lines, state_bits)
    (nts, ntlufs) = parse_decode_lines(lines)
    gs.nts.update(nts)
    gs.ntlufs.update(ntlufs)

if __name__ == "__main__":
    operand = fields_reader.ReadFields(all_field)
    storage_fields = operand.operand_fields
    state_bits = state_bits_reader.ReadState(all_state_file)
    (seqs,nts,ntlufs) = ReadEncPattern(all_enc_pattern, state_bits)

