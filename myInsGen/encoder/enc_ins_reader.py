import state_bits_reader
import fields_reader
import slash_expand
import actions

from patterns import *
from util import *
from global_init import *
from pattern_class import *
from blot import *

def make_decode_patterns(s):
    """ return one or more subpatterns of type.

    Sometimes we specify an decode pattern like MOD[mm] or
    MOD[11_]. The 2nd part of the return tuple is a list of the
    implied decode operands such as MOD=mm or MOD=11_.
    
    @rtype: tuple
    @returns: (list of blot_t's representing patterns,\
                a list of tuples of field bindings)
    """
    decode_patterns = []
    field_bindings = []
    while 1:
        nt = nt_name_pattern.match(s)
        if nt:
            decode_patterns.append(make_nt(nt.group('ntname')))
            break
        opcap = lhs_capture_pattern_end.match(s)
        if opcap:
            # MOD[mm] REG[0b000] 
            bits = opcap.group('bits')
            field_name = opcap.group('name')
            if binary_pattern.match(bits):
                decode_patterns.append(make_binary(bits, field_name))
            elif hex_pattern.match(bits):
                decode_patterns.append(make_hex(bits, field_name))
            elif letter_pattern.match(bits):
                o = make_bits_and_letters( bits, field_name) 
                decode_patterns.extend(o)
            else:
                die("Unrecognaized pattern '{}' for {}".format( bits, s))
            field_bindings.append(  opcap.group('name','bits') )
            break
        if hex_pattern.match(s):
            decode_patterns.append(make_hex(s))
            break
        s_nounder = no_underscores(s)
        if binary_pattern.match(s_nounder):
            decode_patterns.append(make_binary(s_nounder))
            break
        if bits_and_letters_pattern.match(s_nounder):
            decode_patterns.extend(make_bits_and_letters(s_nounder))
            break
        if letter_pattern.match(s_nounder):
            decode_patterns.extend(make_bits_and_letters(s_nounder))
            break
        equals = equals_pattern.match(s)
        if equals:
            (lhs,rhs) = equals.group('lhs','rhs')
            decode_patterns.append(make_decider_blot(lhs,rhs,equals=True))
            break
        not_equals = not_equals_pattern.match(s)
        if not_equals:
            (lhs,rhs) = not_equals.group('lhs','rhs')
            decode_patterns.append(make_decider_blot(lhs,rhs,equals=False))
            break
        die("Could not process decode pattern %s" % s)
    return (decode_patterns, field_bindings)

def force_vl_encoder_output( iclass, operand_str, pattern_str):
    """Return true if we should treat VL as an encoder_output (EO)"""
    if 'VEXVALID=1' in pattern_str or 'VEXVALID=2' in pattern_str:
        if 'XMM' in operand_str or 'YMM' in operand_str or 'ZMM' in operand_str:
            return False
        if ':vv' in operand_str:
            return False
        if 'VL=' in pattern_str:
            #print("SETTING FORCE_VL_ENCODER_OUTPUT FOR {}".format(iclass))
            #print("\t PATTERN:  {}".format(pattern_str))
            #print("\t OPERANDS: {}".format(operand_str))
            return True
    return False

def parse_one_decode_rule( iclass, operand_str, pattern_str):
    """Read the decoder rule from the main ISA file and package it
    up for encoding. Flipping things around as necessary.
    
    @type operand_str: string
    @param operand_str: decode operands

    @type pattern_str: string
    @param pattern_str: decode pattern (bits, nts, ods, etc.)
    
    @rtype: tuple
    @return: (list decode-operands/encode-conditions as operand_t's, \
                list decode-patterns/encode-actions as blot_t's \
                list of modal patterns strings that should become encode condition_t objs)
    """
    # generally:
    #
    #  decode-pattern  --become--> encode-action
    #  decode-operands --become--> encode-condition
    #
    # but there are special cases:
    #
    #  1) Some decode-pattern stuff needs to become encode-conditions
    #     as they are encoder inputs
    #  2) Some decode-operand stuff needs to become encode-actions
    #     as they are encoder outputs

    patterns = []

    # The extra_bindings_list is a list of implied bindings deduced
    # from the decode pattern, for things like  MOD[mm] (etc.) that do
    # field captures in the pattern. We use them to create
    # new (decode) operands (which then become encode conditions).
    extra_bindings = []

    # Some decode patterns become encode conditions.  These are
    # the fields that are listed as "EI" (encoder inputs) in the
    # "fields description" file.
    modal_patterns = []

    # decode-patterns *mostly* become encode-actions, except for
    # fields that are encoder inputs.
    for p in pattern_str.split(): 
        p_short = rhs_pattern.sub('', p)  # grab the lhs

        # special cases

        # VL is generally an encoder input, except in some cases
        # (VZERO*, BMI, KMASKS, etc.)
        do_encoder_input_check = True
        if p_short in ['VL'] and force_vl_encoder_output(iclass, operand_str, pattern_str):
            do_encoder_input_check = False
            
        if do_encoder_input_check:
            if p_short in gs.storage_fields and gs.storage_fields[p_short].encoder_input:
                logger.debug("MODAL PATTERN: %s" %p_short)
                modal_patterns.append(p)
                continue

        if p_short in gs.storage_fields and p == 'BCRC=1':
            # FIXME: 2016-01-28: MJC: HACK TO ENCODE ROUNDC/SAE CONSTRAINTS
            if 'SAE' in pattern_str:
                modal_patterns.append("SAE!=0")
            elif 'AVX512_ROUND' in pattern_str:
                modal_patterns.append("ROUNDC!=0")
        
        # The pattern_list is a list of blot_t's covering the
        # pattern.  The extra_bindings_list is a list of
        # implied bindings deduced from the decode patterns.
        ##
        # The extra bindings are for MOD[mm] (etc.) that do
        # field captures in the pattern. We use them to create
        # new operands.

        # pattern_list is a list of blot_t
        # extra_bindings is list list of tuples (name,bits)
        (pattern_list, extra_bindings_list) = make_decode_patterns(p) 
        s = []
        for p in pattern_list:
            s.append(str(p))
        logger.debug("PATTERN LIST: %s" %", ".join(s))
        logger.debug("EXTRABINDING LIST: %s" %str(extra_bindings_list))
        patterns.extend(pattern_list)
        extra_bindings.extend(extra_bindings_list)
        
    # Decode operands are type:rw:[lencode|SUPP|IMPL|EXPL|ECOND]
    # where type could be X=y or MEM0.  Most decode operands
    # become encode conditions, but some of them get converted in
    # to extra encode actions.
    
    operands = []  # to become encoder inputs, conditions
    extra_actions = [] # to become encoder outputs
    for x in operand_str.split(): # the encode conditions (decode operands)
        x_short = rhs_pattern.sub('', x) # grab the lhs

        # Some "operands" are really side effects of decode.  They
        # are also side effects of encode and so we move them to
        # the list of actions.
        
        special_encode_action = False 
        try:
            # Move some decode operands (the ones that are not
            # encoder inputs) to the extra encode actions.
            if gs.storage_fields[x_short].encoder_input== False:
                logger.debug("ENCODER OUTPUT FIELD: %s" %x_short)
                special_encode_action = True
        except:
            pass

        if special_encode_action:
            logger.debug("SPECIAL_ENCODE_ACTION ATTRIBUTE %s" %x)
            extra_actions.append(x)
        else:
            logger.debug("MAKING A DECODE-OPERAND/ENC-ACTION FROM %s" %x)
            operands.append(operand_t(x))


            
    # Add the extra encode conditions (decode-operands) implied
    # from the instruction decode patterns (MOD[mm] etc.). We
    # ignore the ones for constant bindings!
    for (field_name,value) in extra_bindings:
        if numeric(value):
            #msgerr("IGNORING %s %s" % (field_name, value))
            pass # we ignore things that are just bits at this point.
        else:
            extra_operand = operand_t("%s=%s:SUPP" % (field_name, value))
            logger.debug("EXTRA BINDING %s=%s:SUPP" % (field_name, value))
            operands.append(extra_operand)

    # Add the extra_actions were part of the decode operands as
    # side-effects but are really side-effects of encode too.
    for raw_action in extra_actions:
        okay = False
        equals = equals_pattern.match(raw_action)
        if equals:
            (lhs,rhs) = equals.group('lhs','rhs')
            new_blot = make_decider_blot(lhs,rhs,equals=True)
            okay = True
        not_equals = not_equals_pattern.match(raw_action)
        if not_equals:
            (lhs,rhs) = equals.group('lhs','rhs')
            new_blot = make_decider_blot(lhs,rhs,equals=False)
            okay = True
        if not okay:
            die("Bad extra action: %s" % raw_action)
        #msgerr("NEW BLOT: %s" % str(new_blot))
        patterns.append(new_blot)


    # return:  (decode-operands are encode-conditions,
    #            decode-patterns are encode-actions [blot_t],
    #              modal-patterns that become encode-conditions [string])

    #msgerr("OPERANDS %s" % ' '.join( [str(x) for x in operands]))
    return (operands, patterns, modal_patterns)

def finalize_decode_conversion(iclass, operands, ipattern, uname=None):
    if ipattern  == None:
        die("No ipattern for iclass %s and operands: %s" % 
            (str(iclass), operands ))
    if iclass  == None:
        die("No iclass for " + operands)
    # the encode conditions are the decode operands (as [ operand_t ])
    # the encode actions are the decode patterns    (as [ blot_t ])
    (conditions, actions, modal_patterns) = \
                    parse_one_decode_rule(iclass, operands, ipattern)
    # FIXME do something with the operand/conditions and patterns/actions
    iform = iform_t(iclass, conditions, actions, modal_patterns, uname)

    if uname == 'NOP0F1F':
        # We have many fat NOPS, 0F1F is the preferred one so we
        # give it a higher priority in the iform sorting. 
        iform.priority = 0
    elif 'VEXVALID=2' in ipattern:  # EVEX
        # FIXME: 2016-01-28: MJC: hack. 1st check patterns w/ ROUNDC/SAE.
        # (See other instance of BCRC=1 in this file)
        if 'BCRC=1' in ipattern:
            iform.priority = 0
        else:
            iform.priority = 2
    elif 'VEXVALID=3' in ipattern: # XOP
        iform.priority = 3
    elif 'VEXVALID=4' in ipattern: # KNC
        iform.priority = 3
    else:  # EVERYTHING ELSE
        iform.priority = 1

    try:
        gs.iarray[iclass].append ( iform )
    except:
        gs.iarray[iclass] = [ iform ]

def expand_state_bits_one_line(line):
    new_line = line
    for k,v in gs.state_bits:
        new_line = k.sub(v,new_line)
    return new_line

def read_decoder_instruction_file(lines):
    """Taking a slightly different tack with the ISA file because
    it is so large. Processing each line as we encounter it rather
    than buffering up the whole file. Also, just storing the parts
    I need. """
    continuation_pattern = re.compile(r'\\$')
    lines = process_continuations(lines)
    nts = {}
    nt = None
    iclass = None
    uname = None
    unamed = None
    ipattern = None
    started = False
    while len(lines) > 0:
        line = lines.pop(0)
        line = comment_pattern.sub("",line)
        #line = leading_whitespace_pattern.sub("",line)
        line=line.strip()
        if line == '':
            continue
        line = slash_expand.expand_all_slashes(line)

        if udelete_pattern.search(line):
            m = udelete_full_pattern.search(line)
            unamed = m.group('uname')
            logger.debug("REGISTER BAD UNAME: %s" %unamed)
            gs.deleted_unames[unamed] = True
            continue

        if delete_iclass_pattern.search(line):
            m = delete_iclass_full_pattern.search(line)
            iclass = m.group('iclass')
            gs.deleted_instructions[iclass] = True
            continue
    
        
        line = expand_state_bits_one_line(line)
        p = nt_pattern.match(line)
        if p:
            nt_name =  p.group('ntname')
            if nt_name in nts:
                nt = nts[nt_name]
            else:
                nt = nonterminal_t(nt_name)
                nts[nt_name] = nt
            continue

        if left_curly_pattern.match(line):
            if started:
                die("Nested instructions")
            started = True
            iclass = None
            uname = None
            continue
        
        if right_curly_pattern.match(line):
            if not started:
                die("Mis-nested instructions")
            started = False
            iclass = None
            uname = None
            continue
        ic = iclass_pattern.match(line)
        if ic:
            iclass = ic.group('iclass')
            continue
        
        un = uname_pattern.match(line)
        if un:
            uname = un.group('uname')
            continue
        
        ip = ipattern_pattern.match(line)
        if ip:
            ipattern = ip.group('ipattern')
            continue
        
        if no_operand_pattern.match(line):
            finalize_decode_conversion(iclass,'', ipattern, uname)
            continue

        op = operand_pattern.match(line)
        if op:
            operands = op.group('operands')
            finalize_decode_conversion(iclass, operands, ipattern, uname)
            continue
    return

def ReadIns(filename):
    lines = open(filename, "r").readlines()
    read_decoder_instruction_file(lines)



if __name__ == "__main__":
    ReadIns(all_ins)
    pass