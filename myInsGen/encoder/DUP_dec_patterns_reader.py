import copy

import state_bits_reader
import fields_reader
import actions
import slash_expand

from patterns import *
from util import *

from global_init import *
from pattern_class import *

from dec_class import *

# for the first not commented, non-empty line from lines,
# return if regexp.search succeeds


def accept(regexp, lines):
    #logger.debug("In accept!")
    line = ''
    while line == '':
        if lines == []:
            return None
        line = no_comments(lines[0])
        line = line.strip()
        lines.pop(0)
    #logger.debug("Testing line :" + line)
    if re.search(regexp, line):
        return True
    return False


def expand_hierarchical_records(ii):
    """Return a list of new records splitting the extra_ipatterns and
    extra_operands in to new stuff"""
    new_lines = []

    # FIXME: perf: 2007-08-05 mjc could skip this expansion when not
    # needed and save the copying.

    extra_operands = ii.extra_operands
    extra_ipatterns = ii.extra_ipatterns
    extra_iforms_input = ii.extra_iforms_input
    ii.extra_operands = None
    ii.extra_ipatterns = None
    ii.extra_iforms_input = None

    # start with the first instruction, then expand the "extra" ones
    new_lines.append(ii)

    if len(extra_ipatterns) != len(extra_operands) or \
       len(extra_ipatterns) != len(extra_iforms_input):
        die("Missing some patterns, operands or iforms for " + ii.iclass)

    for (ipattern, operands, iform) in zip(extra_ipatterns,
                                           extra_operands,
                                           extra_iforms_input):
        new_rec = copy.deepcopy(ii)
        new_rec.new_inum()
        new_rec.extra_operands = None
        new_rec.extra_ipatterns = None
        new_rec.extra_iforms_input = None
        new_rec.ipattern_input = ipattern
        new_rec.operands_input = operands
        new_rec.iform_input = iform
        #logger.debug("ISET2: %s -- %s" % (iform, str(operands)))
        new_lines.append(new_rec)

    del extra_ipatterns
    del extra_operands
    return new_lines


def is_nonterminal_line(s):
    g = nonterminal_start_pattern.search(s)
    if g:
        # remove everything from the parens to the end of the line
        # including two colons
        t = parens_to_end_of_line.sub('', s)
        wrds = t.split()
        short_nt_name = wrds[-1]
        if len(wrds) == 1:
            type = None
            logger.debug("NONTERMINAL: " + short_nt_name + " notype")
        else:
            type = wrds[0]
            logger.debug("NONTERMINAL: " + short_nt_name + " type= " + type)
        return (short_nt_name, type)
    return (None, None)


def read_structured_input(agi, options, parser, lines, state_dict):
    logger.debug("read_structured_input")
    while len(lines) != 0:
        # logger.debug("NEXTLINE " + lines[0])
        first_line = no_comments(lines[0])
        if first_line == '':
            lines.pop(0)
            continue
        first_line = slash_expand.expand_all_slashes(first_line)

        if udelete_pattern.search(first_line):
            m = udelete_full_pattern.search(first_line)
            uname = m.group('uname')
            logger.debug("REGISTERING UDELETE %s" % (uname))
            parser.deleted_unames[uname] = True
            lines.pop(0)
        elif delete_iclass_pattern.search(first_line):
            m = delete_iclass_full_pattern.search(first_line)
            iclass = m.group('iclass')
            parser.deleted_instructions[iclass] = True
            lines.pop(0)

        elif nonterminal_start_pattern.search(first_line):
            logger.debug("Hit a nonterminal, returning at: " + first_line)
            break
        else:
            ii = instruction_info_t()
            okay = ii.read_structured_flexible(lines)
            if okay:
                #mbuild.logger.debug("PATTERN:", ii.ipattern_input)
                # when there are multiple patterns/operands in the
                # structured input, we flatten them out here, making
                # multiple complete records, one per
                # pattern/set-of-operands.
                flat_ii_recs = expand_hierarchical_records(ii)

                # finalize initialization of instruction records
                for flat_ii in flat_ii_recs:
                    flat_ii.refine_parsed_line(agi, state_dict)
                    flat_ii.add_fixed_base_attribute()
                    flat_ii.add_scalable_attribute(agi.scalable_widths, agi)
                    if flat_ii.otherwise_ok:
                        parser.otherwise_ok = True  # FIXME 2008-09-25: is this used?
                    else:

                        parser.instructions.append(flat_ii)

    logger.debug("parser returning with " +
                 str(len(lines)) + ' lines remaining.')
    return lines


def parse_extra_operand_bindings(agi, extra_bindings):
    """Add the captures as operands"""
    operands = []
    operand_storage_dict = agi.operand_storage.get_operands()
    for (name, bits) in extra_bindings:
        # FIXME handle something other than bits
        bits_str = make_binary(bits)
        # FIXME: add "i#" width codes for the captured operands!
        try:
            bits = operand_storage_dict[name].bitwidth
            oc2 = "i%s" % (bits)
        except:
            die("Could not find field width for %s" % (name))

        new_operand = opnds.operand_info_t(name,
                                           'imm',
                                           list(bits_str),
                                           vis='SUPP',
                                           oc2=oc2)
        # DENOTE THESE AS INLINE TO ALLOW EARLY CAPTURING
        # logger.debug("INLINE OPERAND %s" % (name))
        new_operand.inline = True
        operands.append(new_operand)
    return operands


def parse_opcode_spec(agi, line, state_dict):
    """Given a string of bits, spaces and hex codes, canonicalize it
    to useful binary, return a list of single char bits or letters, or
    nonterminals.

    @rtype:  tuple
    @return: (list of bits, -- everything is raw bits at this level
              list of operand binding tuples,--  same info as the prebindings
              list bit_info_t, -- interpreted bits with types and positions
              dict of prebinding_t,  -- dictionary of the captured fields 
                                        pointing to bits
              xed_bool_t otherwise_ok)
    """
    # if there are any trailing underscores after a nonterminal paren,
    # convert them to spaces.
    b = paren_underscore_pattern.sub('() ', line)
    # if there are any leading underscores before, convert them to spaces

    extra_bindings = []  # the inline captures become "extra" operands later
    # logger.debug("PARSE OPCODE SPEC " + line)
    # expand things from the state dictionary
    wrds = []
    for w in b.split():
        if w in state_dict:
            wrds.extend(copy.deepcopy(state_dict[w].list_of_str))
        else:
            wrds.append(w)
    all_bits = []
    #
    # 1. hex byte
    # 2. immediate capture IMM(a-z,0-9) ??? IS THIS USED???
    #                      IMM(a,9) -- old form of slash
    # 3. slash pattern (just more letter bits)
    # 4. pattern binding eg: MOD[mm] or MOD[11_]
    # 5. nonterminal
    # Then EXPAND
    all_bit_infos = []
    all_prebindings = {}
    bcount = 0  # bit count
    for w in wrds:
        if w == 'otherwise':
            return (None, None, None, None, True)

        if hex_pattern.match(w):
            bits = pad_to_multiple_of_8bits(hex_to_binary(w))
            for b in bits:
                all_bit_infos.append(bit_info_t(b, 'bit', bcount))
                bcount += 1
            all_bits.extend(bits)
            continue

        # inline captures MOD[mm] REG[rrr] RM[nnn] or REG[111] etc. --
        # can be constant
        pb = pattern_binding_pattern.match(w)
        if pb:
            #logger.debug("PATTERN BINDING", w)
            (field_name, bits) = pb.group('name', 'bits')
            if uppercase_pattern.search(bits):
                die("\n\nUpper case letters in capture pattern" +
                    ": %s in line\n\n %s\n\n" % (w, line))

            validate_field_width(agi, field_name, bits)
            extra_bindings.append((field_name, bits))
            prebinding = prebinding_t(field_name)
            bits_str = make_binary(bits)
            bits_list = list(bits_str)
            # print "BITS %s -> %s" % ( bits, bits_str)
            for b in bits_list:
                # btype is either bit or dontcare
                btype = get_btype(b)
                bi = bit_info_t(b, btype, bcount)
                bcount += 1
                prebinding.add_bit(bi)
                all_bit_infos.append(bi)
            all_prebindings[field_name] = prebinding
            all_bits.extend(bits_list)
            continue
        if nonterminal_pattern.search(w):
            # got a nonterminal
            bits = [w]
            all_bit_infos.append(bit_info_t(w, 'nonterminal', bcount))
            bcount += 1
            all_bits.extend(bits)
            continue

        m = restriction_pattern.search(w)
        if m:
            (token, test, requirement) = m.groups([0, 1, 2])
            # got an operand-decider (requirement)
            #logger.debug("RESTRICTION PATTERN " +  str(w))
            # we skip some field bindings that are only for the encoder.
            # They are denoted DS in the fields data-files.
            if agi.operand_storage.decoder_skip(token):
                #logger.debug("SKIPPING RESTRICTION PATTERN " +  str(w))
                continue

            # avoid adding redundant restriction patterns
            if w not in all_bits:
                # bit_info_t constructor reparses restriction pattern
                all_bit_infos.append(bit_info_t(w, 'operand', bcount))
                bcount += 1
                all_bits.extend([w])
            continue

        if formal_binary_pattern.search(w):
            bits = make_binary(w)
            all_bits.extend(bits)
            for b in list(bits):
                btype = get_btype(b)
                all_bit_infos.append(bit_info_t(b, btype, bcount))
                bcount += 1
            continue

        # remove the underscores now that we know it is a pattern
        w = w.replace('_', '')
        # some binary value or letter
        bits = [str(x) for x in list(w)]
        all_bits.extend(bits)
        for b in list(bits):
            btype = get_btype(b)
            all_bit_infos.append(bit_info_t(b, btype, bcount))
            bcount += 1

    # We now also have a a list of bit_info_t's in all_bit_infos and a
    # dictionary of prebinding_t's in all_prebindings.

    return (all_bits, extra_bindings, all_bit_infos, all_prebindings, False)


def read_flat_input(agi, options, parser, lines, state_dict):
    """These are the simple format records, one per line. Used for
    non-instruction things to make partitionable objects"""
    logger.debug("read_flat_input " + str(global_inum))
    while len(lines) > 0:
        if verb4():
            logger.debug("NEXTLINE " + lines[0])
        first_line = no_comments(lines[0])
        if first_line == '':
            lines.pop(0)
            continue
        first_line = slash_expand.expand_all_slashes(first_line)
        if nonterminal_start_pattern.search(first_line):
            logger.debug("Hit a nonterminal, returning at: " + first_line)
            break

        try:
            (new_bits, bindings) = first_line.split('|')
        except ValueError:
            die('Could not split line in to 2 pieces based on vertical bar: [' +
                first_line + ']')

        (opcode_spec,
         extra_bindings,
         all_bit_infos,
         all_prebindings,
         otherwise_ok) = parse_opcode_spec(agi, new_bits, state_dict)

        if otherwise_ok:
            parser.otherwise_ok = True  # FIXME 2008-09-25 need to change this
            #  if 'otherwise' node have RHS support.
            lines.pop(0)
            continue

        operands_input = bindings.split()
        (operands, reset_for_prefix) = parse_operand_spec(agi, operands_input)
        if extra_bindings:
            extra_operands = parse_extra_operand_bindings(agi, extra_bindings)
            operands.extend(extra_operands)

        # now put  opcode_spec, and operands in to a data structure

        # FIXME add a table and line number for the name?
        pi = partitionable_info_t('', new_bits, operands_input)
        pi.input_str = first_line

        pi.ipattern = bits_list_t()
        pi.ipattern.bits = all_bit_infos

        pi.prebindings = all_prebindings

        pi.operands = operands  # list of opnds.operand_info_t
        pi.reset_for_prefix = reset_for_prefix

        parser.instructions.append(pi)  # FIXME: instruction is a misnomer here

        lines.pop(0)

    return lines


def read_input(agi, lines):
    """Read the input from a flat token-per-line file or a structured
    ISA input file"""
    logger.debug("read_input " + str(global_inum))
    # first line must be a nonterminal
    (nt_name, nt_type) = is_nonterminal_line(lines[0])
    if not nt_name:
        die("Did not find a nonterminal: " + lines[0])

    parser = None
    # see if we  have encountered this nonterminal before
    try:
        gi = agi.generator_dict[nt_name]
        # we have a re-occurrence of an earlier nonterminal. We extend it now.
        logger.debug("FOUND OLD PARSER FOR " + nt_name)
        parser = gi.parser_output
    except:
        # need to make a new generator & parser
        parser = parser_t()
        parser.nonterminal_line = lines[0].strip()
        parser.nonterminal_name = nt_name
        parser.nonterminal_type = nt_type
        gi = agi.make_generator(nt_name)
        gi.parser_output = parser
        agi.nonterminal_dict.record_nonterminal(nt_name, nt_type)

    logger.debug("Nonterminal " + parser.nonterminal_line)
    logger.debug("Nonterminal name " + parser.nonterminal_name)
    lines.pop(0)

    # The {...} defined "instruction" patterns must have the substring
    # "INSTRUCTIONS" in their name.

    if instructions_pattern.search(parser.nonterminal_name):
        nlines = read_structured_input(agi,
                                       agi.common.options,
                                       parser,
                                       lines,
                                       agi.common.state_bits)
    else:
        nlines = read_flat_input(agi,
                                 agi.common.options,
                                 parser,
                                 lines,
                                 agi.common.state_bits)
    return nlines


if __name__ == "__main__":
    all_dec_ins = "all-datafiles\\all_test\\all-dec-instructions.txt"
    with open(all_dec_ins) as f:
        lines = f.readlines()
    lines = process_continuations(lines)
    nlines = read_flat_input()