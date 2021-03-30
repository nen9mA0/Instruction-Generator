import re

from util import *
from global_init import *
from pattern_class import *
from patterns import *

class operand_t(object):
    """These are main ISA (decode) operands being used for encode
    conditions. They are either individual tokens or X=y bindings. The
    tokens or RHS of bindings can have qualifiers separated by colons:
    (1) r/w/rw/cr/crcw/rcw/cw, (2) EXPL, IMPL, SUPP or ECOND, (3)
    length-code. The EXPL/IMPL/SUPP/ECOND is optional as is the length
    code. Memops must have the length code."""

    convert_pattern = re.compile(r'TXT=(?P<rhs>[0-9A-Za-z_]+)')

    opnd_type = ('MEM', "IMM", "REG", "MOD", "RM", "RELBR", "SEG", "BASE", "PTR", "INDEX", "AGEN", "SCALE")
    # now only test on BASE instructions

    def __init__(self,s):
        pieces=s.split(':')
        op_or_binding = pieces[0]
        self.lencode = '?'
        self.vis = None
        explicit_vis = None
        self.rw = '?'
        self.type = None # 'token', 'binding', 'ntluf'
        if len(pieces) >= 2:
            nxt= pieces[1]
            if nxt in [ 'IMPL', 'SUPP','EXPL', 'ECOND']:
                explicit_vis = nxt
            else:
                self.rw = pieces[1]
            if len(pieces) >= 3:
                for p in pieces[2:]:
                    cp=operand_t.convert_pattern.match(p)
                    if cp:
                        cvt = cp.group('rhs') # ignored
                    elif p in [ 'IMPL', 'SUPP', 'EXPL', 'ECOND']:
                        explicit_vis = p
                    elif self.lencode == '?':
                        self.lencode = p
                    else:
                        logger.warning("Ignoring [%s] from %s" % (p,s))
                        #die("Unhandled operand: %s" % s)

        self.value = None
        self.ntluf = False
        ap = equals_pattern.match(op_or_binding)
        if ap:       # binding
            (self.var,self.value) = ap.group('lhs','rhs')
            ntluf_match = nt_name_pattern.match(self.value)
            if ntluf_match:
                self.value = ntluf_match.group('ntname')
                self.ntluf = True
                self.type = 'ntluf'
            else:
                self.type = 'binding'
        else:        # operand (MEM/IMM/DISP/etc.)
            self.var = op_or_binding
            self.type = 'token'

        if explicit_vis:
            self.vis = explicit_vis
        else:
            default_vis = gs.storage_fields[self.var].default_visibility
            if default_vis == 'SUPPRESSED':
                self.vis = 'SUPP'
            elif default_vis == 'EXPLICIT':
                self.vis = 'EXPL'
            elif default_vis == 'ECOND':
                self.vis = 'ECOND'
            else:
                die("unhandled default visibility: %s for %s" % (default_vis, self.var))

    def InOpndType(self):
        flag = False
        for op_type in self.opnd_type:
            if op_type in self.var:
                flag = True
        return flag

    def IsInput(self):
        if 'r' in self.rw:
            return True
        else:
            return False

    def IsOutput(self):
        if 'w' in self.rw:
            return True
        else:
            return False

    def make_condition(self):
        """
        @rtype: condition_t or None
        @return: list of conditions based on this operand """
        # ignore suppressed operands in encode conditions
        if self.vis == 'SUPP':
            return None

        # make s, a string from which we manufacture a condition_t
        if self.type == 'binding':
            if letter_pattern.match(self.value):
                # associate the field with some letters
                s = "%s[%s]=*" % (self.var, self.value)
            else:
                s = "%s=%s" % (self.var, self.value)
        elif self.type  == 'token':
            s = "%s=1" % (self.var) # FIXME need to specify memop widths
        elif self.type == 'ntluf':
            s = "%s=%s()" % (self.var,self.value)
        else:
            die("Unhandled condition: %s" % str(self))
        #msgerr("MAKE COND %s" % s)
        c = condition_t(s)

        #msgerr("XCOND type: %s var: %s lencode: %s" % (self.type, self.var, str(self.lencode)))
        # FIXME: THIS IS A DISGUSTING HACK
        if self.type == 'token' and self.var == 'MEM0':
            # add a secondary condition for checking the width of the memop.
            #
            #  NOTE: this MEM_WIDTH is not emitted! It is used in
            #  xed_encoder_request_t::memop_compatible()
            c2 = condition_t('MEM_WIDTH',self.lencode) # MEM_WIDTH
            #msgerr("\tRETURNING LIST WITH MEM_WIDTH")
            return [c, c2]
        return [c]
    
    def __str__(self):
        if self.vis == 'EXPL':
            pvis = ''
        else:
            pvis = ":%s" % self.vis

        if self.lencode == '?':
            plen = ''
        else:
            plen = ":%s" % self.lencode

        if self.rw == '?':
            prw = ''
        else:
            prw = ":%s" % self.rw
        
        if self.value:
            if self.ntluf:
                parens = '()'
            else:
                parens = ''
            return  "%s=%s%s%s%s%s" % ( self.var, self.value, parens, prw, plen, pvis)
        return  "%s%s%s%s" % ( self.var, prw, plen, pvis)

class iform_t(object):
    """One form of an instruction"""
    mask = max_int
    if int_width == 64:
        hash_mask_low = 0x7fffffff
        hash_mask_high = mask ^ hash_mask_low
    else:
        hash_mask_low = 0x7fff
        hash_mask_high = mask ^ hash_mask_low

    def __init__(self, iclass, enc_conditions, enc_actions, modal_patterns, category, extension, uname=None, cpl=None):
        self.iclass = iclass
        self.uname = uname
        self.enc_conditions = enc_conditions # [ operand_t ]
        self.enc_actions = enc_actions  # [ blot_t ]
        self.modal_patterns = modal_patterns # [ string ]

        # the emit phase action pattern is a comma separated string of
        # strings describing emit activity, created by ins_emit.py.
        self.emit_actions = None 
        
        #the FB actions pattern
        self.fb_ptrn = None
        
        self._fixup_vex_conditions()
        self.rule = self.make_rule()

        self.cpl = cpl
        self.category = category
        self.extension = extension

        self.input_op = []
        self.output_op = []
        self.GetInputOutput()

        tmp1 = hash(self.iclass)
        tmp2 = hash(str(self.rule))
        self.hash = (tmp1 & iform_t.hash_mask_high) | (tmp2 & iform_t.hash_mask_low)  # hash for using set


    def __hash__(self):     # modify for using set structure
        return self.hash

    def __eq__(self, rhs):
        if not isinstance(rhs, type(self)):
            return NotImplemented
        return self.hash == rhs.hash

    def GetInputOutput(self):
        for opnd in self.enc_conditions:
            if opnd.InOpndType():
                if opnd.type == "ntluf":
                    nt = True
                else:
                    nt = False
                if opnd.IsInput():
                    self.input_op.append((opnd.var, nt, opnd.value))
                if opnd.IsOutput():
                    self.output_op.append((opnd.var, nt, opnd.value))
            else:
                logger.error("%s Not in Opnd Type" %opnd.var)

    def _fixup_vex_conditions(self):
        """if action has VEXVALID=1, add modal_pattern MUST_USE_AVX512=0. 
           The modal_patterns become conditions later on."""
        for act in self.enc_actions:
            if act.field_name == 'VEXVALID' and act.value == 1:
                self.modal_patterns.append( "MUST_USE_EVEX=0" )
    
    def make_operand_name_list(self):
        """Make an ordered list of operand storage field names that
        drives encode operand order checking. """
        operand_names = []
        for opnd in self.enc_conditions:
            logger.info( "EOLIST iclass %s opnd %s vis %s" % (self.iclass, opnd.var, opnd.vis))
            if opnd.vis == 'SUPP':
                continue
            if opnd.vis == 'ECOND':
                continue
            if self._check_encoder_input(opnd.var):
                operand_names.append(opnd.var)
        # 2007-07-05 We do not need to add MEM_WIDTH, since that does
        # not affect operand order. It is checked for memops by
        # encode.
        return operand_names
            

    def compute_binding_strings_for_emit(self):
        """Gather up *all* the conditions (suppressed or not) and
        include them as possible canditates for supplying bits for the
        encoder."""

        captures = []
        for opnd in self.enc_conditions: # each is an operand_t
            if opnd.type == 'binding':
                if letter_and_underscore_pattern.match(opnd.value):
                    captures.append((opnd.var, no_underscores(opnd.value)))
                else:
                    pass
                    #msge("SKIPPING BINDING " + str(opnd))

        # add the C decoration to the field name for emitting code.
        decorated_captures = []
        for (f,b) in captures:
            decorated_captures.append((operand_storage.get_op_getter_fn(f),b))
        return decorated_captures

    def _check_encoder_input(self,name):
        """Return True for things that are storage field encoder inputs"""
        if name in gs.storage_fields and gs.storage_fields[name].encoder_input:
            return True
        return False

    def find_encoder_inputs(self):
        """Return a set of encoder input field names"""
        s = set()
        ns = set()
        for mp in self.modal_patterns:
            if self._check_encoder_input(mp):
                s.add(mp)
                
        for op in self.enc_conditions:
            # The encoder ignores SUPP operands.
            if op.vis == 'SUPP':
                continue
            if op.type == 'token' or op.type == 'binding' or op.type == 'ntluf':
                if self._check_encoder_input(op.var):
                    s.add(op.var)
            if op.lencode != '?':
                s.add('MEM_WIDTH')
            if op.ntluf:
                ns.add(op.value)
        return (s,ns)

    def make_rule(self):
        """Return a rule_t based on the conditions and action_list."""
        logger.debug("MAKE RULE for %s" % str(self))
        action_list = []  # [ string ]
        for blot in self.enc_actions:
            a = blot.make_action_string()
            if a:
                action_list.append(a)

        cond = conditions_t()
        for mp in self.modal_patterns:
            logger.debug("Adding MODAL_PATTERN %s" %mp)
            c = condition_t(mp)
            cond.and_cond(c)

        for opnd in self.enc_conditions:
            # some conditions we ignore: like for SUPP registers...
            logger.debug("OPERAND: %s" % (str(opnd)))
            c = opnd.make_condition()
            if c:
                logger.debug("\t MADE CONDITION")
                for subc in c:
                    logger.debug("\t\tANDCOND %s" % str(subc))
                    cond.and_cond(subc)
            else:
                logger.debug("\t SKIPPING OPERAND in the AND CONDITIONS")
        #here we are handling only instructions.
        #Do not need to specify the nt name since the instructions have 
        #their own emit function and this nt name is not used      
        rule = rule_t(cond,action_list, None)
        self._remove_overlapping_actions(rule.actions)
        return rule


    def _remove_overlapping_actions(self, action_list):
        ''' for some actions the generated code looks exactly the same.
            for example:
            action1: MOD=0 
            action2: MOD[0b00]
            
            the generated code for both of them in the BIND phase is the same
            and for action1 we do nothing in the EMIT phase.
            
            we are itereting over all the field binding to see if we have
            overlapping emit action.
            
            modifying to input action_list
        '''
        
        emit_actions = list(filter(lambda x: x.type == 'emit', action_list))
        fb_actions = list(filter(lambda x: x.type == 'FB', action_list))
        
        #iterate to find overlapping actions
        action_to_remove = []
        for fb in fb_actions:
            for emit in emit_actions:
                if fb.field_name.lower() == emit.field_name and \
                  emit.emit_type == 'numeric':
                    if fb.int_value == emit.int_value:
                        # overlapping actions, recored this action
                        # and remove later
                        action_to_remove.append(fb)
                    else:
                        err = "FB and emit action for %s has different values"
                        die(err % fb.field_name) 
        
        #remove the overlapping actions
        for action in action_to_remove:
            action_list.remove(action)
            
    def __str__(self):
        s = []
        s.append("ICLASS: %s" % self.iclass)
        s.append("CONDITIONS:")
        for c in self.enc_conditions:
            s.append("\t%s" % str(c))
        s.append( "ACTIONS:")
        for a in self.enc_actions:
            s.append("\t%s" % str(a))
        return '\n'.join(s)

class blot_t(object):
    """A blot_t is   a fragment of a decoder pattern"""
    def __init__(self,type=None):
        self.type = type  # 'bits', 'letters', 'nt', "od" (operand decider)
        self.nt = None    # name of a nonterminal
        self.value = None # integer representing this blot_t's value
        self.length = 0   # number of bits for this blot_t
        self.letters = None # sequence of substitution letters for this blot. All must be the same letter
        self.field_name = None # name of the operand storage field that has the values for this blot-t
        self.field_offset = 0 # offset within the field
        self.od_equals = None

    def make_action_string(self):
        """
        @rtype: string or None
        @returns: string if the blot is something we want to make in to an action
        """
        logger.debug("Making action for blot %s" %str(self) )
        if self.type == 'bits':
            binary = ''.join(decimal_to_binary(self.value))
            logger.debug("CONVERT %s <-- %s" % ( binary, str(self)))
            blen = len(binary)
            if blen < self.length:
                # pad binary on the left with 0's until it is self.length bits long
                need_zeros = self.length - blen
                #msgerr("Padding with %d zeros" % need_zeros)
                binary = "%s%s" % ('0'*need_zeros , binary)
                blen = len(binary)
            if blen > self.length:
                die("bit length problem in %s --- %s" % (str(self), binary))
            if self.field_name:
                return "%s[0b%s]" % (self.field_name,binary)
            return "0b%s" % binary
        
        elif self.type == 'letters':
            return "%s[%s]" % (self.field_name,self.letters)
        elif self.type == 'od':
            if self.od_equals == False:
                return "%s!=0x%x" % (self.field_name, self.value) #EXPERIMENT 2007-08-07
                # logger.warning("Ignoring OD != relationships in actions: %s" % str(self))
                # return None
            return "%s=0x%x" % (self.field_name, self.value)
        elif self.type == 'nt':
            return "%s()" % self.nt
        else:
            die("Unhandled type: %s" % self.type)

    def __str__(self):
        s = []
        if self.type:
            s.append("%8s" % self.type)
        else:
            s.append("%8s" % "no-type")
        if self.nt:
            s.append("nt: %s" % self.nt)
        if self.field_name:
            s.append("field_name: %s" % self.field_name)

        if self.od_equals != None:
            if self.od_equals:
                v = '='
            else:
                v = '!='
            s.append(v)
        if self.type == 'letters':
            s.append( "".join(self.letters) )
        if self.value != None:
            s.append("0x%x" % self.value) # print as HEX
            s.append("(raw %s)" % self.value)
        if self.nt == None and self.od_equals == None:
            s.append("length: %d" % self.length)
            s.append("field_offset: %d" % self.field_offset)
        return ' '.join(s)

def group_bits_and_letter_runs(s):
    """
    @type s: string
    @param s: string of the form [01a-z]+
    
    @rtype: list of strings
    @return: list of binary bit strings and distinct letter runs
    """
    out = []
    run = None
    last_letter = None
    last_was_number  = False
    # remove underscores from s
    for i in list(s.replace('_','')):
        if i=='0' or i=='1':
            if last_was_number:
                run += i
            else:
                if run:
                    out.append(run) # end last run
                run = i
            last_was_number = True
            last_letter = None

        else: # i is a letter

            if last_letter and last_letter == i:
                run += i
            else:
                if run:
                    out.append(run) # end last run
                run = i
            last_was_number = False
            last_letter = i
    if run:
        out.append(run)
    return out

def make_nt(ntname): 
    blot = blot_t('nt')
    blot.nt = ntname
    return blot

def make_hex(s,field_name=None):
    """
    @param s: string with a 2 nibble hex number
    @rtype: blot_t
    @return: blot containing the integer value
    """
    blot = blot_t('bits')
    blot.value = int(s,16)
    blot.length = 8
    blot.field_name = field_name
    return blot
def make_binary(s,field_name=None): 
    """
    @param s: string with a binary number
    @rtype: blot_t
    @return: blot containing the integer value
    """
    blot = blot_t('bits')
    if re.search(r'^0b',s):
        s = re.sub('0b','',s)
    s = re.sub('_','',s)
    blot.value = int(s,2)
    blot.length = len(s)
    blot.original_bits = s # FIXME: 2007-04-20
    blot.field_name = field_name
    return blot

def make_bits_and_letters(s, field_name=None):
    """
    @type s: string
    @param s: string of letters or binary digits representing the blot_t
    @type field_name: string
    @param field_name: name of the storage field (optional)

    @rtype: list of blot_t's
    @return:  list of blot_t's
    """
    #_vmsgb("MBAL","%s" % s)
    blots = []
    bit_offset_in_field = 0
    runs = group_bits_and_letter_runs(s)
    logger.debug("RUNS\t%s" %str(runs))
    for r in runs:
        #_vmsgb("\t",str(r))
        if len(r) == 0:
            die("Bad run in  " + str(s))
        blot = blot_t()
        if r[0] == '0' or r[0] == '1':
            blot.type = 'bits'
            blot.value = int(r,2)
        else:
            blot.type = 'letters'
            blot.letters = r
        blot.length = len(r)
        blot.field_name = field_name
        blot.field_offset = bit_offset_in_field
        bit_offset_in_field += blot.length
        blots.append(blot)
    return blots
def make_decider_blot( lhs,rhs,equals):
    blot = blot_t('od')
    blot.field_name = lhs
    rhs  = re.sub(r':.*','',rhs)
    blot.value = make_numeric(rhs,"%s %s %s" % (str(lhs),str(equals),str(rhs)))
    blot.od_equals = equals
    return blot