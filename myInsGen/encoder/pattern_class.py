import actions
import slash_expand

from patterns import *
from util import *

from global_init import *


class nonterminal_t(object):
    def __init__(self, name, rettype=None):
        """
        The return type is for the NLTUFs only.
        """
        self.name = name
        self.rettype = rettype # if non None, then this is a NTLUF
        self.rules = []

    def add(self,rule):
        self.rules.append(rule)

    def multiple_otherwise_rules(self):
        c = 0
        for r in self.rules:
            if r.has_otherwise_rule():
                c = c + 1
        if c > 1:
            return True
        return False

    def has_otherwise_rule(self):
        if self.conditions.has_otherwise():
            return True
        return False


class rvalue_t(object):
    """The right hand side of an operand decider equation. It could be
    a value, a NTLUF, a * or an @. 
    For thing that are bits * means any value.  
    A @ is shorthand for ==XED_REG_INVALID"""
    def __init__(self, s):
        self.string = s
        m = nt_name_pattern.search(s)
        if m:
            self.nt = True
            self.value = m.group('ntname')
        else:
            self.nt = False
            if decimal_pattern.match(s) or binary_pattern.match(s):
                #_vmsgb("MAKING NUMERIC FOR %s" %(s))
                self.value = str(make_numeric(s))
            else:
                #_vmsgb("AVOIDING NUMERIC FOR %s" %(s))
                self.value = s

    def nonterminal(self):
        """Returns True if this rvalue is a nonterminal name"""
        return self.nt

    def null(self):
        if self.value == '@':
            return True
        return False

    def any_valid(self):
        if self.value == '*':
            return True
        return False

    def __str__(self):
        s =  self.value
        if self.nt:
            s += '()'
        return s


class condition_t(object):
    """ xxx[bits]=yyyy or xxx=yyy or xxx!=yyyy. bits can be x/n where
    n is a repeat count.  Can also be an 'otherwise' clause that is
    the final action for a nonterminal if no other rule applies.
    """
    def __init__(self,s,lencode=None):
        #_vmsgb("examining %s" % s)
        self.string = s
        self.bits = None # bound bits
        self.rvalue = None
        self.equals = None
        self.lencode = lencode # for memory operands
        
        b = bit_expand_pattern.search(s)
        if b:
            expanded = b.group('bitname') * int(b.group('count'))
            ss = bit_expand_pattern.sub(expanded,s)
        else:
            ss = s
        rhs = None
        e= equals_pattern.search(ss)
        if e:
            #_vmsgb("examining %s --- EQUALS" % s)
            raw_left_side = e.group('lhs')
            lhs = lhs_capture_pattern.search(raw_left_side)
            self.equals = True
            rhs = e.group('rhs')
            self.rvalue = rvalue_t(rhs)
            #_vmsgb("examining %s --- EQUALS rhs = %s" % (s,str(self.rvalue)))
  
        else:
            ne = not_equals_pattern.search(ss)
            if ne:
                raw_left_side = ne.group('lhs')
                lhs = lhs_capture_pattern.search(raw_left_side)
                self.equals = False
                self.rvalue = rvalue_t(ne.group('rhs'))
            else:
                # no equals or not-equals... just a binding. assume "=*"
                raw_left_side = ss
                #msgerr("TOKEN OR  BINDING %s" % (raw_left_side))
                            
                lhs = lhs_capture_pattern.search(raw_left_side)
                self.equals = True
                self.rvalue = rvalue_t('*')

        # the lhs is set if we capture bits for an encode action
        
        if lhs:
            self.field_name = lhs.group('name')
            self.bits = lhs.group('bits')
        else:
            #_vmsgb("examining %s --- NO LHS" % (s))
            self.field_name = raw_left_side
            if self.is_reg_type() and self.rvalue.any_valid():
                die("Not supporting 'any value' (*) for reg type in: %s" % s)
            if self.is_reg_type() and self.equals == False:
                die("Not supporting non-equal sign for reg type in: %s" % s)
            
            # Some bit bindings are done like "SIMM=iiiiiiii" instead
            # of "MOD[mm]=*". We must handle them as well. Modify the captured rvalue
            if rhs and self.equals:
                rhs_short = no_underscores(rhs)
                if letter_pattern.match(rhs_short):
                    #msgerr("LATE LETTER BINDING %s %s" % (raw_left_side, str(self.rvalue)))
                    self.bits = rhs_short
                    del self.rvalue
                    self.rvalue = rvalue_t('*')
                    return
            #msgerr("NON BINDING  %s" % (s)) # FIXME: what reaches here?

    def is_reg_type(self):
        if self.field_name not in gs.storage_fields:
            return False 
        ctype = gs.storage_fields[self.field_name].ctype
        return ctype == 'xed_reg_enum_t'

    def is_otherwise(self):
        """Return True if this condition is an 'otherwise' final
        condition."""
        if self.field_name == 'otherwise':
            return True
        return False

    def memory_condition(self): # MEM_WIDTH
        if self.lencode != None:
            return True
        return False

    def __str__(self):
        s = [ self.field_name ]
        if self.memory_condition(): # MEM_WIDTH
            s.append(" (MEMOP %s)" % self.lencode)
        if self.bits:
            s.append( '[%s]' % (self.bits))
        if self.equals:
            s.append( '=' )
        else:
            s.append('!=')
        s.append(str(self.rvalue))
        return ''.join(s)


class conditions_t(object):
    """Two lists of condition_t's. One gets ANDed together and one gets
    ORed together. The OR-output gets ANDed with the rest of the AND
    terms."""
    def __init__(self):
        self.and_conditions = []
    def contains(self,s):
        for c in self.and_conditions:
            if c.contains(s):
                return True
        return False
            
    def and_cond(self, c):
        if is_stringish(c):
            nc = condition_t(c)
        else:
            nc = c
        self.and_conditions.append(nc)

    def has_otherwise(self):
        for a in self.and_conditions:
            if a.is_otherwise():
                return True
        return False

    def __str__(self):
        s = []
        for a in self.and_conditions:
            s.append(str(a))
            s.append(' ')
        return ''.join(s)


class sequencer_t(object):
    def __init__(self, name):
        self.name = name
        self.nonterminals = []
    def add(self,nt):
        t = nt_name_pattern.search(nt)
        if t:
            self.nonterminals.append(t.group('ntname'))
        else:
            self.nonterminals.append(nt)
    def __str__(self):
        s = ["SEQUENCE " , self.name , "\n"]
        for nt in self.nonterminals:
            s.extend(["\t" , str(nt) , "()\n"])
        return ''.join(s)


class rule_t(object):
    """The encoder conditions -> actions. These are stored in nonterminals."""
    def __init__(self, conditions, action_list, nt):
        """
        @type conditions: conditions_t
        @param conditions: a conditions_t object specifying the encode conditions
        
        @type action_list: list of strings/action_t
        @param action_list: list of actions can string or action_t obj.
        
        @type nt: string
        @param nt: the nt which this rule is belong to 
        """
        self.default = False    #indicates whether this rule is a default rule
        self.nt = nt
        self.index = 0  #index is used to identify the correct emit order 
        self.conditions = self.handle_enc_preferred(conditions)
        self.actions = [] 
        
        for action in action_list:
            if is_stringish(action):
                self.actions.append(actions.action_t(action))
            else:
                self.actions.append(action)

    def handle_enc_preferred(self,conditions):
        ''' remove the ENCODER_PREFERRED constraint and replace it with 
        an attribute  '''
        for cond in conditions.and_conditions:
            if cond.field_name == "ENCODER_PREFERRED":
                self.enc_preferred = True
                conditions.and_conditions.remove(cond)
            
            else:
                self.enc_preferred = False
        return conditions

    def has_otherwise_rule(self):
        if self.conditions.has_otherwise():
            return True
        return False

    def __str__(self):
        s = ""
        for i in self.conditions.and_conditions:
            s += "%s " %str(i)
        for i in self.actions:
            s += "%s " %str(i)
        return s