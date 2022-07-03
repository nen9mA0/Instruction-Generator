from patterns import *
from util import *

from global_init import *
from pattern_class import *

from dec_patterns_reader import *


# $$ parse_t
class parser_t(object):
    def __init__(self):
        self.nonterminal_line = ''
        self.nonterminal_name = ''
        # the actual nonterminal_type is NOW IGNORED 2008-07-22 I take
        # the value from the operand storage fields type spec.  I still
        # use the existence of the nonterminal return type to indicate
        # that an NT is a NTLUF.. FIXME!!
        self.nonterminal_type = None  # for lookup functions only

        # list of partitionable_info_t or instruction_info_t, which is a
        # subclass of partitionable_info_t.
        self.instructions = []

        self.deleted_instructions = {}
        self.deleted_unames = {}

        # if epsilon actions result in errors, otherwise_ok is False. If
        # epsilon actions result in no-error, then otherwise_ok should
        # be set to true.
        self.otherwise_ok = False

    def is_lookup_function(self):
        if self.nonterminal_type != None:
            return True
        return False

    def dump_structured(self, fp):
        "Print out the expanded records."
        for ii in self.instructions:
            slist = ii.dump_structured()
            for s in slist:
                fp.write(s)
            fp.write('\n')

    def print_structured_output(self, fp):
        "Print the input in a structuctured token-per-line fashion"
        fp.write(self.nonterminal_line + "\n")
        fp.write("\n")
        self.dump_structured(fp)

# $$ bits_list_t
class bits_list_t(object):
   """ list of bit_info_t """
   def __init__(self):
      self.bits = []
   def append(self,x):
      self.bits.append(x)
      
   def __str__(self):
      return self.just_bits()

   def just_bits(self):
      """ return a string of just the bits"""
      s = [ x.just_bits() for x in self.bits]
      o  = []
      i = 0
      for b in s:
          o.append(b)
          i = i + 1
          if i == 4:
              i = 0
              o.append('  ')
      return ' '.join(o)

global_inum = 0
# $$ partitionable
class partitionable_info_t(object):
   def new_inum(self):
      global global_inum
      self.inum = global_inum
      global_inum += 1
   
   def __init__(self, name='', ipattern_input='', operands_input=None):

      self.new_inum()
      self.name = name
      self.input_str = ''

      self.ipattern_input = ipattern_input
      self.ipattern =  None # bits_list_t()
      self.prebindings = None # dictionary 

      if operands_input:
          self.operands_input = operands_input
      else:
          self.operands_input = []

      self.operands = [] # list of opnds.operand_info_t's 

      # FOR HIERARCHICAL RECORDS -- THESE GET SPLIT OFF AFTER RECORD-READ
      self.extra_ipatterns = []
      self.extra_operands  = []
      self.extra_iforms_input  = []

      # When we consume a prefix, we must apply state modifications
      # and that might cause us to jump to a different part of the
      # graph, so we must retraverse the state-portion of the graph,
      # but remember what byte we were processing and pick up at the
      # next byte which may or may not be a prefix.
      self.reset_for_prefix = False


      self.encoder_func_obj = None # an instance of a class function_object_t
      
      self.encoder_operands = None

      self.otherwise_ok = False

      # simple nonterminals: either all nonterminals or all operand deciders.
      self.all_nonterminals = None
      self.all_operand_deciders = None

   def get_iclass(self):
       if field_check(self,'iclass'):
           return self.iclass
       return '*NO-ICLASS*'
      
   def refine_parsed_line(self, agi, state_dict):
      """Refine the ipattern_input to ipattern, parse up operands"""
      (simple_pattern,
       extra_bindings,
       all_bit_infos,
       all_prebindings,
       otherwise_ok) = parse_opcode_spec(agi,self.ipattern_input, state_dict)
      
      if otherwise_ok: # FIXME: 2008-09-25 - need to remove this for more
                       #                     general "otherwise" handling
         self.otherwise_ok = True
         return 
      
      self.ipattern = bits_list_t()
      self.ipattern.bits = all_bit_infos
      self.prebindings = all_prebindings

      (self.operands, self.reset_for_prefix) = \
                       parse_operand_spec(agi, self.operands_input)
      if extra_bindings:
         extra_operands = parse_extra_operand_bindings(agi,extra_bindings)
         self.operands.extend(extra_operands)

      self.check_for_simple_nts()
      
   def check_for_simple_nts(self):
      """Check for NTs that do not accept bits. We'll make them in to
      fast functions"""
      all_operand_deciders = True
      all_nonterminals = True
      for bi in self.ipattern.bits:
         if not bi.is_operand_decider():
            all_operand_deciders = False
         if not bi.is_nonterminal():
            all_nonterminals = False

      self.all_nonterminals = all_nonterminals
      self.all_operand_deciders = all_operand_deciders

      
   def __str__(self):
      return self.dump_str()
   
   def dump_str(self, pad='',brief=None):
      return self.input_str 

   def dump_structured(self,pad=''):
      lst = []
      s = pad
      s += self.ipattern_input + ' | '
      s += ' '.join(self.operands_input)
      lst.append( s )
      return lst
   
   def dump(self, pad=''):
      for s in self.dump_structured(pad):
         logger.debug(s)

      s = ' ipatternbits:' + str(len(self.ipattern.bits))
      logger.debug("BITLENGTHS: " + s)
      s = ''
      for b in self.ipattern.bits:
            s += ' ' + b.value 

      logger.debug("GRAPHBITS: " + s)


# $$ instruction_info_t
class instruction_info_t(partitionable_info_t):
   def __init__(self,
                iclass='',
                ipattern_input='',
                operands_input=None,
                category='DEFAULT',
                extension='DEFAULT',
                version = 0,
                isa_set = None):
      partitionable_info_t.__init__(self, iclass,ipattern_input, operands_input)
      self.iclass = iclass
      self.uname = None
      self.ucode = None
      self.comment = None
      self.exceptions = None      

      # Default version. Newer versions replace older versions
      self.version = version 

      self.category = category
      self.extension = extension
      self.isa_set = isa_set
      self.cpl = None
      self.attributes = None
      self.flags_input = None
      self.flags_info = None  # flag_gen.flags_info_t class
      
      self.iform = None
      self.iform_input = None
      self.iform_num = None
      self.iform_enum = None

   def add_attribute(self,s):
      if self.attributes:
         self.attributes.append(s)
      else:
         self.attributes = [s]

   def add_stack_attribute(self, memop_index):
      for op in self.operands:
         if op.bits == 'XED_REG_STACKPUSH':
            self.add_attribute('STACKPUSH%d' % (memop_index))
            return
         elif op.bits == 'XED_REG_STACKPOP':
            self.add_attribute('STACKPOP%d' % (memop_index))
            return
      die("Did not find stack push/pop operand")

   def is_vex(self):
       for bit in self.ipattern.bits: # bit_info_t
           #print("XXR: {} {}  {} {} {}".format(self.iclass, bit.btype, bit.token, bit.test, bit.requirement))
           if bit.btype == 'operand' and  bit.token == 'VEXVALID' and bit.requirement == 1 and bit.test == 'eq':
               return True
       return False
   def is_evex(self):
       for bit in self.ipattern.bits: # bit_info_t
           if bit.btype == 'operand' and bit.token == 'VEXVALID' and bit.requirement == 2 and bit.test == 'eq':
               return True
       return False
   def get_map(self):
       for bit in self.ipattern.bits: # bit_info_t
           if bit.token == 'MAP' and bit.test == 'eq':
               return bit.requirement
       return 0


   def dump_structured(self):
       """Return a list of strings representing the instruction in a
       structured way"""

       slist = []

       slist.append('{\n')

       s = add_str('', 'ICLASS', self.iclass)
       slist.append(s)

       if self.uname:
           s = add_str('', 'UNAME', self.uname)
           slist.append(s)
 
       if self.version != 0:
          s = add_str('','VERSION', str(self.version))
          slist.append(s)
  
          s = add_str('','CATEGORY', self.category)
          slist.append(s)
  
          s = add_str('','EXTENSION', self.extension)
          slist.append(s)
          s = add_str('','ISA_SET', self.isa_set)
          slist.append(s)
          s = add_str('','PATTERN', self.ipattern_input)
          slist.append(s)
          if self.cpl:
              s = add_str('','CPL', self.cpl)
              slist.append(s)
  
  
          if self.attributes:
              s = add_str('','ATTRIBUTES', self.attributes)
              slist.append(s)
          if self.ucode:
              s = add_str('','UCODE', self.ucode)
              slist.append(s)
          if self.comment:
              s = add_str('','COMMENT', self.comment)
              slist.append(s)
          if self.exceptions:
              s = add_str('','EXCEPTIONS', self.exceptions)
              slist.append(s)
          if self.exceptions:
              s = add_str('','DISASM_INTEL', self.disasm_intel)
              slist.append(s)
          if self.exceptions:
              s = add_str('','DISASM_ATTSV', self.disasm_att)
              slist.append(s)
          if self.iform_input:
              s = add_str('','IFORM_INPUT', self.iform_input)
              slist.append(s)
          if self.iform:
              s = add_str('','IFORM', self.iform)
              slist.append(s)
  
          if self.flags_input:
              s = add_str('','FLAGS', self.flags_input)
              slist.append(s)
 
       t = ''
       for op in self.operands_input:
           t = t + op + ' '
       s = add_str('','OPERANDS', t)
       slist.append(s)
         
       slist.append('}\n')
       return slist

   def read_structured_flexible(self,lines):
      debug = False
      accept(r'[{]', lines)
      reached_closing_bracket = False
      # FIXME add more error checking
      structured_input_dict = dict(zip(list(structured_input_tags.keys()),
                                       len(structured_input_tags)*[False]))
      found_operands = False
      filling_extra = False # when there is more than one pattern/operand/iform per {...} definition
      while 1:
         line = read_str_simple(lines)
         if debug:
            logger.debug("Reading: " + line)
         if not line:
            if debug:
               logger.debug("Dead line - ending")
            break
         if line == '}':
            if debug:
               logger.debug("Hit bracket")
            reached_closing_bracket = True
            break
         #print "READING [%s]" % (line)
         if colon_pattern.search(line):
            (token, rest ) = line.split(':',1)
            token = token.strip()
            rest = rest.strip()
            if rest.startswith(':'):
                die("Double colon error {}".format(line))

            # Certain tokens can be duplicated. We allow for triples
            # of (pattern,operands,iform). The iform is optional.  If
            # we see "pattern, operand, pattern" without an
            # intervening iform, the iform is assumed to be
            # auto-generated. But we must have an operand line for
            # each pattern line.
            #logger.debug("LINE: %s" % (line))
            if token in structured_input_dict:
               if structured_input_dict[token] == True:
                  if token in [ 'PATTERN', 'OPERANDS', 'IFORM']:
                     filling_extra = True
                  else:
                     die("Duplicate token %s in entry:\n\t%s\n" % (token, line))
            structured_input_dict[token] =True
            #logger.debug("FILLING EXTRA = %s" %( str(filling_extra)))
                  
            if token == 'ICLASS':
               self.iclass = rest
               if viclass():
                  logger.debug("ICLASS", rest)

            elif token == 'CATEGORY':
               self.category = rest
            elif token == 'CPL':
               self.cpl = rest
            elif token == 'EXTENSION':
               self.extension = rest

               # the isa set defaults to the extension. We can override
               # the isa set with the ISA_SET token.
               if self.isa_set == None:
                   self.isa_set = self.extension

            elif token == 'ISA_SET':
               self.isa_set = rest
            elif token == 'ATTRIBUTES':
               self.attributes = rest.upper().split()
            elif token == 'VERSION':
               self.version = int(rest)
            elif token == 'FLAGS':
               self.flags_input = rest
               self.flags_info = flag_gen.flags_info_t(self.flags_input)
               if vflag():
                  logger.debug("FLAGS parsed = %s" % str(self.flags_info))
            elif token == 'PATTERN':
               if filling_extra:
                  self.extra_ipatterns.append(rest)
                  #logger.debug("APPENDING None TO IFORMS INPUT")
                  self.extra_iforms_input.append(None)
                  self.extra_operands.append(None)
               else:
                  self.ipattern_input = rest
               found_operands=False
            elif token == 'OPERANDS':
               if filling_extra:
                  # overwrite the one that was added when we had an
                  # extra pattern.
                  if len(self.extra_operands) == 0:
                     die("Need to have a PATTERN line before the " + 
                         "OPERANDS line for " + self.iclass)
                  self.extra_operands[-1] = rest.split()
               else:
                  self.operands_input = rest.split()
               found_operands=True
            elif token == 'UCODE':
               self.ucode = rest
            elif token == 'COMMENT':
               self.comment = rest
            elif token == 'EXCEPTIONS':
               self.exceptions = rest
            elif token == 'DISASM':
               self.disasm_intel = rest
               self.disasm_att = rest
            elif token == 'DISASM_INTEL':
               self.disasm_intel = rest
            elif token == 'DISASM_ATTSV':  # AT&T System V
               self.disasm_att = rest
            elif token == 'UNAME':
               self.uname = rest
               if viclass():
                  logger.debug("UNAME", rest)

            elif token == 'IFORM':
               if filling_extra:
                  if len(self.extra_iforms_input) == 0:
                     die("Need to have a PATTERN line before " +
                         "the IFORM line for " + self.iclass)
                  self.extra_iforms_input[-1] = rest
               else:
                  self.iform_input = rest
            else:
               setattr(self,token,rest.strip())
               # die("Unhandled token in line: " + line)
         else:
            print("NEXT FEW LINES: ")
            for x in lines[0:20]:
               print("INPUT LINE: %s" % (x.strip()))
            die("Missing colon in line: " + line)

      if reached_closing_bracket:
         if found_operands == False:
            die("Did not find operands for " + self.iclass)
         for k in  list(structured_input_dict.keys()):
            if structured_input_dict[k] == False:
               if structured_input_tags[k]:
                  die("Required token missing: "+ k)

         if debug:
            logger.debug("\tReturning...")
         return True
      return False
   
   def add_scalable_attribute(self, scalable_widths, agi):
      """Look for operations that have width codes that are scalable
      width codes (z,v,a,p,p2,s,spw8,spw,spw3,spw2,
      etc. (auto-derived) , and add an attribute SCALABLE"""
      
      scalable = False

      for op in self.operands:
         if op.oc2:
            s= op.oc2.upper()
            #logger.debug("RRR Checking for %s in %s" % (s, str(scalable_widths)))
            if s in scalable_widths:
               scalable=True
               break

         if op.lookupfn_name:
            #logger.debug("OPNAME: " + op.lookupfn_name)
            scalable =  look_for_scalable_nt(agi, op.lookupfn_name)
            if scalable:
               break

      if scalable:
         s  = "SCALABLE"
         self.add_attribute(s)


   
   def add_fixed_base_attribute(self):
      """Look for STACKPUSH/STACKPOP operands and then add an
      attribute that says fixed_base0 or fixed_base1 depending on
      which base reg has the SrSP operand."""
      stack_memop_indx = -1
      if vattr():
         logger.debug("ATTRIBUTE-FOR-STACKOP: CHECKING", self.iclass)
      for op in self.operands:
         if op.is_ntluf():
            if vattr():
               logger.debug("ATTRIBUTE-NTLUF",  "%s = %s" % (op.name,op.lookupfn_name))
            if op.lookupfn_name == 'SrSP':
               if op.name == 'BASE0':
                  stack_memop_indx = 0
               elif op.name == 'BASE1':
                  stack_memop_indx = 1
               else:
                  pass # skip other fields
      if stack_memop_indx != -1:
         if vattr():
            logger.debug("ATTRIBUTE-FOR-STACKOP", 
                 "%s memop index %s" % (self.iclass, stack_memop_indx))
         s  = "FIXED_BASE%d" % stack_memop_indx
         self.add_attribute(s)
         self.add_stack_attribute(stack_memop_indx)


   def __str__(self):
      return self.dump_str()
   
   def dump_str(self, pad='', brief=False):
      s = []
      s.append(pad)
      s.append(self.iclass)
      if self.uname:
          s.append(" uname=%s" % str(self.uname))
      s.append(" inum=%s " % str(self.inum))
      if field_check(self,'iform') and self.iform:
          s.append(" iform=%s " % str(self.iform))
      if field_check(self,'iform_input') and self.iform_input:
          s.append(" iform_input=%s " % str(self.iform_input))
      if field_check(self,'isa_set') and self.isa_set:
          s.append(" isa_set=%s " % str(self.isa_set))
      s.append("pattern len=%d\n" % len(self.ipattern.bits))
      s.append(" %s ipattern: %s\n" % (pad,self.ipattern.just_bits()) )
      
      if brief:
          return ''.join(s)
      if self.prebindings:
         s.append('prebindings: \n\t' + 
                  '\n\t'.join( [str(x) for x in list(self.prebindings.values())]) + '\n')
      for op in self.operands:
         s.append(pad)
         s.append("   ")
         s.append(op.dump_str(pad))
         s.append("\n")
      return ''.join(s)
