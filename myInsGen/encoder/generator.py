import pickle
import copy

from global_init import *

# Because every nonterminal has its state variable, for generating every possible instruction, we should
# traversal all rules in the nonterminal.
# I use the member *context_init* to init the conditions we want.
# Eg. `context.context_init["LOCK"] = "1"` indicates that if a condition has an equality `LOCK=1`,
# this rule is satisfied, and we will execute the actions of this rule if all conditions have been satisfied.
# 
# For the conditions didn't specify by *context_init*, we assume that this condition is satisfied, and push all
# equality into the context, then execute the actions.
# Obviously, it's impossible to satisfy both two rules of one nonterminal simultaneously, so we should fork
# different context for different rules.
# Eg. in nonterminal *GPRv_R* has following rules
# ```
# xed_reg_enum_t GPRv_R()::
# EOSZ=3 | OUTREG=GPR64_R()
# EOSZ=2 | OUTREG=GPR32_R()
# EOSZ=1 | OUTREG=GPR16_R()
# ```
# Assume that now the context_init has only `context.context_init["LOCK"] = "1"`
# when execute this nonterminal, we will fork three context from context_init because the variable *EOSZ* haven't
# been appeared in context.
# 1:    context["LOCK"]="1"  context["EOSZ"]="3"
# 2:    context["LOCK"]="1"  context["EOSZ"]="2"
# 3:    context["LOCK"]="1"  context["EOSZ"]="1"
# and for context 1, we will then execute nonterminal GPR64_R. For context 2, execute GPR32_R.
# Such traversal will be done recursively with DFS.


class GeneratorStorage(object):
    def __init__(self):
        self.nts = gs.nts
        self.ntlufs = gs.ntlufs
        self.seqs = gs.seqs
        self.reg_names = gs.reg_names
        self.iarray = gs.iarray
        self.reg_nt_bind = {}
        self.nt_reg_bind = {}
        self.nt_ins_bind = ({}, {})         # 0 for input  1 for output
        self.reg_ins_bind = ({}, {})        # for the iforms that directly specify the register

        self.MakeRegNTlufLst()
        self.MakeInsNTLst()

    # make binding of register name --> nonterminal which has action `OUTREG=reg_name`
    # A register may mentioned by several nonterminal, also a nonterminal may mention different registers
    # So we create both binding reg_nt_bind and nt_reg_bind 
    def MakeRegNTlufLst(self):
        for ntluf_name in gs.ntlufs:
            ntluf = gs.ntlufs[ntluf_name]
            for rule in ntluf.rules:
                for cond in rule.conditions.and_conditions:
                    if cond.field_name == "OUTREG":
                        reg_name = cond.rvalue.value
                        if reg_name in self.reg_names:
                            if reg_name in self.reg_nt_bind:
                                self.reg_nt_bind[reg_name].add(ntluf_name)
                            else:
                                self.reg_nt_bind[reg_name] = set()
                                self.reg_nt_bind[reg_name].add(ntluf_name)

                            if ntluf_name in self.nt_reg_bind:
                                self.nt_reg_bind[ntluf_name].add(reg_name)
                            else:
                                self.nt_reg_bind[ntluf_name] = set()
                                self.nt_reg_bind[ntluf_name].add(reg_name)

    # Create binding between instruction and nonterminal or register
    # Here we distinguish input operand from output operand
    # nt_ins_bind binds nonterminal with instruction
    # Sometimes operand is not a nonterminal, if it's a register, we store it in reg_ins_bind
    def MakeInsNTLst(self):
        for iclass in gs.iarray:
            for iform in gs.iarray[iclass]:
                for (var, nt, value) in iform.input_op:
                    if nt:
                        if value in self.nt_ins_bind[0]:
                            self.nt_ins_bind[0][value].append(iform)
                        else:
                            self.nt_ins_bind[0][value] = [iform]
                    elif value in self.reg_names:
                        if value in self.reg_ins_bind[0]:
                            self.reg_ins_bind[0][value].append(iform)
                        else:
                            self.reg_ins_bind[0][value] = [iform]
                    else:
                        pass
                        # logger.error("MakeInsNTLst: cannot handle input operand %s %s" %(var, value))
                for (var, nt, value) in iform.output_op:
                    if nt:
                        if value in self.nt_ins_bind[1]:
                            self.nt_ins_bind[1][value].append(iform)
                        else:
                            self.nt_ins_bind[1][value] = [iform]
                    elif value in self.reg_names:
                        if value in self.reg_ins_bind[1]:
                            self.reg_ins_bind[1][value].append(iform)
                        else:
                            self.reg_ins_bind[1][value] = [iform]
                    else:
                        pass
                        # logger.error("MakeInsNTLst: cannot handle output operand %s %s" %(var, nt))


# class Filter(object):
#     def __init__(self, gen):
#         self.gen = gen      # generator structure that the filter binding
#         self.filter_context = {}
#         self.iform_set = None

#     def __getitem__(self, item):
#         return self.filter_context[item]

#     def __setitem__(self, item, value):
#         self.filter_context[item] = value

#     def __getattr__(self, item):
#         return getattr(self.filter_context, item)

#     def __len__(self):
#         return len(self.filter_context)

#     def AddRegInput(self, reg):

#         pass

#     def AddRegOutput(self, reg):
#         pass

#     def SpecifyReg(self, reg):
#         self.filter_context["OUTREG"] = reg

#     def SpecifyLock(self):
#         self.filter_context["LOCK"] = "1"


class NTContext(object):
    def __init__(self, ins_filter=None):
        self.i = 0
        self.contexts = []                  # a tuple (parent, child_lst, context_dict), to construct a context tree 
        if ins_filter:
            tmp = ins_filter.filter_context
            self.context_init = tmp
            self.current = tmp
        else:
            self.context_init = None
            self.current = None
        self.current_index = 0
        self.length = len(self.contexts)
        self.Fork()

    def __getitem__(self, item):
        return self.current[item]

    def __setitem__(self, item, value):
        self.current[item] = value

    def __iter__(self):
        self.length = len(self.contexts)
        self.i = self.length-1
        return self

    # this iterator can only iterate the nodes which is leaf node. Because leaf node means the lastest context of our execute
    def __next__(self):
        if len(self.contexts[self.i][1]) == 0 and self.i>=0:
            self.current = self.contexts[self.i]
            self.current_index = self.i
            self.i -= 1
        else:
            raise StopIteration()
        return self.current[2]

    def TestAndAssignment(self, item, value):
        if item in self.current:
            if value != self.current[item]:
                return False
            else:
                return True
        else:
            self.current[item] = value
            return True

    def Assignment(self, item, value):
        self.current[item] = value
        return True

    def Fork(self):                         # fork context
        if self.current:
            p = copy.deepcopy(self.current)
        else:
            p = {}
        root_index = self.current_index
        self.contexts.append( (root_index, [], p) )
        self.length = len(self.contexts)
        self.current = p
        self.current_index = self.length-1
        if root_index != self.current_index:                        # avoid rings
            self.contexts[root_index][1].append(self.current_index) # add leaf to root
        return self.current_index

    def ForkFrom(self, root_index):
        if root_index < self.length:
            root = self.contexts[root_index][2]
            p = copy.deepcopy(root)
            self.contexts.append( (root_index, [], p) )
            self.length = len(self.contexts)
            self.current = p
            self.current_index = self.length-1
            if root_index != self.current_index:                        # avoid rings
                self.contexts[root_index][1].append(self.current_index) # add leaf to root
            return self.current_index
        else:
            raise ValueError("ForkFrom root_index error: root_index = %d but len(contexts) = %d" %(root_index, self.length))


class Generator(object):
    def __init__(self):
        self.gens = GeneratorStorage()
        self.context = None

    def __getattr__(self, item):
        return getattr(self.context, item)

    def _ExecNT(self, nt, exec_type="bind"):        # exec_type: bind/emit
        for context in self.context:
            root_index = self.context.current_index
            for rule in nt.rules:
                self.ForkFrom(root_index)
                flag = True
                for cond in rule.conditions.and_conditions:
                    if cond.equals == True:
                        if not self.TestAndAssignment(cond.field_name, cond.rvalue.value):      # for conditions, we must test first to verify if conditions are satisfied
                            flag = False                        # conditions unsatisfy
                            break
                        else:                                   # if context don't have the value
                            pass                                #fork context
                    else:
                        logger.error("_ExecNT: Not Equal condition %s in\n%s" %(cond, rule))

                for act in rule.actions:
                    if act.type == "FB":                        # for actions, we don't need to test, for whose key has been in context, just overwrite it
                        #if not self.TestAndAssignment(act.field_name, act.value):
                        #raise ValueError("_ExecNT: Action conflict with condition: %s=%s" %(act.field_name, act.value))
                        self.Assignment(act.field_name, act.value)
                    else:
                        a = 0
                        pass
        return self.context

    def _InstructionNT(self, iform):
        nts = []
        flag = True                             # Record if context satisfy conditions
        for cond in iform.rule.conditions.and_conditions:
            if cond.rvalue.nt:
                nt_name = cond.rvalue.value
                if not nt_name in self.gens.ntlufs:
                    logger.error("err: GeneratorIform: Can not find nt %s" %nt_name)
                    exit(-1)
                nts.append(nt_name)             # execute nt after all equality handled
            elif cond.equals:
                if not self.context.TestAndAssignment(cond.field_name, cond.rvalue.value):
                    flag = False                # if test return false, means that context has this key while value is different, indicates that condition unsatisfy
                    break
            else:
                logger.error("err: GeneratorIform: Can not execute conditions %s\niform: %s" %(str(cond), str(iform)))

        if not flag:
            return None
                                                # until now, there is only one context in NTContext
        for nt_name in nts:                     # execute nonterminals
            self._ExecNT(self.gens.ntlufs[nt_name])
        return self.context


    def _ExecSeqBind(self, seqname, iform):
        if not seqname in self.gens.seqs:
            raise KeyError("_ExecSeq: Cannot find seqname: %s" %seqname)
        for name in self.gens.seqs[seqname].nonterminals:
            nt_name = name[:-5]                         # [:-5] to remove the _BIND or _EMIT
            if not nt_name in self.gens.nts:
                if nt_name == "INSTRUCTIONS":
                    self._InstructionNT(iform)
                else:
                    raise KeyError("_ExecSeq: Cannot find ntname: %s" %nt_name)
            else:
                self._ExecNT(self.gens.nts[nt_name])
            pass
        return self.context

    def GetOutputRegIform(self, reg):
        if reg not in self.gens.reg_names:
            logger.error("Register name Error")
            raise ValueError

        ret_iforms = []
        if reg in self.gens.reg_nt_bind:
            for nt_name in self.gens.reg_nt_bind[reg]:
                if nt_name in self.gens.nt_ins_bind[1]:
                    for i in self.gens.nt_ins_bind[1][nt_name]:
                        ret_iforms.append(i)
        if reg in self.gens.reg_ins_bind[1]:
            for i in self.gens.reg_ins_bind[1][reg]:
                ret_iforms.append(i)
        return ret_iforms

    def GetInputRegIform(self, reg):
        if reg not in self.gens.reg_names:
            logger.error("Register name Error")
            raise ValueError

        ret_iforms = []
        if reg in self.gens.reg_nt_bind:
            for nt_name in self.gens.reg_nt_bind[reg]:
                if nt_name in self.gens.nt_ins_bind[0]:
                    for i in self.gens.nt_ins_bind[0][nt_name]:
                        ret_iforms.append(i)
        if reg in self.gens.reg_ins_bind[0]:
            for i in self.gens.reg_ins_bind[0][reg]:
                ret_iforms.append(i)
        return ret_iforms

    def GeneratorIform(self, iform, ins_filter=None):        # a iform_t structure only contains one rule_t
        #print(iform)
        ins_lst = []
        tmp_num = 0         # fill bits from bottom
        shift_num = 0

        if self.context:
            del self.context
        self.context = NTContext(ins_filter)

        tst_nocomplete = False

        self._ExecSeqBind("ISA_BINDINGS", iform)

        for context in self.context:
            ins_hex = []
            for act in iform.rule.actions:
                if act.type == "emit":
                    if act.emit_type == "numeric":
                        tmp_num = tmp_num << act.nbits
                        tmp_num |= act.int_value
                        shift_num += act.nbits
                        if shift_num >= 8:
                            mask = 0xff << (shift_num - 8)
                            shift_num -= 8
                            ins_hex.append(tmp_num & mask)
                            tmp_num = tmp_num >> 8
                    elif act.emit_type == "letters":
                        key = act.field_name.upper()
                        if key in context:
                            tmp_num = tmp_num << act.nbits
                            tmp_num |= int(context[key])
                            shift_num += act.nbits
                            if shift_num >= 8:
                                mask = 0xff << (shift_num - 8)
                                shift_num -= 8
                                ins_hex.append(tmp_num & mask)
                                tmp_num = tmp_num >> 8
                        else:
                            logger.error("err: GeneratorIform: Cannot emit letter type value %s" %act.value)
                    else:
                        logger.error("err: GeneratorIform: Unknown emit type: %s" %act.emit_type)
                elif act.type == "nt":
                    if act.nt in self.gens.nts:
                        pass
                    else:
                        logger.error("err: GeneratorIform: Unknown nt type: %s or ntluf type: %s" %(act.nt, act.ntluf))
                elif act.type == "FB":
                    pass
                else:
                    print(act.type)
            if len(ins_hex) > 0:
                ins_lst.append(bytes(ins_hex))

        return ins_lst