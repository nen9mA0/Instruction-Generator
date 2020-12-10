import pickle
import copy
from typing import TypeVar, Optional, Generic

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



# ====== ContextNode ======
# A ContextNode save contexts of current NT that inherit from the same context from previous NT
# Eg.
# Both NT1 and NT2 have 4 rules, and there is only one input context. And we assume that every condition is satisfied
#                   -----------
#                  |   [c00]   |   ContextNode 1
#                   -----------
#                        |
#                     -------
#                    |  NT_1 |
#                      -------
#                     /  |  |  \            NTContext 1
#                    /   |  |   \           /
#              --------------------------- /
#             |  ______________________   |
#             | | [c10, c11, c12, c13] |<-+-- ContextNode 2, inherit from c01
#             |  \____________________/   |
#              ---------------------------
#                   \   |    |   /
#                       -------
#                      |  NT_2 |
#           _______________|_____________________________________                         NTContext 2
#          /               |                \                    \                       /
#  ------------------------------------------------------------------------------------ /
# |  _________________    _________________    _________________    _________________  |
# | |[c20 c21 c22 c23]|  |[c24 c25 c26 c27]|  |[c28 c29 c2A c2B]|  |[c2C c2D c2E c2F]| |
# | \_________________/   \_______________/    \_______________/    \_______________/  |
# |        ^                    ^                   ^                   ^              |
#  --------+--------------------+-------------------+-------------------+--------------
#  ContextNode31        ContextNode32         ContextNode33         ContextNode34
#   inherit from c10     inherit from c11    inherit from c12       inherit from c13

class ContextNode(object):
    def __init__(self, init_context:dict=None):
        self.i = 0
        self.contexts = []                  # a tuple (parent, child_lst, context_dict), to construct a context tree 
        if init_context:
            self.context_init = init_context
            self.current = None
        else:
            self.context_init = None
            self.current = None
        self.current_index = 0
        self.length = len(self.contexts)
        self.sat = True                     # used by NTContext.TestAndAssignment
        # self.Fork()

    def __getitem__(self, item):
        return self.current[item]

    def __setitem__(self, item, value):
        self.current[item] = value

    def __iter__(self):
        self.length = len(self.contexts)
        self.i = 0
        return self

    # this iterator can only iterate the nodes which is leaf node. Because leaf node means the lastest context of our execute
    def __next__(self):
        if self.i < self.length:
            self.current = self.contexts[self.i]
            self.current_index = self.i
            self.i += 1
        else:
            raise StopIteration()
        return self.current

    def Remove(self):
        if self.current != None:
            self.contexts.pop()
            self.length = len(self.contexts)
            self.current = None             # TODO: Here current maybe None, and will be fill with value again 
                                            # after fork. Find a better way to solve it?
            self.current_index = 0

    def TestAndAssignment(self, item, value):
        if self.current != None:
            if item in self.current:
                if value != self.current[item]:
                    return False
                else:
                    return True
            else:
                self.current[item] = value
                return True
        return False

    def Assignment(self, item, value):
        if self.current != None:
            self.current[item] = value
            return True
        else:
            return False

    def Fork(self):                         # fork context from init context, if there is no init_context, create a empty context
        if self.context_init:
            p = copy.deepcopy(self.context_init)
        else:
            p = {}
        self.contexts.append(p)
        self.length = len(self.contexts)
        self.current = p
        self.current_index = self.length-1
        self.sat = True
        return self.current_index

    def ForkFrom(self, root_index):
        if root_index < self.length:
            root = self.contexts[root_index]
            p = copy.deepcopy(root)
            self.contexts.append(p)
            self.length = len(self.contexts)
            self.current = p
            self.current_index = self.length-1
            self.sat = True
            return self.current_index
        else:
            raise ValueError("ForkFrom root_index error: root_index = %d but len(contexts) = %d" %(root_index, self.length))


# List of ContextNode, binding with each nonterminal
class NTContext(object):
    def __init__(self, prev_ntcontext:Optional['NTContext']=None, init_context:dict=None):     # init_context: ContextNode structure
        self.context_nodes = []
        if prev_ntcontext:
            for cnode in prev_ntcontext.context_nodes:
                for context in cnode.contexts:
                    self.context_nodes.append(ContextNode(context))
        else:                       # for init
            if init_context:
                init = init_context
            else:
                init = None
            self.context_nodes.append(ContextNode(init))
        self.length = len(self.context_nodes)
        self.current_index = 0
        self.current = self.context_nodes[0]

    def __iter__(self):
        self.i = 0
        self.length = len(self.context_nodes)

    def __next__(self):
        if self.i < self.length:
            return self.context_nodes[self.i]

    def Fork(self):
        for node in self.context_nodes:
            node.Fork()

    def TestAndAssignmentWithRemove(self, item, value):
        unsat = []
        for node in self.context_nodes:
            flag = node.TestAndAssignment(item, value)
            if not flag:
                unsat.append(node)      # remove the context after loop
        flag = True
        for node in unsat:
            flag = False                # return if all flags are satisfy
            node.Remove()
        return flag

    def TestAndAssignment(self, item, value):
        ret = True
        for node in self.context_nodes:
            if node.sat:
                flag = node.TestAndAssignment(item, value)
                if not flag:
                    node.sat = False
                    ret = False
        return ret

    def Assignment(self, item, value):
        for node in self.context_nodes:
            if node.current:
                node.Assignment(item, value)

    def GetSatNode(self):
        sat = []
        for node in self.context_nodes:
            if node.sat:
                sat.append(node)
        return sat

    def CleanRedundantUnsat(self):
        for node in self.context_nodes:
            if not node.sat:
                node.Remove()


class SeqContext(object):
    def __init__(self, init_context:dict=None):
        self.nt_contexts = {}
        self.init_context = init_context

    def __getitem__(self, item):
        return self.nt_contexts[item]

    def __setitem__(self, item, value):
        self.nt_contexts[item] = value

    def AddNT(self, ntname, prev_ntcontext=None):
        if prev_ntcontext:
            self.nt_contexts[ntname] = NTContext(prev_ntcontext=prev_ntcontext)
        else:
            self.nt_contexts[ntname] = NTContext(init_context=self.init_context)
        return self.nt_contexts[ntname]


class Emulator(object):
    def __init__(self, gens):
        self.gens = gens
        self.context = None                         # save a NTContext structure for ExecNT

    def _ExecNT(self, nt, exec_type="bind"):        # exec_type: bind/emit
        has_otherwise = False
        first = True
        if hasattr(nt, "otherwise"):
            has_otherwise = True                    # TODO: for now we regard all otherwise as nothing, and it can be error(in REX_PREFIX_ENC)
        for rule in nt.rules:
            self.context.Fork()
            flag = True
            for cond in rule.conditions.and_conditions:
                if cond.equals == True:
                    if not has_otherwise:           # rule has no otherwise, if any condition is unsatisfy, the context will be removed
                        if not self.context.TestAndAssignmentWithRemove(cond.field_name, cond.rvalue.value):      # for conditions, we must test first to verify if conditions are satisfied
                            flag = False                        # Deplicate: conditions unsatisfy
                        else:                                   # if context don't have the value
                            pass                                #fork context
                    else:                           # rule has otherwise nothing, if condition is unsatisfy, just go on
                        self.context.TestAndAssignment(cond.field_name, cond.rvalue.value)
                                                    # sat save all context node that satisfy conditions
                else:
                    logger.error("_ExecNT: Not Equal condition %s in\n%s" %(cond, rule))

            for act in rule.actions:
                if act.type == "FB":                        # for actions, we don't need to test, for whose key has been in context, just overwrite it
                    #if not self.TestAndAssignment(act.field_name, act.value):
                    #raise ValueError("_ExecNT: Action conflict with condition: %s=%s" %(act.field_name, act.value))
                    if not act.field_name == "ERROR":
                        if has_otherwise:
                            sat = self.context.GetSatNode()
                            for node in sat:
                                node.Assignment(act.field_name, act.value)
                        else:
                            self.context.Assignment(act.field_name, act.value)
                    else:                               # if error, delete
                        for node in self.context:
                            node.sat = False
                else:
                    pass
            if first:                                       # only reserve one unsat node because every unsat node are the same
                first = False
            else:
                self.context.CleanRedundantUnsat()
        return self.context

    def _InstructionNTBind(self, iform):
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


    def BFSExecSeqBind(self, seqname, iform):
        seq_context = SeqContext()              # TODO: add initial context
        prev_ntcontext = None
        if not seqname in self.gens.seqs:
            raise KeyError("_ExecSeq: Cannot find seqname: %s" %seqname)

        for name in self.gens.seqs[seqname].nonterminals:
            nt_name = name[:-5]                         # [:-5] to remove the _BIND or _EMIT
            if not nt_name in self.gens.nts:
                if nt_name == "INSTRUCTIONS":
                    self._InstructionNTBind(iform)
                else:
                    raise KeyError("_ExecSeq: Cannot find ntname: %s" %nt_name)
            else:
                prev_ntcontext = seq_context.AddNT(nt_name, prev_ntcontext)
                self.context = prev_ntcontext           # NTContext structure
                self._ExecNT(self.gens.nts[nt_name])
            pass
        return self.context

    def DFSExecSeqBind(self, seqname, iform):
        seq_context = SeqContext()              # TODO: add initial context
        prev_ntcontext = None
        if not seqname in self.gens.seqs:
            raise KeyError("_ExecSeq: Cannot find seqname: %s" %seqname)

        for name in self.gens.seqs[seqname].nonterminals:
            nt_name = name[:-5]                         # [:-5] to remove the _BIND or _EMIT
            if not nt_name in self.gens.nts:
                if nt_name == "INSTRUCTIONS":
                    self._InstructionNTBind(iform)
                else:
                    raise KeyError("_ExecSeq: Cannot find ntname: %s" %nt_name)
            else:
                prev_ntcontext = seq_context.AddNT(nt_name, prev_ntcontext)
                self.context = prev_ntcontext           # NTContext structure
                self._ExecNT(self.gens.nts[nt_name])
            pass
        return self.context


class Generator(object):
    def __init__(self):
        self.gens = GeneratorStorage()
        self.emu = Emulator(self.gens)
        self.context = None

    def __getattr__(self, item):
        return getattr(self.emu, item)

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

        # if self.context:
        #     del self.context
        # self.context = NTContext(ins_filter)

        tst_nocomplete = False

        self.BFSExecSeqBind("ISA_BINDINGS", iform)

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
