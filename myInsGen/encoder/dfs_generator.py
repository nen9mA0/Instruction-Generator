import copy
from typing import TypeVar, Optional, Generic

from global_init import *
from generator_storage import *

from pattern_class import *
from actions import *
from blot import *

class Node(object):
    def __init__(self, prev=None, next=None):
        self.prev = prev
        self.next = next

class ActionNode(Node):
    def __init__(self, obj, prev=None, next=None):
        super(ActionNode, self).__init__(prev, next)

    def __iter__(self):
        self.i = 0

    def __next__(self):
        if self.i < self.rule_len:
            ret = self.i
            self.i += 1
        else:
            raise StopIteration

class ConditionNode(Node):
    def __init__(self, obj, prev=None, next=None):
        super(ConditionNode, self).__init__(prev, next)

class NTNode(Node):
    def __init__(self, nt, prev=None, next=None):
        super(NTNode, self).__init__(prev, next)
        self.nt = nt
        if isinstance(nt, nonterminal_t):
            self.rules = nt.rules
        elif isinstance(nt, iform_t):
            self.rules = [nt.rule]
        self.rule_len = len(self.rules)
        self.next_statement = None
        self.iter = None

    def __iter__(self):
        self.rule_num = 0

    def __next__(self):
        if self.rule_num < self.rule_len:
            rule = self.rules[self.rule_num]
            if not self.next_statement:
                for cond in rule.conditions.and_conditions:
                    pass

class Emulator(object):
    def __init__(self, gens):
        self.gens = gens
        self.head = None

    def __iter__(self):
        self.node = self.head
        self.depth = 0

    def __next__(self):
        node = self.node
        if isinstance(node, NTNode):
            if node.iter != None:
                try:
                    ret_num, ret_node = next(node.iter)
                except StopIteration:
                    pass
            else:
                node.iter = iter(node)
        # if node.next != None:
        #     ret_num = self.depth
        #     ret_node = node
        #     self.node = node.next
        #     self.depth += 1
        # else:
        #     try:
        #         ret_node = next(node)
        #         ret_num = self.depth
        #     except StopIteration:
        #         ret_node = node.prev
        #         self.depth -= 1
        #         ret_num = self.depth
        # return (ret_num, ret_node)

    def BuildTreeFromNT(self, nt):
        node = NTNode(nt)
        return node

    def BuildSeqNode(self, seq, iform):
        nts = self.gens.nts
        p_prev = None
        head = None
        for nt_name in seq.nonterminals:
            nt_name = nt_name[:-5]
            if not nt_name == "INSTRUCTIONS":
                nt = nts[nt_name]
                p = self.BuildTreeFromNT(nt)
            else:
                nt = iform
                p = self.BuildTreeFromNT(nt)
            if head == None:
                head = p
            else:
                p.prev = p_prev
                p_prev.next = p
            p_prev = p

    def DFSExecSeqBind(self, seqname, iform):
        if not seqname in self.gens.seqs:
            raise KeyError("_ExecSeq: Cannot find seqname: %s" %seqname)

        seq = self.gens.seqs[seqname]
        self.BuildSeqNode(seq, iform)

        nodes = iter(self)
        for node in nodes:
            pass

        return 0

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

        self.emu.DFSExecSeqBind("ISA_BINDINGS", iform)

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