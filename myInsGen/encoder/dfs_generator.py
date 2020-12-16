import copy
from typing import TypeVar, Optional, Generic

from global_init import *
from generator_storage import *

from pattern_class import *
from actions import *
from blot import *


prev_seqNT = None           # The only global variable, used to bind an emit number with an seqNT

class Node(object):
    def __init__(self, prev=None, next=None):
        self.prev = prev
        self.next = next
        self.iter = None

    def __iter__(self):
        self.exec = False
        return self

    def __next__(self):
        if self.exec:
            raise StopIteration
        else:
            self.exec = True
            return self

    def ClearIter(self):
        self.iter = None


class ActionNode(Node):
    def __init__(self, obj, prev=None, next=None):
        super(ActionNode, self).__init__(prev, next)
        self.act = obj
        self.type = "act"

    def ExecNode(self, context):
        global prev_seqNT
        if self.act.type == "FB":
            if not self.act.field_name == "ERROR":
                context[self.act.field_name] = self.act.value
                flag = True
            else:                   # if action is "error", return false
                flag = False
        elif self.act.type == "emit":
            context["emit"].append((prev_seqNT.name, self.act))
            flag = True
        elif self.act.type == "nothing":
            flag = True             # nothing encode
        else:
            a = 0
        return (flag, context)

    def __str__(self):
        return str(self.act)


class ConditionNode(Node):
    def __init__(self, obj, prev=None, next=None):
        super(ConditionNode, self).__init__(prev, next)
        self.cond = obj
        self.type = "cond"
        if obj.equals:          # condition is equal
            self.equal = True
        else:                   # condition is not equal
            self.equal = False

    def TestAndAssignment(self, context, item, value):
        if item in context:
            if value != context[item]:
                return False
            else:
                return True
        else:
            context[item] = value
            return True
        return False

    def Test(self, context, item, value):
        if item in context:
            if value == context[item]:      # only has key and it not equal to value will return false
                return False
        return True                         # if dict has no key, return true

    def ExecNode(self, context):
        flag = False
        if self.equal:
            if self.TestAndAssignment(context, self.cond.field_name, self.cond.rvalue.value):
                flag = True
        else:
            if self.Test(context, self.cond.field_name, self.cond.rvalue.value):
                flag = True

        return (flag, context)

    def __str__(self):
        return str(self.cond)


class NTNode(Node):
    def __init__(self, nt, gens, obj=None, prev=None, next=None, name=""):
        super(NTNode, self).__init__(prev, next)
        self.name = name
        self.nt = nt
        self.gens = gens
        self.obj = obj                                      # save the binding action or condition, is none for seqnt or iform_t
        self.init_context = None
        if obj != None:
            if isinstance(obj, action_t):
                self.nt_binding = "act"
            elif isinstance(obj, condition_t):
                self.nt_binding = "cond"
            else:
                raise TypeError("NTNode: obj is neither act nor cond. Type is: %s" %type(obj))
        if isinstance(nt, nonterminal_t):
            self.rules = nt.rules
            self.type = "nt"
        elif isinstance(nt, iform_t):
            self.rules = [nt.rule]
            self.type = "iform"
        if hasattr(self.nt, "otherwise"):
            if len(self.nt.otherwise) > 1:
                logger.error("otherwise length greater than 1")
            self.otherwise = self.nt.otherwise[0]
            self.otherwise_done = True
        else:
            self.otherwise = None
            self.otherwise_done = False
        self.rule_len = len(self.rules)
        self.is_seqnt = False

    def __iter__(self):
        self.rule_num = 0
        self.nodelst = []
        if self.otherwise:
            self.otherwise_done = True
        else:
            self.otherwise_done = False
        return self

    def __next__(self):
        global prev_seqNT
        if self.is_seqnt:
            prev_seqNT = self
        if self.rule_num < self.rule_len:
            self.UnlinkOldRule()
            rule = self.rules[self.rule_num]
            self.rule_num += 1
            self.BuildOneRule(rule)
        elif self.otherwise_done:
            self.otherwise_done = False
            self.UnlinkOldRule()
            self.BuildOtherwise(self.otherwise)
        else:
            raise StopIteration
        return self

    def UnlinkOldRule(self):
        if len(self.nodelst) > 0:                       # unlink old linklist
            head = self.nodelst[0]
            tail = self.nodelst[-1]
            head.prev.next = tail.next
            tail.next.prev = head.prev
            head.prev = None
            tail.next = None
            self.nodelst = []                           # reset nodelst

    def BuildOneRule(self, rule):
        head = None
        tail = None
        flag = False
        for cond in rule.conditions.and_conditions:     # construct new route
            if cond.equals == True:
                if cond.rvalue.nt:
                    nt_name = cond.rvalue.value
                    if not nt_name in self.gens.ntlufs:
                        raise KeyError("err: NTNode next: Can not find nt %s" %nt_name)
                    nt = self.gens.ntlufs[nt_name]
                    p = NTNode(nt, self.gens, cond)
                else:
                    p = ConditionNode(cond)
                flag = True
            else:
                if cond.rvalue.nt:
                    logger.error("NTNode next: Not Equal condition with nt %s in\n%s" %(cond, rule))
                    flag = False
                else:
                    p = ConditionNode(cond)
                    flag = True

            if flag:                                    # if condition is valid
                if not head:                            # linklist operation
                    head = p
                else:
                    p.prev = tail
                    tail.next = p
                tail = p
                self.nodelst.append(p)

        for act in rule.actions:
            if act.nt or act.ntluf:
                nt_name = act.value
                if act.nt:
                    if not nt_name in self.gens.ntlufs:
                        raise KeyError("err: NTNode next: Can not find ntluf %s" %nt_name)
                    nt = self.gens.ntlufs[nt_name]
                else:
                    if not nt_name in self.gens.nts:
                        raise KeyError("err: NTNode next: Can not find nt %s" %nt_name)
                    nt = self.gens.nts[nt_name]
                p = NTNode(nt, self.gens, act)
            else:
                p = ActionNode(act)

            if not head:                            # linklist operation
                head = p
            else:
                p.prev = tail
                tail.next = p
            tail = p
            self.nodelst.append(p)
        if head:
            tail.next = self.next                       # insert the operation linklist into main linklist
            tail.next.prev = tail
            self.next = head
            head.prev = self
        else:
            raise Exception("err: NTNode next: A rule has neither conditions nor actions (WTF?)")

    def ExecNode(self, context):
        if self.init_context != None:
            del context
            context = copy.deepcopy(self.init_context)
        else:
            self.init_context = context
            context = copy.deepcopy(self.init_context)
        return (True, context)

    def ClearIter(self):
        if len(self.nodelst) > 0:                       # unlink old linklist
            head = self.nodelst[0]
            tail = self.nodelst[-1]
            head.prev.next = tail.next
            tail.next.prev = head.prev
            head.prev = None
            tail.next = None
        self.iter = None
        del self.init_context
        self.init_context = None

    def BuildOtherwise(self, otherwise):
        if otherwise.type == "return":                  # no action, directly connect current NT with next NT
            pass                                        # because at the beginning both NT are connected, so we don't need to handle it
        else:
            a = 0
            pass

    def __str__(self):
        mystr = self.type + ": "
        if self.type == "iform":
            mystr += self.nt.iclass
        else:
            mystr += self.nt.name
        return mystr


class HeadNode(Node):                     # used as a head or tail of a sequence
    def __init__(self, prev=None, next=None):
        super(HeadNode, self).__init__(prev, next)
        self.type = "head"

    def ExecNode(self, context):
        return (True, context)

    def SetHead(self, next):
        self.prev = None
        self.next = next

    def SetTail(self, prev):
        self.prev = prev
        self.next = None


class Emulator(object):
    def __init__(self, gens):
        self.gens = gens
        self.head = None
        self.ins_lst = []

    def __iter__(self):
        self.node = self.head
        self.depth = 0
        return self

    def __next__(self):
        node = self.node
        if node.next != None:
            if node.type == "nt" or node.type == "iform":
                self.prev_nt = node        # for invalid path
                self.prev_depth = self.depth
            if node.iter == None:
                node.iter = iter(node)
            try:
                ret_node = next(node.iter)
                ret_num = self.depth
                self.depth += 1
                self.node = node.next
            except StopIteration:
                node.ClearIter()
                ret_node = None
                ret_num = -1
                self.depth -= 1
                self.node = node.prev       # backtracking
        else:                               # this path has reached the end, must output
            ret_node = None
            ret_num = -2
            self.depth -= 1
            self.node = node.prev
        if self.depth == 0:                 # when depth equal 0, node is headnode, so only the last backtracking will reach this point
            raise StopIteration
        # self.prev_node = node             # for debugging
        return (ret_num, ret_node)

    def InvalidPath(self):
        if self.prev_nt != None:
            self.node = self.prev_nt
            self.depth = self.prev_depth
        else:
            raise ValueError("InvalidPath: prev_nt is None")

    def BuildSeqNode(self, seq, iform):
        nts = self.gens.nts
        p_prev = None
        head = None
        for nt_name in seq.nonterminals:
            nt_name = nt_name[:-5]
            if not nt_name == "INSTRUCTIONS":
                nt = nts[nt_name]
                p = NTNode(nt, self.gens, name=nt_name)
            else:
                p = NTNode(iform, self.gens, name="INSTRUCTIONS")
            if head == None:
                head = HeadNode(next=p)
            else:
                p.prev = p_prev
                p_prev.next = p
            p_prev = p
            p.is_seqnt = True
        p = HeadNode(prev=p_prev)          # add an end point
        p_prev.next = p
        return head

    def DFSExecSeqBind(self, seqname, emit_seqname, iform, init_context=None):
        if not seqname in self.gens.seqs:
            raise KeyError("_ExecSeq: Cannot find seqname: %s" %seqname)

        if not emit_seqname in self.gens.seqs:
            raise KeyError("_ExecSeq: Cannot find emit seqname: %s" %emit_seqname)

        if init_context != None:
            context = init_context
        else:
            context = {"emit":[],}

        seq = self.gens.seqs[seqname]
        emit_seq = self.gens.seqs[emit_seqname]
        self.head = self.BuildSeqNode(seq, iform)

        nodes = iter(self)
        prev_depth = 0
        for depth, node in nodes:
            if depth >= 0:
                flag, context = node.ExecNode(context)
                if not flag:            # if this path cannot satisfy condition, invalid it
                    self.InvalidPath()
            elif depth == -1:
                pass
            elif depth == -2:
                self.EmitCode(context, emit_seq, print=True)
                pass
        return 0

    def EmitCode(self, obj, emitseq, print=False):
        emit_lst = obj["emit"]
        ins = []
        for name in emitseq.nonterminals:
            nt_name = name[:-5]
            for emit_name, act in emit_lst:
                if emit_name == nt_name:
                    a = 0




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