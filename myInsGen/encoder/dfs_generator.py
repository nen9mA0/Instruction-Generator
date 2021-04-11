import copy
from typing import TypeVar, Optional, Generic

import ins_filter
import HashTable

from global_init import *
from generator_storage import *

from pattern_class import *
from actions import *
from blot import *


# The only two global variable
prev_NT = None          # Point to previous NT, used to get a return number of previous NT(eg. OUTREG)
prev_emitNT = None       # Point to previous sequence NT, used to bind an emit number with an seqNT

class Node(object):
    def __init__(self, prev=None, next=None):
        self.touchflag = False          # just used to determine whether the node is a new generated node
                                        # used by nt_emitnum in Emulator
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

    def GetIterLen(self):
        return 1

    def GetIterNum(self):
        return 1

    def ClearIter(self):
        self.iter = None


class ActionNode(Node):
    def __init__(self, obj, father, prev=None, next=None):
        super(ActionNode, self).__init__(prev, next)
        self.act = obj
        self.father = father
        self.type = "act"

    def Assignment(self, context, item, value):
        if item != "OUTREG":
            context[item] = value
        else:
            global prev_NT                       # if item is OUTREG, binding the return value with NT.outreg
            prev_NT.outreg = value
            context[item] = value               # fixed 20210326: we also put OUTREG into context

    def ExecNode(self, context, depth=None):
        global prev_emitNT
        if self.act.nt:
            try:
                global prev_NT
                value = prev_NT.outreg
            except:
                raise KeyError("ActionNode ExecNode: prev_NT.outreg not exist")
        else:
            value = self.act.value

        if self.act.type == "FB":
            if not self.act.field_name == "ERROR":
                self.Assignment(context, self.act.field_name, value)
                flag = True
            else:                   # if action is "error", return false
                flag = False
        elif self.act.type == "emit":
            if prev_emitNT:
                if isinstance(prev_emitNT, str):
                    context["emit"].append((prev_emitNT, self.act, self.father.emitbits_binding))
                else:
                    context["emit"].append((prev_emitNT.name, self.act, self.father.emitbits_binding))
            else:
                context["emit"].append(("", self.act, self.father.emitbits_binding))
            flag = True
        elif self.act.type == "nothing":
            flag = True             # nothing encode
        elif self.act.type == "return":
            flag = True
        else:
            if self.act.not_equal:  # TODO: Add for not equal actions
                flag = True
                field_name = self.act.field_name.upper()
                if field_name in context:
                    if context[field_name] == self.act.int_value:
                        del context[field_name]
            else:
                raise ValueError("Cannot Handle Action Type: %s" %self.act.type)
        return (flag, context)

    def __str__(self):
        return str(self.act)


class ConditionNode(Node):
    def __init__(self, obj, father, prev=None, next=None):
        super(ConditionNode, self).__init__(prev, next)
        self.cond = obj
        self.type = "cond"
        self.father = father
        if obj.equals:          # condition is equal
            self.equal = True
        else:                   # condition is not equal
            self.equal = False

    def TestAndAssignment(self, context, item, value):
        if item != "OUTREG":
            if item in context:
                if value != context[item]:
                    return False
            else:
                context[item] = value
        else:                                       # if item is OUTREG, binding return value with NT
            global prev_NT
            prev_NT.outreg = value               # for condition of a NTNode, eg. reg0=REG_8()
            context[item] = value                   # fixed 20210326: we also put OUTREG into context
        return True

    def Test(self, context, item, value):   # Duplicate: used to handle not equal
        if item in context:
            if value != context[item]:      # only has key and it not equal to value will return True
                return True
        return False                         # if dict has no key, return False

    def TestNeq(self, context, item, value):    # now use this to handle not equal conditions
        if item in context:                     # only when context has key and equal to value will return False
            if value != context[item]:
                return True
            else:
                return False
        else:
            return True

    def ExecNode(self, context, depth=None):
        flag = False
        if self.cond.rvalue.nt:                    # if is a condition of NTNode
            try:
                global prev_NT
                value = prev_NT.outreg
            except:
                raise KeyError("ConditionNode ExecNode: prev_NT.outreg not exist")
        else:                               # for normal situations
            value = self.cond.rvalue.value

        if self.equal:
            if self.TestAndAssignment(context, self.cond.field_name, value):
                flag = True
        else:
            if self.TestNeq(context, self.cond.field_name, value):
                flag = True

        if flag and self.cond.bits:
            if not self.father.emitbits_binding:
                self.father.emitbits_binding = {}
            self.father.emitbits_binding[self.cond.bits] = self.cond.field_name
        return (flag, context)

    def __str__(self):
        return str(self.cond)


# **Attension**: See Note
#                Because the way we treat otherwise is different from NTHashNode, 
#                so please DON'T use NTNode to handle NTs instead of NTHashNode in GeneratorIform.
#                In the current implementation, NTNode is only used to handle iform_t.
#                Fixed 20210409
class NTNode(Node):
    def __init__(self, nt, gens, obj=None, prev=None, next=None, name="", binding_emitNT=None, otherwise_first_dict=None):
        super(NTNode, self).__init__(prev, next)
        self.name = name
        self.nt = nt
        self.gens = gens
        self.obj = obj                                      # save the binding action or condition, is none for seqnt or iform_t
        self.init_context = None
        self.otherwise_first = True                         # if is true, otherwise will be execute first
        self.otherwise_first_dict = otherwise_first_dict
        self.last_emit_num = -1
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
            if hasattr(self.nt, "otherwise"):
                self.otherwise = self.nt.otherwise
                self.otherwise_done = False
            else:
                self.otherwise = None
                self.otherwise_done = True
        elif isinstance(nt, iform_t):
            self.rules = [nt.rule]
            self.type = "iform"
            self.otherwise = None
            self.otherwise_done = True

        self.rule_len = len(self.rules)
        self.is_seqnt = False
        self.binding_seq = None
        self.binding_emitNT = binding_emitNT

    def __iter__(self):
        self.rule_num = 0
        self.last_emit_num = None
        self.nodelst = []
        if self.otherwise:
            self.otherwise_done = False
        else:
            self.otherwise_done = True
        return self

    def __next__(self):
        global prev_emitNT
        global prev_NT

        prev_NT = self
        prev_emitNT = self.binding_emitNT

        self.emitbits_binding = None
        exec_otherwise = not self.otherwise_done and self.otherwise_first

        if not exec_otherwise and self.rule_num < self.rule_len:
            self.UnlinkOldRule()
            rule = self.rules[self.rule_num]
            self.rule_num += 1
            self.BuildOneRule(rule)
        elif not self.otherwise_done:
            self.otherwise_done = True
            self.UnlinkOldRule()
            self.BuildOtherwise(self.otherwise)
        else:
            raise StopIteration
        return self

    def GetIterLen(self):
        ret = self.rule_len
        if self.otherwise:
            ret += 1
        return ret

    def GetIterNum(self):
        ret = self.rule_num
        if self.otherwise and self.otherwise_done:
            ret += 1
        return ret

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
            # if str(cond) == "BASE0=ArBP()":              # just 4 debug
            #     a = 0
            if cond.equals == True:
                if cond.rvalue.nt:
                    nt_name = cond.rvalue.value
                    if not nt_name in self.gens.ntlufs:
                        raise KeyError("err: NTNode next: Can not find nt %s" %nt_name)
                    nt = self.gens.ntlufs[nt_name]
                    p1 = CreateNTNode(nt, self.gens, cond, name=nt_name, binding_emitNT=self.binding_emitNT, otherwise_first_dict=self.otherwise_first_dict)
                    p2 = ConditionNode(cond, self)            # TODO: special operation for nt condition
                else:
                    p1 = ConditionNode(cond, self)
                    p2 = None
                flag = True
            else:
                if cond.rvalue.nt:
                    logger.error("NTNode next: Not Equal condition with nt %s in\n%s" %(cond, rule))
                    flag = False
                else:
                    p1 = ConditionNode(cond, self)
                    p2 = None
                    flag = True

            if flag:                                    # if condition is valid
                if not head:                            # linklist operation
                    head = p1
                else:
                    p1.prev = tail
                    tail.next = p1
                if p2:
                    p1.next = p2
                    p2.prev = p1
                    tail = p2
                    self.nodelst.append(p1)
                    self.nodelst.append(p2)
                else:
                    tail = p1
                    self.nodelst.append(p1)

        for act in rule.actions:
            is_seq = False
            if act.nt or act.ntluf:
                if act.value:
                    nt_name = act.value
                elif act.nt:
                    nt_name = act.nt
                elif act.ntluf:
                    nt_name = act.ntluf
                if act.nt:
                    flag = False
                    if nt_name in self.gens.nts:
                        flag = True
                        nt = self.gens.nts[nt_name]
                    if nt_name+"_BIND" in self.gens.seqs:           # TODO: 20210320 fix, an action nt may be a sequence
                        flag = True
                        is_seq = True
                        seq = self.gens.seqs[nt_name+"_BIND"]
                    if not flag:
                        raise KeyError("err: NTNode next: Can not find nt %s" %nt_name)
                else:
                    if not nt_name in self.gens.ntlufs:
                        raise KeyError("err: NTNode next: Can not find ntluf %s" %nt_name)
                    nt = self.gens.ntlufs[nt_name]
                if not is_seq:
                    p1 = CreateNTNode(nt, self.gens, act, name=nt_name, binding_emitNT=self.binding_emitNT, otherwise_first_dict=self.otherwise_first_dict)
                    p2 = None
                else:                                       # nt is a sequence
                    p1 = None                               # use as p_head
                    p2 = None                               # use as p_prev
                    nodelst_tmp = []
                    for nt_name in seq.nonterminals:        # build seq nt is the same as the method in BuildSeqNode
                        nt_name = nt_name[:-5]
                        nt = self.gens.nts[nt_name]
                        p = CreateNTNode(nt, self.gens, name=nt_name, otherwise_first_dict=self.otherwise_first_dict)
                        p.binding_emitNT = p             # for a seqNT, the binding_emitNT is itself
                        p.is_seqnt = True
                        p.binding_seq = seq
                        if p1 == None:
                            p1 = p
                        else:
                            p2.next = p
                            p.prev = p2
                        p2 = p
                        nodelst_tmp.append(p)
                # p2 = ActionNode(act)                # TODO: special operation for nt action
            else:
                p1 = ActionNode(act, self)
                p2 = None

            if not head:                            # linklist operation, same as conditions
                head = p1
            else:
                p1.prev = tail
                tail.next = p1
            if not is_seq:
                if p2:
                    p1.next = p2
                    p2.prev = p1
                    tail = p2
                    self.nodelst.append(p1)
                    self.nodelst.append(p2)
                else:
                    tail = p1
                    self.nodelst.append(p1)
            else:                                   # if is a sequence
                tail = p2
                self.nodelst.extend(nodelst_tmp)

        if head:
            tail.next = self.next                       # insert the operation linklist into main linklist
            tail.next.prev = tail
            self.next = head
            head.prev = self
        else:
            raise Exception("err: NTNode next: A rule has neither conditions nor actions (WTF?)")

    def ExecNode(self, context, depth=None):
        if self.init_context != None:
            del context
            context = copy.deepcopy(self.init_context)
        else:
            self.init_context = context
            context = copy.deepcopy(self.init_context)

        # if depth:
        #     print("  "*depth + str(self))
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

    def BuildOtherwise(self, otherwise_lst):
        head = None
        tail = None
        flag = False
        for act in otherwise_lst:
            if act.nt or act.ntluf:
                raise ValueError("I used to think that nt will never appear here")
            else:
                p1 = ActionNode(act, self)

            if not head:                            # linklist operation, same as conditions
                head = p1
            else:
                p1.prev = tail
                tail.next = p1
            tail = p1
            self.nodelst.append(p1)

        if head:
            tail.next = self.next                       # insert the operation linklist into main linklist
            tail.next.prev = tail
            self.next = head
            head.prev = self
        else:
            raise ValueError("WTF?")

        # for otherwise in otherwise_lst:
        #     if otherwise.type == "return":                      # no action, directly connect current NT with next NT
        #         return True                                     # because at the beginning both NT are connected, so we don't need to handle it
        #     elif otherwise.type == "FB":
        #         if otherwise.field_name == "ERROR":             # TODO: Otherwise may has many other operations, such as error or an action
        #             return False                                # 20210316: TODO fixed, but may has other conditions
        #         else:
        #             raise ValueError("BuildOtherwise FB is not ERROR")
        #     else:
        #         raise ValueError("BuildOtherwise Unknown Operation")

    def __str__(self):
        mystr = self.type + ": "
        if self.type == "iform":
            mystr += self.nt.iclass
        else:
            mystr += self.nt.name
        return mystr


# Every NTHashTableNode can only bind with one context.
# If you want to emulate other context, you should rebuild a NTHashTableNode, 
# which is just like NTNode only binding with one init_context
class NTHashTableNode(Node):
    def __init__(self, nt, hashtable, prev=None, next=None, binding_emitNT=None):
        super(NTHashTableNode, self).__init__(prev, next)
        self.type = "hashnode"
        self.name = nt.name
        self.hashtable = hashtable
        self.binding_emitNT = binding_emitNT
        self.is_seqnt = False
        self.otherwise_first = False
        self.binding_seq = None
        self.last_emit_num = -1
        self.nodelst = [self]

    def __iter__(self):
        self.context_set = None
        self.context_iter = None
        self.init_context = None
        self.act_context = None
        self.num = 0
        self.last_emit_num = None
        return self

    def __next__(self):
        global prev_NT
        global prev_emitNT

        prev_NT = self
        prev_emitNT = self.binding_emitNT

        if self.init_context:
            self.act_context = next(self.context_iter)[1]
            self.num += 1
        return self

    def GetIterLen(self):
        if self.context_set:
            ret = len(self.context_set)
        else:
            ret = 0
        return ret

    def GetIterNum(self):
        return self.num-1

    def ExecNode(self, context, depth=None):
        if self.init_context:
            del context
            context = copy.deepcopy(self.init_context)
        else:                               # init here
            self.init_context = context
            self.context_set = self.hashtable.GetActContext(context, self.otherwise_first)
            self.context_iter = iter(self.context_set)
            context = copy.deepcopy(self.init_context)      # use a new context to do following things
            try:
                self.act_context = next(self.context_iter)[1]
                self.num += 1
            except StopIteration:
                return (False, context)

        has_outreg, outreg = self.hashtable.RefreshContext(context, self.act_context)
        if has_outreg:
            global prev_NT
            prev_NT.outreg = outreg
        return (True, context)

    def __str__(self):
        mystr = "%s: %s" %(self.type, self.name)
        return mystr


class HeadNode(Node):                     # used as a head or tail of a sequence
    def __init__(self, prev=None, next=None):
        super(HeadNode, self).__init__(prev, next)
        self.type = "head"

    def ExecNode(self, context, depth=None):
        return (True, context)

    def SetHead(self, next):
        self.prev = None
        self.next = next

    def SetTail(self, prev):
        self.prev = prev
        self.next = None

    def __str__(self):
        return "HEAD===="


class EmitNode(Node):
    def __init__(self, name, prev=None, next=None):
        super(EmitNode, self).__init__(prev, next)
        self.type = "emit"
        self.is_seq = False
        self.name = name
        self.index = 0
        self.child = []


def CreateNTNode(nt, gens, obj=None, prev=None, next=None, name="", binding_emitNT=None, otherwise_first_dict=None):
    if isinstance(nt, nonterminal_t):
        nt_name = nt.name
        htm = gens.htm
        if nt_name in htm:
            hashtable = htm[nt_name]
            node = NTHashTableNode(nt, hashtable, prev, next, binding_emitNT)
            if otherwise_first_dict:
                if nt_name in otherwise_first_dict:
                    node.otherwise_first = otherwise_first_dict[nt_name]        # Attension: only NTHashTableNode will set otherwise_first flag
                                                                                # according to otherwise_first_dict. See develop_note/note.md for reason
        else:
            if not htm.done:
                node = NTNode(nt, gens, obj, prev, next, name, binding_emitNT, otherwise_first_dict)
            else:                                                               # fixed 20210409, because of bug(see note:20210408), we CAN'T simply use NTNode to handle NTs
                raise ValueError("Use NTNode to handle NT after HashTableNode has already created")
    else:
        node = NTNode(nt, gens, obj, prev, next, name, binding_emitNT, otherwise_first_dict)
    return node


class Emulator(object):
    def __init__(self, gens):
        self.gens = gens
        self.head = None
        self.ins_set = set()
        self.weak_ins_set = set()
        self.nt_iternum = {}        # used to specify the iter number of some NTs

        self.iform_emit_limit = 0
        self.iform_emit_limit_clean = []
        self.nt_emitnum_limit = {}
        self.nt_emitnum = {}        # different from nt_iternum, is also used to limit number of iteration
                                    # but only when the current route reach the end and emit code, 
                                    # the value of emitnum will increase by 1
        self.otherwise_first_dict = {}

        self.route = []
        self.route_num = []
        self.default_emit_num = {"default":0}
        # self.tst_ins_set_dict = {}

    def __iter__(self):
        self.node = self.head
        self.depth = 0
        self.prev_ret_num = 0
        return self

    def __next__(self):
        node = self.node
        is_nt = False
        if node.next != None:
            if node.type == "nt" or node.type == "iform" or node.type == "hashnode":
                self.prev_nt = node        # for invalid path
                self.prev_nt_depth = self.depth
                is_nt = True
            if node.iter == None:
                node.iter = iter(node)
            try:
                ret_node = next(node.iter)
                if is_nt:
                    if ret_node.name in self.nt_iternum:
                        if ret_node.GetIterNum() >= self.nt_iternum[ret_node.name]:
                            raise StopIteration
                    if ret_node.name in self.nt_emitnum_limit:
                        if ret_node.touchflag:          # not a new node generated by new route
                            if self.nt_emitnum[ret_node.name] >= self.nt_emitnum_limit[ret_node.name]:
                                raise StopIteration
                        else:                           # it's a new node
                            ret_node.touchflag = True
                            self.nt_emitnum[ret_node.name] = 0
                    elif ret_node.type == "iform" and self.iform_emit_limit != 0:
                        for tmp_node in ret_node.nodelst:
                            if tmp_node.type == "nt" or tmp_node.type == "hashnode":
                                if not tmp_node.name in self.nt_emitnum_limit:
                                    self.nt_emitnum_limit[tmp_node.name] = self.iform_emit_limit
                                    self.iform_emit_limit_clean.append(tmp_node.name)
                ret_num = self.depth
                self.depth += 1
                self.node = node.next
                self.route.append(node)
            except StopIteration:
                node.ClearIter()
                ret_node = node
                ret_num = -1
                self.depth -= 1
                self.node = node.prev       # backtracking
                if node.type == "iform":    # special operation for cleaning node that auto added into nt_emitnum_limit
                    for name in self.iform_emit_limit_clean:
                        del self.nt_emitnum_limit[name]
                    self.iform_emit_limit_clean.clear()
        else:                               # this path has reached the end, must output
            ret_node = node
            ret_num = -2
            self.depth -= 1
            self.node = node.prev
        if self.depth == 0:                 # when depth equal 0, node is headnode, so only the last backtracking will reach this point
            raise StopIteration
        # self.prev_node = node             # for debugging
        if self.prev_ret_num == -1 or self.prev_ret_num == -2:
            self.route.pop()
            self.route_num.pop()
        self.prev_ret_num = ret_num
        return (ret_num, ret_node)

    def InvalidPath(self):
        if self.prev_nt != None:
            current_node = self.node.prev                   # when InvalidPath be called, self.node has pointed to next node
            nodelst = self.prev_nt.nodelst
            if not current_node in nodelst:
                prev_nt_last_node = nodelst[-1]
                while current_node != prev_nt_last_node:    # Attention! when a condition is unsatisfied,
                                                            # and this condition/action is outside previous NT,
                                                            # we should reset all iterator of these cond/act.
                                                            # Bug fix: 2020-12-19
                    current_node.ClearIter()
                    current_node = current_node.prev
            self.node = self.prev_nt
            self.depth = self.prev_nt_depth
            while len(self.route) > self.depth:
                self.route.pop()
                self.route_num.pop()
        else:
            raise ValueError("InvalidPath: prev_nt is None")

    def ResetInslst(self):
        self.ins_set = set()
        self.tst_ins_set_dict = {}

    def RefreshNTEmitNum(self):
        head = self.head
        node = head.next
        while node.type != "head":      # if we haven't readched the end
            if node.type == "nt" or node.type == "iform" or node.type == "hashnode":
                if node.name in self.nt_emitnum_limit:
                    iter_num = node.GetIterNum()
                    if node.last_emit_num == -1:
                        node.last_emit_num = iter_num
                        self.nt_emitnum[node.name] += 1
                    else:
                        if node.last_emit_num != iter_num:     # if current emit use a new NTContext than last emit, add nt_emitnum
                            self.nt_emitnum[node.name] += 1
                            node.last_emit_num = iter_num
            node = node.next
        return self.nt_emitnum

    def BuildSeqNode(self, seq, iform=None):
        nts = self.gens.nts
        p_prev = None
        head = None
        for nt_name in seq.nonterminals:
            nt_name = nt_name[:-5]
            if not nt_name == "INSTRUCTIONS":
                nt = nts[nt_name]
                p = CreateNTNode(nt, self.gens, name=nt_name, otherwise_first_dict=self.otherwise_first_dict)
            else:
                p = CreateNTNode(iform, self.gens, name="INSTRUCTIONS", otherwise_first_dict=self.otherwise_first_dict)
            p.binding_emitNT = p             # for a seqNT, the binding_emitNT is itself
            p.binding_seq = seq
            p.is_seqnt = True
            if head == None:
                head = HeadNode(next=p)
            else:
                p.prev = p_prev
                p_prev.next = p
            p_prev = p
        p = HeadNode(prev=p_prev)           # add an end point
        p_prev.next = p
        return head

    def GetRoute(self):
        mystr = ""
        for i in self.route:
            mystr += "%s\t" %str(i)
        return mystr

    def DFSNTContext(self, nt_lst, binding_emit=None):       # nt_lst can be a list of str or nonterminal_t
        nts = self.gens.nts
        ntlufs = self.gens.ntlufs

        first_nt = None
        prev_nt = None
        for nt in nt_lst:
            if isinstance(nt, str):
                nt_name = nt
                # if nt_name == "SIBBASE_ENCODE":             # just 4 debug
                #     a = 0
                if "_BIND" in nt_name or "_EMIT" in nt_name:
                    nt_name = nt_name[:-5]
                if not (nt_name in nts or nt_name in ntlufs):
                    raise KeyError("Cannot find NT/NTluf: %s" %nt_name)
                else:
                    if nt_name in nts:
                        nt = nts[nt_name]
                    else:
                        nt = ntlufs[nt_name]
            else:
                nt_name = nt.name
            if not nt:                          # nt is none, occurs when nt is in repeat_nts pr repeat_ntlufs
                return []
            p = CreateNTNode(nt, self.gens, name=nt_name, binding_emitNT=binding_emit)
            if first_nt == None:
                first_nt = p
            else:
                prev_nt.next = p
                p.prev = prev_nt

            prev_nt = p

        head = HeadNode(next=first_nt)
        tail = HeadNode(prev=prev_nt)
        first_nt.prev = head
        prev_nt.next = tail

        self.head = head

        self.nt_emitnum = {}
        context = {"emit":[]}                   # used to save end context for one cond_context
        cond_context = {}                       # used to save all conds
        cond_context_dict = {}                  # used to save nt's binding cond_context
        backtrack = False
                                                # fix bug 20210323: if one route have multi NTs, and these NT's conditions
                                                # contains the same item, previous condition will be covered.
                                                # For example, NT1 has condition EASZ=0, then NT2 has condition EASZ=2,
                                                # the condition EASZ=0 will be covered.
        all_context = []
        # all_route = []                # all_route: just 4 debug
        prev_cond = False

        nodes = iter(self)
        prev_depth = 0
        num = 0
        for depth, node in nodes:
            # if node and (node.type == "nt" or node.type == "hashnode"):    # just 4 debug
            #     if node.name == "DISP_WIDTH_32":
            #         a = 0
            if depth >= 0:
                if node.type == "cond":         # now context is all conditions, create a new context for actions
                    prev_cond = True
                    unuse_flag, cond_context = node.ExecNode(cond_context, depth=depth)
                    if unuse_flag:              # first we must verify if the path is available
                        if node.equal == False:     # add special handler for not equal conditions
                            name = node.cond.field_name
                            value = "!" + node.cond.rvalue.value        # neq conditions has a "!" prefix
                            if not name in cond_context:
                                cond_context[name] = value
                            else:
                                if cond_context[name] != value:
                                    raise ValueError("Neq context %s reassignment from %s to %s" %(name, cond_context[name], value))
                elif node.type == "nt" or node.type == "hashnode":
                    if backtrack:
                        cond_context = copy.deepcopy(cond_context_dict[node.name])
                    else:
                        if len(node.name) == 0: # just 4  debug
                            a = 0
                        cond_context_dict[node.name] = copy.deepcopy(cond_context)
                flag, context = node.ExecNode(context, depth=depth) # real context is executed here
                self.route_num.append((node.GetIterLen(), node.GetIterNum()))
                backtrack = False
                if not flag:            # if this path cannot satisfy condition, invalid it
                    self.InvalidPath()
                    backtrack = True
                # print(node)
            elif depth == -1:
                backtrack = True
                node.touchflag = False
            elif depth == -2:
                # if num == 11:         # just 4 debug
                #     a = 0
                all_context.append(HashTable.HashTableItem( (cond_context, context) ))
                self.RefreshNTEmitNum()
                # all_route.append(copy.deepcopy([str(i) for i in self.route]))     # all_route: just 4 debug
                # print(self.GetRoute())
                num += 1
        self.head = None
        self.route.clear()
        self.route_num.clear()
        return all_context


    def DFSSeqContext(self, seqname):
        if not seqname in self.gens.seqs:
            raise KeyError("_ExecSeq: Cannot find seqname: %s" %seqname)
        seq = self.gens.seqs[seqname]
        all_context = self.DFSNTContext(seq.nonterminals, seq)
        return all_context

    def DFSExecSeqBind(self, seqname, iform=None, init_context=None, weak_context=None, output_num=1):
        if not seqname in self.gens.seqs:
            raise KeyError("_ExecSeq: Cannot find seqname: %s" %seqname)

        # if not emit_seqname in self.gens.seqs:
        #     raise KeyError("_ExecSeq: Cannot find emit seqname: %s" %emit_seqname)

        if init_context != None:
            context = init_context
        else:
            context = {"emit":[],}

        self.iform = iform
        seq = self.gens.seqs[seqname]
        # emit_seq = self.gens.seqs[emit_seqname]
        self.head = self.BuildSeqNode(seq, iform)

        self.nt_emitnum = {}
        nodes = iter(self)
        prev_depth = 0
        num = 0
        for depth, node in nodes:
            if depth >= 0:
                flag, context = node.ExecNode(context, depth=depth)
                self.route_num.append((node.GetIterLen(), node.GetIterNum()))
                if not flag:            # if this path cannot satisfy condition, invalid it
                    self.InvalidPath()
                # print(node)
            elif depth == -1:
                node.touchflag = False
            elif depth == -2:
                ins_str = self.EmitCode(context, self.route)
                self.ins_set.add(ins_str)
                num += 1
                self.RefreshNTEmitNum()
                if num >= output_num:
                    break

        self.head = None
        self.route.clear()
        self.route_num.clear()
        return 0

    def BuildEmitTree(self, route):
        head = None
        prev = None
        seq = self.gens.seqs["ISA_BINDINGS"]
        seq_node = EmitNode("ISA_BINDINGS")
        seq_node.is_seq = True
        seq_lst = [seq_node]
        for seq_nt_name in seq.nonterminals:
            p = EmitNode(seq_nt_name.replace("_BIND", ""))
            if not head:
                head = p
            else:
                prev.next = p
                p.prev = prev
            prev = p
            seq_node.child.append(p)

        nt_name = ""
        emit_node = head
        stack = []
        current_emit_seq = seq_lst[0]
        for node in route:                      # traver route of execution and build a tree that indicate where
                                                # every sequence executed
            flag = False
            emit_seq = None
            nt_name = None
            if node.type == "iform":
                nt_name = "INSTRUCTIONS"
                emit_seq = "ISA_BINDINGS"
            elif node.type == "nt" or node.type == "hashnode":
                # if node.is_seqnt:
                nt_name = node.name
                if node.binding_seq:
                    emit_seq = node.binding_seq.name
            if nt_name:
                while not emit_node:
                    emit_node, current_emit_seq = stack.pop()
                if nt_name == emit_node.name:
                    emit_node = emit_node.next
                else:
                    if node.is_seqnt:
                        seq_node = EmitNode(emit_seq)
                        seq_node.is_seq = True
                        seq_lst.append(seq_node)
                        emit_node.prev.child.append(seq_node)    # new sequence is added into a NT's chil
                        seq = self.gens.seqs[emit_seq]
                        prev = None
                        for seq_nt_name in seq.nonterminals:
                            p = EmitNode(seq_nt_name.replace("_BIND", ""))
                            if prev:
                                prev.next = p
                                p.prev = prev
                            prev = p
                            seq_node.child.append(p)
                        stack.append( (emit_node, current_emit_seq) )
                        current_emit_seq = seq_node
                        emit_node = seq_node.child[0]
                        if emit_node.name == nt_name:
                            emit_node = emit_node.next
                        else:
                            raise ValueError("Emit name not Equal to nt_name")
                    else:
                        node = EmitNode(nt_name)
                        emit_node.prev.child.append(node)

        for seq_node in seq_lst:                             # now we rebuild the tree with emit order
            if seq_node.name == "ISA_BINDINGS":
                seq = self.gens.seqs["ISA_EMIT"]
            else:
                name = seq_node.name.replace("_BIND", "_EMIT")
                seq = self.gens.seqs[name]
            old_child = seq_node.child
            new_child = []
            prev = None
            for nt_name in seq.nonterminals:
                nt_name = nt_name.replace("_EMIT", "")
                flag = False
                for node in old_child:
                    if node.name == nt_name:
                        flag = True
                        new_child.append(node)
                        if prev:
                            prev.next = node
                        node.prev = None
                        prev = node
                        break
                if not flag:
                    ValueError("Cannot Find Emit Node in Sequence")
            seq_node.child = new_child
            prev.next = None                        # the last node's next must be None

        emit_nt_lst = []
        stack = []
        node = seq_lst[0]
        index = 0
        while node:
            if node.is_seq:
                node = node.child[0]
            else:
                if node.index == 0:
                    emit_nt_lst.append(node.name)
                if node.index < len(node.child):
                    stack.append(node)
                    tmp = node.index
                    node.index += 1
                    node = node.child[tmp]
                else:
                    if node.next:
                        node = node.next
                    elif len(stack):
                        node = stack.pop()
                    else:
                        node = None

        return emit_nt_lst

    def GetDefaultEmitNum(self, key):
        if key in self.default_emit_num:
            ret = self.default_emit_num[key]
        else:
            ret = self.default_emit_num["default"]
            logger.info("Assume %s  Emit %d" %(key, ret))
        return ret

    # when important_NT specify, any output that without executing important_NT will be ignore
    # def EmitCode(self, context, emitseq, important_NT=None, print=False):
    def EmitCode(self, context, route):
        emit_lst = context["emit"]
        ins_hex = []
        tmp_num = 0         # fill bits from bottom
        shift_num = 0

        emit_nt_lst = self.BuildEmitTree(route)

        # if important_NT:
        #     important = True
        #     important_flag = 0
        #     important_mask = 2 ** len(important_NT) - 1
        # else:
        #     important = False

        for nt_name in emit_nt_lst:
            for emit_name, act, emitbits_binding in emit_lst:
                if emit_name == nt_name:
                    # if important and nt_name in important_NT:
                    #     n = important_NT.index(nt_name)
                    #     important_flag |= 1 << n
                    if act.emit_type == "numeric":
                        tmp_num = tmp_num << act.nbits
                        act_value_mask = (1 << act.nbits) - 1
                        tmp_num |= (act.int_value & act_value_mask)
                        shift_num += act.nbits
                        while shift_num >= 8:
                            mask = 0xff << (shift_num - 8)
                            shift_num -= 8
                            ins_hex.append(tmp_num & mask)
                            tmp_num = tmp_num >> 8
                    elif act.emit_type == "letters":
                        key = act.field_name
                        if key:
                            key = key.upper()
                            if key in context:
                                context_value = context[key]
                                if context_value == "*":
                                    context_value = self.GetDefaultEmitNum(key)
                                int_value = int(context_value)
                                tmp_num = tmp_num << act.nbits
                                act_value_mask = (1 << act.nbits) - 1
                                tmp_num |= (int_value & act_value_mask)    # TODO: Emit Immediate
                                shift_num += act.nbits
                                while shift_num >= 8:
                                    mask = 0xff << (shift_num - 8)
                                    shift_num -= 8
                                    ins_hex.append(tmp_num & mask)
                                    tmp_num = tmp_num >> 8
                            else:
                                int_value = int(self.GetDefaultEmitNum(key))
                                tmp_num = tmp_num << act.nbits
                                act_value_mask = (1 << act.nbits) - 1
                                tmp_num |= (int_value & act_value_mask)
                                shift_num += act.nbits
                                while shift_num >= 8:
                                    mask = 0xff << (shift_num - 8)
                                    shift_num -= 8
                                    ins_hex.append(tmp_num & mask)
                                    tmp_num = tmp_num >> 8
                                logger.warning("Assume %s  Emit %s" %(key, int_value))
                                # logger.error("err: GeneratorIform: Cannot emit letter type value %s" %act.value)
                        else:                       # act.field_name == None
                            value = act.value
                            value_bits = []
                            tmp = None
                            name = ""               # imm value formats:
                                                    #  aaa_bbb_ccc abc aaaaaaaa
                            for c in value:
                                if c == "_":
                                    continue
                                if c != tmp:
                                    if len(name):
                                        value_bits.append(name)
                                    tmp = c
                                    name = str(c)
                                else:
                                    name += c
                            if len(name):
                                value_bits.append(name)

                            bit_num = 0
                            for bits in value_bits:
                                bits_field = emitbits_binding[bits]
                                bits_field = bits_field.upper()
                                bits_len = len(bits)
                                bit_num += bits_len

                                context_value = self.GetDefaultEmitNum(bits_field)
                                flag = True
                                if bits_field in context:
                                    tmp = context[bits_field]
                                    if not tmp == "*":
                                        context_value = tmp
                                        flag = False
                                if flag:
                                    logger.warning("Assume %s  Emit %s" %(bits_field, context_value))
                                int_value = int(context_value)
                                tmp_num = tmp_num << bits_len
                                act_value_mask = (1 << bits_len) - 1
                                tmp_num |= (int_value & act_value_mask)
                                shift_num += bits_len
                                while shift_num >= 8:
                                    mask = 0xff << (shift_num - 8)
                                    shift_num -= 8
                                    ins_hex.append(tmp_num & mask)
                                    tmp_num = tmp_num >> 8
                            # === check ===
                            if bit_num != act.nbits:
                                raise ValueError("Bits Emit Length No Equal To Act.nbits")
                    else:
                        logger.error("err: GeneratorIform: Unknown emit type: %s" %act.emit_type)
                        raise ValueError("err: GeneratorIform: Unknown emit type: %s" %act.emit_type)
        ins_str = bytes(ins_hex)
        return ins_str
        # if not ins_str in self.tst_ins_set_dict:              # for testing output and its' context
        #     self.tst_ins_set_dict[ins_str] = context

        # if important:
        #     if important_flag == important_mask:
        #         self.ins_lst.append(ins_hex)
        # else:
        #     self.ins_lst.append(ins_hex)
