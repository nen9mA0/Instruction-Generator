# 2022.8.8
# cond act 更新规则：
#       非strict模式
#           从前向后遍历，若context中
#                   * 没有cond与对应act，则加入cond与act（包含neq的各种判断情况，见下面）
#                   * 若cond或act在context中，则判断cond与act是否满足当前context，注意这里若act不满足也会判定为整体条件不满足，与dfs_generator中不一样
#       strict模式
#           从前向后遍历，当且仅当cond **或** act在context中存在且 **相等**，才视为满足条件


from multiprocessing.sharedctypes import Value
import fields_reader
import state_bits_reader
import enc_patterns_reader
import enc_ins_reader
import register_reader
import dfs_generator
import generator_storage
import ins_filter
import HashTable
import checker

from global_init import *

import capstone
import copy
from collections import deque


class FieldTable(object):
    def __init__(self, nt_field, ntluf_field, iform_field):
        self.nt_field = nt_field
        self.ntluf_field = ntluf_field
        self.iform_field = iform_field

    def __getitem__(self, name):
        if name in self.nt_field:
            return self.nt_field[name]
        elif name in self.ntluf_field:
            return self.ntluf_field[name]
        elif name in self.iform_field:
            return self.iform_field[name]
        else:
            raise KeyError("Item %s Not Found in FieldTable" %(name))


# def isseq(nt_name):
#     nt_name = nt_name.toupper()
#     for seq in 

def DfsSeq(seq, n, n_max, print_nt):
    if n >= n_max:
        return
    for raw_nt_name in seq.nonterminals:
        nt_name = raw_nt_name
        if nt_name.endswith("_BIND"):
            nt_name = nt_name[:-5]
        elif nt_name.endswith("_EMIT"):
            nt_name = nt_name[:-5]
        if raw_nt_name in gs.seqs:
            print("%s%s" %("   "*n, raw_nt_name))
            new_seq = gs.seqs[raw_nt_name]
            if not new_seq:                 # seq == None, has repeat seq
                new_seq = gs.repeat_seqs[raw_nt_name][0]        # Attention: use first repeat ones
            DfsSeq(new_seq, n+1, n_max, print_nt)
        elif nt_name in gs.ntlufs:
            print("%sntluf: %s" %("   "*(n+1), raw_nt_name))
            if print_nt:
                nt = gs.ntlufs[nt_name]
                if hasattr(nt, "otherwise"):
                    print("%s    otherwise:  " %("    "*(n+1)), end="")
                    for act in nt.otherwise:
                        print("%s  " %str(act), end="")
                    print("")
                for rule in nt.rules:
                    print("%s  %s" %("   "*(n+1), str(rule)))
        elif nt_name in gs.nts:
            print("%snt   :%s" %("   "*(n+1), raw_nt_name))
            if print_nt:
                nt = gs.nts[nt_name]
                if hasattr(nt, "otherwise"):
                    print("%s    otherwise:  " %("    "*(n+1)), end="")
                    for act in nt.otherwise:
                        print("%s  " %str(act), end="")
                    print("")
                for rule in nt.rules:
                    print("%s  %s" %("   "*(n+1), str(rule)))
        else:
            print("%snt   :%s" %("   "*(n+1), raw_nt_name))
            logger.error("cannot find nt_name:%s raw_nt_name:%s" %(nt_name, raw_nt_name))
    return

def ParseSeq(seqname, n_max=2, print_nt=False):        # seq_type can be BIND or EMIT
    if seqname in gs.seqs:
        print("%s" %seqname)
        seq = gs.seqs[seqname]
        if not seq:                 # seq == None, has repeat seq
            seq = gs.repeat_seqs[seqname][0]        # Attention: use first repeat ones
        DfsSeq(seq, 1, n_max, print_nt)

def ParseIclass():
    for iclass in gs.iarray:
        print("ICLASS %s" %iclass)
        i = 0
        for iform in gs.iarray[iclass]:
            i += 1
            print("\tIFORM %d" %i)
            for action in iform.rule.actions:
                print("\t\taction: %s" %str(action))
            for cond in iform.rule.conditions.and_conditions:
                print("\t\tconditon: %s" %str(cond))

def ParseNT(gs, nt_lst_name):
    if hasattr(gs, nt_lst_name):
        nt_dct = getattr(gs, nt_lst_name)
        for nt_name in nt_dct:
            nt = nt_dct[nt_name]
            if not nt:
                repeat_name = "repeat_" + nt_lst_name
                if hasattr(gs, repeat_name):
                    repeat_dct = getattr(gs, repeat_name)
                    nt = repeat_dct[nt_name][0]     # Attension: use the first one
                else:
                    raise ValueError("%s not in global init")
            print("%s" %nt_name)
            if hasattr(nt, "otherwise"):
                otherwise_act = nt.otherwise
                print("   otherwise: %s" %("  ".join([str(i) for i in otherwise_act])))
            for rule in nt.rules:
                print("   %s" %str(rule))

def GetUsedNT():
    num = 0
    nt_used = {}
    for iclass in gs.iarray:
        for iform in gs.iarray[iclass]:
            for action in iform.rule.actions:
                if action.is_nonterminal():
                    nt_name = action.nt
                elif action.is_ntluf():
                    nt_name = action.ntlufs
                else:
                    continue
                if not nt_name in nt_used:
                    nt_used[nt_name] = 1
            for cond in iform.rule.conditions.and_conditions:
                if cond.rvalue.nt:
                    nt_name = cond.rvalue.value
                    if not nt_name in nt_used:
                        nt_used[nt_name] = 1
                pass
    return nt_used

def IsRegOnly(action):
    if action.field_name == "mod" and not action.is_not_equal() and action.int_value == 3:
        return True
    return False

def GetRegOnly():
    iform_dct = {}
    for iclass in gs.iarray:
        iform_lst = gs.iarray[iclass]
        for i in range(len(iform_lst)):
            iform = iform_lst[i]
            for action in iform.rule.actions:
                if IsRegOnly(action):
                    if iclass in iform_dct:
                        iform_dct[iclass].append(i)
                    else:
                        iform_dct[iclass] = [i]
                    break
    return iform_dct

def GetNTsHashTable(gen, nt_list):
    hashtable_lst = []
    for nt in nt_list:
        if isinstance(nt, str):
            nt_name = nt
        else:
            nt_name = nt.name
        all_context = gen.DFSNTContext([nt], nt)
        if len(all_context) == 0:
            continue
        if nt_name.endswith("_BIND") or nt_name.endswith("_EMIT"):
            nt_name = nt_name[:-5]
        hashtable = HashTable.HashTable(nt_name)
        hashtable.LoadContext(all_context)
        hashtable_lst.append(hashtable)
    return hashtable_lst

# def CreateNTHashTable(gen, gens, nt_list):
#     hashtable_lst = GetNTsHashTable(gen, gens, nt_list)
#     for hashtable in hashtable_lst:
#         gens.htm.AddHashTable(hashtable)
#     return gens

def CreateNTHashTable(gen, gens, nt_list):
    for nt in nt_list:
        if isinstance(nt, str):
            nt_name = nt
        else:
            nt_name = nt.name
        all_context = gen.DFSNTContext([nt], nt, limit_path=300000)
        if all_context:
            if len(all_context) == 0:
                continue
            if nt_name.endswith("_BIND") or nt_name.endswith("_EMIT"):
                nt_name = nt_name[:-5]
            hashtable = HashTable.HashTable(nt_name)
            hashtable.LoadContext(all_context)
            gens.htm.AddHashTable(hashtable)

    return gens


def CreateDecNTHashTable(gen, gens, nt_list):
    for nt in nt_list:
        if isinstance(nt, str):
            nt_name = nt
        else:
            nt_name = nt.name
        all_context = gen.DFSDecNTContext([nt], nt, limit_path=300000)
        if all_context:
            if len(all_context) == 0:
                continue
            if nt_name.endswith("_BIND") or nt_name.endswith("_EMIT"):
                nt_name = nt_name[:-5]
            hashtable = HashTable.HashTable(nt_name)
            hashtable.LoadContext(all_context)
            gens.htm.AddHashTable(hashtable)

    return gens

# use Node definition in dfs_generator.py
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

# iter_type:
#       0:  ActCondNode with no nt
#       1:  ActCondNode with nt
#       2:  NTFieldNode
class ActCondNode(Node):
    def __init__(self, acts, conds, field_table, field_node_table, father, strict=False, prev=None, next=None):
        super(ActCondNode, self).__init__(prev, next)
        self.acts = acts
        self.conds = conds
        self.field_table = field_table
        self.father = father
        self.strict = strict
        if "nt" in acts:
            self.nt_nodes = []
            for nt_name in acts["nt"]:
                if not nt_name in field_node_table:
                    self.nt_nodes.append(NTFieldNode(nt_name, field_table, field_node_table))
                else:
                    self.nt_nodes.append(field_node_table[nt_name])
            self.length = len(self.nt_nodes)
            self.has_nt = True
        else:
            self.nt_nodes = None
            self.length = 0
            self.has_nt = False


#   ___       ___
#  | A | --> | B |
#  |___| <-- |___|
#    | act
#  [C D]
#
#
#   ___       ___       ___       ___
#  | A | --> | C | --> | D | --> | B |
#  |___| <-- |___| <-- |___| <-- |___|


    def BuildTree(self):
        if self.has_nt:
            prev = self.father
            next_node = self.father.next
            for nt_node in self.nt_nodes:
                prev.next = nt_node
                nt_node.prev = prev
                prev = nt_node
            if next_node != None:
                prev.next = next_node
                next_node.prev = prev

    def DisableRoute(self):
        self.iter_index = self.length

    def GetIterLen(self):
        return self.length

    def GetIterNum(self):
        return self.iter_index

    def __len__(self):
        return self.GetIterLen()

    def __str__(self):
        mystr = "acts: %s   conds: %s" %(str(self.acts), str(self.conds))
        return mystr

    def __repr__(self):
        return str(self)

    def __iter__(self):
        self.flag = False       # if has traversed
        self.current = None
        self.BuildTree()
        return self

    # don't have nt:
    #   case 1: haven't traversed   --> return 0, self
    #   case 2: have traversed      --> if self.father.next   iter()

    # have nt:
    #   case 1: have nt and current=None             begin to iterate first nt
    #                        --> iter(nt[0]) return 1, self
    #   case 2:  have nt and current!=None
    #                        --> next(iter)

    def __next__(self):
        if self.current != None:
            try:
                iter_type, tmp = next(self.current)
            except StopIteration:
                if self.has_nt:
                    if self.father.next == self.nt_nodes[0]:
                        next_node = self.nt_nodes[-1].next
                        self.father.next = next_node
                        if next_node:
                            next_node.prev = self.father
                raise StopIteration
        else:
            if not self.has_nt:
                if not self.flag:       # haven't traverse
                    self.flag = True
                    tmp = self
                    iter_type = 0

                    if self.father.next != None:
                        self.current = iter(self.father.next)
                else:
                    self.current = None
                    raise StopIteration
            else:
                if not self.flag:
                    self.flag = True
                    self.current = iter(self.nt_nodes[0])
                    tmp = self
                    iter_type = 1
                else:
                    raise ValueError()
        return iter_type, tmp


class NTFieldNode(Node):
    strict_nt = ["MEMDISP"]
    def __init__(self, nt_name, field_table, field_node_table, init=False, prev=None, next=None):
        super(NTFieldNode, self).__init__(prev, next)
        self.name = nt_name
        self.field_table = field_table
        self.nt = field_table[nt_name]
        self.act_conds = []
        if not init and nt_name in self.strict_nt:
            for acts, conds in self.nt:
                act_cond_node = ActCondNode(acts, conds, field_table, field_node_table, self, strict=True)
                self.act_conds.append(act_cond_node)
        else:
            for acts, conds in self.nt:
                act_cond_node = ActCondNode(acts, conds, field_table, field_node_table, self, strict=False)
                self.act_conds.append(act_cond_node)
        self.length = len(self.act_conds)
        self.iter_index = -1

    def GetIterLen(self):
        return self.length

    def GetIterNum(self):
        return self.iter_index

    def __len__(self):
        return self.GetIterLen()

    def __str__(self):
        mystr = "Name: %s  Index: %d" %(self.name, self.iter_index)
        return mystr

    def __repr__(self):
        return str(self)

    def __iter__(self):
        self.iter_index = -1
        self.current = None
        return self

    def __next__(self):
        flag = True
        if self.current != None:
            try:
                iter_type, tmp = next(self.current)
                flag = False
            except StopIteration:
                pass
        if flag:
            if self.iter_index < self.length-1:
                self.iter_index += 1
                next_iter = self.act_conds[self.iter_index]
                self.current = iter(next_iter)
                tmp = self
                iter_type = 2
            else:
                self.current = None
                raise StopIteration
        return iter_type, tmp


class NTFieldHashNode(Node):
    def __init__(self):
        pass


class EmitTable(object):
    def __init__(self):
        pass

#            ______
#      NT1  | cond |    if cond
#           |  |   |    then act
#           | act  |
#              |
#              |
#            ______
#      NT2  | cond |
#           |  |   |    NT2's act may overwrite properties
#           | act  |    but NT1's cond will never conflict with NT1

# for action, the later exec nonterminal will overwrite the previous properties
# for conditions, if the later exec nonterminal conflict with previous ones, this route will be drop

class CondException(Exception):
    pass

class ActException(Exception):
    pass

class ActCondDict(object):
    skip_name = ("emit", "nt")
    def __init__(self):
        self.act = ActDict()
        self.cond = CondDict()

    def update(self, act_dict, cond_dict, strict=False):
        for name in act_dict:
            flag = False
            neq = False
            value = act_dict[name]
            if name[0] == "!":
                neq = True
            if name in self.skip_name:
                # self.act[name] = value
                continue
            if neq:
                flag = self.act.NeqActTest(name, value) and self.cond.NeqCondTest(name, value)
                if flag:
                    if not "neq" in self.act:
                        self.act["neq"] = {}
                    self.act["neq"][name[1:]] = value
                else:
                    raise ActException("")
            else:
                flag = self.act.Test(name, value, strict) or self.cond.Test(name, value, strict)
                if flag:
                    self.act[name] = value
                else:
                    raise ActException("")

        for name in cond_dict:
            flag = True
            neq = False
            value = cond_dict[name]
            if name[0] == "!":
                neq = True
            if neq:
                flag = self.act.NeqActTest(name, value) and self.cond.NeqCondTest(name, value)
                if flag:
                    if not "neq" in self.act:
                        self.cond["neq"] = {}
                    self.cond["neq"][name[1:]] = value
                else:
                    raise CondException("")
            else:
                # flag = self.act.Test(name, value, strict) or self.cond.Test(name, value, strict)
                if flag:
                    self.cond[name] = value
                else:
                    raise CondException("")

    def __getitem__(self, name):
        if name in self.act:
            return (0, self.act[name])
        elif name in self.cond:
            return (1, self.cond[name])
        else:
            raise KeyError("Key %s not in ActCondDict" %name)

    def __setitem__(self, name, value):
        item_type, item = value
        if item_type == 0:
            self.act[name] = item
        else:
            self.cond[name] = item

    def __iter__(self):
        self.iter = iter(self.act)
        self.flag = True
        return self.iter

    def __next__(self):
        try:
            obj = next(self.iter)
        except StopIteration:
            if self.flag:
                self.iter = iter(self.cond)
                self.flag = False
            else:
                raise StopIteration

    def __str__(self):
        return str(self.act) + str(self.cond)

    def __repr__(self):
        return str(self)


class CondDict(object):
    def __init__(self):
        self.dict = {}

    # def update(self, b_dict):
    #     for name in b_dict:
    #         if name in self.dict and name != "OTHERWISE" and self.dict[name] != b_dict[name]:
    #             raise CondException("")
    #         else:
    #             self.dict[name] = b_dict[name]
    #     return self.dict

    def NeqCondTest(self, name, value):
        if name in self.dict:
            if self.dict[name] == value:
                return False
        if "neq" in self.dict:
            if name in self.dict["neq"]:
                if self.dict["neq"][name] != value:
                    raise ValueError("")               # reassign not equal
        return True

    def Test(self, name, value, strict=False):
        if not strict:
            if name in self.dict and name != "OTHERWISE" and (self.dict[name] != value or not self.TestNeq(name, value)):
                return False
            else:
                return True
        else:
            if name in self.dict and self.dict[name] == value and self.TestNeq(name, value):
                return True
            else:
                return False

    def TestNeq(self, name, value):
        if "neq" in self.dict:
            if name in self.dict["neq"]:
                if self.dict["neq"][name] == value:
                    return False
        return True

    def __getitem__(self, name):
        return self.dict[name]

    def __setitem__(self, name, value):
        self.dict[name] = value

    def __iter__(self):
        self.iter = iter(self.dict)
        return self.iter

    def __next__(self):
        return next(self.iter)

    def __str__(self):
        return str(self.dict)

    def __repr__(self):
        return str(self.dict)


class ActDict(object):
    def __init__(self):
        self.dict = {}

    # def update(self, b_dict, strict=False):
    #     for name in b_dict:
    #         # new condition is a neq condition
    #         if name in self.skip_name:
    #             continue
    #         if name[0] == "!":
    #             o_name = name[1:]
    #             if o_name in self.dict:                       # if new neq condition equals old condition
    #                 if self.dict[o_name] == b_dict[name]:
    #                     raise ActException
    #             if o_name in self.dict["neq"]:
    #                 raise ValueError()
    #             self.dict["neq"][o_name] = b_dict[name]
    #             continue

    #         # new condition is a normal condition
    #         if name in self.dict["neq"]:                    # if new condition equals old neq condition
    #             if b_dict[name] == self.dict["neq"][name]:
    #                 raise ActException("")

    #         if name in self.dict:
    #             if self.dict[name] != b_dict[name]:
    #                 raise ActException("")
    #             else:
    #                 if strict:                  # for debug
    #                     a = 0
    #         else:
    #             if strict:
    #                 raise ActException("")
    #             else:
    #                 self.dict[name] = b_dict[name]
    #     return self.dict

    def NeqActTest(self, name, value):
        if name in self.dict:
            if self.dict[name] == value:
                return False
        if "neq" in self.dict:
            if name in self.dict["neq"]:
                raise ValueError("")
        return True

    def Test(self, name, value, strict=False):
        if not strict:
            if name in self.dict and (self.dict[name] != value or not self.TestNeq(name, value)):
                return False
            else:
                return True
        else:
            if name in self.dict and self.dict[name] == value and self.TestNeq(name, value):
                return True
            else:
                return False

    def TestNeq(self, name, value):
        if "neq" in self.dict:
            if name in self.dict["neq"]:
                if self.dict["neq"][name] == value:
                    return False
        return True

    def __getitem__(self, name):
        return self.dict[name]

    def __setitem__(self, name, value):
        self.dict[name] = value

    def __iter__(self):
        self.iter = iter(self.dict)
        return self.iter

    def __next__(self):
        return next(self.iter)

    def __str__(self):
        return str(self.dict)

    def __repr__(self):
        return str(self.dict)


def ParseActCond(rule):
    acts = {}
    for act in rule.actions:
        if act.type == "FB":
            acts[act.field_name.upper()] = act.int_value
        elif act.type == "nothing":
            pass
        elif act.type == "emit":
            field_name = act.field_name
            if field_name != None:
                field_name = field_name.upper()
            if not "emit" in acts:
                acts["emit"] = []
            if act.int_value != None:
                acts["emit"].append( (act.nbits, act.int_value, field_name) )
            else:
                acts["emit"].append( (act.nbits, act.value, field_name) )
        elif act.type == "NEQ":
            acts["!"+act.field_name.upper()] = act.int_value
        elif act.type == "nt" or act.type == "ntluf":
            if not "nt" in acts:
                acts["nt"] = []
            if act.nt:
                acts["nt"].append(act.nt)
            elif act.ntluf:
                acts["nt"].append(act.ntluf)
            else:
                raise ValueError("NT is None")
        else:
            raise ValueError("Unhandled Action %s" %str(act))
    conds = {}
    for cond in rule.conditions.and_conditions:
        if cond.equals == True:
            if cond.rvalue.string == '*':
                conds[cond.field_name.upper()] = cond.bits
            else:
                if cond.bits:
                    raise ValueError("Bits is not None")
                try:
                    conds[cond.field_name.upper()] = int(cond.rvalue.string)
                except:
                    conds[cond.field_name.upper()] = cond.rvalue.string
        elif cond.equals == False:
            try:
                conds["!"+cond.field_name.upper()] = int(cond.rvalue.string)
            except:
                conds["!"+cond.field_name.upper()] = cond.rvalue.string
        else:
            raise ValueError("Unhandled Condition %s" %str(cond))
    return (acts, conds)

def CreateActionBindingField(nts):
    nt_field = {}
    for nt_name in nts:
        nt = nts[nt_name]
        field = []
        if nt:
            for rule in nt.rules:
                field.append( ParseActCond(rule) )
            nt_field[nt_name] = field
    return nt_field

def CreateInsActionBindingField(iarray):
    iform_field = {}
    for ins_name in iarray:
        iform_lst = iarray[ins_name]
        field = []
        if iform_lst:
            for iform in iform_lst:
                rule = iform.rule
                field.append( ParseActCond(rule) )
            if ins_name not in iform_field:
                iform_field[ins_name] = field
            else:
                raise ValueError("Iform has more than one rule")
    return iform_field


def FindBindCond(value, binding, act_cond):
    acts = act_cond.act
    conds = act_cond.cond
    ret_value = None

    if binding and binding in acts:
        ret_value = acts[binding]
    else:
        var_str = ""
        for cond in conds:
            var = conds[cond]
            if var and type(var)==str and var in value:
                if not len(var_str):
                    var_str = value
                var_str = var_str.replace(var, cond+" ")
            if len(var_str):
                ret_value = var_str.split()
    return ret_value



# def FindBindCond(value, binding, route):
#     ret_value = None
#     for node in route:
#         if type(node) == NTFieldNode:
#             pass
#         elif type(node) == ActCondNode:
#             for act in node.acts:
#                 if act == "emit":
#                     continue
#                 elif act == binding:
#                     if ret_value != None:
#                         a = 0
#                         # raise ValueError("ret_value overwrite")
#                     ret_value = node.acts[act]
#                 else:
#                     pass

#             var_str = ""
#             for cond in node.conds:
#                 var = node.conds[cond]
#                 if var and var in value:
#                     if not len(var_str):
#                         var_str = value
#                     var_str = var_str.replace(var, cond+" ")
#             if len(var_str):
#                 ret_value = var_str.split()
#         else:
#             raise ValueError("Unknown Node Type")

#     return ret_value


# def EmitBindAct(emit_table, route):
#     i = 0
#     for nbits, value, binding in emit_table:
#         if type(value) == str:
#             bind_value = FindBindCond(value, binding, route)
#             if bind_value != None:
#                 if type(bind_value) == list:
#                     emit_table[i] = (nbits, value, bind_value)
#                 else:
#                     emit_table[i] = (nbits, bind_value, binding)
#         i += 1

def EmitBindAct(emit_table, act_cond):
    i = 0
    for nbits, value, binding in emit_table:
        if type(value) == str:
            bind_value = FindBindCond(value, binding, act_cond)
            if bind_value != None:
                if type(bind_value) == list:
                    emit_table[i] = (nbits, value, bind_value)
                else:
                    emit_table[i] = (nbits, bind_value, binding)
        i += 1


def GetRoute(route):
    act_dict = {}
    cond_dict = {}
    for node in route:
        if type(node) == NTFieldNode:
            pass
        elif type(node) == ActCondNode:
            act_dict.update(node.acts)
            cond_dict.update(node.conds)
    return (act_dict, cond_dict)


def TraverseEmit(traverse_nt_name, field_table, field_node_table):
    nt_node = NTFieldNode(traverse_nt_name, field_table, field_node_table, init=True)
    emit_table = []
    emit_table_lst = []

    act_cond = ActCondDict()
    emit_table_stack = []
    actcond_stack = []
    actcond_lst = []

    route = []
    prev_nt = None

    emit_hash_table = {}

    # for debug
    if traverse_nt_name == "MODRM":
        a = 0

    for iter_type, node in nt_node:
        if iter_type == 2:
            # for debug
            # if node.name == "SIB" and node.iter_index == 1:
            #     a = 0

            if node in route:       # backtrace
                if not flag:
                    actcond_lst.append( act_cond )
                    if len(emit_table):
                        EmitBindAct(emit_table, actcond_lst[-1])
                        emit_hash = str(emit_table)
                        actcond_ref = actcond_lst[-1]
                        if not emit_hash in emit_hash_table:
                            emit_table_lst.append( (emit_table, [actcond_ref]) )
                            emit_hash_table[emit_hash] = emit_table_lst[-1]
                        else:
                            emit_hash_table[emit_hash][1].append(actcond_ref)
                    # route_lst.append( GetRoute(route) )
                while node != route[-1]:
                    top_node = route.pop()
                    if len(emit_table_stack):
                        bind_node, top_emit_stack = emit_table_stack[-1]
                        if bind_node == top_node:
                            emit_table_stack.pop()
                            actcond_stack.pop()
                act_cond = copy.deepcopy(actcond_stack[-1])
                if len(emit_table_stack):
                    emit_table = copy.deepcopy(emit_table_stack[-1][1])
            else:
                route.append(node)
                prev_nt = node
                # if len(emit_table):
                emit_table_stack.append( (node, copy.deepcopy(emit_table)) )
                actcond_stack.append( (copy.deepcopy(act_cond)) )
        else:
            flag = False
            try:
                act_cond.update(node.acts, node.conds, node.strict)
            except CondException as e:                  # if conditon conflict
                flag = True
            except ActException as e:
                flag = True

            if flag:
                node.DisableRoute()
                continue

            route.append(node)
            if "emit" in node.acts:
                emit_table.extend(node.acts["emit"])    # reflush emit_table

    # the last round of iteration will not save the context
    if not flag:
        actcond_lst.append( (act_cond) )
        if len(emit_table):
            EmitBindAct(emit_table, actcond_lst[-1])
            emit_hash = str(emit_table)
            actcond_ref = actcond_lst[-1]
            if not emit_hash in emit_hash_table:
                emit_table_lst.append( (emit_table, [actcond_ref]) )
                emit_hash_table[emit_hash] = emit_table_lst[-1]
            else:
                emit_hash_table[emit_hash][1].append(actcond_ref)

    return emit_table_lst, actcond_lst


# def GetRegNTBinding(ntluf, dct)


# all_ins = "all-datafiles/just_for_test/just4test.txt"

# save = True
# needreload = False

# save = False
# needreload = True

if __name__ == "__main__":
# =========== Load GlobalStruct ================
    save = False
    needreload = False                  # control if we need to reload pattern files or save them again

    sd = save_data.SaveData(all_dec_ins, pkl_dir, logger)
    if sd.haspkl and not needreload:
        sd.Load(GsLoad, gs)
    else:
        gs.regs_lst = register_reader.ReadReg(all_reg)
        gs.reg_names = register_reader.MakeRegsNameLst(gs.regs_lst)
        operand = fields_reader.ReadFields(all_field)
        gs.storage_fields = operand.operand_fields
        gs.state_bits = state_bits_reader.ReadState(all_state_file)
        (gs.nts, gs.ntlufs, gs.repeat_nts, gs.repeat_ntlufs) = \
                            enc_patterns_reader.ReadDecPattern(all_dec_pattern, gs.state_bits)
        enc_patterns_reader.ReadEncDecPattern(all_enc_dec_pattern, gs.state_bits)
        enc_ins_reader.ReadIns(all_dec_ins)

        if save:
            sd.Save(GsSave, gs)
# ==============================================

    print("parse end")


# ===== Parse All Action Binding Field =====
    nt_act_field = CreateActionBindingField(gs.nts)
    ntluf_act_field = CreateActionBindingField(gs.ntlufs)
    iform_act_field = CreateInsActionBindingField(gs.iarray)

    field_table = FieldTable(nt_act_field, ntluf_act_field, iform_act_field)

    field_node_table = {}

    # nt_act_emit_bind = {}
    # for nt_name in nt_act_field:
    #     nt_act_emit_bind[nt_name] = TraverseEmit(nt_name, field_table, field_node_table)

    # ntluf_act_emit_bind = {}
    # for nt_name in ntluf_act_field:
    #     ntluf_act_emit_bind[nt_name] = TraverseEmit(nt_name, field_table, field_node_table)

    iform_act_emit_bind = {}
    for nt_name in iform_act_field:
        iform_act_emit_bind[nt_name] = TraverseEmit(nt_name, field_table, field_node_table)

    print("parse 2 end")


# TODO  处理不等的condition  Done
#       开始分块优化
#       -- 看一下为什么displacement没有被加进emit数组中  有bug
#       需要把act与cond合并，因为NEED_MEMDISP在cond中，而对应判断在act中
#       emit列表的对应关系有问题，出现emit列表不唯一的情况  Done