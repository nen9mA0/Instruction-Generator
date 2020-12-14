import pickle
import copy
from typing import TypeVar, Optional, Generic

from global_init import *
from generator_storage import *

# DFS version to traversal all the path
# ======================================
# In DFS version, algorithm is easier.
# We don't need to save all the context, instead, we can just save the context of current path.
# And we must save a num which indicates the path now we are taking for every nonterminal.
# Another problem is backtracking, the simplest way is to save one init context for every nonterminal.
# When we take one path, fork a context from the init context. If the context unsatisfy the rule, just delete it and backtrack.
# Another way is to delete all change in this nonterminal, which I think is more difficult and it brings very few advantage.

class NTContext(object):
    def __init__(self, bindingNT, init_ntcontext:Optional['NTContext']=None):
        if init_ntcontext != None:
            self.init_context = init_ntcontext.context
        else:
            self.init_context = {}
        self.context = None
        self.i = 0                  # counter of rule path
        self.j = 0                  # counter of otherwise path
        self.otherwise = 0
        self.nt = bindingNT
        self.rules = self.nt.rules
        self.rule_len = len(bindingNT.rules)
        self.is_seqnt = False
        self.next = None
        self.prev = None
        self.next_seq = None
        self.prev_seq = None
        self.backtracking = True
        self.exec_otherwise = True      # otherwise of this context has been execute
        self.skip = False               # if a NT's rule conditions or actions have another NT, it will be break into several contexts,
                                        # and the original context will be skip when execute.
                                        # This flag will be reset when execute another rule, and it's reset in Fork
        if hasattr(bindingNT, "otherwise"):
            if len(bindingNT.otherwise) > 1:
                logger.error("Nonterminal has more than one otherwise: %s" %bindingNT)
            self.otherwise += 1

    def __str__(self):
        return str(self.context)

    def __iter__(self):
        self.i = 0
        return self

    def __next__(self):
        if self.i < self.rule_len:
            tmp = self.rules[self.i]
            self.i += 1
            return tmp
        else:
            raise StopIteration()

    def __getitem__(self, item):
        if self.context != None:
            return self.context[item]
        else:
            raise TypeError("context is None")

    def __setitem__(self, item, value):
        if self.context != None:
            self.context[item] = value
        else:
            raise TypeError("context is None")

    def SetPrev(self, prev):
        self.prev = prev

    def SetNext(self, next):
        self.next = next

    def SetInitContext(self, context):
        self.init_context = context

    def ResetContext(self, context):
        self.SetInitContext(context)
        self.backtracking = False
        self.exec_otherwise = True

    def Fork(self):
        self.skip = False
        if self.context != None:
            del self.context
        self.context = copy.deepcopy(self.init_context)
        return self.context

    def TestAndAssignment(self, item, value):
        if self.context != None:
            if item in self.context:
                if value != self.context[item]:
                    return False
                else:
                    return True
            else:
                self.context[item] = value
                return True
        else:
            raise TypeError("context is None")
        return False

    def Assignment(self, item, value):
        if self.context != None:
            self.context[item] = value
            return True
        else:
            return False


class SeqNTContext(NTContext):
    def __init__(self, seq_sum, bindingNT=None, prevSeqNT=None, nextSeqNT=None, init_ntcontext:Optional['NTContext']=None):
        if init_ntcontext != None:
            self.init_context = init_ntcontext.context
        else:
            self.init_context = {}
        self.context = None
        self.i = 0                  # counter of rule path
        self.j = 0                  # counter of otherwise path
        self.otherwise = 0
        self.seq_num = seq_sum
        self.is_seqnt = True
        self.next_seq = nextSeqNT   # record the next Sequence nonterminal
        self.prev_seq = prevSeqNT
        self.next = nextSeqNT       # record the next nonterminal that will be execute
        self.prev = prevSeqNT
        self.backtracking = True
        self.exec_otherwise = True
        if bindingNT != None:
            self.nt = bindingNT
            self.nt_name = bindingNT.name
            self.rules = bindingNT.rules
            self.rule_len = len(bindingNT.rules)
            if hasattr(bindingNT, "otherwise"):
                if len(bindingNT.otherwise) > 1:
                    logger.error("Nonterminal has more than one otherwise: %s" %bindingNT)
                self.otherwise += 1
        else:
            self.nt_name = "INSTRUCTIONS"

    def SetInstruction(self, iform):
        if not self.nt_name == "INSTRUCTIONS":
            raise ValueError("Set a wrong INSTRUCTIONS NT")
        self.nt = iform
        self.nt_name = iform.iclass
        self.rules = [iform.rule]
        self.rule_len = 1

class SeqContext(object):
    def __init__(self, seq, init_context:dict=None, gens=None):
        self.nt_contexts = []
        self.context_dict = {}
        self.init_context = init_context

        self.seq = seq
        self.seqname = seq.name
        self.nts = seq.nonterminals
        self.gens = gens

        self.BuildSeqNT()

    def __getitem__(self, item):
        return self.context_dict[item]

    def __setitem__(self, item, value):
        self.context_dict[item] = value

    def __iter__(self):
        self.iter = []
        self.iter_num = 0
        self.disable_path = False
        for context in self.nt_contexts:
            self.iter.append(iter(context))
        self.iter_len = len(self.iter)
        return self

    def __next__(self):
        iter_num = self.iter_num
        if iter_num < self.iter_len:
            current_iter = self.iter[iter_num]
            context = self.nt_contexts[iter_num]
            if context.backtracking and context.prev != None:
                context.ResetContext(context.prev.context)
            context.backtracking = False    # no matter we reset init context or not, 
                                            # backtracking flag should be reset when we reach this context again
            try:
                if self.disable_path:       # indicates that this path is unreachable
                    self.disable_path = False
                    raise StopIteration
                ret_rule = next(current_iter)
                self.iter_num += 1
                context.Fork()              # Every time we get a new rule, we must fork one new context for new rule
            except StopIteration:           # NT has been traversed, backtracking
                if iter_num == 0:           # if the first iterator has been traversed, stop iteration
                    raise StopIteration
                ntc = current_iter          # current_iter and ntc is the same, both are NTContext. I define ntc for clear code.
                ntc.backtracking = True     # When backtracking is true, indicates that the binding iterator has been traversed,
                                            # and next time we should update init_context of this NTContext
                if ntc.is_seqnt:
                    self.iter[iter_num] = iter(ntc) # if is SequenceNT, new a iterator
                else:
                    self.iter.pop(iter_num)         # if is a normal NT, just delete it
                self.iter_num -= 1
                iter_num = -1               # indicates that this step is a backtracking step
                ret_rule = None
        else:                               # one path has been done
            self.iter_num -= 1
            ret_rule = None
            context = None
            if self.disable_path:
                self.disable_path = False
                iter_num = -1
            else:
                iter_num = -2                   # indicates that is the end of one path
        return (iter_num, context, ret_rule)

    def DisablePath(self):
        self.disable_path = True

    def BuildSeqNT(self):
        prev_ntc = None
        for i in range(len(self.nts)):
            nt_name = self.nts[i][:-5]
            if nt_name == "INSTRUCTIONS":
                tmp = SeqNTContext(i)
            else:
                nt = self.gens.nts[nt_name]
                tmp = SeqNTContext(i, nt)
            self.nt_contexts.append(tmp)
            if not nt_name in self.context_dict:
                self.context_dict[nt_name] = tmp
            else:
                logger.error("Sequence NT name conflict: %s" %nt_name)
            if prev_ntc != None:
                tmp.SetPrev(prev_ntc)
                prev_ntc.SetNext(tmp)
            prev_ntc = tmp

    def SetInstruction(self, iform):
        seqntc = self.context_dict["INSTRUCTIONS"]
        seqntc.SetInstruction(iform)

    def AddNT(self, nt, seqnum, init_context=None):
        tmp = NTContext(nt, init_context)
        self.nt_contexts.append(tmp)
        self.context_dict[nt.name] = tmp
        self.iter.append(iter(tmp))
        self.iter_len = len(self.iter)
        self.addone = False
        return tmp


class Emulator(object):
    def __init__(self, gens):
        self.gens = gens
        self.context = None                         # save a NTContext structure for ExecNT
        self.nt_iter = None

    def DFSExecSeqBind(self, seqname, iform, init_context=None):
        if not seqname in self.gens.seqs:
            raise KeyError("_ExecSeq: Cannot find seqname: %s" %seqname)

        seq = self.gens.seqs[seqname]
        seq_context = SeqContext(seq, init_context, gens=self.gens)
        seq_context.SetInstruction(iform)
        seq_iter = iter(seq_context)
        prev_iternum = -1
        prev_context = None

        while True:
            ins_hex = []
            try:
                iter_num, context, rule = next(seq_iter)
                if iter_num >= 0:
                    self.context = context
                    if rule != None:
                        flag = self._ExecNT(rule, context)
                        if not flag:                # if flag is False, disable this path
                            seq_iter.DisablePath()
            # print, for debuging
                    # init_context = context.init_context
                    # self.PrintIter(iter_num, rule, init_context, context)
                elif iter_num == -1:                # backtracking
                    print("backtracking...")
                    pass
                elif iter_num == -2:                # output ins_hex
                    print("output: %s" %self.context.context)
                    pass
                    ins_hex = []
            except StopIteration:
                break

        return self.context

    def _ExecNT(self, rule, context):
        if not context.skip:
            otherwise = None
            if context.otherwise > 0:
                otherwise = context.nt.otherwise[0]     # TODO: here only handle the first otherwise
            flag = True
            for cond in rule.conditions.and_conditions:
                if cond.equals == True:
                    if cond.rvalue.nt:
                        nt_name = cond.rvalue.value
                        if not nt_name in self.gens.ntlufs:
                            logger.error("err: GeneratorIform: Can not find nt %s" %nt_name)
                            exit(-1)
                        
                        context.skip = True
                    elif not self.context.TestAndAssignment(cond.field_name, cond.rvalue.value):
                        flag = False
                        break
                else:
                    logger.error("_ExecNT: Not Equal condition %s in\n%s" %(cond, rule))

            if not flag:        # if conditions not satisfied
                if otherwise != None and context.exec_otherwise:   # if has otherwise, execute otherwise action
                    flag = True
                    context.exec_otherwise = False
                    act = otherwise
                    if act.type == "FB":
                        if not act.field_name == "ERROR":
                            self.context.Assignment(act.field_name, act.value)
                        else:
                            flag = False        # if action is "error", return false
                    elif act.type == "return":
                        pass                    # do nothing
                    else:
                        a = 0
                        pass
                else:
                    pass                        # if don't have otherwise, return false
            else:
                for act in rule.actions:
                    if act.type == "FB":                        # for actions, we don't need to test, for whose key has been in context, just overwrite it
                        if not act.field_name == "ERROR":
                            self.context.Assignment(act.field_name, act.value)
                        else:                   # if action is "error", return false
                            flag = False
                    else:
                        a = 0
                        pass
        else:
            flag = True
        return flag

    def PrintIter(self, iternum, rule, prev_context, context):
        prefix = "  " * iternum
        mystr = prefix
        mystr += str(rule)
        mystr += ":\n" + prefix
        mystr += str(prev_context) + " --> " + str(context)
        print(mystr)



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
