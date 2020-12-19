import fields_reader
import state_bits_reader
import enc_patterns_reader
import enc_ins_reader
import register_reader
import dfs_generator

import ins_filter

from global_init import *

import capstone


# def isseq(nt_name):
#     nt_name = nt_name.toupper()
#     for seq in 

def DfsSeq(seq, n, n_max, print_nt):
    if n >= n_max:
        return
    for raw_nt_name in seq.nonterminals:
        nt_name = raw_nt_name
        if "_BIND" in nt_name:
            nt_name = nt_name[:-5]
        elif "_EMIT" in nt_name:
            nt_name = nt_name[:-5]
        if raw_nt_name in gs.seqs:
            print("%s%s" %("   "*n, raw_nt_name))
            new_seq = gs.seqs[raw_nt_name]
            DfsSeq(new_seq, n+1, n_max, print_nt)
        elif nt_name in gs.ntlufs:
            print("%sntluf: %s" %("   "*(n+1), raw_nt_name))
            if print_nt:
                nt = gs.ntlufs[nt_name]
                for rule in nt.rules:
                    print("%s  %s" %("   "*(n+1), str(rule)))
        elif nt_name in gs.nts:
            print("%snt   :%s" %("   "*(n+1), raw_nt_name))
            if print_nt:
                nt = gs.nts[nt_name]
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

def ParseNT(nt_dct):
    for nt_name in nt_dct:
        nt = nt_dct[nt_name]
        print("%s" %nt_name)
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

# def GetRegNTBinding(ntluf, dct):



# all_ins = "../../datafiles_test/all-enc-instructions.txt"

save = True
needreload = False

if __name__ == "__main__":
    sd = save_data.SaveData(all_ins, pkl_dir, logger)
    if sd.haspkl and not needreload:
        sd.Load(GsLoad, gs)
    else:
        gs.regs_lst = register_reader.ReadReg(all_reg)
        gs.reg_names = register_reader.MakeRegsNameLst(gs.regs_lst)
        operand = fields_reader.ReadFields(all_field)
        gs.storage_fields = operand.operand_fields
        gs.state_bits = state_bits_reader.ReadState(all_state_file)
        (gs.seqs,gs.nts,gs.ntlufs) = enc_patterns_reader.ReadEncPattern(all_enc_pattern, gs.state_bits)
        enc_patterns_reader.ReadEncDecPattern(all_enc_dec_pattern, gs.state_bits)
        enc_ins_reader.ReadIns(all_ins)

        if save:
            sd.Save(GsSave, gs)

    print("parse end")

    # nt_used = GetUsedNT()
    # for nt_name in nt_used:
    #     print(nt_name)
    # print(num)

    # for seqname in gs.seqs:
    #     ParseSeq(seqname, 10, True)

    # ParseIclass()

    # regonly_iform_dct = GetRegOnly()

    # for iclass in regonly_iform_dct:
    #     print("%s" %iclass)
    #     for i in regonly_iform_dct[iclass]:
    #         # print(gs.iarray[iclass][i])
    #         iform = gs.iarray[iclass][i]
    #         for action in iform.rule.actions:
    #             print("\t\taction: %s" %str(action))
    #         for cond in iform.rule.conditions.and_conditions:
    #             print("\t\tconditon: %s" %str(cond))
    #         print("")

    gen = dfs_generator.Generator()
    # ins_filter = generator.Filter(gen)

    iforms_al = gen.GetOutputRegIform("XED_REG_EAX")
    iforms_bl = gen.GetInputRegIform("XED_REG_EBX")

    set_al = set(iforms_al)
    set_bl = set(iforms_bl)

    iforms = set_al & set_bl
    print(len(iforms))

    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

    # set_iter = iter(iforms)
    # iform = next(set_iter)
    # print(str(iform))
    # my_ins_filter = ins_filter.InsFilter(iform=iform)
    # ins_lst = gen.GeneratorIform(iform, ins_filter=my_ins_filter)
    # if len(ins_lst) > 0:
    #     for ins in ins_lst:
    #         print(ins.hex(), end="")
    #         decode = cs.disasm(ins, 0)
    #         mystr = ""
    #         for insn in decode:
    #             mystr += "\t%s  %s\n" % (insn.mnemonic, insn.op_str)
    #         print(mystr)


    my_ins_filter = ins_filter.InsFilter()
    my_ins_filter["REG0"] = "XED_REG_EAX"
    my_ins_filter["REG1"] = "XED_REG_EBX"

    for i in iforms:
        print(str(i))
        ins_lst = gen.GeneratorIform(i, ins_filter=my_ins_filter)
        if len(ins_lst) > 0:
            for ins in ins_lst:
                print(ins.hex(), end="")
                decode = cs.disasm(ins, 0)
                mystr = ""
                for insn in decode:
                    mystr += "\t%s  %s" % (insn.mnemonic, insn.op_str)
                print(mystr)
    pass
