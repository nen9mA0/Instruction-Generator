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


# def GetRegNTBinding(ntluf, dct)


# all_ins = "all-datafiles/just_for_test/just4test.txt"

# save = True
# needreload = False

# save = False
# needreload = True

if __name__ == "__main__":
# =========== Load GlobalStruct ================
    save = True
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

    # ins_filter = generator.Filter(gen)

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

# =============== Load Generator Storage ===================
    # needreload = False     # for test
    # save = False
    sd = save_data.SaveData(all_dec_ins[:-4]+"_gens", pkl_dir, logger)
    if sd.haspkl and not needreload:
        gens = generator_storage.GeneratorStorage(load=True)
        sd.Load(generator_storage.GensLoad, gens)
    else:
        gens = generator_storage.GeneratorStorage()
    if save and needreload:
        sd.Save(generator_storage.GensSave, gens)
# ==========================================================
    gen = ins_filter.Generator(gens)
# =============== Load NT Hash Table =======================
    # needreload = True
    # save = True
    # needreload = False
    # save = False

    sd = save_data.SaveData(all_dec_ins[:-4]+"_htm", pkl_dir, logger)
    htm = HashTable.HashTableManager()
    gens.AddHashTableManager(htm)
    if sd.haspkl and not needreload:
        sd.Load(HashTable.HTMLoad, htm)
    else:
        CreateNTHashTable(gen, gens, gs.ntlufs)
        CreateNTHashTable(gen, gens, gs.nts)
        for nt_name in gs.repeat_nts:
            htm.repeat_nts[nt_name] = GetNTsHashTable(gen, gs.repeat_nts[nt_name])
        for nt_name in gs.repeat_ntlufs:
            htm.repeat_ntlufs[nt_name] = GetNTsHashTable(gen, gs.repeat_ntlufs[nt_name])
        # CreateNTHashTable(gen, gens, htm, ["XMM_SE"])
        # === check ===
        # check if old htm is the same as new one, only when the old one is already correct, and new edition just add some optimization
        # old_htm = HashTable.HashTableManager()
        # sd.Load(HashTable.HTMLoad, old_htm)
        # checker.CheckHashTableManager(old_htm, htm)

        # check new htm correction
        for ht in htm.nt_names:
            all_context = htm.nt_names[ht].all_context
            for context in all_context:
                checker.CheckContextCondNum(context)
        # === ===
    if save and needreload:
        sd.Save(HashTable.HTMSave, htm)
    htm.done = True

    # ==== print note\nt_tree.txt note\nts.txt and note\ntlufs.txt
    # for seqname in gs.seqs:
    #     ParseSeq(seqname, 10, True)
    # ParseNT(gs, "nts")
    # ParseNT(gs, "ntlufs")

    gen.DFSSeqContext("MODRM_BIND")

# ==========================================================

    my_ins_filter = ins_filter.InsFilter(gens)
    # my_ins_filter.AppendReg("XED_REG_AL", "output")
    # my_ins_filter.AppendReg("GPRv_B()", "")
    # my_ins_filter.AppendReg("XED_REG_EAX", "")
    # my_ins_filter.AppendReg("GPRv_B()", "")
    # my_ins_filter["MOD"] = "!3"

    # Extension XSAVE XSAVEC XSAVEOPT 
    # my_ins_filter["extension"] = ["BASE", "XSAVE", "XSAVEC", "XSAVES", "XSAVEOPT", "SMAP", "RDSEED", "RDWRFSGS",
    #                             "ADOX_ADCX", "PKU", "INVPCID", "SVM", "MOVBE", "PREFETCHWT1", "CLFSH",
    #                             "CLFLUSHOPT", "RDRAND", "RDTSCP", "RDPID"]         # TODO: Attension: there are some special operation for AVX512VEX and AVX512EVEX
    # "BMI1", "BMI2"
    # my_ins_filter["iclass"] = ["CRC32", "POPCNT", "PREFETCHW"]

    # my_ins_filter["extension"] = ["X87"]
    my_ins_filter["extension"] = ["SSE2"]
    # my_ins_filter["iclass"] = ["FXSAVE", "FXRSTOR"]
    # my_ins_filter["iclass"] = ["MOV"]
    my_ins_filter.SpecifyMode(32)
    # === specify register ===
    # my_ins_filter["BASE0"] = "XED_REG_EAX"

    iforms = my_ins_filter.GetIforms()

    # my_ins_filter["REG0"] = "XED_REG_AX"       # here we just specify input and output reg
    # my_ins_filter["REG1"] = "XED_REG_BX"

    # my_ins_filter["REG0"] = "XED_REG_CL"
    # my_ins_filter["REG1"] = "XED_REG_DL"

# === for x87 ===
    # my_ins_filter["REG1"] = "XED_REG_ST0"
    # my_ins_filter["REG0"] = "XED_REG_ST1"
# === ===

# === for sse ===
    # my_ins_filter["REG0"] = "XED_REG_XMM0"
    my_ins_filter["REG0"] = "XED_REG_ECX"
    my_ins_filter["REG1"] = "XED_REG_XMM0"
# === ===


    my_ins_filter["BASE0"] = "XED_REG_ESI"
    my_ins_filter["INDEX"] = "XED_REG_EDI"
    my_ins_filter["SEG0"] = "@"
    # my_ins_filter["EOSZ"] = "2"
    # my_ins_filter["EASZ"] = "2"
    # my_ins_filter["SIB"] = "0"
    my_ins_filter["SCALE"] = "1"            # can be 1 2 4 8
    my_ins_filter["DISP_WIDTH"] = "0"
    # gen.DFSNTContext(["VEX_REXR_ENC"])
    # gen.DFSSeqContext("MODRM_BIND")
    # all_context = gen.DFSNTContext(["SIB_REQUIRED_ENCODE", "SIBSCALE_ENCODE", "SIBINDEX_ENCODE", "SIBBASE_ENCODE", "MODRM_RM_ENCODE"])

    # for route in all_route:           # all_route: just 4 debug
    #     print(route)


# ============== Set NT iter num ================
    nt_emitnum = {}
    nt_emitnum["FIXUP_EOSZ_ENC"] = 1
    nt_emitnum["FIXUP_EASZ_ENC"] = 1
    nt_emitnum["ASZ_NONTERM"] = 1
    nt_emitnum["OSZ_NONTERM_ENC"] = 1
    nt_emitnum["PREFIX_ENC"] = 1
    nt_emitnum["REX_PREFIX_ENC"] = 1

# === for x87 ===
    # nt_emitnum["X87"] = 1
# === ===

    # nt_emitnum["iform"] = 20

    # nt_emitnum["SIB_REQUIRED_ENCODE"] = 1
    # nt_emitnum["SIBSCALE_ENCODE"] = 1
    # nt_emitnum["SIBINDEX_ENCODE"] = 1
    # nt_emitnum["SIBBASE_ENCODE"] = 1
    # nt_emitnum["MODRM_RM_ENCODE"] = 1
    # nt_emitnum["MODRM_MOD_ENCODE"] = 1
    # nt_emitnum["SEGMENT_DEFAULT_ENCODE"] = 1
    # nt_emitnum["SEGMENT_ENCODE"] = 1
    # nt_emitnum["SIB_NT"] = 1
    # nt_emitnum["DISP_NT"] = 2
    gen.SetNTEmitNum(nt_emitnum)
# ============== ============

# ============== Set NT otherwise_first ================
# **See Note**
# Specify if this NT will execute otherwise **first**
# **Attension** : otherwise_first setting here only work to NTHashNode
    nt_otherwise_first = {}
    nt_otherwise_first["SIB_REQUIRED_ENCODE"] = True
    nt_otherwise_first["SEGMENT_ENCODE"] = True
    nt_otherwise_first["DISP_NT"] = True
    nt_otherwise_first["PREFIX_ENC"] = True
    nt_otherwise_first["REX_PREFIX_ENC"] = True
    gen.SetOtherwiseFirst(nt_otherwise_first)
# ============== ============

# ============== Set Default Emit Number =================
    default_emit_num = {}
    default_emit_num["REXW"] = 0
    default_emit_num["REXR"] = 0
    default_emit_num["REXB"] = 0
    default_emit_num["REXX"] = 0
    default_emit_num["REG"] = 0
    default_emit_num["UIMM0"] = 10
    default_emit_num["UIMM1"] = 20
    default_emit_num["DISP"] = 0x10
    gen.SetDefaultValidEmitNum(default_emit_num)
# ============== ============

    # print(len(iforms))

    for i in iforms:
        tmp_str = str(i).split()
        print("%s %s"%(tmp_str[0], tmp_str[1]))
        logger.info("%s %s"%(tmp_str[0], tmp_str[1]))
        ins_lst = gen.GeneratorIform(i, ins_filter=my_ins_filter, output_num=20)
        if len(ins_lst) > 0:
            for ins in ins_lst:
                print(ins.hex(), end="")
                logger.info(ins.hex())
                decode = cs.disasm(ins, 0)
                mystr = ""
                i = 0
                for insn in decode:
                    if i == 0:
                        first_ins_size = insn.size
                        mystr += "\t%s  %s" % (insn.mnemonic, insn.op_str)
                        i += 1
                    else:
                        mystr += "\t\tremain %d bytes" %(len(ins) - first_ins_size)
                        break
                print(mystr)
                logger.info(mystr)
        else:
            logger.warning(str(i))
    pass
