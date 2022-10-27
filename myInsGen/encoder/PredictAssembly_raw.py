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

import YaraReader
import pickle


def ExpandHash(myhash, hash_tmp=None):    # hash_tmp for speed
    if " " in myhash:
        return []
    if hash_tmp and myhash in hash_tmp:
        return hash_tmp[myhash]

    num_lst = []
    mask = 0
    masked_value = 0
    for i in range(len(myhash)):    # for every hash, generate a mask and a masked_value
                                    # when hash[i] is a determined number, the corresponding mask bit must be 1, masked_value is hash[i] itself
                                    # and for not determined number, mask bit is 0, masked_value can be 0 or 1 (because it make no sense), but we set it 0 here
        mask = mask << 1
        masked_value = masked_value << 1
        if myhash[i] == "0":
            mask |= 1
        elif myhash[i] == "1":
            mask |= 1
            masked_value |= 1
    if hash_tmp:
        hash_tmp[myhash] = []
    for num in range(256):
        if num & mask == masked_value:
            num_lst.append(num)
            if hash_tmp:
                hash_tmp[myhash].append(num)
    return num_lst

def MakeMODRMBind(gens):
    modrm_bind = {}
    hash_tmp = {}
    for i in range(256):        # traverse every situation of modrm
        modrm_bind[i] = []
    for opcode in gens.ptn_dict:
        for modrm_hash in gens.ptn_dict[opcode]:
            lst = ExpandHash(modrm_hash, hash_tmp)
            a = 0
            for num in lst:
                modrm_bind[num].append(opcode)
    return modrm_bind

def MakeMODRMSIBBind(gens):
    modrm_bind = {}
    hash_tmp = {}
    for i in range(256):        # traverse every situation of modrm
        modrm_bind[i] = []
    for opcode in gens.ptn_dict:
        for modrm_hash in gens.ptn_dict[opcode]:
            lst = ExpandHash(modrm_hash, hash_tmp)
            a = 0
            for num in lst:
                modrm_bind[num].append(opcode)
    return modrm_bind


def MakeOpcodeBind(gens):
    search_trees = []
    for opcode in gens.ptn_dict:                        # build a trie tree for every length of opcode
        length = len(opcode)
        while length > len(search_trees):
            search_trees.append({})

        reverse_opcode = opcode[::-1]
        search_node = search_trees[length-1]           # search from the root
        for tmp_byte in reverse_opcode:
            if not tmp_byte in search_node:
                search_node[tmp_byte] = {}
            prev_node = search_node
            search_node = search_node[tmp_byte]
        if len(search_node):
            raise ValueError("Opcode Ending Is Not A Leaf Node")
        else:
            prev_node[tmp_byte] = None              # prevent some unexpected operation
    return search_trees

# Calc mismath
# test_bytes:
#   01 02 03 04
# assume the max opcode length is 6
# (if len(test_bytes) >= max opcode length-1)
#  xx 01 02 03 04 05
#
#  xx xx 01 02 03 04
#  xx 01 02 03 04
#
#  xx xx xx 01 02 03
#  xx xx 01 02 03
#  xx 01 02 03
#
#  xx xx xx xx 01 02
#  xx xx xx 01 02
#  xx xx 01 02
#  xx 01 02
#
#  xx xx xx xx xx 01
#  xx xx xx xx 01
#  xx xx xx 01
#  xx xx 01
#  xx 01

def GenOpcodeMismatch(test_bytes, search_trees):
    mismatch_lst = []
    opcode_length = len(search_trees)
    if opcode_length-1 > len(test_bytes):
        begin_mismatch_len = len(test_bytes)
    else:
        begin_mismatch_len = opcode_length-1

    for i in range(begin_mismatch_len, 0, -1):
        for j in range(i, opcode_length):
            index = i-1
            search_node = search_trees[j]
            opcode_lst = []
            while test_bytes[index] in search_node:
                new_byte = test_bytes[index]
                index -= 1
                search_node = search_node[new_byte]
                opcode_lst.append(new_byte)
                if index < 0:
                    break
            if index >= 0:          # means the bytes doesn't meet any prefix
                continue
            else:
                if search_node != None:
                    stack = [ (search_node, iter(search_node), opcode_lst) ]
                else:
                    raise ValueError("Search Node Reach None Before Emit")
                while len(stack):
                    search_node, search_node_iter, my_opcode_lst = stack.pop()
                    try:
                        new_opcode = next(search_node_iter)
                    except StopIteration:
                        continue
                    stack.append( (search_node, search_node_iter, copy.deepcopy(my_opcode_lst)) )
                    new_search_node = search_node[new_opcode]
                    my_opcode_lst.append(new_opcode)
                    if new_search_node != None:
                        stack.append( (new_search_node, iter(new_search_node), copy.deepcopy(my_opcode_lst)) )
                    else:
                        mismatch_code = bytes(my_opcode_lst[::-1])
                        flag = True
                        for exist_code, exist_i in mismatch_lst:
                            if mismatch_code==exist_code and exist_i==i:
                                flag = False
                        if flag:
                            mismatch_lst.append( (mismatch_code, i) )
    return mismatch_lst

def GenModrmMismatch(test_bytes, modrm_bind):
    first_byte = test_bytes[0]
    modrm_mismatch_lst = []
    if first_byte in modrm_bind:
        i = 0
        for byte in modrm_bind[first_byte]:
            i += 1
            modrm_mismatch_lst.append( (byte, 0) )
    return modrm_mismatch_lst

# only consider 32-bit now
def InitSibLst():
    # wrong config: sib_modrm_hash = ["00100___", "01100___", "10100___"]
    sib_modrm_hash = ["00___100", "01___100", "10___100"]
    sib_modrm_lst = []
    for myhash in sib_modrm_hash:
        sib_modrm_lst.extend(ExpandHash(myhash))
    return sib_modrm_lst

def GenSibMismatch(modrm_sib_bind, sib_modrm_lst):
    sib_mismatch_lst = []
    for sib in sib_modrm_lst:
        tmp = [sib]
        modrm_mismatch_lst = GenModrmMismatch(tmp, modrm_sib_bind)
        for modrm, i in modrm_mismatch_lst:
            sib_mismatch_item = modrm+bytes(tmp)
            sib_mismatch_lst.append( (sib_mismatch_item, 0) )
    return sib_mismatch_lst

def CheckOpcodeMismatch(test_bytes, gens):
    mismatch_lst = []
    for i in range(1, len(test_bytes)+1):
        for opcode in gens.ptn_dict:
            if len(opcode) > i:
                if opcode[-i:] == test_bytes[:i]:
                    flag = True
                    for exist_code, exist_i in mismatch_lst:
                        if opcode == exist_code and exist_i==i:
                            flag = False
                    if flag:
                        mismatch_lst.append( (opcode, i) )
    return mismatch_lst

# length to specify how long the bytes_rule appear in first disasm
def DisasmMismatch(cs, mismatch_lst, bytes_rule, length_first=0, restrict_one_insn=False):
    mismatch_insn_lst = []
    for mismatch_bytes, mismatch_index in mismatch_lst:
        new_bytes = mismatch_bytes + bytes_rule[mismatch_index:]
        length_tmp = length_first + len(mismatch_bytes)-mismatch_index
        total_length = len(new_bytes)
        decode_len = 0
        try:
            decode = cs.disasm(new_bytes, 0)
        except Exception as e:
            continue
        first = True                    # the first insn length must greater than mismatch_index
        insn_lst = []
        for insn in decode:
            if first:
                first = False
                if insn.size < mismatch_index:
                    global log_name
                    global log_index
                    # raise ValueError("%s first insn shorter than mismatch index %d" %(new_bytes.hex(), mismatch_index))
                    print("%s first insn shorter than mismatch index %d  PackYara: %s  Rule: %d" %(new_bytes.hex(), mismatch_index, log_name, log_index))
                    continue
                decode_len += insn.size

                # === here restrict a bytes rule must be in one instruction ===
                if restrict_one_insn:
                    if decode_len >= length_tmp:
                        insn_lst.append(insn)
                    else:
                        break
                # === if we don't use this restrict ===
                else:
                    insn_lst.append(insn)
            else:
                decode_len += insn.size
                insn_lst.append(insn)
        if decode_len >= length_tmp:
            if len(insn_lst):
                mismatch_insn_lst.append( (insn_lst, len(mismatch_bytes)-mismatch_index) )
    return mismatch_insn_lst

# Port from AutoYara_ngram
def HashInsn(slice):
    ret = b""
    # checksum = self.HashBytes(slice)

    # for debug
    slice_bytes = b""

    for insn in slice:
        myhash = []
        opcode_size = 1             # for add 
                                    # 00 /r	ADD r/m8, r8	MR	Valid	Valid	Add r8 to r/m8.
        for i in range(len(insn.opcode)-1, -1, -1):
            if insn.opcode[i] != 0:
                opcode_size = i+1
                break
        prefix_group = 0
        prefix_size = 0
        for i in range(len(insn.prefix)):
            if insn.prefix[i] != 0:
                prefix_group |= 1<<i
                prefix_size += 1
        opfix_size = opcode_size + prefix_size
        insn_size = len(insn.bytes)
        hash_type = 0
        tmp_byte = (hash_type << 4) | insn_size

        myhash.append( (tmp_byte<<3) | opfix_size )

        mnemonic_len = len(insn.mnemonic)
        mnemonic_too_long = False
        if mnemonic_len >= 15:
            mnemonic_too_long = True
            mnemonic_len = 15
        tmp_byte = (prefix_group << 4) | mnemonic_len
        myhash.append(tmp_byte)

        if prefix_size > 0:
            for i in range(len(insn.prefix)):
                if insn.prefix[i] != 0:
                    myhash.append(insn.prefix[i])
        myhash.extend(insn.opcode[:opcode_size])

        ops = 0
        op_num = 0
        for i in insn.operands:
            ops = ops << 2
            op_num += 1
            if i.type == capstone.x86.X86_OP_REG:
                op_type = 1
            elif i.type == capstone.x86.X86_OP_MEM:
                op_type = 2
            elif i.type == capstone.x86.X86_OP_IMM:
                op_type = 3
            else:
                raise ValueError("")
            ops |= op_type
        if op_num > 4:
            raise ValueError("")

        for num in range(op_num, 4):
            ops = ops << 2
        myhash.append(ops)

        tmp_byte = bytes(insn.mnemonic, "ascii")
        if not mnemonic_too_long and len(tmp_byte) != mnemonic_len:
            raise ValueError("Length different after encode")
        ret += bytes(myhash) + tmp_byte
        if mnemonic_too_long:
            ret += b"\x00"

        # for debug
        slice_bytes += insn.bytes

    return ret, slice_bytes



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
        (gs.seqs, gs.nts, gs.ntlufs, gs.repeat_seqs, gs.repeat_nts, gs.repeat_ntlufs) = \
                            enc_patterns_reader.ReadEncPattern(all_enc_pattern, gs.state_bits)
        enc_patterns_reader.ReadEncDecPattern(all_enc_dec_pattern, gs.state_bits)
        enc_ins_reader.ReadIns(all_dec_ins)

        if save:
            sd.Save(GsSave, gs)

# =============== Load Generator Storage ===================
    needreload = False     # for test
    save = False
    sd = save_data.SaveData(all_dec_ins[:-4]+"_gens", pkl_dir, logger)
    if sd.haspkl and not needreload:
        gens = generator_storage.GeneratorStorage(load=True)
        sd.Load(generator_storage.GensLoad, gens)
    else:
        gens = generator_storage.GeneratorStorage()
    if save and needreload:
        sd.Save(generator_storage.GensSave, gens)

# ===============
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    cs.detail = True
    modrm_bind = MakeMODRMBind(gens)
    search_trees = MakeOpcodeBind(gens)

    opc_lst = []
    for opcode in gens.ptn_dict:
        opc_lst.append(opcode.hex())
    opc_lst.sort(reverse=True, key=lambda x: len(x))

    # sib mismatch has nothing to do with test bytes
    modrm_sib_bind = MakeMODRMSIBBind(gens)
    sib_modrm_lst = InitSibLst()
    sib_mismatch_lst = GenSibMismatch(modrm_sib_bind, sib_modrm_lst)

    # test opcode mismatch
    # bytes_rule = b"\xa4\xeb"
    # bytes_rule = b"\x6a\x10\x68\x28\x89\x00\x01"
    bytes_rule = b"\x03\xd3\xeb"
    # bytes_rule = b"\x41\xe9"
    orig_bytes_len = len(bytes_rule)

    bytes_rule += b"\x00" * (15-orig_bytes_len)

    mismatch_lst = []
    opcode_mismatch_lst = GenOpcodeMismatch(bytes_rule, search_trees)
    # mismatch_lst_check = CheckOpcodeMismatch(test_bytes, gens)
    modrm_mismatch_lst = GenModrmMismatch(bytes_rule, modrm_bind)
    mismatch_lst.append( ("Opcode Mismatch", opcode_mismatch_lst) )
    mismatch_lst.append( ("MODRM Mismatch", modrm_mismatch_lst) )
    # mismatch_lst.append( ("SIB Mismatch", sib_mismatch_lst) )


    print("===== No Mismatch =====")
    try:
        decode = cs.disasm(bytes_rule, 0)
    except Exception as e:
        pass
    ori_index = 0
    for insn in decode:
        if ori_index < orig_bytes_len:
            print("%s\t%s %s" %(insn.bytes.hex(), insn.mnemonic, insn.op_str))
            ori_index += insn.size

    for describe, mismatch in mismatch_lst:
        print("===== %15s =====" %describe)
        mismatch_insn_lst = DisasmMismatch(cs, mismatch, bytes_rule, length_first=orig_bytes_len, restrict_one_insn=False)
        print("Total: %d" %len(mismatch_insn_lst))
        index = 0
        for insn_lst, mismatch_len in mismatch_insn_lst:
            # print("=================")
            size = 0
            index += 1
            for insn in insn_lst:
                # print("%d:  %20s\t\t%s %s" %(index, insn.bytes.hex(), insn.mnemonic, insn.op_str))
                insn_str = "%s %s" %(insn.mnemonic, insn.op_str)
                print("{0:>20}{1:>50}".format(insn.bytes.hex(), insn_str), end="")
                size += insn.size
                if size >= mismatch_len+orig_bytes_len:
                    break
            print("")
    # ori_insn = []
    # try:
    #     decode = cs.disasm(bytes_rule, 0)
    # except Exception as e:
    #     print(e)
    #     print("Disasm Bytes %s Failed!  PackYara: %s  Rule: %d" %(bytes_rule.hex(), log_name, rule_index))
    # decode_len = 0
    # for insn in decode:
    #     ori_insn.append(insn)
    #     decode_len += insn.size
    #     if decode_len > ori_bytes_len:
    #         break


# TODO:  hash中使用了MODRM的reg，但没有区分哪条指令是确实使用reg来作为opcode的，这可能使得某些指令操作的寄存器不同就被当做不同指令
# TODO:  predict 过程中似乎缺失了一些情况，比如opcode比bytes长，所以完全覆盖bytes的情况
# TODO:  SIB Mismatch 有大问题，查表的时候没有判断对应的opcode中是否存在MODRM编码，会导致一部分实际上没有MODRM()的也被认为存在SIB字段，然后就被识别成立即数了