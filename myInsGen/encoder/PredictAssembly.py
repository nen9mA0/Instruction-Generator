from turtle import st
from sklearn.tree import export_text
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


def ExpandHash(myhash, hash_tmp=None):    # hash_tmp for speed
    if " " in myhash:
        return []
    if myhash in hash_tmp:
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
    hash_tmp[myhash] = []
    for num in range(256):
        if num & mask == masked_value:
            num_lst.append(num)
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

def CheckMismatch(test_bytes, gens):
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

    modrm_bind = MakeMODRMBind(gens)
    search_trees = MakeOpcodeBind(gens)

    # test opcode mismatch
    # test_bytes = b"\x00\x00\x00\x00\x00"
    test_bytes = b"\x41\xe9"
    mismatch_lst = GenOpcodeMismatch(test_bytes, search_trees)
    # mismatch_lst_check = CheckMismatch(test_bytes, gens)
    a = 0