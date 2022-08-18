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
    opcode_bind_reverse = []
    opcode_bind_forward = []
    for opcode in gens.ptn_dict:
        prev_code = None
        for i in range(len(opcode)):
            if i > len(opcode_bind_reverse)-1:
                opcode_bind_reverse.append({})
                opcode_bind_forward.append({})
            new_opcode = opcode[i]
            if not new_opcode in opcode_bind_reverse[i]:
                opcode_bind_reverse[i][new_opcode] = []
            if not new_opcode in opcode_bind_forward[i]:
                opcode_bind_forward[i][new_opcode] = []

            if prev_code != None:
                if not prev_code in opcode_bind_reverse[i][new_opcode]:
                    opcode_bind_reverse[i][new_opcode].append(prev_code)
                if not new_opcode in opcode_bind_forward[i-1][prev_code]:
                    opcode_bind_forward[i-1][prev_code].append(new_opcode)
            prev_code = new_opcode
    return opcode_bind_forward, opcode_bind_reverse


# check forward and backward
# assume that 0F 1F 44 00, 0F 1F 80 00, 0E 1F 44 00 (may not exist)
# reverse bind:
#   (1) ["0F":[], "0E":[]]
#   (2) ["1F":[0E, 0F]]
#   (3) ["44":[1F], "80":[1F]]
#   (4) ["00":[44, 80]]
# when we traverse back, all possible results are:
#   * 00 44 1F 0E
#   * 00 44 1F 0F
#   * 00 80 1F 0E       # wrong
#   * 00 80 1F 0F
# so we must create a forward table:
#   (1) ["0F":[1F], "0E":[1F]]
#   (2) ["1F":[44 80]]
#   (3) ["44":[00], "80":[00]]
#   (4) ["00":[]]
# when we traverse back, we check if the new bytes meet the rules of forward table
#   * 00 44 1F 0E
#   * 00 44 1F 0F
#   * 00 80 1F 0E       # wrong
#   * 00 80 1F 0F
def GenOpcodeMismatch(test_bytes, opcode_bind_forward, opcode_bind_reverse):
    begin_index = len(opcode_bind_reverse) - 1
    index = begin_index
    first_byte = test_bytes[0]
    while index > 0:
        if first_byte in opcode_bind_reverse[index]:
            mismatch_lst = []
            depth = index-1
            tmp_byte_lst = [first_byte]
            tmp_byte = first_byte
            stack = []

            flag = True
            while (depth < index-1) or flag:
                flag = False
                if depth == 0:
                    if tmp_byte in opcode_bind_reverse[depth]:
                        tmp_byte_lst.append(tmp_byte)
                        mismatch_lst.append(tmp_byte_lst)           # emit one mismatch context
                        depth += 1                                  # backward
                else:
                    if index-1-depth >= len(stack):             # forward
                        if tmp_byte in opcode_bind_reverse[depth] and tmp_byte_lst[-1] in opcode_bind_forward[depth][tmp_byte]:
                            next_iter = iter(opcode_bind_reverse[depth][tmp_byte])
                            tmp_byte_lst.append(tmp_byte)
                            try:
                                tmp_byte = next(next_iter)
                                stack.append(next_iter)
                                depth -= 1
                            except StopIteration:       # empty iterator, backward
                                tmp_byte_lst.pop()
                                depth += 1
                        else:                           # else: tmp_byte invalid, backward
                            depth += 1
                    else:                               # backward
                        pass
        else:
            index -= 1



if __name__ == "__main__":
# =========== Load GlobalStruct ================
    save = False
    needreload = False                  # control if we need to reload pattern files or save them again

    sd = save_data.SaveData(all_ins, pkl_dir, logger)
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
        enc_ins_reader.ReadIns(all_ins)

        if save:
            sd.Save(GsSave, gs)

# =============== Load Generator Storage ===================
    needreload = False     # for test
    save = False
    sd = save_data.SaveData(all_ins[:-4]+"_gens", pkl_dir, logger)
    if sd.haspkl and not needreload:
        gens = generator_storage.GeneratorStorage(load=True)
        sd.Load(generator_storage.GensLoad, gens)
    else:
        gens = generator_storage.GeneratorStorage()
    if save and needreload:
        sd.Save(generator_storage.GensSave, gens)

    modrm_bind = MakeMODRMBind(gens)
    opcode_bind_forward, opcode_bind_reverse = MakeOpcodeBind(gens)

    # test opcode mismatch
    test_bytes = b"\x00"
    GenOpcodeMismatch(test_bytes, opcode_bind_forward, opcode_bind_reverse)