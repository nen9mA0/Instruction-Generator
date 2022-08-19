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
        for byte in modrm_bind[first_byte]:
            modrm_mismatch_lst.append( (byte, 0) )
    return modrm_mismatch_lst

# only consider 32-bit now
def InitSibLst():
    sib_modrm_hash = ["00100___", "01100___", "10100___"]
    sib_modrm_lst = []
    for myhash in sib_modrm_hash:
        sib_modrm_lst.extend(ExpandHash(myhash))
    return sib_modrm_lst

def GenSibMismatch(modrm_bind, sib_modrm_lst):
    sib_mismatch_lst = []
    for sib in sib_modrm_lst:
        tmp = [sib]
        modrm_mismatch_lst = GenModrmMismatch(tmp, modrm_bind)
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

def DisasmMismatch(cs, mismatch_lst, bytes_rule):
    mismatch_insn_lst = []
    for mismatch_bytes, mismatch_index in mismatch_lst:
        new_bytes = mismatch_bytes + bytes_rule[mismatch_index:]
        length = len(new_bytes)
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
            insn_lst.append(insn)
        if decode_len == length:
            mismatch_insn_lst.append(insn_lst)
    return mismatch_insn_lst

# Port from AutoYara_ngram
def HashInsn(slice):
    myhash = []
    # checksum = self.HashBytes(slice)

    # for debug
    # slice_bytes = b""
    for insn in slice:
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

        myhash.append( (insn_size<<3) | opfix_size )

        reg = (insn.modrm >> 3) & 0x7
        myhash.append(prefix_group << 3 | reg)

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
        if op_num > 3:
            return b""

        ops = ops | (op_num << 6 )

        myhash.append(ops)

        # for debug
        # slice_bytes += insn.bytes

    return bytes(myhash)




yara_file = "I:\\Project\\auto_yara\\rules\\automine-new721test_back.yar"

gram1_database = "C:\\Users\\root\\Documents\\WeChat Files\\wxid_k0oaccu7xi0a22\\FileStorage\\File\\2022-08\\databases_1\\database_1_0.pkl"
gram2_database = ""
gram3_database = ""
gram4_database = "C:\\Users\\root\\Documents\\WeChat Files\\wxid_k0oaccu7xi0a22\\FileStorage\\File\\2022-08\\database10.pkl"

gram_filename = [gram1_database, gram2_database, gram3_database, gram4_database]
gram_database = [None for i in range(len(gram_filename))]
gram_data =     [None for i in range(len(gram_filename))]
gram_max = len(gram_data)-1

result_file = "result\\result.pkl"
slice_length = 4

# for logging
log_name = ""
log_index = -1

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

    # sib mismatch has nothing to do with test bytes
    sib_modrm_lst = InitSibLst()
    sib_mismatch_lst = GenSibMismatch(modrm_bind, sib_modrm_lst)

    with open(yara_file) as f:
        lines = f.readlines()

    packyara_lst = []
    reader = YaraReader.YaraReader(lines)
    for name, lines in reader:
        packyara = YaraReader.PackerYara(name, lines)
        packyara_lst.append(packyara)

    a = 0
    # test opcode mismatch
    # test_bytes = b"\x00\x00\x00\x00\x00"

    index = 0
    for path in gram_filename:
        with open(path, "rb") as f:
            tmp_database = pickle.load(f)
        tmp_data = tmp_database["data"]
        gram_database[index] = tmp_database
        gram_data[index] = tmp_data
        index += 1


    result = {}
    for packyara in packyara_lst:
        print("==== Processing %s ====" %packyara.name)
        log_name = packyara.name
        rule_index = -1
        result[packyara.name] = []
        for bytes_rule in packyara.rule:
            ori_bytes_len = len(bytes_rule)
            bytes_rule += b"\x00\x00\x00\x00\x00\x00\x00"        # we pad 6 bytes for fixing the last jump opcode

            rule_index += 1
            log_index = rule_index
            mismatch_lst = []
            opcode_mismatch_lst = GenOpcodeMismatch(bytes_rule, search_trees)
            # mismatch_lst_check = CheckOpcodeMismatch(test_bytes, gens)
            modrm_mismatch_lst = GenModrmMismatch(bytes_rule, modrm_bind)
            mismatch_lst.extend(opcode_mismatch_lst)
            mismatch_lst.extend(modrm_mismatch_lst)
            mismatch_lst.extend(sib_mismatch_lst)
            mismatch_insn_lst = DisasmMismatch(cs, mismatch_lst, bytes_rule)
            ori_insn = []
            try:
                decode = cs.disasm(bytes_rule, 0)
            except Exception as e:
                print(e)
                print("Disasm Bytes %s Failed!  PackYara: %s  Rule: %d" %(bytes_rule.hex(), log_name, rule_index))
                continue
            decode_len = 0
            for insn in decode:
                ori_insn.append(insn)
                decode_len += insn.size
                if decode_len > ori_bytes_len:
                    break
            # if decode_len != len(bytes_rule):         # now the last byte of rule is an opcode of a jump/call/ret instruction
            #     # raise ValueError("Someting Wrong With Bytes %s? Disasm Failed" %(bytes_rule.hex()))
            #     print("Someting Wrong With Bytes %s? Disasm Failed!  PackYara: %s  Rule: %d" %(bytes_rule.hex(), packyara.name, rule_index))
            #     continue
            flag = False
            total_insn = 0
            ori_insn_num = 0
            probability = 0.0
            ori_insn_len = len(ori_insn)
            if ori_insn_len >= slice_length:                   # if length of origin insn equal or greater than slice length
                tmp_data = gram_data[gram_max]
                length = slice_length
            else:
                tmp_data = gram_data[ori_insn_len-1]
                length = ori_insn_len
            for mismatch_insn in mismatch_insn_lst:
                if len(mismatch_insn) >= length:
                    insn_hash = HashInsn(mismatch_insn[:length])
                    if insn_hash in tmp_data:
                        total_insn += tmp_data[insn_hash]
            ori_insn_hash = HashInsn(ori_insn[:length])
            if ori_insn_hash in tmp_data:
                ori_insn_num = tmp_data[ori_insn_hash]
                total_insn += ori_insn_num
                probability = ori_insn_num / total_insn
                result[packyara.name].append( (rule_index, total_insn, ori_insn_num, probability) )
                flag = True
            else:
                print("Rule%d:\t  %s  Not In Database  HASH:%s  rule_insn_length: %d" %(rule_index, bytes_rule[:ori_bytes_len], ori_insn_hash.hex(), len(ori_insn)))
            tmp_data = None
            if flag:
                print("Rule%d:\t\ttotal_insn: %d  ori_insn_num: %d  rule_insn_length: %d  probability: %f" %(rule_index, total_insn, ori_insn_num, len(ori_insn), probability))
        with open(result_file, "wb") as f:                      # save every packer to prevent accident
            pickle.dump(result, f)
    a = 0