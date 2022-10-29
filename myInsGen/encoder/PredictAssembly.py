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
import binascii
from fractions import Fraction

import YaraReader
import pickle


yara_file = "I:\\Project\\auto_yara\\GetStat\\yara_rules\\20221028\\autoyara.yar"

gram1_database = "I:\\Project\\auto_yara\\ngram\\database\\1gram\\database.pkl"
gram2_database = "I:\\Project\\auto_yara\\ngram\\database\\2gram\\database.pkl"
gram3_database = "I:\\Project\\auto_yara\\ngram\\database\\3gram\\database.pkl"
gram4_database = "I:\\Project\\auto_yara\\ngram\\database\\4gram\\database.pkl"

gram_filename = [gram1_database, gram2_database, gram3_database, gram4_database]
gram_data =     [None for i in range(len(gram_filename))]
gram_database = [None for i in range(len(gram_filename))]
gram_max = len(gram_data)-1

result_file = "I:\\Project\\auto_yara\\GetStat\\final_data\\20221028\\artificial.pkl"
slice_length = 4

use_zero_padding = True

# for logging
log_name = ""
log_index = -1


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
# 这里传入的ori_insn_index参数用来指示原bytes_rule中每条指令的长度。
# 这边目前的处理是这样的，只考虑mismatch和原指令有相同后缀串的情况，因为后缀串不同计算n-gram似乎有问题（意义不明）
# 因为存在大量n-gram数据集没有覆盖的情况，因此需要在这一步找到相同的后缀（注意，这里是n-gram，因此相同的后缀需要有(n-1)条对齐的指令）
# 使用ori_insn_index参数实现。此后在计算概率时就可以不考虑
def DisasmMismatch(cs, mismatch_lst, bytes_rule, ori_insn_index, length_first=0, restrict_one_insn=False):
    mismatch_insn_lst = []
    i = 0
    for mismatch_bytes, mismatch_index in mismatch_lst:
        i += 1
        new_bytes = mismatch_bytes + bytes_rule[mismatch_index:]

        # 注意，这里的mismatch_index表示的意思是，当前传入的mismatch元素会占用bytes_rule的几个字节
        # 目前一共三种mismatch形式
        #   opcode mismatch 表示当前bytes_rule的第一字节是某条指令的opcode
        #   modrm mismatch  表示当前bytes_rule的第一字节是某条指令的modrm字段
        #   sib mismatch    表示当前bytes_rule的第一字节是某条指令的sib字段
        # 后两种情况，由于modrm和sib都固定占用一个字节，所以mismatch_index为0
        # 第一种情况，由于opcode长度不固定，当前bytes_rule的第一字节可能是opcode的某一字节，因此不一定为0
        # 举个例子
        # bytes_rule第一字节为60，opcode mismatch的一个元素为66 60
        # 则传入的mismatch列表中60与bytes_rule中的第一个元素重复，所以mismatch_index为1
        length_tmp = length_first + len(mismatch_bytes) - mismatch_index
        decode_len = mismatch_index - len(mismatch_bytes)
        ori_bytes_len = len(new_bytes) + decode_len     # 这里需要跟decode_len的初始值对齐
        if use_zero_padding:
            new_bytes += b"\x00\x00\x00\x00\x00\x00\x00"
        total_length = len(new_bytes)
        try:
            decode = cs.disasm(new_bytes, 0)
        except Exception as e:
            continue
        first = True                    # the first insn length must greater than mismatch_index
        get_alignment = False
        n = slice_length-1
        insn_lst = []
        for insn in decode:
            if not get_alignment and decode_len in ori_insn_index:
                get_alignment = True
            if first:
                first = False
                if insn.size < mismatch_index:
                    global log_name
                    global log_index
                    # raise ValueError("%s first insn shorter than mismatch index %d" %(new_bytes.hex(), mismatch_index))
                    print("%s first insn shorter than mismatch index %d  PackYara: %s  Rule: %d" %(new_bytes.hex(), mismatch_index, log_name, log_index))
                    break
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
            elif not get_alignment:
                decode_len += insn.size
                insn_lst.append(insn)
            elif n > 0:
                decode_len += insn.size
                insn_lst.append(insn)
                n -= 1
            else:
                break
            if decode_len >= ori_bytes_len:
                break
        if get_alignment:
            mismatch_insn_lst.append( (insn_lst, mismatch_index - len(mismatch_bytes), decode_len) )
        elif decode_len > ori_bytes_len:
            logger.debug("Fully Mismatch %s" %new_bytes[:decode_len].hex())
        # if decode_len >= ori_bytes_len:
        #     if len(insn_lst):
        #         mismatch_insn_lst.append( (insn_lst, len(mismatch_bytes), decode_len) )
    return mismatch_insn_lst

# Port from AutoYara_ngram
def HashInsn(slice):
    ret = b""
    index = []
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

        index.append(len(ret))
        # for debug
        # slice_bytes += insn.bytes
    # return ret, slice_bytes
    return ret, index


def CvtBytesRule(bytes_rule_raw):
    if not '?' in bytes_rule_raw:
        bytes_rule_raw = bytes_rule_raw.replace(' ', '')
        bytes_rule = binascii.a2b_hex(bytes_rule_raw)
    else:           # now we just fill them with \x00
        bytes_rule_raw = bytes_rule_raw.replace('?', '0')
        bytes_rule_raw = bytes_rule_raw.replace(' ', '')
        bytes_rule = binascii.a2b_hex(bytes_rule_raw)
    return bytes_rule

def GetProbability(my_lst, n=0, smooth=True, smooth_gram=2, detail=True):
    if detail:
        lst = []
    else:
        lst = None
    insn_lst = my_lst[0]
    mismatch = my_lst[1]
    mydecode_len = my_lst[2]

    insn_len = len(insn_lst)
    if n == 0:
        if insn_len <= slice_length:
            n = insn_len
        else:
            n = slice_length
    tmp_data = gram_data[n-1]
    tmp_database = gram_database[n-1]

    i = 0
    for i in range(insn_len-n+1):
        insn_hash, index = HashInsn(insn_lst[i:i+n])
        if insn_hash in tmp_data:
            num, total = tmp_data[insn_hash]
        elif smooth:            # n-gram laplace smoothing
            num = 1
            flag = False
            low = -1 if (smooth_gram-2 < -1) else smooth_gram-2
            for j in range(n-2, low, -1):
                new_hash = insn_hash[:index[j]]
                if new_hash in tmp_database["every_total"][j]:
                    total = tmp_database["every_total"][j][new_hash] + tmp_database["total"]
                    flag = True
                    break
            if not flag:
                if low > -1:
                    num = 0
                    total = 1
                else:
                    total = tmp_database["total"]
            # add to hash for speeding
            tmp_data[insn_hash] = (num, total)
        else:
            num = 0
            total = 1

        if num == 0:
            break
        if detail:
            lst.append( (num, total) )
    return n, lst, mydecode_len

# === for debug ===
def PrintInsn(insn_lst):
    for insn in insn_lst:
        logger.debug("%s:  %s %s" %(insn.bytes.hex(), insn.mnemonic, insn.op_str))

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

    with open(yara_file) as f:
        lines = f.readlines()

    packyara_lst = []
    reader = YaraReader.YaraReader(lines)
    for name, lines in reader:
        packyara = YaraReader.PackerYara(name, lines)
        if not packyara.no_test:
            packyara_lst.append(packyara)

    a = 0
    # test opcode mismatch
    # test_bytes = b"\x00\x00\x00\x00\x00"

    index = 0
    for path in gram_filename:
        with open(path, "rb") as f:
            tmp_database = pickle.load(f)
        gram_data[index] = tmp_database["data"]
        gram_database[index] = tmp_database
        index += 1


    result = {}
    for packyara in packyara_lst:
        logger.info("\n\n\n==== Processing %s ====" %packyara.name)
        log_name = packyara.name
        result[packyara.name] = []
        group_index = -1
        for group_name in packyara.rule_groups:
            logger.info("\n\n=== RuleGroup %s ===" %group_name)
            rule_group = packyara.rule_groups[group_name]
            rule_index = -1
            group_index += 1
            for bytes_rule_raw in rule_group.rules:
                bytes_rule = CvtBytesRule(bytes_rule_raw)
                ori_bytes_len = len(bytes_rule)
                rule_index += 1
                log_index = rule_index
                mismatch_lst = []
                opcode_mismatch_lst = GenOpcodeMismatch(bytes_rule, search_trees)
                # mismatch_lst_check = CheckOpcodeMismatch(test_bytes, gens)
                modrm_mismatch_lst = GenModrmMismatch(bytes_rule, modrm_bind)
                mismatch_lst.extend(opcode_mismatch_lst)
                mismatch_lst.extend(modrm_mismatch_lst)
                mismatch_lst.extend(sib_mismatch_lst)

                ori_bytes_rule = bytes_rule
                if use_zero_padding:
                    bytes_rule += b"\x00\x00\x00\x00\x00\x00\x00"   # duplicated: we pad 6 bytes for fixing the last jump opcode
                                                                    # don't do this because we don't know the operand of these jmp
                ori_insn = []
                ori_insn_index = []
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
                    ori_insn_index.append(decode_len)
                    if decode_len >= ori_bytes_len:
                        break

                mismatch_insn_lst = DisasmMismatch(cs, mismatch_lst, ori_bytes_rule, ori_insn_index)
                # if decode_len != len(bytes_rule):         # now the last byte of rule is an opcode of a jump/call/ret instruction
                #     # raise ValueError("Someting Wrong With Bytes %s? Disasm Failed" %(bytes_rule.hex()))
                #     print("Someting Wrong With Bytes %s? Disasm Failed!  PackYara: %s  Rule: %d" %(bytes_rule.hex(), packyara.name, rule_index))
                #     continue
                flag = False
                total_insn = 0
                ori_insn_num = 0
                probability = 0.0

                # n, ori_num, ori_total, ori_lst = GetProbability( (ori_insn, 0, decode_len), smooth_gram=1 )
                n, ori_lst, mydecode_len = GetProbability( (ori_insn, 0, decode_len), smooth_gram=1, smooth=False )
                if len(ori_lst) == 0:
                    probability_deno = Fraction(1, 1)
                    probability_mole = Fraction(0, 1)
                else:
                    # pre-calculated
                    ori_probability_lst = []
                    tmp = Fraction(1, 1)
                    for num, total in ori_lst:
                        tmp = tmp * Fraction(num, total)
                        ori_probability_lst.append(tmp)

                    probability_deno = Fraction(1, 1)       # 分母
                    probability_mole = Fraction(0, 1)       # 分子

                    max_probability = probability_mole / probability_deno

                    mismatch_insn_index = 0
                    for mismatch_insns in mismatch_insn_lst:
                        needed_len = len(mismatch_insns[0]) - n + 1
                        a, lst, mydecode_len = GetProbability(mismatch_insns, n=n, smooth_gram=1, smooth=False)
                        # a, num, total, lst = GetProbability(mismatch_insns, n, decode_len, smooth=False)
                        if len(lst) == needed_len:
                            # for debug
                            if len(lst) > 1:
                                a = 0
                            ori_probability_index = ori_insn_index.index(mydecode_len)
                            ori_probability_index -= n-1
                            if ori_probability_index >= len(ori_probability_lst):
                                a = 0
                                logger.debug("lst larger than ori_lst")
                                logger.debug("ori_lst: %s" %ori_lst)
                                logger.debug("lst    : %s" %lst)
                                logger.debug("ori_insn:")
                                PrintInsn(ori_insn)
                                logger.debug("insn:")
                                PrintInsn(mismatch_insns[0])
                            else:
                                ori_probability = ori_probability_lst[ori_probability_index]
                                tmp = Fraction(1, 1)
                                for num, total in lst:
                                    tmp = tmp * Fraction(num, total)
                                sum_tmp = tmp + ori_probability
                                if ( tmp / sum_tmp ) > max_probability:
                                    probability_deno = sum_tmp
                                    probability_mole = tmp
                                    max_probability = tmp / sum_tmp
                        else:
                            a = 0
                        mismatch_insn_index += 1
                    a = 0
                result[packyara.name].append( (group_index, rule_index, probability_deno, probability_mole) )
                logger.info( "%s  %s" %(probability_deno, probability_mole) )
                logger.info( "%s  %f" %(probability_mole/probability_deno, float(probability_mole/probability_deno)) )

                # === for debug ===

                # if ori_insn_hash in tmp_data:
                #     ori_insn_num = tmp_data[ori_insn_hash]
                #     total_insn += ori_insn_num
                #     probability = ori_insn_num / total_insn
                #     result[packyara.name].append( (rule_index, total_insn, ori_insn_num, probability) )
                #     flag = True
                # else:
                #     result[packyara.name].append( (rule_index, total_insn, ori_insn_num, probability) )
                #     print("Rule %s_%d:\t  %s  Not In Database  HASH:%s  rule_insn_length: %d" %(group_name, rule_index, bytes_rule[:ori_bytes_len], ori_insn_hash.hex(), len(ori_insn)))
                # tmp_data = None
                # if flag:
                #     print("Rule %s_%d:\t\ttotal_insn: %d  ori_insn_num: %d  rule_insn_length: %d  probability: %f" %(group_name, rule_index, total_insn, ori_insn_num, len(ori_insn), probability))
            with open(result_file, "wb") as f:                      # save every packer to prevent accident
                pickle.dump(result, f)
    a = 0

# TODO:  hash中使用了MODRM的reg，但没有区分哪条指令是确实使用reg来作为opcode的，这可能使得某些指令操作的寄存器不同就被当做不同指令
# TODO:  predict 过程中似乎缺失了一些情况，比如opcode比bytes长，所以完全覆盖bytes的情况