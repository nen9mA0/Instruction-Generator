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
from ngram_slice import *
import YaraReader

import capstone
import copy
import binascii
import math
from fractions import Fraction
import decimal

import pickle
import copy
import os


# debug = True
debug = False

# 断点续执行功能，继续执行前别忘了把log保存
break_continue_flag = True

# yara_file = "I:\\Project\\auto_yara\\GetStat\\yara_rules\\20221028\\test.yar"
# yara_file = "I:\\Project\\auto_yara\\GetStat\\yara_rules\\20221028\\autoyara.yar"
yara_file = "I:\\Project\\auto_yara\\GetStat\\yara_rules\\20221028\\artificial.yar"

gram1_database = "I:\\Project\\auto_yara\\ngram\\database\\database\\1gram_database.pkl"
gram2_database = "I:\\Project\\auto_yara\\ngram\\database\\database\\2gram_database.pkl"
gram3_database = "I:\\Project\\auto_yara\\ngram\\database\\database\\3gram_database.pkl"
gram4_database = "I:\\Project\\auto_yara\\ngram\\database\\database\\4gram_database.pkl"

gram_filename = [gram1_database, gram2_database, gram3_database, gram4_database]
gram_data =     [None for i in range(len(gram_filename))]
gram_database = [None for i in range(len(gram_filename))]
gram_max = len(gram_data)-1

result_file = "I:\\Project\\auto_yara\\GetStat\\data\\20230115\\artificial.pkl"
# result_file = "I:\\Project\\auto_yara\\GetStat\\data\\20230115\\autoyara.pkl"
slice_length = 4

use_zero_padding = True
padding_len = 8

max_wildcard = 1

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

# [duplicate, 是有意义的]
# ~~这边目前的处理是这样的，只考虑mismatch和原指令有相同后缀串的情况，因为后缀串不同计算n-gram似乎有问题（意义不明）~~
# ~~因为存在大量n-gram数据集没有覆盖的情况，因此需要在这一步找到相同的后缀（注意，这里是n-gram，因此相同的后缀需要有(n-1)条对齐的指令）~~
# ~~使用ori_insn_index参数实现。此后在计算概率时就可以不考虑~~
def DisasmMismatch(cs, mismatch_lst, bytes_rule, ori_insn_index, padding, length_first=0, restrict_one_insn=False, restrict_alignment=False):
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
        # length_tmp = length_first + len(mismatch_bytes) - mismatch_index
        decode_len = mismatch_index - len(mismatch_bytes)
        ori_bytes_len = len(new_bytes) + decode_len     # 这里需要跟decode_len的初始值对齐
        new_bytes += padding
        # total_length = len(new_bytes)
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
                    if decode_len >= ori_bytes_len:
                        insn_lst.append(insn)
                    else:
                        break
                # === if we don't use this restrict ===
                else:
                    insn_lst.append(insn)
            else:
                # 若为True，表示目前的模式是强制对齐的模式，若mismatch的结果与原rule在末尾没有对齐的指令则直接跳过
                if restrict_alignment:
                    if not get_alignment:
                        decode_len += insn.size
                        insn_lst.append(insn)
                    elif n > 0:
                        # 当找到第一个对齐指令，之后还需要往下找n-1个指令，n为ngram的长度
                        decode_len += insn.size
                        insn_lst.append(insn)
                        n -= 1
                    else:
                        break
                else:
                    decode_len += insn.size
                    insn_lst.append(insn)
            if decode_len >= ori_bytes_len:
                break
        if restrict_alignment:
            if get_alignment:
                mismatch_insn_lst.append( (insn_lst, len(mismatch_bytes)-mismatch_index, decode_len) )
            elif decode_len > ori_bytes_len:
                pass
        else:
            if decode_len >= ori_bytes_len:
                if len(insn_lst):
                    mismatch_insn_lst.append( (insn_lst, len(mismatch_bytes)-mismatch_index, decode_len-ori_bytes_len) )

            # logger.debug("Fully Mismatch %s" %new_bytes[:decode_len].hex())
        # if decode_len >= ori_bytes_len:
        #     if len(insn_lst):
        #         mismatch_insn_lst.append( (insn_lst, len(mismatch_bytes), decode_len) )
    return mismatch_insn_lst

# 将bytes_rule转换为二进制形式，并且对wildcard进行展开
# TODO: 目前对于处理多段wildcard的情况会产生非常大的计算量，因为每条子规则都会产生500条左右的mismatch，因此一段wildcard理论上就需要500*500的计算量，n段需要500^n（实际上在FilterMismatchInsn中进行了部分剪枝）
#       因此目前对算法进行进一步的优化，具体的优化方法是限制wildcard段数，由全局变量max_wildcard确定（默认为2），若当前的wildcard段数超出max_wildcard，则会根据下列规则进行优化
#       * 将rule近似处理成与max_wildcard段数相同的规则，主要遵循下列假设
#         * 两个子规则串的距离越远，最终计算得到的概率越趋近于P1 * P2，因此优先在wildcard段落中寻找wildcard较长的情况进行切分
#         * 若多段wildcard长度相等，则根据尽量保留每段bytes_rule最长的原则进行切分
#       进行上述操作直至切分后的每条规则满足max_wildcard限制
#       切分后的多条rule加入rule_group，并标记bytes_rule_type，之后计算时将连续被标记的rule概率相乘
def DivideSubBytesRule(bytes_rule_lst_gap, bytes_rule_lst, bytes_rule_gap):
    if len(bytes_rule_gap) > max_wildcard:
        tmp_index = []
        len_index = 0
        max_gap = 0
        for i in range(len(bytes_rule_gap)):
            len_index += len(bytes_rule_lst[i])
            tmp_index.append(len_index)
            gap = bytes_rule_gap[i]
            len_index += gap
            if gap > max_gap:
                max_gap = gap
            tmp_index.append(len_index)
        len_index += len(bytes_rule_lst[-1])
        tmp_index.append(len_index)

        # 获取距离中心最小的最长wildcard
        gap_index = [i for i,j in enumerate(bytes_rule_gap) if j==max_gap]
        new_bytes_rule_len_avg = (len_index - max_gap) / 2
        min_distance = len_index
        min_index = -1
        for i in gap_index:
            distance = abs(new_bytes_rule_len_avg - tmp_index[i*2+1])
            if distance < min_distance:
                min_distance = distance
                min_index = i
        DivideSubBytesRule(bytes_rule_lst_gap, bytes_rule_lst[:min_index+1], bytes_rule_gap[:min_index])
        DivideSubBytesRule(bytes_rule_lst_gap, bytes_rule_lst[min_index+1:], bytes_rule_gap[min_index+1:])
    else:
        bytes_rule_lst_gap.append( (bytes_rule_lst, bytes_rule_gap) )

def CvtBytesRule(bytes_rule_raw):
    bytes_rule_lst_gap = []
    if not '[' in bytes_rule_raw:
        bytes_rule_raw = bytes_rule_raw.replace(' ', '')
        bytes_rule = binascii.a2b_hex(bytes_rule_raw)
        bytes_rule_lst_gap.append( ([bytes_rule], []) )
    else:
        i = 0
        end = 0
        bytes_rule_lst = []
        bytes_rule_gap = []
        while i < len(bytes_rule_raw):
            if bytes_rule_raw[i] == '[':
                begin = i
                while bytes_rule_raw[i] != ']':
                    i += 1
                bytes_rule_tmp = bytes_rule_raw[end:begin]
                end = i+1
                gap_num = int(bytes_rule_raw[begin+1:end-1])
                bytes_rule_tmp = bytes_rule_tmp.replace(' ', '')
                bytes_rule = binascii.a2b_hex(bytes_rule_tmp)
                if len(bytes_rule):
                    bytes_rule_lst.append(bytes_rule)
                    bytes_rule_gap.append(gap_num)
            else:
                i += 1
        bytes_rule_tmp = bytes_rule_raw[end:i]
        bytes_rule_tmp = bytes_rule_tmp.replace(' ', '')
        bytes_rule = binascii.a2b_hex(bytes_rule_tmp)
        bytes_rule_lst.append(bytes_rule)

        # max_wildcard处理
        DivideSubBytesRule(bytes_rule_lst_gap, bytes_rule_lst, bytes_rule_gap)
    return bytes_rule_lst_gap

def ProbabilitySmooth(insn_lst, tmp_database):
    pass

# [20230115 Duplicate]
# 20221107: 因为最后计算的是指令序列在整个程序空间出现的概率，因此不需要参数n
# 之前引入参数n是因为原来的算法需要将预测反汇编得到的序列概率与原bytes_rule进行比较，为了结果的准确性因此统一使用bytes_rule使用的n-gram参数n
# def GetProbability(my_lst, n=0, smooth=True, smooth_gram=2):
#     lst = []

#     insn_lst = my_lst[0]
#     mismatch = my_lst[1]
#     mydecode_len = my_lst[2]

#     insn_len = len(insn_lst)
#     if n == 0:
#         if insn_len <= slice_length:
#             n = insn_len
#         else:
#             n = slice_length
#     tmp_data = gram_data[n-1]
#     tmp_database = gram_database[n-1]

#     # prior probability
#     insn_hash, index = HashInsn(insn_lst[:n-1])
#     if insn_hash in tmp_database["every_total"][n-2]:
#         num = tmp_database["every_total"][n-2][insn_hash]
#         total = tmp_database["total"]
#     elif smooth:
#         pass
#     else:
#         num = 0
#         total = 1

#     lst.append( (num, total) )

#     i = 0
#     for i in range(insn_len-n+1):
#         insn_hash, index = HashInsn(insn_lst[i:i+n])
#         if insn_hash in tmp_data:
#             num, total = tmp_data[insn_hash]
#         elif smooth:            # n-gram laplace smoothing
#             num = 1
#             flag = False
#             low = -1 if (smooth_gram-2 < -1) else smooth_gram-2
#             for j in range(n-2, low, -1):
#                 new_hash = insn_hash[:index[j]]
#                 if new_hash in tmp_database["every_total"][j]:
#                     total = tmp_database["every_total"][j][new_hash] + tmp_database["total"]
#                     flag = True
#                     break
#             if not flag:
#                 if low > -1:
#                     num = 0
#                     total = 1
#                 else:
#                     total = tmp_database["total"]
#             # add to hash for speeding
#             tmp_data[insn_hash] = (num, total)
#         else:
#             num = 0
#             total = 1

#         if num == 0:
#             break
#         lst.append( (num, total) )
#     return n, lst, mydecode_len

# 新的概率计算，不使用smooth，但会对每个slice都求4种gram
def GetProbability(my_lst):
    lst = []
    insn_hash_lst = []      # 这里主要是给下面的ProbabilityAmend函数用，既然算过一遍就不再算了省点时间吧

    insn_lst = my_lst[0]
    mismatch = my_lst[1]
    mydecode_len = my_lst[2]

    insn_len = len(insn_lst)
    for i in range(1, slice_length+1):
        lst.append([])
        if insn_len < i:
            # 如果当前指令长度小于gram数，直接返回None
            lst[i-1] = None
        else:
            n = i

            tmp_data = gram_data[n-1]
            tmp_database = gram_database[n-1]

            # prior probability
            if n > 1:
                insn_hash, index = HashInsn(insn_lst[:n-1])
                if insn_hash in tmp_database["every_total"][n-2]:
                    num = tmp_database["every_total"][n-2][insn_hash]
                    total = tmp_database["total"]
                else:
                    num = 0
                    total = 1
                lst[i-1].append( (num, total) )
                i = 0
            else:
                # for 1-gram, which has no prior
                i = 0

            for j in range(insn_len-n+1):
                insn_hash, index = HashInsn(insn_lst[j:j+n])
                if n == 1:
                    insn_hash_lst.append(insn_hash)
                if insn_hash in tmp_data:
                    num, total = tmp_data[insn_hash]
                else:
                    num = 0
                    total = 1

                # if num == 0:
                #     break
                lst[i-1].append( (num, total) )
    return lst, insn_hash_lst

# 概率修正算法
# TODO
# 发现一个比较难办的情况：用capstone解析operand，有一些情况下操作数是固定的，如
# a0 00 00 00 00          mov    al,ds:0x0
# 这里al是固定的操作数，但operand中仍然会出现
# 所以若直接以operand参数作为修正的依据，会出现误修正的情况，如这里目标操作数只可能是AL，但仍会按照寄存器修正方法乘上1/8
# 目前看了几个编码类型，发现好像一般这种有固定操作数的情况不会使用modrm？(包括像mov cr0, eax这种指令)
# 所以目前采用的处理方式是：先根据capstone提供的disp_size和imm_size将最重要的立即数类型修正好，剩下的字节数减去opcode和prefix长度
# 剩下的字节就只可能是modrm或者sib，若存在modrm或sib则认为内存和寄存器操作数的编码是正常的，按照文档里的方法修正
def ProbabilityAmend(insn_tuple, insn_hash_lst, wildcard_pos_lst):
    insn_lst = insn_tuple[0]
    begin_mismatch = insn_tuple[1]
    end_mismatch = insn_tuple[2]

    amend_lst = []
    i = 0
    pos = -begin_mismatch
    for insn in insn_lst:
        amend_lst.append([])
        insn_hash = insn_hash_lst[i]

        opfix_size = insn_hash[0] & 0x7
        prefix_group = insn_hash[1] >> 4
        prefix_size = 0
        for j in range(4):
            if prefix_group & 1:
                prefix_size += 1
            prefix_group = prefix_group >> 1
        opcode_size = opfix_size - prefix_size

        pos += insn.size        # pos先指向指令末尾
        end = pos
        # handle srm operand
        opcode = insn_hash[2+prefix_size:2+opfix_size]
        if opcode in opcode_cvt_dict:
            # for srm operand insn, only has 8 cases of reg operand
            amend_lst[i].append(8)
        else:
            # 注意，这里需要根据wildcard对概率进行修正
            # handle imm
            imm_size = insn.imm_size
            if imm_size:
                adjust_size = imm_size
                pos -= imm_size             # pos指向imm开头
                imm_pos = [pos+p for p in range(imm_size)] # imm所在的字节位置
                for wildcard_pos in wildcard_pos_lst:
                    if wildcard_pos in imm_pos:             # 若wildcard在imm对应的字节
                        adjust_size -= 1
                amend_lst[i].append( 2**(adjust_size*8) )
            # handle disp in mem
            disp_size = insn.disp_size
            if disp_size:
                adjust_size = disp_size
                pos -= disp_size            # pos指向disp开头
                disp_pos = [pos+p for p in range(disp_size)]
                for wildcard_pos in wildcard_pos_lst:
                    if wildcard_pos in disp_pos:
                        adjust_size -= 1
                amend_lst[i].append( 2**(adjust_size*8) )
            # if has modrm, remain_size must be 1, and if has sib, remain_size must be 2
            remain_size = insn.size - opfix_size - imm_size - disp_size
            if remain_size:
                if remain_size >= 1 and remain_size <= 2:
                    # has modrm, maybe has mem operand, or reg operand
                    if remain_size == 1:
                        modrm_pos = pos-1
                        sib_pos = -1        # no sib
                    else:
                        modrm_pos = pos-2
                        sib_pos = pos-1
                    modrm_is_wildcard = modrm_pos in wildcard_pos_lst
                    for operand in insn.operands:
                        if operand.type == capstone.x86.X86_OP_REG:
                            # reg
                            if not modrm_is_wildcard:
                                amend_lst[i].append(8)
                        elif operand.type == capstone.x86.X86_OP_MEM:
                            # mem
                            # for modrm encode
                            if not modrm_is_wildcard:
                                amend_lst[i].append(8)
                            # if has sib
                            if sib_pos>0 and not sib_pos in wildcard_pos_lst:
                                amend_lst[i].append(256)
                            if disp_size:
                                # modrm + sib + displacement
                                if not modrm_is_wildcard:
                                    amend_lst[i].append(3)    # MOD=00 01 10
                # 佛了，f30f102400 movss 解析不出f3这个前缀，所以这里的remain_size可能大于2
                # else:
                #     raise ValueError("Unexpected Instruction")
        pos = end
        i += 1
    return amend_lst

# log probability
# P = a/b * c/d => log(P) = log( (a*c)/(b*d) ) = log(a)+log(c)-log(b)-log(d)

# for speed up
log_num_dict = {}
def CalcLogProbability(probability_lst, amend_lst):
    # ====== convert to log probability ======
    cvt_probability_lst = []
    i = 0
    # 对于Prbability_lst，若某个项为None，说明当前的mismatch insns不存在对应的gram
    for ngram_probability_lst in probability_lst:
        if ngram_probability_lst:
            cvt_probability_lst.append([])
            for num, total in ngram_probability_lst:
                tmp_log_probability = decimal.Decimal(0.0)
                if num:
                    # for num
                    if num in log_num_dict:
                        tmp_num = log_num_dict[num]
                    else:
                        tmp_num = decimal.Decimal(num).ln()
                        log_num_dict[num] = tmp_num
                    tmp_log_probability += tmp_num
                    # for total
                    if total in log_num_dict:
                        tmp_num = log_num_dict[total]
                    else:
                        tmp_num = decimal.Decimal(total).ln()
                        log_num_dict[total] = tmp_num
                    tmp_log_probability -= tmp_num

                    # add to list
                    cvt_probability_lst[i].append(tmp_log_probability)
                else:
                    # 若存在分母为0的情况，则log为负无穷
                    cvt_probability_lst[i].append(decimal.Decimal("-inf"))
        else:
            cvt_probability_lst.append(None)
        i += 1

    cvt_amend_lst = []
    for insn_amend_lst in amend_lst:
        tmp_log_probability = decimal.Decimal(0.0)       # 默认修正概率为1（即不修正），对应log为0.0
        for amend in insn_amend_lst:
            if amend in log_num_dict:
                tmp_num = log_num_dict[amend]
            else:
                tmp_num = decimal.Decimal(amend).ln()
                log_num_dict[amend] = tmp_num
            tmp_log_probability -= tmp_num
        cvt_amend_lst.append(tmp_log_probability)

    # calculate probability
    # for every ngram
    log_probability_lst = []
    for n in range(len(cvt_probability_lst)):
        if cvt_probability_lst[n] != None:          # if not None
            log_probability = decimal.Decimal(0.0)
            flag = True
            # == calculate like ngram formula first ==
            for log_num in cvt_probability_lst[n]:
                log_probability += log_num
                if math.isinf(log_num):
                    flag = False
                    break
            # == then do amend ==
            if flag:
                if n == 0:
                    # for 1-gram, which has no prior
                    # we can simply multiply all numbers
                    for amend_log in cvt_amend_lst:
                        log_probability += amend_log
                else:
                    # for n-gram, n>1
                    # P(ABCDE) = P(ABC) * P(D|ABC) * P(E|BCD)
                    #          = P(ABC) * P(ABCD) / P(ABC) * P(BCDE) / P(BCD)
                    # so for n-gram
                    # P'(lst) = P(lst[:n-1]) * P'(lst[:n-1])  *  P(lst[:n]) * P'(lst[:n]) / P(lst[:n-1]) / P'(lst[:n-1])
                    # ============================

                    # for prior
                    for amend_log in cvt_amend_lst[:n]:
                        log_probability += amend_log
                    # for other probabilitys
                    for j in range(len(cvt_amend_lst)-n):
                        for amend_log in cvt_amend_lst[j:j+n+1]:
                            log_probability += amend_log
                        for amend_log in cvt_amend_lst[j:j+n]:
                            log_probability -= amend_log
            log_probability_lst.append(log_probability)
        else:
            log_probability_lst.append(None)
    if len(log_probability_lst) == 0:
        for i in range(len(probability_lst)):
            log_probability_lst.append(decimal.Decimal("-inf"))
    return log_probability_lst


def BytesRulePadding(bytes_rule_index, bytes_rule_lst, bytes_rule_gap):
    # 若当前bytes_rule含有wildcard，则根据wildcard的长度调整字节后的padding
    # 如 ff 74 24 [2] 8f 45 00
    # 原来第一段padding后应为
    # ff 74 24 00 00 00 00 00 00 00 00
    # 这里调整为
    # ff 74 24 00 00 8f 45 00 00 00 00
    # ========
    # TODO：    这里有个问题：部分被wildcard分割的bytes_rule可能只有一个字节，而我们padding默认为00 padding
    #           这会导致一个问题：假设单字节rule为 01
    #           opcode mismatch可能出现的结果是 0f 01，但此时因为padding固定为00，所以modrm必为00，但对于0f 01来说，modrm.reg也作为opcode编码
    #           这会导致opcode mismatch少了很多结果
    #           这个问题在rule大于1字节时并不明显，因为这种情况仅会出现在opcode mismatch时，而大于1字节时opcode mismatch的概率很低
    padding = b""
    gap_flag = False
    if bytes_rule_index < len(bytes_rule_gap):
        # 首先取当前bytes_rule后的一个gap，若该gap小于padding长度，说明需要对padding进行修正
        gap = bytes_rule_gap[bytes_rule_index]
        if gap < padding_len:
            gap_flag = True
            gap_index = bytes_rule_index
            paded_length = 0
            # 这里需要考虑padding横跨多个gap的情况
            while paded_length < padding_len:
                padding += gap * b"\x00"                 # === add to bytes_rule
                paded_length += gap
                bytes_rule_index += 1
                if bytes_rule_index < len(bytes_rule_lst):
                    new_bytes_rule_padding = bytes_rule_lst[bytes_rule_index][:padding_len-paded_length]
                    padding += new_bytes_rule_padding    # === add to bytes_rule
                    new_padding_len = len(new_bytes_rule_padding)
                    paded_length += new_padding_len
                    # 新的gap
                    gap_index += 1
                    if gap_index < len(bytes_rule_gap):
                        gap = bytes_rule_gap[gap_index]
                    else:
                        break
            if paded_length < padding_len:
                padding += b"\x00" * (padding_len-paded_length)
    if not gap_flag and use_zero_padding:
        padding += b"\x00"*padding_len               # duplicated: we pad 8 bytes for fixing the last jump opcode
                                                        # don't do this because we don't know the operand of these jmp
    return padding


def GetWildCardPosLst(bytes_rule_lst, bytes_rule_gap):
    wildcard_pos_lst = []
    pos = 0
    for i in range(len(bytes_rule_lst)):
        pos += len(bytes_rule_lst[i])
        if i >= len(bytes_rule_gap):
            break
        for j in range(bytes_rule_gap[i]):
            wildcard_pos_lst.append(pos)
            pos += 1
    return wildcard_pos_lst


def DfsWildcardProbability(bytes_rule_lst_log_probability, bytes_rule_gap, bytes_rule_probability, prev_end_mismatch, index, p):
    total_lst = [0] * slice_length
    total_mismatch_lst = [0] * slice_length
    if index < len(bytes_rule_lst_log_probability):
        j = 0
        for log_probability, begin_mismatch, end_mismatch in bytes_rule_lst_log_probability[index]:
            gap = bytes_rule_gap[index-1]
            if prev_end_mismatch + begin_mismatch <= gap:
                new_p = copy.deepcopy(p)
                for i in range(slice_length):
                    # 若log_probability[i]，说明当前的子规则串本身指令数小于i（因此没有对应的ngram），这里的处理是简单地把这种情况drop掉，即不计算整个串第i个ngram了
                    if new_p[i] != None and log_probability[i] != None:
                        new_p[i] += log_probability[i]
                    elif not log_probability[i]:
                        new_p[i] = None
                new_total_lst, new_total_mismatch_lst = DfsWildcardProbability(bytes_rule_lst_log_probability, bytes_rule_gap, bytes_rule_probability, end_mismatch, index+1, new_p)
                for i in range(slice_length):
                    total_lst[i] += new_total_lst[i]
                    total_mismatch_lst[i] += new_total_mismatch_lst[i]
            j += 1
        return total_lst, total_mismatch_lst
    else:
        for i in range(slice_length):
            # 如果p[i]为None，则直接忽略，对概率没有影响
            if p[i] != None:
                prob_tmp = p[i].exp()
                if prob_tmp:
                    bytes_rule_probability[i] += p[i].exp()
                    total_mismatch_lst[i] += 1
                total_lst[i] = 1
        return total_lst, total_mismatch_lst

def FilterMismatchInsn(bytes_rule_lst_log_probability, bytes_rule_gap):
    new_lst = []
    i = 0
    gap_len = len(bytes_rule_gap)
    for bytes_rule_log_probability in bytes_rule_lst_log_probability:
        new_lst.append([])
        for item in bytes_rule_log_probability:                 # prevent copy
            log_probability, begin_mismatch, end_mismatch = item
            # check end_mismatch
            # 第一个rule，只需要比较end_mismatch
            if i == 0 and end_mismatch <= bytes_rule_gap[i]:
                new_lst[i].append(item)
            # 最后一个rule，只需要比较begin_mismatch
            elif i == gap_len and begin_mismatch <= bytes_rule_gap[i-1]:
                new_lst[i].append(item)
            # 中间的，需要比较两边
            elif begin_mismatch <= bytes_rule_gap[i-1] and end_mismatch <= bytes_rule_gap[i]:
                new_lst[i].append(item)
        i += 1
    return new_lst


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
    if break_continue_flag:
        if os.path.exists(result_file):
            with open(result_file, "rb") as f:
                result = pickle.load(f)

    for packyara in packyara_lst:
        logger.info("==== Processing %s ====" %packyara.name)
        log_name = packyara.name
        group_index = -1

        # 有些规则因为都是string，解析不出来
        if len(packyara.rule_groups) == 0:
            logger.info("\tYara has no rule, run next")
            continue

        if break_continue_flag:
            if packyara.name in result:
                continue
        for group_name in packyara.rule_groups:
            logger.info("\t=== RuleGroup %s ===" %group_name)
            rule_group = packyara.rule_groups[group_name]
            rule_index = -1
            group_index += 1
            for bytes_rule_raw in rule_group.rules:
                logger.info("\tRule: %s" %bytes_rule_raw)
                bytes_rule_lst_gap = CvtBytesRule(bytes_rule_raw)

                # 对于wildcard段数大于max_wildcard的处理
                for bytes_rule_lst, bytes_rule_gap in bytes_rule_lst_gap:
                    # 多个wildcard切分的子规则串之间的概率是相乘的关系
                    bytes_rule_final_probability = [decimal.Decimal(1)] * slice_length

                    bytes_rule_lst_log_probability = []
                    # for debug
                    if debug:
                        all_insn_lst = []

                    for bytes_rule_index in range(len(bytes_rule_lst)):
                        bytes_rule = bytes_rule_lst[bytes_rule_index]
                        bytes_rule_log_probability = []
                        ori_bytes_len = len(bytes_rule)
                        rule_index += 1
                        log_index = rule_index
                        mismatch_lst = []
                        opcode_mismatch_lst = GenOpcodeMismatch(bytes_rule, search_trees)
                        # mismatch_lst_check = CheckOpcodeMismatch(test_bytes, gens)
                        modrm_mismatch_lst = GenModrmMismatch(bytes_rule, modrm_bind)
                        mismatch_lst.extend(opcode_mismatch_lst)
                        mismatch_lst.extend(modrm_mismatch_lst)
                        # mismatch_lst.extend(sib_mismatch_lst)

                        ori_bytes_rule = bytes_rule
                        padding = BytesRulePadding(bytes_rule_index, bytes_rule_lst, bytes_rule_gap)
                        bytes_rule += padding

                        wildcard_pos_lst = GetWildCardPosLst(bytes_rule_lst, bytes_rule_gap)

                        ori_insn = []
                        ori_insn_index = []
                        try:
                            decode = cs.disasm(bytes_rule, 0)
                        except Exception as e:
                            print(e)
                            print("Disasm Bytes %s Failed!  PackYara: %s  Rule: %d" %(bytes_rule.hex(), log_name, rule_index))
                            continue
                        ori_decode_len = 0
                        for insn in decode:
                            ori_insn.append(insn)
                            ori_decode_len += insn.size
                            ori_insn_index.append(ori_decode_len)
                            if ori_decode_len >= ori_bytes_len:
                                break

                        mismatch_insn_lst = DisasmMismatch(cs, mismatch_lst, ori_bytes_rule, ori_insn_index, padding)
                        # if decode_len != len(bytes_rule):         # now the last byte of rule is an opcode of a jump/call/ret instruction
                        #     # raise ValueError("Someting Wrong With Bytes %s? Disasm Failed" %(bytes_rule.hex()))
                        #     print("Someting Wrong With Bytes %s? Disasm Failed!  PackYara: %s  Rule: %d" %(bytes_rule.hex(), packyara.name, rule_index))
                        #     continue
                        flag = False
                        total_insn = 0
                        ori_insn_num = 0
                        probability = decimal.Decimal(0.0)

                        # =======
                        ori_insn_tuple = (ori_insn, 0, ori_decode_len-ori_bytes_len)
                        ori_lst, ori_insn_hash_lst = GetProbability( ori_insn_tuple )
                        ori_amend_lst = ProbabilityAmend(ori_insn_tuple, ori_insn_hash_lst, wildcard_pos_lst)
                        ori_log_probability = CalcLogProbability(ori_lst, ori_amend_lst)

                        bytes_rule_log_probability.append( (ori_log_probability, 0, ori_decode_len-ori_bytes_len) )

                        mismatch_insn_index = 0
                        for mismatch_insns in mismatch_insn_lst:
                            lst, insn_hash_lst = GetProbability(mismatch_insns)
                            amend_lst = ProbabilityAmend(mismatch_insns, insn_hash_lst, wildcard_pos_lst)
                            log_probability = CalcLogProbability(lst, amend_lst)
                            bytes_rule_log_probability.append( (log_probability, mismatch_insns[1], mismatch_insns[2]) )
                        bytes_rule_lst_log_probability.append(bytes_rule_log_probability)
                        # for debug
                        if debug:
                            all_insn_lst.append([ori_insn_tuple]+mismatch_insn_lst)

                    bytes_rule_probability = [decimal.Decimal(0)] * slice_length
                    total_lst = [0] * slice_length              # 统计各个gram一共有多少条mismatch被计算
                    total_mismatch_lst = [0] * slice_length     # 统计各个gram一共有多少条mismatch大于0
                    if len(bytes_rule_lst_log_probability) > 1:
                        # 对于存在wildcard的情况
                        # TODO: 文档中关于规则2的计算处理很繁琐（特别是如果考虑间隔多个wildcard的情况），后续再补充吧
                        # TODO: 文档中关于计算方法的近似，我一直认为可以找到一个只跟指令长度的概率有关的方法近似计算wildcard之间的内容，之后考虑
                        # 这里因为直接算的话，当rule串中存在多段wildcard时效率实在是太低，而且目前没有处理规则2，所以直接先将超出wildcard的mismatch全部过滤掉
                        bytes_rule_lst_log_probability = FilterMismatchInsn(bytes_rule_lst_log_probability, bytes_rule_gap)
                        i = 0
                        for log_probability, begin_mismatch, end_mismatch in bytes_rule_lst_log_probability[0]:
                            new_total_lst, new_total_mismatch_lst = DfsWildcardProbability(bytes_rule_lst_log_probability, bytes_rule_gap, bytes_rule_probability, end_mismatch, 1, copy.deepcopy(log_probability))
                            for i in range(slice_length):
                                total_lst[i] += new_total_lst[i]
                                total_mismatch_lst[i] += new_total_mismatch_lst[i]
                            i += 1
                    else:
                        # 这种情况下bytes_rule_lst_log_probability只有一个元素
                        for ngram_log_probability_lst in bytes_rule_lst_log_probability[0]:
                            for i in range(slice_length):
                                ngram_log_probability = ngram_log_probability_lst[0][i]
                                if ngram_log_probability != None:
                                    prob_tmp = ngram_log_probability.exp()
                                    if prob_tmp:            # if not zero
                                        bytes_rule_probability[i] += prob_tmp
                                        total_mismatch_lst[i] += 1
                                    else:
                                        a = 0
                                    total_lst[i] += 1
                    for i in range(slice_length):
                        bytes_rule_final_probability[i] *= bytes_rule_probability[i]
                rule_group.AddRuleProbability( (bytes_rule_final_probability, total_lst, total_mismatch_lst) )
            logger.info("\tProbability:")
            for i in range(slice_length):
                logger.info("\t\t%d-gram Probability:\t%35s  \tTotal Mismatch: %d  \tTotal Insn: %d" %(i+1, rule_group.probability[i], rule_group.total_mismatch_lst[i], rule_group.total_lst[i]))
            logger.info("")
            # 到这里，一条rule的概率被计算完成
            a = 0

        result[packyara.name] = packyara
        with open(result_file, "wb") as f:                      # save every packer to prevent accident
            pickle.dump(result, f)
        # 到这里， 一条Yara规则中的所有rule都计算完概率了，下一步需要根据Yara条件计算最终的mismatch概率
        packyara.CalcMismatch()
        logger.info("=Total Mismatch Probability:=")
        for i in range(slice_length):
            logger.info("\t%d-gram Probability:\t%35s" %(i+1, packyara.mismatch_probability[i]))
        logger.info("\n")
    a = 0

# Done:  hash中使用了MODRM的reg，但没有区分哪条指令是确实使用reg来作为opcode的，这可能使得某些指令操作的寄存器不同就被当做不同指令
# TODO:  predict 过程中似乎缺失了一些情况，比如opcode比bytes长，所以完全覆盖bytes的情况