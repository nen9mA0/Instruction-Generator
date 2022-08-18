from multiprocessing.sharedctypes import Value
import opcode
from global_init import *
import HashTable
import pickle
import copy


def GensSave(f, obj):
    pickle.dump(obj.reg_nt_bind, f)
    pickle.dump(obj.nt_reg_bind, f)
    pickle.dump(obj.nt_ins_bind, f)
    pickle.dump(obj.reg_ins_bind, f)
    pickle.dump(obj.all_iforms, f)
    pickle.dump(obj.MODRM_lst, f)
    pickle.dump(obj.IMM_lst, f)
    pickle.dump(obj.branch_ins, f)
    pickle.dump(obj.sub_NT, f)
    pickle.dump(obj.sub_NT_reverse, f)
    pickle.dump(obj.nt_iform_bind, f)
    pickle.dump(obj.iform_ptn_lst, f)
    pickle.dump(obj.ptn_dict, f)

def GensLoad(f, obj):
    obj.reg_nt_bind = pickle.load(f)
    obj.nt_reg_bind = pickle.load(f)
    obj.nt_ins_bind = pickle.load(f)
    obj.reg_ins_bind = pickle.load(f)
    obj.all_iforms = pickle.load(f)
    obj.MODRM_lst = pickle.load(f)
    obj.IMM_lst = pickle.load(f)
    obj.branch_ins = pickle.load(f)
    obj.sub_NT = pickle.load(f)
    obj.sub_NT_reverse = pickle.load(f)
    obj.nt_iform_bind = pickle.load(f)
    obj.iform_ptn_lst = pickle.load(f)
    obj.ptn_dict = pickle.load(f)

class GeneratorStorage(object):
    emit_letter = ("mod", "reg", "rm")
    emit_letter_bits = (2, 3, 3)
    def __init__(self, load=False):
        self.nts = gs.nts
        self.ntlufs = gs.ntlufs
        self.seqs = gs.seqs
        self.reg_names = gs.reg_names
        self.iarray = gs.iarray
        self.reg_nt_bind = {}
        self.nt_reg_bind = {}
        self.nt_ins_bind = ({}, {})         # 0 for input  1 for output
        self.reg_ins_bind = ({}, {})        # for the iforms that directly specify the register
        self.seq_nt_bind = {}
        self.all_iforms = []
        self.MODRM_lst = ([], [])
        self.IMM_lst = ([], [])
        self.branch_ins = []
        self.sub_NT = {}                    # record the NT that calls other NTs
        self.sub_NT_reverse = {}
        self.nt_iform_bind = {}
        self.iform_ptn_lst = []
        self.ptn_dict = {}
        self.htm = None

        if not load:
            self.MakeAllIforms()
            self.MakeSubNTLst()
            self.MakeRegNTlufLst()
            self.MakeInsNTLst()
            self.MakeOpcodeLst()
            # self.MakeMODRMLst()           # duplicated

    def AddHashTableManager(self, htm):
        self.htm = htm
        return htm

    # make binding of register name --> nonterminal which has action `OUTREG=reg_name`
    # A register may mentioned by several nonterminal, also a nonterminal may mention different registers
    # So we create both binding reg_nt_bind and nt_reg_bind 
    def MakeRegNTlufLst(self):
        for ntluf_name in gs.ntlufs:
            ntluf = gs.ntlufs[ntluf_name]
            for rule in ntluf.rules:
                for cond in rule.conditions.and_conditions:
                    if cond.field_name == "OUTREG":
                        reg_name = cond.rvalue.value
                        if reg_name in self.reg_names:
                            if reg_name in self.reg_nt_bind:
                                self.reg_nt_bind[reg_name].add(ntluf_name)
                            else:
                                self.reg_nt_bind[reg_name] = set()
                                self.reg_nt_bind[reg_name].add(ntluf_name)

                            if ntluf_name in self.nt_reg_bind:
                                self.nt_reg_bind[ntluf_name].add(reg_name)
                            else:
                                self.nt_reg_bind[ntluf_name] = set()
                                self.nt_reg_bind[ntluf_name].add(reg_name)

                            if ntluf_name in self.sub_NT_reverse:
                                nt_lst = self.sub_NT_reverse[ntluf_name]
                                nt_set = set(nt_lst)
                                self.reg_nt_bind[reg_name] = self.reg_nt_bind[reg_name] | nt_set
                                for nt_name in nt_lst:
                                    if nt_name in self.nt_reg_bind:
                                        self.nt_reg_bind[nt_name].add(reg_name)
                                    else:
                                        self.nt_reg_bind[nt_name] = set()
                                        self.nt_reg_bind[nt_name].add(reg_name)

    # Create binding between instruction and nonterminal or register
    # Here we distinguish input operand from output operand
    # nt_ins_bind binds nonterminal with instruction
    # Sometimes operand is not a nonterminal, if it's a register, we store it in reg_ins_bind
    def MakeInsNTLst(self):
        for iclass in gs.iarray:
            for iform in gs.iarray[iclass]:
                mem_flag = True             # if a iform have 2 mem or imm input operand, it will be appended only one time
                imm_flag = True
                for (var, nt, value) in iform.input_op:
                    if nt:
                        if value in self.nt_ins_bind[0]:
                            self.nt_ins_bind[0][value].append(iform)
                        else:
                            self.nt_ins_bind[0][value] = [iform]
                    elif value in self.reg_names:
                        if value in self.reg_ins_bind[0]:
                            self.reg_ins_bind[0][value].append(iform)
                        else:
                            self.reg_ins_bind[0][value] = [iform]
                    elif "MEM" in var:
                        if mem_flag:
                            mem_flag = False
                            self.MODRM_lst[0].append(iform)
                    elif "IMM" in var:
                        if imm_flag:
                            imm_flag = False
                            self.IMM_lst[0].append(iform)
                    elif "RELBR" in var:
                        self.branch_ins.append(iform)
                    else:                   # else: PTR: jmp_far call_far
                                            #       AGEN: lea bndmk bndcl bndcu bndcn
                                            #       SCALE: xlat
                        a = 0
                        pass
                        # logger.error("MakeInsNTLst: cannot handle input operand %s %s" %(var, value))
                mem_flag = True
                imm_flag = True
                for (var, nt, value) in iform.output_op:
                    if nt:
                        if value in self.nt_ins_bind[1]:
                            self.nt_ins_bind[1][value].append(iform)
                        else:
                            self.nt_ins_bind[1][value] = [iform]
                    elif value in self.reg_names:
                        if value in self.reg_ins_bind[1]:
                            self.reg_ins_bind[1][value].append(iform)
                        else:
                            self.reg_ins_bind[1][value] = [iform]
                    elif "MEM" in var:
                        if mem_flag:
                            mem_flag = False
                            self.MODRM_lst[1].append(iform)
                    elif "IMM" in var:
                        if imm_flag:
                            imm_flag = False
                            self.IMM_lst[1].append(iform)
                    else:
                        pass
                        # logger.error("MakeInsNTLst: cannot handle output operand %s %s" %(var, nt))

    # copy from dfs_generator.py
    def EmitNum(self, tmp_num, shift_num, int_value, nbits, ins_hex):
        # in this case, we meet an imm and should convert it to little endian format
        if nbits%8 == 0 and nbits // 8 in (2,4,8,16,32):        # But I think only 2 4 8 is available
            new_num = 0
            old_num = int_value
            shift_bit = 0
            while shift_bit < nbits:
                new_num = new_num << 8
                new_num |= old_num & 0xff
                old_num = old_num >> 8
                shift_bit += 8
            int_value = new_num

        tmp_num = tmp_num << nbits
        act_value_mask = (1 << nbits) - 1
        tmp_num |= (int_value & act_value_mask)    # TODO: Emit Immediate
        shift_num += nbits
        while shift_num >= 8:
            shift_tmp = shift_num - 8
            mask = 0xff << shift_tmp
            shift_num -= 8
            ins_hex.append( (tmp_num & mask) >> shift_tmp )
            tmp_num = tmp_num & (~mask)
        return tmp_num, shift_num


    #          _ opcode_bytes1            _ 0 --> iform_ptn
    #         |                  _ mod __|_ 1
    # opcode -|_ opcode_bytes2 _|_ reg   |_ 2
    #         |                 |_ rm
    #         |                  
    #         |_ opcode_bytes3 __ ptn -> iform_ptn

    def BuildOpcodeDict(self, opcode_bytes, iform_ptn):
        opcode_dict = {}

        opcode_dict[opcode_bytes] = {}
        flag = 0
        lst_emit = []
        for letter in iform_ptn:
            if letter in self.emit_letter:
                if type(iform_ptn[letter]) == list:
                    flag += 1
                    lst_emit.append(letter)
        if flag == 1:
            letter = lst_emit[0]
            for item in iform_ptn[letter]:
                new_iform_ptn = copy.deepcopy(iform_ptn)
                new_iform_ptn[letter] = item
                emit_letter_hash = self.HashEmitLetter(new_iform_ptn)
                opcode_dict[opcode_bytes][emit_letter_hash] = new_iform_ptn
        elif flag == 0:
            emit_letter_hash = self.HashEmitLetter(iform_ptn)
            opcode_dict[opcode_bytes][emit_letter_hash] = iform_ptn
        else:
            raise ValueError("Now Only Support One list emit_letter")

        return opcode_dict

    def HashEmitLetter(self, iform_ptn):
        hash_str = ""
        i = 0
        flag = False            # if iform has one emit letter, now it ought to be has all
        for letter in self.emit_letter:
            if letter in iform_ptn:
                flag = True
                if type(iform_ptn[letter][0]) != str:
                    value = iform_ptn[letter][0]
                    format_str = "{0:0" + "%d"%self.emit_letter_bits[i] + "b}"
                    hash_str += format_str.format(value)
                else:
                    hash_str += "_"*self.emit_letter_bits[i]
            else:
                if flag:
                    raise ValueError("Emit Letter Wrong: %s" %iform_ptn)
                else:
                    hash_str += " "*self.emit_letter_bits[i]
            i += 1
        return hash_str

    def PtnDictUpdate(self, a_dict, b_dict):
        for opcode_bytes in b_dict:
            if not opcode_bytes in a_dict:
                a_dict[opcode_bytes] = b_dict[opcode_bytes]
            else:
                for hash_letter in b_dict[opcode_bytes]:
                    if hash_letter in a_dict[opcode_bytes]:
                        # some iforms has the same modrmreg but different actions, eg. FLDENV
                        for iform in b_dict[opcode_bytes][hash_letter]["iform"]:
                            if iform in a_dict[opcode_bytes][hash_letter]["iform"]:
                                raise ValueError("Two Dict Has The Same iform")
                            else:
                                a_dict[opcode_bytes][hash_letter]["iform"].extend(b_dict[opcode_bytes][hash_letter]["iform"])
                    else:
                        a_dict[opcode_bytes][hash_letter] = b_dict[opcode_bytes][hash_letter]

    def Ptn2Opcode(self, iform_ptn):
        new_opcode_dict = {}

        opcode_lst = []
        need_expand = 0
        expand_size = []
        shift_num = 0
        value = 0
        for opcode in iform_ptn["opcode"]:
            if type(opcode[0]) == int:
                value, shift_num = self.EmitNum(value, shift_num, opcode[0], opcode[1], opcode_lst)
            elif type(opcode[0]) == str:
                need_expand += 1
                expand_size.append(opcode[1])
            else:
                raise ValueError("Unknown Opcode Type %s:%s" %(type(opcode[0]), opcode))
        if not need_expand:
            if shift_num % 8 != 0:
                raise ValueError("Emit Number Error:  shift_num=%d  value=%d  opcode_lst=%s" %(shift_num, value, opcode_lst))
            opcode_dict = self.BuildOpcodeDict(bytes(opcode_lst), iform_ptn)
            self.PtnDictUpdate(new_opcode_dict, opcode_dict)
        else:
            if need_expand > 1:
                raise ValueError("Now Cannot Handle This: need_expand > 1")
            else:
                for i in expand_size:
                    max_num = 1 << i
                    for num in range(max_num):
                        opcode_lst = []
                        shift_num = 0
                        value = 0
                        for opcode in iform_ptn["opcode"]:
                            if type(opcode[0]) == int:
                                value, shift_num = self.EmitNum(value, shift_num, opcode[0], opcode[1], opcode_lst)
                            elif type(opcode[0]) == str:
                                value, shift_num = self.EmitNum(value, shift_num, num, opcode[1], opcode_lst)
                        if shift_num % 8 != 0:
                            raise ValueError("Emit Number Error:  shift_num=%d  value=%d  opcode_lst=%s" %(shift_num, value, opcode_lst))
                        new_iform_ptn = copy.deepcopy(iform_ptn)
                        opcode_dict = self.BuildOpcodeDict(bytes(opcode_lst), new_iform_ptn)
                        self.PtnDictUpdate(new_opcode_dict, opcode_dict)
        return new_opcode_dict

    def HandlePrefix(self, iform_ptn):
        # hard code according to enc-pattern.txt
        # TODO: convert to rules
        # now we don't care not equal prefix conditions
        # TODO: care about not equal
        prefix_encode = {
            "REP": {
                2: 0xf2,
                3: 0xf3
            },
            "OSZ": {
                1: 0x66
            },
            "ASZ": {
                1: 0x67
            },
            "LOCK": {
                1: 0xf0
            },
            "SEG_OVD": {
                1: 0x2e,
                2: 0x3e,
                3: 0x26,
                4: 0x64,
                5: 0x65,
                6: 0x36
            }
        }

        prefix_lst = []
        nbits = 8       # now for 32 mode, all nbits are 8
        if "prefix" in iform_ptn:
            for prefix in iform_ptn["prefix"]:
                # don't care not equal at present
                if prefix in prefix_encode:
                    if iform_ptn["prefix"][prefix] in prefix_encode[prefix]:
                        num = iform_ptn["prefix"][prefix]
                        prefix_lst.append( (prefix_encode[prefix][num], nbits) )
        return prefix_lst

    def MakeOpcodeLst(self):
        # hard code here
        # TODO: convert to rules
        special_letter = ("srm")
        prefix_letter = ("REP", "OSZ", "ASZ", "LOCK", "SEG_OVD")
        for iclass in gs.iarray:
            for iform in gs.iarray[iclass]:
                iform_ptn = {"opcode":[], "iform":[iform]}
                # iform_ptn = {"opcode":[]}
                rule = iform.rule
                has_modrm = False
                for act in rule.actions:
                    field_name = act.field_name
                    if act.emit_type == None:
                        if act.nt != None:
                            # ======= update self.nt_iform_bind =======
                            if not act.nt in self.nt_iform_bind:
                                self.nt_iform_bind[act.nt] = []
                            self.nt_iform_bind[act.nt].append(iform)
                        elif act.type == "FB":
                            if field_name in prefix_letter:
                                if not "prefix" in iform_ptn:
                                    iform_ptn["prefix"] = {}
                                if act.not_equal:
                                    new_key = "!%s"%act.field_name
                                    if new_key in iform_ptn["prefix"]:
                                        raise ValueError("Prefix %s Collision in %s" %(str(act), iform_ptn["prefix"]))
                                    else:
                                        iform_ptn["prefix"][new_key] = act.int_value
                                else:
                                    new_key = act.field_name
                                    if new_key in iform_ptn["prefix"]:
                                        raise ValueError("Prefix %s Collision in %s" %(str(act), iform_ptn["prefix"]))
                                    else:
                                        iform_ptn["prefix"][new_key] = act.int_value
                        elif act.not_equal:
                            if field_name in self.emit_letter:
                                has_modrm = True
                                if field_name in iform_ptn:
                                    value = iform_ptn[field_name]
                                    if type(value[0]) == int and value != act.int_value:
                                        continue
                                    elif type(value[0]) == str:
                                        nbits = value[1]
                                        tmp_lst = [(i, act.nbits) for i in range(1<<nbits)]
                                        tmp_lst.remove( (act.int_value, act.nbits) )
                                        iform_ptn[field_name] = tmp_lst
                                    else:
                                        raise ValueError("Not Equal Act %s Conflict With Context %s=%d" %(str(act), field_name, iform_ptn[field_name]))
                                else:
                                    raise ValueError("Cannot Find Field %s In Context" %field_name)
                            else:
                                pass
                    elif act.emit_type == "numeric":
                        if field_name == None:
                            iform_ptn["opcode"].append( (act.int_value, act.nbits) )
                        elif field_name in self.emit_letter:
                            iform_ptn[field_name] = act.int_value, act.nbits
                            has_modrm = True
                        elif field_name in special_letter:
                            iform_ptn["opcode"].append( (act.int_value, act.nbits) )
                        else:
                            raise ValueError("Emit Unknown Letter %s" %act.field_name)
                    elif act.emit_type == "letters":
                        if field_name in self.emit_letter:
                            has_modrm = True
                            iform_ptn[field_name] = act.value, act.nbits       # type(act.value) == str
                        elif field_name in special_letter:
                            iform_ptn["opcode"].append( (act.value, act.nbits) )
                        else:
                            pass
                    else:
                        raise ValueError("Unknown Emit Type")
                prefix_lst = self.HandlePrefix(iform_ptn)
                for prefix in prefix_lst:
                    iform_ptn["opcode"].insert(0, prefix)
                self.iform_ptn_lst.append(iform_ptn)
                ptn_dict = self.Ptn2Opcode(iform_ptn)
                self.PtnDictUpdate(self.ptn_dict, ptn_dict)

    def MakeMODRMLst(self):         # This method is duplicated and the MODRM_lst is now built by MakeInsNTLst
        for iclass in gs.iarray:
            for iform in gs.iarray[iclass]:
                rule = iform.rule
                for act in rule.actions:
                    if act.nt == "MODRM":
                        self.MODRM_lst.append(iform)
                        break

    def MakeAllIforms(self):
        for ins in self.iarray:
            self.all_iforms.extend(self.iarray[ins])

    def MakeSubNTLst(self):
        for nt_name in self.ntlufs:
            nt = self.ntlufs[nt_name]
            for rule in nt.rules:
                for act in rule.actions:
                    if act.type == "ntluf":
                        if nt_name in self.sub_NT:
                            self.sub_NT[nt_name].append(act.ntluf)
                        else:
                            self.sub_NT[nt_name] = [act.ntluf]
        for nt_name in self.sub_NT:
            for sub_nt_name in self.sub_NT[nt_name]:
                if sub_nt_name in self.sub_NT_reverse:
                    if not nt_name in self.sub_NT_reverse[sub_nt_name]:
                        self.sub_NT_reverse[sub_nt_name].append(nt_name)
                else:
                    self.sub_NT_reverse[sub_nt_name] = [nt_name]

    def MakeSeqNTBind(self):
        for seq in self.seqs:
            for nt_name in self.seqs[seq].nonterminals:
                self.seq_nt_bind[nt_name] = seq