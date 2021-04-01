from global_init import *
import HashTable
import pickle


def GensSave(f, obj):
    pickle.dump(obj.reg_nt_bind, f)
    pickle.dump(obj.nt_reg_bind, f)
    pickle.dump(obj.nt_ins_bind, f)
    pickle.dump(obj.reg_ins_bind, f)
    pickle.dump(obj.MODRM_lst, f)
    pickle.dump(obj.IMM_lst, f)
    pickle.dump(obj.branch_ins, f)
    pickle.dump(obj.sub_NT, f)
    pickle.dump(obj.sub_NT_reverse, f)

def GensLoad(f, obj):
    obj.reg_nt_bind = pickle.load(f)
    obj.nt_reg_bind = pickle.load(f)
    obj.nt_ins_bind = pickle.load(f)
    obj.reg_ins_bind = pickle.load(f)
    obj.MODRM_lst = pickle.load(f)
    obj.IMM_lst = pickle.load(f)
    obj.branch_ins = pickle.load(f)
    obj.sub_NT = pickle.load(f)
    obj.sub_NT_reverse = pickle.load(f)

class GeneratorStorage(object):
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
        self.all_iforms = []
        self.MODRM_lst = ([], [])
        self.IMM_lst = ([], [])
        self.branch_ins = []
        self.sub_NT = {}                    # record the NT that calls other NTs
        self.sub_NT_reverse = {}
        self.htm = None

        self.MakeAllIforms()

        if not load:
            self.MakeSubNTLst()
            self.MakeRegNTlufLst()
            self.MakeInsNTLst()
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
