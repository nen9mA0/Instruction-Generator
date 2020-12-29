from global_init import *
import pickle

def GensSave(f, obj):
    pickle.dump(obj.reg_nt_bind, f)
    pickle.dump(obj.nt_reg_bind, f)
    pickle.dump(obj.nt_ins_bind, f)
    pickle.dump(obj.reg_ins_bind, f)
    pickle.dump(obj.all_iforms, f)
    pickle.dump(obj.MODRM_lst, f)
    pickle.dump(obj.sub_NT, f)

def GensLoad(f, obj):
    obj.reg_nt_bind = pickle.load(f)
    obj.nt_reg_bind = pickle.load(f)
    obj.nt_ins_bind = pickle.load(f)
    obj.reg_ins_bind = pickle.load(f)
    obj.all_iforms = pickle.load(f)
    obj.MODRM_lst = pickle.load(f)
    obj.sub_NT = pickle.load(f)

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
        self.MODRM_lst = []
        self.sub_NT = {}                    # record the NT that calls other NTs

        if not load:
            self.MakeRegNTlufLst()
            self.MakeInsNTLst()
            self.MakeAllIforms()
            self.MakeMODRMLst()
            self.MakeSubNTLst()

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
                    else:
                        pass
                        # logger.error("MakeInsNTLst: cannot handle input operand %s %s" %(var, value))
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
                    else:
                        pass
                        # logger.error("MakeInsNTLst: cannot handle output operand %s %s" %(var, nt))

    def MakeMODRMLst(self):
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
