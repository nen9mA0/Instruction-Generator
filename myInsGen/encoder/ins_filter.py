from global_init import *
import generator_storage

import dfs_generator


class Generator(object):
    def __init__(self, gens):
        self.gens = gens
        self.emu = dfs_generator.Emulator(self.gens)
        self.context = None

    def __getattr__(self, item):
        return getattr(self.emu, item)

    def GeneratorIform(self, iform, ins_filter=None, onetime=False):        # a iform_t structure only contains one rule_t
        self.emu.ResetInslst()
        self.emu.DFSExecSeqBind("ISA_BINDINGS", "ISA_EMIT", iform, init_context=ins_filter.context, weak_context=ins_filter.weak_context, onetime=onetime)
        return self.emu.ins_set
        # return self.emu.tst_ins_set_dict

    def TestMODRM(self):
        self.emu.ResetInslst()
        self.emu.DFSExecSeqBind("MODRM_BIND", "MODRM_EMIT")
        return self.emu.ins_set


class InsFilter(object):
    def __init__(self, gens, init_context=None, iform=None):
        if init_context:
            self.context = init_context
        else:
            self.context = {}
        if not "emit" in self.context:
            self.context["emit"] = []
        if iform:
            self.iform = iform
            self.input_op = iform.input_op
            self.output_op = iform.output_op
        else:
            self.iform = None
        self.gens = gens
        self.reg_index = 0
        self.reg_type = []
        self.weak_context = {}      # weak context only control the output after EmitCode.
                                    # If an instruction satisfy the conditions in weak_context,
                                    # they'll be pushed into an unique list

    def __getitem__(self, item):
        return self.context[item]

    def __setitem__(self, item, value):
        self.context[item] = value

    def __getattr__(self, item):
        return getattr(self.context, item)

    def __len__(self):
        return len(self.context)

    def TestWeakContext(self, context):
        flag = True
        for item in self.weak_context:
            if item in context:
                if context[item] != self.weak_context[item]:
                    flag = False
        return flag

    def GetIfroms(self):
        ret_set = None
        del_item = []
        for name in self.context:
            tmp_lst = None
            flag = False
            if "REG" in name:
                flag = True
                index = int(name[-1])
                reg_type = self.reg_type[index]
                value = self.context[name]
                if reg_type == "input":
                    is_input = True
                elif reg_type == "output":
                    is_input = False
                else:
                    is_input = None

                if value[-2:] == "()":      # if is ntlufs
                    nt_name = value[:-2]
                    tmp_lst = self.GetNTIform(nt_name, is_input)
                    del_item.append(name)
                else:
                    tmp_lst = self.GetRegIform(value, is_input)
            elif "MOD" == name:
                flag = True
                value = self.context["MOD"]
                try:
                    int_value = int(value)
                    pass                                # TODO: handler for normal conditions?
                except ValueError:                      # only for MOD != 3
                    del_item.append("MOD")              # is not a valid condition for emitting, so should be delete
                    tmp_lst1 = self.gens.MODRM_lst
                    tmp_lst2 = self.GetAllIform()
                    modrm_set = set(tmp_lst1)
                    all_set = set(tmp_lst2)
                    tmp_set = all_set - modrm_set
            else:
                pass

            if flag:
                if tmp_lst:                     # some cases is a list, otherwise is a set
                    tmp_set = set(tmp_lst)
                if ret_set:
                    ret_set = ret_set & tmp_set
                else:
                    ret_set = tmp_set

        for i in del_item:
            del self.context[i]
        return ret_set


    def SpecifyLock(self):
        self.context["LOCK"] = "1"

    def SpecifyMode(self, bits):
        if bits == 16:
            self.context["MODE"] = "0"
        elif bits == 32:
            self.context["MODE"] = "1"
        elif bits == 64:
            self.context["MODE"] = "2"

    def GetAllIform(self):
        return self.gens.all_iforms

    def GetRegIform(self, reg, is_input=None):
        if reg not in self.gens.reg_names:
            logger.error("Register name Error")
            raise ValueError

        ret_iforms = []
        if is_input == None or is_input == True:
            if reg in self.gens.reg_nt_bind:
                for nt_name in self.gens.reg_nt_bind[reg]:
                    if nt_name in self.gens.nt_ins_bind[0]:
                        for i in self.gens.nt_ins_bind[0][nt_name]:
                            ret_iforms.append(i)
            if reg in self.gens.reg_ins_bind[0]:
                for i in self.gens.reg_ins_bind[0][reg]:
                    ret_iforms.append(i)
        if is_input == None or is_input == False:
            if reg in self.gens.reg_nt_bind:
                for nt_name in self.gens.reg_nt_bind[reg]:
                    if nt_name in self.gens.nt_ins_bind[1]:
                        for i in self.gens.nt_ins_bind[1][nt_name]:
                            ret_iforms.append(i)
            if reg in self.gens.reg_ins_bind[1]:
                for i in self.gens.reg_ins_bind[1][reg]:
                    ret_iforms.append(i)

        return ret_iforms

    def GetNTIform(self, nt_name, is_input=None):
        ret_iforms = []
        flag = True
        nt_name_lst = [nt_name]
        if nt_name in self.gens.sub_NT:
            nt_name_lst.extend(self.gens.sub_NT[nt_name])
        if is_input == None or is_input == True:
            for tmp_nt_name in nt_name_lst:
                if tmp_nt_name in self.gens.nt_ins_bind[0]:
                    flag = False
                    ret_iforms.extend(self.gens.nt_ins_bind[0][tmp_nt_name])
        if is_input == None or is_input == False:
            for tmp_nt_name in nt_name_lst:
                if tmp_nt_name in self.gens.nt_ins_bind[1]:
                    flag = False
                    ret_iforms.extend(self.gens.nt_ins_bind[1][tmp_nt_name])
        if flag:
            raise ValueError("nt %s not in nt_ins_bind" %nt_name)

        return ret_iforms

    def AppendReg(self, reg, reg_type=""):             # reg_type: "input"/"output"
        if reg_type != "" and not reg_type in ("input", "output"):
            raise ValueError("reg_type not in input/output: %s" %reg_type)
        reg_name = "REG" + str(self.reg_index)

        if self.iform:
            if reg_type == "input":
                operands = self.input_op
            elif reg_type == "output":
                operands = self.output_op
            else:
                operands = []
                operands.extend(self.input_op)
                operands.extend(self.output_op)
            flag = False
            for name, is_nt, value in operands:
                if reg_name == name:
                    if not is_nt:
                        if reg == value:
                            flag = True
                            break
                    else:
                        flag = True
                        break
        else:
            flag = True

        if flag:
            self.context[reg_name] = reg
            self.reg_index += 1
            self.reg_type.append(reg_type)
        return flag
