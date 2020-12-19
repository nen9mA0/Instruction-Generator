from global_init import *
from generator_storage import *

class InsFilter(object):
    def __init__(self, init_context=None, iform=None):
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
        self.input_index = 0
        self.output_index = 0

    def __getitem__(self, item):
        return self.context[item]

    def __setitem__(self, item, value):
        self.context[item] = value

    def __getattr__(self, item):
        return getattr(self.context, item)

    def __len__(self):
        return len(self.context)

    def AppendRegInput(self, reg):
        reg_name = "REG" + self.input_index
        if self.iform:
            flag = False
            for name, is_nt, value in self.input_op:
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
            self.input_index += 1
        return flag

    def AppendRegOutput(self, reg):
        reg_name = "REG" + self.output_index
        if self.iform:
            flag = False
            for name, is_nt, value in self.output_op:
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
            self.output_index += 1
        return flag

    def SpecifyReg(self, reg):
        self.context["OUTREG"] = reg

    def SpecifyLock(self):
        self.context["LOCK"] = "1"