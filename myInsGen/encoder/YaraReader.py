import re
from tkinter import S, Pack

class YaraReader(object):
    packer_name_ptn = re.compile(r"^rule (?P<name>.*)\n$")
    def __init__(self, lines):
        self.lines = lines
        self.index = 0
        self.length = len(self.lines)

    def __iter__(self):
        self.index = 0
        return self

    def __next__(self):
        end_index = self.index
        begin_index = self.index
        begin = False
        while end_index < self.length:
            line = self.lines[end_index]
            p = self.packer_name_ptn.match(line)
            if p:
                name = p.group("name")
                end_index += 1
                continue
            if line[0] == "{":
                begin = True
                begin_index = end_index
                end_index += 1
                continue
            elif line[0] == "}":
                if not begin:
                    raise ValueError("")
                begin = False
                end_index += 1
                break
            else:
                end_index += 1
        if end_index >= self.length:
            raise StopIteration
        lines = self.lines[begin_index:end_index]
        self.index = end_index
        return name, lines

class PackerYara(object):
    rule_ptn = re.compile(r"\s*\$rule(?P<index>\d+) = \{(?P<rule>[0-9a-f \(\)\|]+)\}")
    def __init__(self, name, lines):
        self.name = name
        self.rule_raw = []
        self.rule = []
        for line in lines:
            p = self.rule_ptn.match(line)
            if p:
                index = p.group("index")
                rule = p.group("rule")
                self.AddRule(index, rule)
                continue

    def AddRule(self, index, rule):
        self.rule_raw.append(rule)
        self.CvtRule(rule)

    def IsNum(self, ch):
        if ch >= '0' and ch <= '9':
            return True
        elif ch >= 'a' and ch <= 'f':
            return True
        return False

    def ReadByte(self, mybytes):
        i = 0
        num_str = ""
        while i < len(mybytes):
            ch = mybytes[i]
            if self.IsNum(ch):
                num_str += ch
                i += 1
            elif ch == "|":
                break
            elif len(num_str) == 0:
                i += 1
            else:
                break
        if len(num_str) and len(num_str) != 2:
            raise ValueError("")    # check
        if len(num_str):
            return int(num_str, 16), i
        else:
            return -1, 1

    def __str__(self):
        return "%s: %04d rules" %(self.name, len(self.rule))

    def __repr__(self):
        return str(self)


    def CvtRule(self, rule, suffix=b""):
        i = 0
        mybytes = suffix
        while i < len(rule):
            ch = rule[i]
            if ch == "(":
                i += 1
                begin_i = i
                while rule[i] != ")":
                    i += 1

                end_i = i
                i = begin_i
                while i<end_i:
                    num_lst = []
                    flag = False
                    while True:
                        num, i_add = self.ReadByte(rule[i:end_i])
                        if num != -1:
                            num_lst.append(num)
                            i += i_add
                        elif rule[i] == "|":
                            self.CvtRule(rule[end_i+1:], suffix=mybytes+bytes(num_lst))     # fork the context and generate one rule
                            i += 1
                            flag = True
                            break
                        else:
                            i += i_add
                            break
                if flag:
                    break
                else:
                    mybytes += bytes(num_lst)
                    continue
            elif ch == " ":
                i += 1
                continue
            else:
                num, i_add = self.ReadByte(rule[i:])
                if num != -1:
                    mybytes += bytes([num])
                    i += i_add
                else:
                    break
        self.rule.append(mybytes)


yara_file = "I:\\Project\\auto_yara\\rules\\automine-new721test.yar"
if __name__ == "__main__":
    with open(yara_file) as f:
        lines = f.readlines()

    packyara_lst = []
    reader = YaraReader(lines)
    for name, lines in reader:
        packyara = PackerYara(name, lines)
        packyara_lst.append(packyara)

    a = 0