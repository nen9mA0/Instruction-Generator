import re

expand_chr = [chr(i) for i in range(ord('0'), ord('9')+1)] + [chr(i) for i in range(ord('a'), ord('f')+1)]

class YaraReader(object):
    packer_name_ptn = re.compile(r"^rule (?P<name>.*)\n$")
    comment_ptn = re.compile(r"(?P<comment>//.*$)")
    empty_ptn = re.compile(r"^\s+$")
    def __init__(self, lines):
        self.lines = lines
        self.index = 0
        self.length = len(self.lines)

    def __iter__(self):
        self.index = 0
        return self

    def __next__(self):
        new_lines = []
        end_index = self.index
        begin_index = self.index
        begin = False

        flag = False
        while end_index < self.length:
            line = self.lines[end_index]
            p = self.packer_name_ptn.match(line)
            if p:
                name = p.group("name")
                end_index += 1
                flag = True
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

        if not flag and end_index >= self.length:
            raise StopIteration
        # filter comments and empty
        for i in range(begin_index, end_index):
            line = self.lines[i]
            line = self.comment_ptn.sub("", line)       # replace first, because some line may become empty after replace
            p = self.empty_ptn.match(line)
            if p:
                continue
            new_lines.append(line)
        self.index = end_index
        return name, new_lines

class PackerYara(object):
    keyword_ptn = re.compile(r"^\s*(?P<keyword>\w+):\s*$")
    need_mask = 0x3
    def __init__(self, name, lines):
        self.name = name
        self.rule_raw = []
        self.rule_groups = {}
        self.no_test = False        # Some Yara Rules That Didn't Match Our Test Conditions Will Be Mark As no_test
        self.condition = None
        needed = 0
        in_strings = False
        in_condition = False
        for line in lines:
            p = self.keyword_ptn.match(line)
            if p:
                keyword = p.group("keyword")
                if keyword == "strings":
                    in_condition = False
                    in_strings = True
                    needed |= 1
                elif keyword == "condition":
                    in_condition = True
                    in_strings = False
                    needed |= 2
                continue
            if in_strings:
                rule_group = YaraRuleGroup(line)
                self.rule_raw.append(line)
                if rule_group.name and rule_group.type == "bytes":      # now only test bytes rules
                    self.rule_groups[rule_group.name] = rule_group
                else:
                    self.no_test = True
            elif in_condition:
                self.cond = YaraCondition(line, self.rule_groups)
                in_condition = False
        if needed != self.need_mask:
            raise ValueError("Rule Uncomplete")

    def AddRule(self, name, rule):
        self.rule_raw.append(rule)
        self.CvtRule(rule)

    def __str__(self):
        return "%s: %04d rules" %(self.name, len(self.rule))

    def __repr__(self):
        return str(self)


class YaraRuleGroup(object):
    rule_ptn = re.compile(r"^\s*\$(?P<name>[\d\w]+)*\s*=\s*\{(?P<rule>[0-9a-fA-F \(\)\|\?\[\-\]]+)\}\s*$")
    # string_ptn = re.compile(r"^\s*\$(?P<name>[\d\w]+)*\s*=\s*\"(?P<rule>.+)\"\s*fullword (ascii|wide)\s*$")
    string_ptn = re.compile(r"^\s*\$(?P<name>[\d\w]+)*\s*=\s*\"(?P<rule>.+)\".*$")
    def __init__(self, rule_raw):
        self.rules = []
        p = self.rule_ptn.match(rule_raw)
        self.name = None
        self.type = ""
        if p:
            self.name = p.group("name")
            self.rule_raw = p.group("rule")
            self.type = "bytes"
            rule = self.PreprocessRule(self.rule_raw)
            self.CvtRule(rule)
        else:
            p = self.string_ptn.match(rule_raw)
            if p:
                self.name = p.group("name")
                self.rule_raw = p.group("rule")
                self.type = "string"
            else:
                raise ValueError("Rule Format Eror")

    def IsNum(self, ch):
        if ch >= '0' and ch <= '9':
            return True
        elif ch >= 'a' and ch <= 'f':
            return True
        elif ch >= 'A' and ch <= 'F':
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
            elif ch == "?":
                num_str += ch
                i += 1
            elif len(num_str) == 0:
                i += 1
            else:
                break
        if len(num_str) and len(num_str) != 2:
            # raise ValueError("")    # check
            return num_str[:2], 2
        if len(num_str):
            return num_str[:2], i
        else:
            return "", 1

    def ReadNum(self, mybytes):
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
        if len(num_str):
            return int(num_str, 10), i
        else:
            return -1, 1

    def PreprocessRule(self, rule_raw):
        rule = self.ExpandWildCard(rule_raw)
        return rule

    def ExpandWildCard(self, rule):
        new_rule = ""
        j = 0
        i = 0
        new_obj = ""
        expand_num = 0
        while i < len(rule):
            if not rule[i] in (' ', '[', ']', '|', '(', ')'):
                # check
                if not (self.IsNum(rule[i]) or rule[i] == '?'):
                    raise ValueError("")
                new_obj += rule[i]
                j += 1
                if j%2 == 0:
                    # shit code, expand one ? to 16 case of bytes
                    if '?' in new_obj:
                        if not "??" in new_obj:
                            expand_rule = "("
                            expand_num += 1
                            if expand_num >= 4:
                                raise ValueError("May Expand Too Many Rules: %d" %(16**expand_num))
                            for num in expand_chr:
                                expand_rule += new_obj.replace('?', num) + "|"
                            new_obj = expand_rule[:-1] + ")"
                    new_rule += new_obj + " "
                    new_obj = ""
                i += 1
            else:
                if rule[i] == '[':
                    tmp = i
                    while rule[tmp] != ']':     # Here I didn't add an exception handle
                        tmp += 1
                    new_rule += rule[i:tmp+1] + " "
                    i = tmp + 1
                elif rule[i] != ' ':
                    new_rule += rule[i]
                    i += 1
                else:
                    i += 1
        return new_rule

    def CvtRule(self, rule, suffix=""):
        i = 0
        myrule = suffix
        while i < len(rule):
            ch = rule[i]
            # handle (xx|xx|xx)
            if ch == "(":
                i += 1
                begin_i = i
                while rule[i] != ")":
                    i += 1

                end_i = i
                i = begin_i
                byte_lst = ""
                while i<end_i:
                    ch = rule[i]
                    if ch == " ":
                        byte_lst += " "
                        i += 1
                    elif ch == "|":
                        self.CvtRule(rule[end_i+1:], suffix=myrule+byte_lst)
                        byte_lst = ""
                        i += 1
                    else:
                        num, i_add = self.ReadByte(rule[i:])
                        if num != "":
                            byte_lst += num
                            i += i_add
                        else:
                            raise ValueError("")
                i += 1      # jump out ")"
                myrule += byte_lst
                # self.CvtRule(rule[end_i+1:], suffix=myrule+byte_lst)
            # handle [xx-xx]
            elif ch == "[":
                i += 1
                begin_i = i
                while rule[i] != "]":
                    i += 1

                end_i = i
                i = begin_i
                # handle jumpout number
                begin_num, i_add = self.ReadNum(rule[i:])
                if begin_num == -1:
                    raise ValueError("")
                end_num = begin_num
                i += i_add
                if i < end_i and rule[i] == '-':
                    i += 1
                    end_num, i_add = self.ReadNum(rule[i:])
                    i += i_add
                    if end_num == -1:
                        raise ValueError("")
                # check
                if i != end_i:
                    raise ValueError("")

                for wildcard_num in range(begin_num, end_num):
                    wildcard_lst = " ??" * wildcard_num
                    self.CvtRule(rule[end_i+1:], suffix=myrule+wildcard_lst)

                wildcard_lst = " ??" * end_num
                i = end_i + 1
                myrule += wildcard_lst
            elif ch == " ":
                i += 1
                myrule += " "
                continue
            else:
                num, i_add = self.ReadByte(rule[i:])
                if num != "":
                    myrule += num
                    i += i_add
                else:
                    raise ValueError("")
        self.rules.append(self.FormatRule(myrule))

    def FormatRule(self, rule_str):
        i = 0
        formatted_rule = ""
        while rule_str[i] == " " and i < len(rule_str):
            i += 1

        j = 0
        while i < len(rule_str):
            if self.IsNum(rule_str[i]) or rule_str[i] == "?":
                formatted_rule += rule_str[i]
                j += 1
                if j%2 == 0:
                    formatted_rule += " "
            i += 1
        if formatted_rule[-1] == " ":
            formatted_rule = formatted_rule[:-1]
        return formatted_rule

class YaraConditionOp(object):
    def __init__(self, lnode, rnode, op):
        self.op = op
        self.lnode = lnode
        self.rnode = rnode

class YaraConditionNode(object):
    range_ptn = re.compile(r"^\s*\(?(?P<range>[\d\w]+) of (?P<total>[\w\d\$\(\)\*]+?)\)?\s*$")
    # num_ptn = re.compile(r"^\s*\(?(?P<range>[\d\w]+) of them\)?\s*$")
    onerule_ptn = re.compile(r"^\s*\$(?P<range>[\w\d]+)\s*$")
    def __init__(self, cond_str, rule_groups):
        self.raw_cond = cond_str
        self.rule_groups = rule_groups
        self.type = ""
        self.Parse(cond_str)

    def Parse(self, cond_str):
        p = self.range_ptn.match(cond_str)
        if p:
            mytotal = p.group("total")
            if mytotal == "them":
                self.keys = self.rule_groups.keys()
            elif '$' in mytotal:
                if '*' in mytotal:
                    self.keys = []
                    begin = mytotal.find('$')
                    end = mytotal.find('*')
                    tmp_key = mytotal[begin:end]
                    for key in self.rule_groups.keys():
                        if tmp_key in key:
                            self.keys.append(key)
                else:
                    raise ValueError("")
            else:
                raise ValueError("")

            myrange = p.group("range")
            if myrange == "any":
                self.type = "any"
            elif myrange == "all":
                self.type = "all"
            else:
                self.type = "num"
                self.num = int(myrange)
        else:
            p = self.onerule_ptn.match(cond_str)
            if p:
                myrange = p.group("range")
                if myrange in self.rule_groups.keys():
                    self.type = "any"
                    self.keys = [myrange]
            else:
                print(cond_str)
                self.type = "system"

class YaraCondition(object):
    ops = ("and", "or", "not")
    def __init__(self, cond_str, rule_groups):
        self.raw_cond = cond_str
        self.rule_groups = rule_groups
        self.cond_node = self.ParseCond(cond_str)

    def ParseCond(self, cond_str):
        flag = False
        for op in self.ops:
            if op in cond_str:
                flag = True
                index = cond_str.find(op)
                lnode = self.ParseCond(cond_str[:index])
                rnode = self.ParseCond(cond_str[index+len(op):])
                break
        if not flag:
            node = YaraConditionNode(cond_str, self.rule_groups)
        else:
            node = YaraConditionOp(lnode, rnode, op)
        return node



yara_file = "I:\\Project\\auto_yara\\GetStat\\yara_rules\\20221028\\autoyara.yar"
# yara_file = "I:\\Project\\auto_yara\\ngram\\new-rules\\automine_818.yar"
if __name__ == "__main__":
    with open(yara_file) as f:
        lines = f.readlines()

    packyara_lst = []
    reader = YaraReader(lines)
    for name, lines in reader:
        packyara = PackerYara(name, lines)
        packyara_lst.append(packyara)

    a = 0