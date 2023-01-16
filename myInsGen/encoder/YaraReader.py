from global_init import *
import re
import decimal

slice_length = 4

expand_chr = [chr(i) for i in range(ord('0'), ord('9')+1)] + [chr(i) for i in range(ord('a'), ord('f')+1)]
rule_threshold = 200

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
        self.cond = None
        needed = 0
        in_strings = False
        in_condition = False
        self.mismatch_probability = None
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
                rule_group = YaraRuleGroup(name, line)
                self.rule_raw.append(line)
                if rule_group.name and rule_group.type == "bytes":      # now only test bytes rules
                    self.rule_groups[rule_group.name] = rule_group
                # Now some rules with string rule will also be tested
                # else:
                #     self.no_test = True
            elif in_condition:
                self.cond = YaraCondition(line, self)
                in_condition = False
        if needed != self.need_mask:
            raise ValueError("Rule Uncomplete")
        if not self.cond:
            raise ValueError("Rule has no condition")

    def CalcMismatch(self):
        if self.cond:
            self.mismatch_probability = self.cond.Calc()

    def __str__(self):
        return "%s: %04d rules" %(self.name, len(self.rule_groups))

    def __repr__(self):
        return str(self)

class TooManyRulesError(Exception):
    def __init__(self, yara_name, rule_name):
        self.yara_name = yara_name
        self.rule_name = rule_name

    def __str__(self):
        return "Rule number in %s:%s receive threshold" %(self.yara_name, self.rule_name)

    def __repr__(self):
        return str(self)


class YaraRuleGroup(object):
    rule_ptn = re.compile(r"^\s*(?P<name>\$[\d\w]*)*\s*=\s*\{(?P<rule>[0-9a-fA-F \(\)\|\?\[\-\]]+)\}\s*$")
    # string_ptn = re.compile(r"^\s*\$(?P<name>[\d\w]+)*\s*=\s*\"(?P<rule>.+)\"\s*fullword (ascii|wide)\s*$")
    string_ptn = re.compile(r"^\s*(?P<name>\$[\d\w]*)*\s*=\s*\"(?P<rule>.+)\".*$")
    wildcard_ptn = re.compile(r"^\[(?P<low>\d+)(-(?P<high>\d+))?\]$")
    def __init__(self, yara_name, rule_raw):
        self.rules = []
        self.rule_probability = []
        self.probability = [decimal.Decimal(0)] * slice_length
        self.total_lst = [0] * slice_length
        self.total_mismatch_lst = [0] * slice_length
        p = self.rule_ptn.match(rule_raw)
        self.yara_name = yara_name
        self.name = None
        self.type = ""
        if p:
            self.name = p.group("name")
            self.rule_raw = p.group("rule")
            self.type = "bytes"
            rule = self.PreprocessRule(self.rule_raw)
            try:
                self.CvtRule(rule)
            except TooManyRulesError as e:
                print(e)
        else:
            p = self.string_ptn.match(rule_raw)
            if p:
                self.name = p.group("name")
                self.rule_raw = p.group("rule")
                self.type = "string"
            else:
                raise ValueError("Rule Format Eror")

    def AddRuleProbability(self, probability_lst):
        if len(probability_lst[0]) != len(self.probability):
            raise ValueError("")
        self.rule_probability.append(probability_lst)
        for i in range(slice_length):
            self.probability[i] += probability_lst[0][i]
            self.total_lst[i] += probability_lst[1][i]     # 统计该gram计算的所有mismatch串个数
            self.total_mismatch_lst[i] += probability_lst[2][i]

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

    def CvtWildcard(self, low, high=None):
        if not high:
            return "[%d]" %low
        if low < high:
            return "[%d-%d]" %(low, high)
        elif low == high:
            return "[%d]" %low
        else:
            raise ValueError("param low is larger than high")

    def GetWildcardThres(self, str):
        p = self.wildcard_ptn.match(str)
        if p:
            low = p.group("low")
            high = p.group("high")
            low = int(low)
            if high:
                high = int(high)
            return low, high
        else:
            return None, None

    def ExpandWildCard(self, rule):
        new_rule = ""
        j = 0
        i = 0
        new_obj = ""
        expand_num = 0
        wildcard = False
        wildcard_high = 0
        wildcard_low = 0
        while i < len(rule):
            wildcard = False
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
                            new_obj = expand_rule[:-1] + ") "
                        else:
                            wildcard = True
                            wildcard_high += 1
                            wildcard_low += 1
                            new_obj = ""
                    if not wildcard:        # 延迟填充wildcard规则，因为可能出现[0-2] [0-2]这种规则，所以需要读取直到下一个元素不是wildcard再加入新的规则[0-4]
                        if  wildcard_high > 0:
                            new_rule += self.CvtWildcard(wildcard_low, wildcard_high) + " "
                            wildcard_high = 0
                            wildcard_low = 0
                        new_rule += new_obj + " "
                        new_obj = ""
                i += 1
            else:
                if rule[i] == '[':
                    wildcard = True
                    tmp = i
                    while rule[tmp] != ']':     # Here I didn't add an exception handle
                        tmp += 1
                    low, high = self.GetWildcardThres(rule[i:tmp+1])
                    wildcard_low += low
                    if high:
                        wildcard_high += high
                    else:
                        wildcard_high += low
                    i = tmp + 1
                elif rule[i] != ' ':
                    new_rule += rule[i] + " "
                    i += 1
                else:
                    i += 1
        new_rule = new_rule.strip()
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
                range_flag = False
                while rule[i] != "]":
                    if rule[i] == '-':
                        range_flag = True
                    i += 1

                if range_flag:      # 处理[n-m]
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

                    # 以前把所有的[n]转换为n个??，现在反过来
                    # for wildcard_num in range(begin_num, end_num):
                    #     wildcard_lst = " ??" * wildcard_num
                    #     self.CvtRule(rule[end_i+1:], suffix=myrule+wildcard_lst)

                    # wildcard_lst = " ??" * end_num

                    for wildcard_num in range(begin_num, end_num):
                        if wildcard_num:
                            wildcard_lst = " [%d]" %wildcard_num
                            self.CvtRule(rule[end_i+1:], suffix=myrule+wildcard_lst)
                        else:
                            self.CvtRule(rule[end_i+1:], suffix=myrule)

                    wildcard_lst = " [%d]" %end_num
                    i = end_i + 1
                    myrule += wildcard_lst
                else:
                    # 若只是[n]，直接保留
                    myrule += "%s " %rule[begin_i-1:i+1]
                    i += 1
            elif ch == "?":
                i += 1
                wildcard_num = 1
                while rule[i] == '?' or rule[i] == ' ':
                    if rule[i] == '?':
                        wildcard_num += 1
                    i += 1
                if wildcard_num % 2:
                    raise ValueError("")
                wildcard_num = wildcard_num // 2
                myrule += " [%d]" %wildcard_num
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
        if len(self.rules) >= rule_threshold:
            raise TooManyRulesError(self.yara_name, self.name)

    def FormatRule(self, rule_str):
        i = 0
        formatted_rule = ""
        while rule_str[i] == " " and i < len(rule_str):
            i += 1

        # 这套写法针对wildcar全部转换为??的情况
        # j = 0
        # while i < len(rule_str):
        #     if self.IsNum(rule_str[i]) or rule_str[i] == "?":
        #         formatted_rule += rule_str[i]
        #         j += 1
        #         if j%2 == 0:
        #             formatted_rule += " "
        #     i += 1

        j = 0
        in_wildcard = False
        while i < len(rule_str):
            if rule_str[i] in "[]":
                formatted_rule += rule_str[i]
                if rule_str[i] == '[':
                    if j%2:
                        raise ValueError("")
                    in_wildcard = True
                elif rule_str[i] == ']':
                    formatted_rule += " "
                    in_wildcard = False
            elif self.IsNum(rule_str[i]):
                formatted_rule += rule_str[i]
                if not in_wildcard:
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

    def Calc(self):
        # calculate first
        lst = []
        if self.lnode:
            tmp = self.lnode.Calc()
            if tmp != None:
                lst.append(tmp)
        if self.rnode:
            tmp = self.rnode.Calc()
            if tmp != None:
                lst.append(tmp)

        if self.op == "or":
            probability = [decimal.Decimal(0)] * slice_length
            for prob in lst:
                for i in range(slice_length):
                    probability[i] += prob[i]
        elif self.op == "and":
            probability = [decimal.Decimal(1)] * slice_length
            for prob in lst:
                for i in range(slice_length):
                    probability[i] *= prob[i]
        elif self.op == "not":
            probability = [decimal.Decimal(1)] * slice_length
            if len(lst) == 1:
                for i in range(slice_length):
                    probability[i] -= lst[0][i]
            else:
                raise ValueError("")
        return probability

    def __str__(self):
        return "( %s ) %s ( %s )" %(str(self.lnode), self.op, str(self.rnode))

    def __repr__(self):
        return str(self)

class YaraConditionNode(object):
    range_ptn = re.compile(r"^(?P<range>[\d\w]+) of \(*(?P<total>[\w\d\$\*,]+)\)*\s*$")
    # num_ptn = re.compile(r"^\s*\(?(?P<range>[\d\w]+) of them\)?\s*$")
    onerule_ptn = re.compile(r"^(?P<range>\$[\w\d]*)\s*$")
    def __init__(self, cond_str, packyara):
        self.raw_cond = cond_str
        self.packyara = packyara
        self.rule_groups = packyara.rule_groups
        self.type = ""
        self.Parse(cond_str)

    def Calc(self):
        if self.type == "system":
            # 这种情况不对结果产生影响，但因为可能采用了or或and运算符，所以返回None做特殊处理
            return None
        elif self.type == "any":
            probability = [decimal.Decimal(0)] * slice_length
            for rule_name in self.rule_groups:
                for i in range(slice_length):
                    probability[i] += self.rule_groups[rule_name].probability[i]
            return probability
        elif self.type == "all":
            probability = [decimal.Decimal(1)] * slice_length
            for rule_name in self.rule_groups:
                for i in range(slice_length):
                    probability[i] *= self.rule_groups[rule_name].probability[i]
            return probability
        elif self.type == "num":
            probability = [decimal.Decimal(1)] * slice_length
            rule_probability_lst = []

            # ==========
            # TODO: 这里有个让我纠结的问题，默认是按1gram排的，但1gram的顺序不一定是2gram的顺序
            # 我觉得这里既然是计算整个规则的误匹配度，那我还是把每个gram都排序后再算吧

            # 原来的做法是只按照1gram的排序来算
            # for rule_name in self.rule_groups:
            #     if rule_name in self.keys:
            #         rule_probability_lst.append(self.rule_groups[rule_name].probability)
            # rule_probability_lst.sort(reverse=True)

            # 现在换成全部排序，注意，这样修改后rule_probability_lst的i和j与之前是相反的，之前第一维是每个mismatch指令，第二维是指令对应的4个gram，修改后需要排序gram所以是反的
            for i in range(slice_length):
                rule_probability_lst.append([])
                for rule_name in self.rule_groups:
                    if rule_name in self.keys:
                        rule_probability_lst[i].append(self.rule_groups[rule_name].probability[i])
                rule_probability_lst[i].sort(reverse=True)
            # ==========

            match_num = len(rule_probability_lst)
            if match_num > self.num:        # if length of rule_probability_lst < number, maybe some rules are ignored, such as string rules 
                match_num = self.num

            for i in range(match_num):
                for j in range(slice_length):
                    probability[j] *= rule_probability_lst[j][i]
            return probability

    def Parse(self, cond_str):
        p = self.range_ptn.match(cond_str)
        if p:
            mytotal = p.group("total")
            # total用来解析condition中的全局范围，them/$*表示范围为全部rule，其他情况则会指定rule的名字
            if mytotal == "them":
                self.keys = list(self.rule_groups.keys())
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
                    self.keys = []
                    keyname_lst = mytotal.split(",")
                    all_keys = self.rule_groups.keys()
                    for keyname in keyname_lst:
                        keyname = keyname.strip()
                        if keyname in all_keys:
                            self.keys.append(keyname)
                        else:
                            # 这种情况有很大概率是因为对应的rule是一条ascii的rule，所以没有被读取，因此这边直接选择忽略而非抛出异常
                            random_rule_group = next(iter(self.rule_groups))
                            logger.warning("Rule %s not found in %s, Maybe it's a ascii rule, pass" %(keyname, self.rule_groups[random_rule_group].yara_name))
                            # raise ValueError("")
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
                if not cond_str == "pe.is_32bit":
                    logger.warning("Unhandle condition: %s" %cond_str)
                self.type = "system"

    def __str__(self):
        return self.raw_cond

    def __repr__(self):
        return self.raw_cond


class YaraCondition(object):
    ops = ("and", "or", "not")
    def __init__(self, cond_str, packyara):
        self.raw_cond = cond_str
        self.packyara = packyara
        self.cond_node = self.ParseCond(cond_str)

    def Calc(self):
        return self.cond_node.Calc()

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
            cond_str = cond_str.strip().strip("()")
            node = YaraConditionNode(cond_str, self.packyara)
            if node.type == "system":
                node = None
        else:
            if not lnode:
                node = rnode
            elif not rnode:
                node = lnode
            else:
                node = YaraConditionOp(lnode, rnode, op)
        return node

    def __str__(self):
        return str(self.cond_node)

    def __repr__(self):
        return str(self.cond_node)


yara_file = "I:\\Project\\auto_yara\\GetStat\\yara_rules\\20221028\\autoyara.yar"
# yara_file = "I:\\Project\\auto_yara\\GetStat\\yara_rules\\20221028\\test.yar"
# yara_file = "I:\\Project\\auto_yara\\ngram\\new-rules\\automine_818.yar"
# yara_file = "I:\\Project\\auto_yara\\GetStat\\yara_rules\\20221028\\automine_accessible1016.yar"
# yara_file = "I:\\Project\\auto_yara\\GetStat\\yara_rules\\20221028\\artificial.yar"
if __name__ == "__main__":
    with open(yara_file) as f:
        lines = f.readlines()

    packyara_lst = []
    reader = YaraReader(lines)
    for name, lines in reader:
        packyara = PackerYara(name, lines)
        packyara_lst.append(packyara)

    a = 0