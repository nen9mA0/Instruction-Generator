import os
import re

output_dir = "output/20210412"
# files_process = ["out_eax_ebx.txt", "out_ax_bx.txt", "out_al_bl.txt"]
files_process = ["x87_output.txt"]

ins_num_pattern = re.compile("^\d+$")
iclass_pattern = re.compile("^ICLASS.*$")
ins_pattern = re.compile(r"^(?P<hex>[0-9a-f]+)\s*(?P<ins>.*)$")

def GetAllIns(file_lst):
    lines = []
    prev_len = len(lines)
    ins_num = []
    for filename in file_lst:
        fullfilename = os.path.join(output_dir, filename)
        with open(fullfilename) as f:
            lines.extend(f.readlines())
        if "parse end" in lines[prev_len]:
            del lines[prev_len]
        if ins_num_pattern.match(lines[prev_len]):
            ins_num.append(int(lines[prev_len]))
            del lines[prev_len]
        prev_len = len(lines)
    return lines, ins_num

def DeleteIClass(lines):
    del_lines = []
    for i in range(len(lines)):
        if iclass_pattern.match(lines[i]):
            del_lines.append(i)

    deleted = 0
    for i in del_lines:
        num = i - deleted
        del lines[num]
        deleted += 1

    return lines

def GetUniqueIns(lines):
    ins_set = set()
    ins_lst = []
    ins_hex = []
    for line in lines:
        line = line.strip()
        if "remain" in line:
            continue
        ins = ins_pattern.match(line)
        if ins:
            tmp_ins = ins.group("ins")
            tmp_hex = ins.group("hex")
            if len(tmp_ins) > 0:
                ins_set.add(tmp_ins)
                ins_lst.append(tmp_ins)
                ins_hex.append(tmp_hex)
    return ins_set, ins_lst, ins_hex


if __name__ == "__main__":
    lines, ins_num = GetAllIns(files_process)
    lines = DeleteIClass(lines)
    ins_set, ins_lst, ins_hex = GetUniqueIns(lines)

    tmp_lst = list(ins_set)
    tmp_lst.sort()
    print("ins num: %d" %len(tmp_lst))
    for ins in tmp_lst:
        print(ins)

    for ins in tmp_lst:
        ins_lst.remove(ins)
    # print("================")
    # for ins in ins_lst:
    #     print(ins)