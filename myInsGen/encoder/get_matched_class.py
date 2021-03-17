import re
import os

import slash_expand
import util
from patterns import *


ext_pattern = re.compile(r'^EXTENSION\s*[:]\s*(?P<extension>.+)')
category_pattern = re.compile(r'^CATEGORY\s*[:]\s*(?P<category>.+)')
file_pattern = re.compile("^###FILE\s*:\s*(?P<filename>.+)$")

def no_comments(line):
    if file_pattern.search(line):
        oline = line
    else:
        comment_pattern = re.compile(r'[#].*$')
        oline = comment_pattern.sub('', line)
    oline = oline.strip()
    return oline

def process_continuations(lines):
    continuation_pattern = re.compile(r'\\$')
    olines = []
    while len(lines) != 0:
        line = no_comments(lines[0])
        line = line.strip()
        lines.pop(0)
        if line == '':
            continue
        if continuation_pattern.search(line):
            # combine this line with the next line if the next line exists
            line = continuation_pattern.sub('', line)
            if len(lines) >= 1:
                combined_lines = [line + lines[0]]
                lines.pop(0)
                lines = combined_lines + lines
                continue
        olines.append(line)
    del lines
    return olines


def GetCategoryMatchedICLASS(lines, category_regex="", add_file=False):
    """Taking a slightly different tack with the ISA file because
    it is so large. Processing each line as we encounter it rather
    than buffering up the whole file. Also, just storing the parts
    I need. """
    continuation_pattern = re.compile(r'\\$')
    match_category_pattern = re.compile(category_regex)
    lines = process_continuations(lines)
    nts = {}
    nt = None
    iclass = None
    uname = None
    unamed = None
    ipattern = None
    started = False

    is_matched_class = False
    has_ext = False
    category = ""
    filename = ""
    filename_line = ""

    categorys = {}

    i = 0
    while len(lines) > 0:
        i += 1
        line = lines.pop(0)

        if add_file:
            fn = file_pattern.search(line)
            if fn:
                filename = fn.group("filename")
                filename_line = line
                continue

        line = comment_pattern.sub("",line)
        #line = leading_whitespace_pattern.sub("",line)
        line=line.strip()
        if line == '':
            continue
        line = slash_expand.expand_all_slashes(line)

        if udelete_pattern.search(line):
            m = udelete_full_pattern.search(line)
            unamed = m.group('uname')
            print("LINE %d : REGISTER BAD UNAME: %s" %(i, unamed))
            continue

        if delete_iclass_pattern.search(line):
            m = delete_iclass_full_pattern.search(line)
            iclass = m.group('iclass')
            continue

        if left_curly_pattern.match(line):
            if started:
                util.die("LINE %d : Nested instructions" %i)
            tmp_lines = []
            started = True
            iclass = None
            uname = None
            is_matched_class = False
            has_ext = False
            tmp_lines.append(line)
            continue

        if started:
            tmp_lines.append(line)

        if right_curly_pattern.match(line):
            if not started:
                util.die("LINE %d : Mis-nested instructions" %i)
            # ======= IS_MATCHED ======
            if is_matched_class:
                if add_file:
                    categorys[category].append(filename_line)
                categorys[category].extend(tmp_lines)
            # ======= HAS_EXT ======
            if not has_ext:
                print("LINE %d : ICLASS %s has no category" %(i, iclass))

            started = False
            iclass = None
            uname = None
            continue
        ic = iclass_pattern.match(line)
        if ic:
            iclass = ic.group('iclass')
            continue

        ext = category_pattern.match(line)
        if ext:
            category = ext.group("category")
            has_ext = True
            if category not in categorys:
                categorys[category] = []
            if match_category_pattern.match(category):
                is_matched_class = True

        un = uname_pattern.match(line)
        if un:
            uname = un.group('uname')
            continue
        
        ip = ipattern_pattern.match(line)
        if ip:
            ipattern = ip.group('ipattern')
            continue
        
        if no_operand_pattern.match(line):
            continue

        op = operand_pattern.match(line)
        if op:
            operands = op.group('operands')
            continue
    return categorys

def GetExtensionMatchedICLASS(lines, ext_regex="", add_file=False):
    """Taking a slightly different tack with the ISA file because
    it is so large. Processing each line as we encounter it rather
    than buffering up the whole file. Also, just storing the parts
    I need. """
    continuation_pattern = re.compile(r'\\$')
    match_ext_pattern = re.compile(ext_regex)
    lines = process_continuations(lines)
    nts = {}
    nt = None
    iclass = None
    uname = None
    unamed = None
    ipattern = None
    started = False

    is_matched_class = False
    has_ext = False
    extension = ""
    filename = ""
    filename_line = ""

    exts = {}
    while len(lines) > 0:
        line = lines.pop(0)

        if add_file:
            fn = file_pattern.search(line)
            if fn:
                filename = fn.group("filename")
                filename_line = line
                continue

        line = comment_pattern.sub("",line)
        #line = leading_whitespace_pattern.sub("",line)
        line=line.strip()
        if line == '':
            continue
        line = slash_expand.expand_all_slashes(line)

        if udelete_pattern.search(line):
            m = udelete_full_pattern.search(line)
            unamed = m.group('uname')
            print("REGISTER BAD UNAME: %s" %unamed)
            continue

        if delete_iclass_pattern.search(line):
            m = delete_iclass_full_pattern.search(line)
            iclass = m.group('iclass')
            continue

        if left_curly_pattern.match(line):
            if started:
                util.die("Nested instructions")
            tmp_lines = []
            started = True
            iclass = None
            uname = None
            is_matched_class = False
            has_ext = False
            tmp_lines.append(line)
            continue

        if started:
            tmp_lines.append(line)

        if right_curly_pattern.match(line):
            if not started:
                util.die("Mis-nested instructions")
            # ======= IS_MATCHED ======
            if is_matched_class:
                if add_file:
                    exts[extension].append(filename_line)
                exts[extension].extend(tmp_lines)
            # ======= HAS_EXT ======
            if not has_ext:
                print("ICLASS %s has no extension" %iclass)

            started = False
            iclass = None
            uname = None
            continue
        ic = iclass_pattern.match(line)
        if ic:
            iclass = ic.group('iclass')
            continue

        ext = ext_pattern.match(line)
        if ext:
            extension = ext.group("extension")
            has_ext = True
            if extension not in exts:
                exts[extension] = []
            if match_ext_pattern.match(extension):
                is_matched_class = True

        un = uname_pattern.match(line)
        if un:
            uname = un.group('uname')
            continue
        
        ip = ipattern_pattern.match(line)
        if ip:
            ipattern = ip.group('ipattern')
            continue
        
        if no_operand_pattern.match(line):
            continue

        op = operand_pattern.match(line)
        if op:
            operands = op.group('operands')
            continue
    return exts

all_ins = "all-datafiles/all_test/all-enc-instructions.txt"
# all_ins = "../../datafiles_test/all-enc-instructions.txt"
# match_ins = "../../datafiles_test/x87_instructions.txt"
match_ins_dir = "all-datafiles/extension/x87"

# X87 SSE3 BASE VTX LONGMODE MMX SSE2 SSE MONITOR RDTSCP CLFSH PAUSE
# SSSE3 SSE4 XSAVE MOVBE SMX AES PCLMULQDQ 3DNOW
# VIA_PADLOCK_RNG VIA_PADLOCK_AES VIA_PADLOCK_SHA VIA_PADLOCK_MONTMUL
# SVM SSE4a AMD CLZERO MONITORX MCOMMIT RDPRU SNP XOP TBM FMA4 MPX CET
# RDRAND SHA XSAVEOPT XSAVES XSAVEC CLFLUSHOPT RDSEED RDWRFSGS SMAP SGX
# RDPID PT MOVDIR WAITPKG CLDEMOTE SGX_ENCLV AVX AVXAES F16C FMA AVX2GATHER
# AVX2 BMI2 BMI1 VMFUNC INVPCID LZCNT RTM ADOX_ADCX PKU CLWB AVX512EVEX
# PREFETCHWT1 AVX512VEX WBNOINVD PCONFIG GFNI VAES VPCLMULQDQ ENQCMD TSX_LDTRK SERIALIZE
ext = "X87"

if __name__ == "__main__":
    lines = open(all_ins).readlines()
    exts = GetExtensionMatchedICLASS(lines, ext, True)      # cannot run together with GetCategoryMatchedICLASS because lines is changed
    # categorys = GetCategoryMatchedICLASS(lines, "", True)

    if ext == "":
        for ext in exts:
            match_ins_filename = ext.lower() + "_instructions.txt"
            match_ins_filename = os.path.join(match_ins_dir, match_ins_filename)
            with open(match_ins_filename, "w") as f:
                lst = exts[ext]
                for line in lst:
                    f.write(line + "\n")
        for i in exts:
            print(i)
    else:
        match_ins_filename = ext.lower() + "_instructions.txt"
        match_ins_filename = os.path.join(match_ins_dir, match_ins_filename)
        with open(match_ins_filename, "w") as f:
            lst = exts[ext]
            for line in lst:
                f.write(line + "\n")


    # for i in categorys:
    #     print(i)