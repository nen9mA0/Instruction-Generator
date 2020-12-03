import re

import slash_expand
from patterns import *
from util import *

ext_pattern = re.compile(r'^EXTENSION\s*[:]\s*(?P<extension>.+)')

def read_decoder_instruction_file(lines, ext_regex):
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

    exts = {}
    new_lines = []
    while len(lines) > 0:
        line = lines.pop(0)
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
                die("Nested instructions")
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
                die("Mis-nested instructions")
            # ======= IS_MATCHED ======
            if is_matched_class:
                new_lines.extend(tmp_lines)
            # ======= HAS_EXT ======
            if not has_ext:
                logger.warning("ICLASS %s has no extension" %iclass)

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
                exts[extension] = 1
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
    return new_lines, exts

all_ins = "../../all-datafiles/all-enc-instructions.txt"
# all_ins = "../../datafiles_test/all-enc-instructions.txt"
match_ins = "../../datafiles_test/x87_instructions.txt"

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
    newlines, exts = read_decoder_instruction_file(lines, ext)
    # with open(match_ins, "w") as f:
    #     for i in newlines:
    #         f.write(i + "\n")
    # for i in exts:
    #     print(i)