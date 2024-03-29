import Logger
#from global_storage import gs
import save_data
import pickle
import sys
import math

class GlobalStruct(object):
    def __init__(self):
        self.regs_lst = {}
        self.reg_names = {}
        self.storage_fields = {}
        self.state_bits = {}
        self.seqs = {}
        self.nts = {}
        self.ntlufs = {}
        self.repeat_seqs = {}
        self.repeat_nts = {}
        self.repeat_ntlufs = {}
        self.deleted_unames = {}
        self.deleted_instructions = {}
        self.iarray = {}

        self.seq_context = {}       # For quick executing sequence in generator/_ExecSeqBind.
                                    # Because for every iform_t, we should rebuild sequence context before instruction

    def StoreContext(self, seqname, contextlst):
        self.seq_context[seqname] = contextlst

    def GetContext(self,seqname):
        return self.seq_context[seqname]



def GsSave(f, obj):
    pickle.dump(obj.regs_lst, f)
    pickle.dump(obj.reg_names, f)
    pickle.dump(obj.storage_fields, f)
    pickle.dump(obj.state_bits, f)
    pickle.dump(obj.seqs, f)
    pickle.dump(obj.nts, f)
    pickle.dump(obj.ntlufs, f)
    pickle.dump(obj.repeat_seqs, f)
    pickle.dump(obj.repeat_nts, f)
    pickle.dump(obj.repeat_ntlufs, f)
    pickle.dump(obj.deleted_unames, f)
    pickle.dump(obj.deleted_instructions, f)
    pickle.dump(obj.iarray, f)

def GsLoad(f, obj):
    obj.regs_lst = pickle.load(f)
    obj.reg_names = pickle.load(f)
    obj.storage_fields = pickle.load(f)
    obj.state_bits = pickle.load(f)
    obj.seqs = pickle.load(f)
    obj.nts = pickle.load(f)
    obj.ntlufs = pickle.load(f)
    obj.repeat_seqs = pickle.load(f)
    obj.repeat_nts = pickle.load(f)
    obj.repeat_ntlufs = pickle.load(f)
    obj.deleted_unames = pickle.load(f)
    obj.deleted_instructions = pickle.load(f)
    obj.iarray = pickle.load(f)

pkl_dir = "pklfiles"

# ===== all =====
all_reg =               "all-datafiles/all_test/all-registers.txt"
all_state_file =        "all-datafiles/all_test/all-state.txt"
all_enc_pattern =       "all-datafiles/all_test/all-enc-patterns.txt"
all_dec_pattern =       "all-datafiles/all_test/all-dec-patterns.txt"
# all_dec_pattern =       "all-datafiles/all_test/all-dec-patterns_change.txt"
all_enc_dec_pattern =   "all-datafiles/all_test/all-enc-dec-patterns.txt"
all_field =             "all-datafiles/all_test/all-fields.txt"

all_ins =               "all-datafiles/basic_test/basic-test-enc-instructions.txt"
# all_ins =               "all-datafiles/all_test/all-enc-instructions.txt"
all_dec_ins =           "all-datafiles/basic_test/basic-test-dec-instructions.txt"

# ===== basic test =====
# all_reg =               "all-datafiles/basic_test/basic-test-registers.txt"
# all_state_file =        "all-datafiles/basic_test/basic-test-state.txt"
# all_enc_pattern =     "all-datafiles/basic_test/basic-test-enc-patterns.txt"
# all_enc_dec_pattern =   "all-datafiles/basic_test/basic-test-enc-dec-patterns.txt"
# all_field =             "all-datafiles/basic_test/basic-test-fields.txt"
# all_ins =               "all-datafiles/basic_test/basic-test-enc-instructions.txt"

# ===== just for test =====
# all_enc_pattern =       "../../datafiles_test/test-enc-pattern.txt"         # didn't has REX about
# all_ins =             "../../datafiles_test/test-enc-instructions.txt"
# all_ins =             "all-datafiles/base_instructions.txt"
# all_ins =               "all-datafiles/extension/base/base_instructions.txt"
# all_ins = "all-datafiles/extension/x87/x87_instructions.txt"

logger = Logger.logger_t("log/out.txt")
# logger = Logger.logger_t()

gs = GlobalStruct()
# storage_fields = gs.storage_fields
# state_bits = gs.state_bits
# seqs = gs.seqs
# nts = gs.nts
# ntlufs = gs.ntlufs

int_width = math.floor(math.log2(sys.maxsize * 2 + 2))  # platform related, used in iform_t hashing
max_int = sys.maxsize