import Logger
#from global_storage import gs

class GlobalStruct(object):
    storage_fields = {}
    state_bits = {}
    seqs = {}
    nts = {}
    ntlufs = {}

    deleted_unames = {}
    deleted_instructions = {}
    iarray = {}
    def __init__(self):
        pass

all_state_file = "../../all-datafiles/all-state.txt"
all_enc_pattern = "../../all-datafiles/all-enc-patterns.txt"
all_field = "../../all-datafiles/all-fields.txt"
all_ins = "../../all-datafiles/all-enc-instructions.txt"


gs = GlobalStruct()
# storage_fields = gs.storage_fields
# state_bits = gs.state_bits
# seqs = gs.seqs
# nts = gs.nts
# ntlufs = gs.ntlufs

logger = Logger.logger_t("log/out.txt")
# logger = Logger.logger_t()