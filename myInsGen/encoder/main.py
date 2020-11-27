import fields_reader
import state_bits_reader
import enc_patterns_reader
import enc_ins_reader

from global_init import *


if __name__ == "__main__":
    operand = fields_reader.ReadFields(all_field)
    gs.storage_fields = operand.operand_fields
    gs.state_bits = state_bits_reader.ReadState(all_state_file)
    (gs.seqs,gs.nts,gs.ntlufs) = enc_patterns_reader.ReadEncPattern(all_enc_pattern, gs.state_bits)
    enc_ins_reader.ReadIns(all_ins)
