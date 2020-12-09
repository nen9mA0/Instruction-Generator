import re
import util


class operand_field_t(object):
    def __init__(self,
                 name,
                 aggtype,
                 ctype,
                 bitwidth,
                 default_visibility=None,
                 default_initializer=None,
                 xprint='NOPRINT',
                 internal_or_public="INTERNAL",
                 dio="DO",
                 eio="EO",):

        self.name = name
        self.aggtype = aggtype
        self.ctype = ctype
        self.bitwidth = int(bitwidth)
        self.default_visibility = default_visibility
        self.xprint = xprint
        self.internal_or_public = internal_or_public
        self.dio = dio
        self.eio = eio

        if self.eio in ['EI', 'EO']:
            pass
        else:
            err = "Bad Encoder IO value: %s -- need one of {EI,EO}"
            util.die(err % self.eio)

        if self.dio in ['DI', 'DO', 'DS']:
            pass
        else:
            err = "Bad decoder IO value: %s -- need one of {DI,DO,DS}"
            util.die(err % self.eio)

        if self.eio == 'EI':
            self.encoder_input = True
        else:
            self.encoder_input = False

        if self.dio == 'DS':
            self.decoder_skip = True
        else:
            self.decoder_skip = False

        # NOTE: this next field is only used if initialize_each_field is True.
        self.default_initializer = default_initializer
        self.is_enum = 'enum' in self.ctype

        # this is the C type that will be used in the operand storage struct.
        self.storage_type = None

        # if True using bit fields
        self.compressed = False

    def __str__(self):
        #mystr = "OP NAME:\t  %s\n" % (self.name)
        mystr = "%s\n" %(self.name)
        mystr += "  SCALAR:\t  %s\n" % (self.aggtype)
        mystr += "  CTYPE:\t  %s\n" % (self.ctype)
        mystr += "  WIDTH:\t  %s\n" % (self.bitwidth)
        mystr += "  VISIB:\t  %s\n" % (self.default_visibility)
        if self.eio == "EI":
            eio = "encoder input"
        elif self.eio == "EO":
            eio = "encoder output"
        if self.dio == "DI":
            dio = "decoder input"
        elif self.dio == "DO":
            dio = "decoder output"
        elif self.dio == "DS":
            dio = "decoder skip"
        mystr += "  DIO:\t\t  %s\n" % (dio)
        mystr += "  EIO:\t\t  %s\n" % (eio)
        return mystr


class operands_storage_t(object):
    """This is where we build up the storage for the fields that hold
    the operand values. 
    """

    def __init__(self, lines, compress_operands=False):
        # a dict of operand name to operand_field_t
        self.operand_fields = self._read_storage_fields(lines)

        self.compressed = compress_operands

        # list of bin, each bin is operands
        # used for squeezing operands with a few bits to one 32 bit variable
        self.bins = []

    def _read_storage_fields(self, lines):
        ''' Return a dictionary of operand_field_t objects 
            indexed by field name '''

        comment_pattern = re.compile(r'[#].*$')
        operand_types = {}
        for line in lines:
            pline = comment_pattern.sub('', line).strip()
            if pline == '':
                continue
            wrds = pline.split()
            if len(wrds) != 9:
                util.die("Bad number of tokens on line: " + line)
            # aggtype is "SCALAR"
            (name, aggtype, ctype, width, default_visibility,
             xprint, internal_or_public, dio, eio) = wrds
            if name in operand_types:
                util.die("Duplicate name %s in input-fields file." % (name))

            if aggtype != 'SCALAR':
                err = ("type different than SCALAR is not" +
                       " supported in: %s" % (line))
                util.die(err)

            if ctype == 'xed_reg_enum_t':
                default_initializer = 'XED_REG_INVALID'
            elif ctype == 'xed_iclass_enum_t':
                default_initializer = 'XED_ICLASS_INVALID'
            else:
                default_initializer = '0'
            operand_types[name] = operand_field_t(name, aggtype,
                                                  ctype, width,
                                                  default_visibility,
                                                  default_initializer,
                                                  xprint,
                                                  internal_or_public,
                                                  dio,
                                                  eio,)
        return operand_types

    def __str__(self):
        mystr = ""
        for i in self.operand_fields:
            mystr += "%s\n" % str(self.operand_fields[i])
        return mystr


def ReadFields(filename):
    lines = open(filename, 'r').readlines()
    operand = operands_storage_t(lines)
    return operand


if __name__ == "__main__":
    operand = ReadFields("../../all-datafiles/all-fields.txt")
    print(operand)
    pass
