#BEGIN_LEGAL
#
#Copyright (c) 2019 Intel Corporation
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#  
#END_LEGAL
import re

macro_def_pattern = \
          re.compile(r'^MACRO_DEF[ \t]*[:][ \t]*(?P<name>[_A-Za-z0-9]+)[ \t]*$')
macro_use_pattern = \
          re.compile(r'^MACRO_USE[ \t]*[:][ \t]*(?P<name>[_A-Za-z0-9]+)[(](?P<args>[^)]+)[)][ \t]*$')


xed_reg_pattern = re.compile(r'(?P<regname>XED_REG_[A-Za-z0-9_]+)')

nt_name_pattern  =  re.compile(r'^(?P<ntname>[A-Za-z_0-9]+)[(][)]')
ntluf_name_pattern  =  re.compile(r'^(?P<ntname>[A-Za-z_0-9]+)[(]OUTREG[)]')
nt_pattern       =  re.compile(r'^(?P<ntname>[A-Za-z_0-9]+)[(][)]::')
ntluf_pattern  =  re.compile(r'^(?P<rettype>[A-Za-z0-9_]+)\s+(?P<ntname>[A-Za-z_0-9]+)[(][)]::')

# for the decode rule, the rhs might be empty
decode_rule_pattern = re.compile(r'(?P<action>.+)[|](?P<cond>.*)')

file_pattern = re.compile(r'###FILE:\s*(?P<file>[A-Za-z0-9-_./]+)')
comment_pattern = re.compile(r'#.*$')
leading_whitespace_pattern = re.compile(r'^\s+')
full_line_comment_pattern = re.compile(r'^\s*#')
arrow_pattern = re.compile(r'(?P<cond>.+)->(?P<action>.+)')
curly_pattern = re.compile(r'(?P<curly>[{}])')
left_curly_pattern = re.compile(r'^[{]$') # whole line
right_curly_pattern = re.compile(r'^[}]$') # whole line

delete_iclass_pattern = re.compile('^DELETE')
delete_iclass_full_pattern = \
    re.compile(r'^DELETE[ ]*[:][ ]*(?P<iclass>[A-Za-z_0-9]+)')

udelete_pattern = re.compile('^UDELETE')
udelete_full_pattern = \
    re.compile(r'^UDELETE[ ]*[:][ ]*(?P<uname>[A-Za-z_0-9]+)')

iclass_pattern = re.compile(r'^ICLASS\s*[:]\s*(?P<iclass>[A-Za-z0-9_]+)')
uname_pattern = re.compile(r'^UNAME\s*[:]\s*(?P<uname>[A-Za-z0-9_]+)')
cpl_pattern = re.compile(r"^CPL\s*[:]\s*(?P<cpl>[0-9]+)")
category_pattern = re.compile(r'^CATEGORY\s*[:]\s*(?P<category>[A-Za-z0-9_]+)')
extension_pattern = re.compile(r'^EXTENSION\s*[:]\s*(?P<extension>[A-Za-z0-9_]+)')
ipattern_pattern = re.compile(r'^PATTERN\s*[:]\s*(?P<ipattern>.+)')
operand_pattern = re.compile(r'^OPERANDS\s*[:]\s*(?P<operands>.+)')
no_operand_pattern = re.compile(r'^OPERANDS\s*[:]\s*$')
equals_pattern = re.compile(r'(?P<lhs>[^!]+)=(?P<rhs>.+)')
return_pattern = re.compile(r'return[ ]+(?P<retval>[^ ]+)')
not_equals_pattern = re.compile(r'(?P<lhs>[^!]+)!=(?P<rhs>.+)')
bit_expand_pattern = re.compile(r'(?P<bitname>[a-z])/(?P<count>\d{1,2})')
rhs_pattern = re.compile(r'[!]?=.*$')
lhs_capture_pattern = re.compile(r'(?P<name>[A-Za-z_0-9]+)[\[](?P<bits>[a-z]+)]')
lhs_capture_pattern_end = re.compile(r'(?P<name>[A-Za-z_0-9]+)[\[](?P<bits>[a-z01_]+)]$')
lhs_pattern = re.compile(r'(?P<name>[A-Za-z_0-9]+)[!=]')
hex_pattern = re.compile(r'0[xX][0-9a-fA-F]+')
decimal_pattern = re.compile(r'^[0-9]+$')
binary_pattern = re.compile(r"^0b(?P<bits>[01_]+$)") # only 1's and 0's
old_binary_pattern = re.compile(r"B['](?P<bits>[01_]+)") #  Explicit leading "B'" 
bits_pattern = re.compile(r'^[10]+$')
bits_and_underscores_pattern = re.compile(r'^[10_]+$')
bits_and_letters_pattern = re.compile(r'^[10a-z]+$')
bits_and_letters_underscore_pattern = re.compile(r'^[10a-z_]+$')
sequence_pattern = re.compile(r'^SEQUENCE[ \t]+(?P<seqname>[A-Za-z_0-9]+)')
encoding_template_pattern = re.compile(r'[a-z01]+')
letter_pattern = re.compile(r'^[a-z]+$')
letter_and_underscore_pattern = re.compile(r'^[a-z_]+$')
simple_number_pattern = re.compile(r'^[0-9]+$')

# =================================================================

operand_token_pattern = re.compile('OPERAND')
underscore_pattern = re.compile(r'_')
invert_pattern = re.compile(r'[!]')
instructions_pattern = re.compile(r'INSTRUCTIONS')

quick_equals_pattern= re.compile(r'=')
colon_pattern= re.compile(r'[:]')

slash_macro_pattern = re.compile(r'([a-z][/][0-9]{1,2})')
nonterminal_string = r'([A-Z][a-zA-Z0-9_]*)[(][)]'

parens_to_end_of_line = re.compile(r'[(][)].*::.*$') # with double colon
lookupfn_w_args_pattern =  re.compile(r'[\[][a-z]+]')

nonterminal_start_pattern=re.compile(r'::')
nonterminal_pattern=re.compile(nonterminal_string)
nonterminal_parens_pattern = re.compile(r'[(][^)]*[)]')

dec_binary_pattern = re.compile(r'^[01_]+$') # only 1's and 0's
formal_binary_pattern = re.compile(r'^0b[01_]+$') # only 1's and 0's leading 0b
one_zero_pattern = re.compile(r'^[01]') # just a leading 0 or 1
completely_numeric = re.compile(r'^[0-9]+$') # only numbers

# things identified by the restriction_pattern  are the operand deciders:
restriction_pattern = re.compile(r'([A-Z0-9_]+)(!=|=)([bx0-9A-Z_]+)')
all_caps_pattern = re.compile(r'^[A-Z_0-9]+$')

not11_pattern = re.compile(r'NOT11[(]([a-z]{2})[)]')
letter_basis_pattern = re.compile(r'[a-z]')

all_zeros_pattern = re.compile(r'^[0]+$')
type_ending_pattern = re.compile(r'_t$')
uniq_pattern = re.compile(r'_uniq(.*)$')
ntwidth_pattern = re.compile('NTWIDTH')
paren_underscore_pattern = re.compile(r'[(][)][_]+')

all_lower_case_pattern = re.compile(r'^[a-z]+$')


pattern_binding_pattern = re.compile(
               r'(?P<name>[A-Za-z_0-9]+)[\[](?P<bits>[A-Za-z01_]+)]')
uppercase_pattern = re.compile(r'[A-Z]')


reg_operand_name_pattern = re.compile("^REG(?P<regno>[0-9]+)$")
