#!/usr/bin/env python3
#
# decrypt_pridelocker_esxi_stackstrings.py
# Copyright (C) 2022 - Synacktiv, Théo Letailleur
# contact@synacktiv.com
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from idautils import Heads, XrefsTo, DecodePreviousInstruction
from idc import print_insn_mnem, print_operand, get_operand_type, get_operand_value, get_bytes, get_strlit_contents, set_cmt
from ida_bytes import get_wide_dword
from ida_funcs import get_func
import idaapi

from binascii import unhexlify, hexlify
import random
import math

# Function Taken from https://github.com/gdataadvancedanalytics/ida-python/blob/master/Trickbot/stringDecryption.py
def setCommentToDecompilation(comment, address):
    #Works in IDA 6.9 - May not work in IDA 7
    #see https://www.hex-rays.com/products/decompiler/manual/sdk/hexrays_8hpp_source.shtml used structures, const and functions
    cfunc = idaapi.decompile(address)
    
    #get the line of the decompilation for this address
    eamap = cfunc.get_eamap()
    decompObjAddr = eamap[address][0].ea

    #get a ctree location object to place a comment there
    tl = idaapi.treeloc_t()
    tl.ea = decompObjAddr
    
    commentSet = False
    #since the public documentation on IDAs APIs is crap and I don't know any other way, we have to brute force the item preciser
    #we do this by setting the comments with different idaapi.ITP_* types until our comment does not create an orphaned comment
    for itp in range(idaapi.ITP_SEMI, idaapi.ITP_COLON):
        tl.itp = itp    
        cfunc.set_user_cmt(tl, comment)
        cfunc.save_user_cmts()
        #apparently you have to cast cfunc to a string, to make it update itself
        unused = cfunc.__str__()
        if not cfunc.has_orphan_cmts():
            commentSet = True
            cfunc.save_user_cmts()
            break
        cfunc.del_orphan_cmts()

    if not commentSet:
        print("[ERROR] Please set \"%s\" to line %s manually" % (comment, hex(int(address))))


def decrypt_string(enc_str, qword_key):
    dec_str = bytearray(len(enc_str))
    for i in range(0, len(enc_str)):
        tmp = (qword_key >> (8 * (i&7)))&0xff
        dec_str[i] = enc_str[i] ^ tmp
    return dec_str

def get_random():
    num = random.random()
    nn = math.floor(num * 2**8)
    return str(nn)

def get_function_with_encrypted_string(ea):
    f = get_func(ea)
    idaapi.set_name(f.start_ea, f"CRYPT__decrypt{get_random()}", idaapi.SN_FORCE)
    for x in XrefsTo(f.start_ea):
        f_parent = get_func(x.frm)
        idaapi.set_name(f_parent.start_ea, f"CRYPT__m_decrypt{get_random()}", idaapi.SN_FORCE)
        for y in XrefsTo(f_parent.start_ea):
            #print(hex(y.frm))
            prev = DecodePreviousInstruction(y.frm)
            if prev is not None:
                prev = DecodePreviousInstruction(prev.ip)
                mnem = print_insn_mnem(prev.ip)
                if mnem == "call":
                    func_with_encstring = get_operand_value(prev.ip, 0)
                    return func_with_encstring, prev.ip
                    #print(f"Function containing the encrypted string: {hex(func_with_encstring)}")
                else:
                    print("WARNING: unusual call has been made")
                    return 0

def get_encrypted_string(start_ea, end_ea, enclen):
    k = -1
    encrypted_string = bytearray(enclen)
    for ea in Heads(start_ea, end_ea):
        if k != 0:
            ea_inst = DecodeInstruction(ea)
            mnem = print_insn_mnem(ea_inst.ip)
            if mnem == "mov":
                op_type = get_operand_type(ea_inst.ip, 0)
                if op_type == o_displ:
                    encbyte_t = get_operand_type(ea_inst.ip, 1)
                    if encbyte_t == o_imm:
                        encbyte = get_operand_value(ea_inst.ip, 1)
                        if k == -1 and enclen == encbyte:
                            k = encbyte
                            print(f"Found correct length of string: {k}")
                        else:
                            #print(f"Enc Byte: {hex(encbyte)}")
                            encrypted_string[enclen - k] = encbyte
                            k = k - 1
    return encrypted_string


decrypt_fun = 0x408D0C
for x in XrefsTo(decrypt_fun):
    #print(f"{hex(x.frm)} -> {hex(x.to)}")
    prev = DecodePreviousInstruction(x.frm)
    if prev is not None:
        prev = DecodePreviousInstruction(prev.ip)
        enc_str_len = get_operand_value(prev.ip, 1)
        print(f"Length of encrypted string: {hex(enc_str_len)}")

        if prev is not None:
            prev = DecodePreviousInstruction(prev.ip)
            key = get_operand_value(prev.ip, 1)
            print(f"Key: {hex(key)}")
            encfunc_start, xref_encfunc_start = get_function_with_encrypted_string(prev.ip)
            if encfunc_start == 0:
                print("WARNING: could not find encfunc")
                continue
            idaapi.set_name(encfunc_start, f"CRYPT__fetch_encstring{get_random()}", idaapi.SN_FORCE)
            encfunc = get_func(encfunc_start)

            #print("%x %x" % (encfunc.start_ea, encfunc.end_ea))
            enc_string = get_encrypted_string(encfunc.start_ea, encfunc.end_ea, enc_str_len)
            plain_string = decrypt_string(enc_string, key)
            print(f"Decrypted string: {plain_string.decode('utf-8')}")
            set_cmt(xref_encfunc_start, plain_string.decode('utf-8'), 0)
            set_cmt(encfunc_start, plain_string.decode('utf-8'), 0)
            setCommentToDecompilation(plain_string.decode('utf-8'), xref_encfunc_start)
            setCommentToDecompilation(plain_string.decode('utf-8'), encfunc_start)
            """
            set_cmt(xref_encfunc_start, "", 0)
            set_cmt(encfunc_start, "", 0)
            setCommentToDecompilation("", xref_encfunc_start)
            setCommentToDecompilation("", encfunc_start)
            """


            


