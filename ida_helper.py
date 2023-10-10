import ida_bytes
import ida_idaapi
import ida_nalt
import ida_ua
import idc

import idaapi
import idautils

class IdaHelper():

    def __init__(self, text_start=None, text_end=None, *args, **kwargs):
        self.text_start = text_start
        self.text_end = text_end

    def search_byte_sequence(self, *sequences, text_start=None, text_end=None, only_heads=False, search_forward=True):
        """
        Search the text segment for the given pattern

        :yield: Addresses that matches the pattern
        """

        text_start = text_start if text_start else self.text_start
        text_end = text_end if text_end else self.text_end
        assert text_start and text_end, "text_start or text_end not specified"
        patterns_obj = ida_bytes.compiled_binpat_vec_t()
        encoding = ida_nalt.get_default_encoding_idx(ida_nalt.BPU_1B)
        for s in sequences:
            err = ida_bytes.parse_binpat_str(
                patterns_obj,
                text_start,
                s,
                16, # radix (not that it matters though, since we're all about string literals)
                encoding
            )
            if err:
                raise Exception(f"Error {err} occurred during parsing pattern '{s}'")
        
        ea = text_start
        # Keep searching forward until the end of the segment (indicated by BADADDR)
        while ea != ida_idaapi.BADADDR:
            ea = ida_bytes.bin_search(
                ea,
                text_end,
                patterns_obj,
                (ida_bytes.BIN_SEARCH_FORWARD if search_forward else ida_bytes.BIN_SEARCH_BACKWARD)
            | ida_bytes.BIN_SEARCH_NOBREAK
            | ida_bytes.BIN_SEARCH_NOSHOW
            | ida_bytes.BIN_SEARCH_NOCASE)
            if ea == ida_idaapi.BADADDR:
                break
            if not only_heads or self.is_head(ea):
                yield ea
            ea += 1 # Prevent infinite loop

    def is_head(self, ea):
        return ea == idc.prev_head(idc.next_head(ea))

    def get_insn_name(self, ea):
        assert self.is_head(ea)
        return idc.print_insn_mnem(ea)

    def print_ea(self, ea):
        func_name = idc.get_func_name(ea)
        ops = ' '.join(filter(lambda i: i, [ idc.print_operand(ea, i) for i in range(10) ]))
        print(f'[{func_name}] @ {hex(ea)}: {idc.print_insn_mnem(ea)} { ops }')

    def get_func_address(self, ea):
        return idc.get_func_attr(ea, idc.FUNCATTR_START)
    
    def get_xrefs_to(self, ea, only_code=False):
        res = list(idautils.XrefsTo(ea))
        return [ r.frm for r in res if not only_code or r.iscode ]

    def get_xrefs_from(self, ea, only_code=False):
        res = list(idautils.XrefsFrom(ea))
        return [ r.to for r in res if not only_code or r.iscode ]

    def get_relative_head(self, ea, delta : int = 0):
        res = ea
        if delta < 0:
            for _ in range(abs(delta)):
                res = idc.prev_head(res)
        else:
            for _ in range(abs(delta)):
                res = idc.next_head(res)
        return res

    def get_operand_value(self, ea, position):
        return idc.get_operand_value(ea, position)

    def get_insn_bytes(self, ea):
        return idc.get_bytes(ea,idc.get_item_size(ea))
