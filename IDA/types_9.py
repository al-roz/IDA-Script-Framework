import ida_bytes
import ida_idp
import ida_typeinf
import idaapi
import idc


import Utils.structs
import IDA.bytes
import IDA.info

import AbstructAPI.types


def create_type_info_by_str(type):
    type_info = ida_typeinf.tinfo_t()
    parsed = type_info.get_named_type(None, type)
    ida_typeinf.parse_decl(type_info, None, type, ida_typeinf.PT_TYP | ida_typeinf.PT_SIL)
    return type_info


def apply_type_to_memory(addr, struct_name):
    struct_tid: idaapi.tinfo_t = idaapi.get_named_type_tid(struct_name)
    struct_size = struct_tid.get_size()
    idaapi.create_struct(addr, struct_size, struct_tid, True)


def is_struct_exist(struct_name):
    struct_tid: idaapi.tinfo_t = idaapi.get_named_type_tid(struct_name)
    return struct_tid != idaapi.BADADDR


class Struct(AbstructAPI.types.Struct):
    def __init__(self, struct_name):
        self.struct_tid: int = idaapi.get_named_type_tid(struct_name)

        if self.struct_tid == idaapi.BADADDR:
            empty_udt = ida_typeinf.udt_type_data_t()
            self.struct_tif = ida_typeinf.tinfo_t.create_udt(None)
            self.struct_tid = idaapi.get_named_type_tid(struct_name)

        self.struct_tif = ida_typeinf.tinfo_t()

        self.struct_udt = ida_typeinf.udt_type_data_t()
        self.struct_tif.get_named_type(None, struct_name)
        self.struct_tif.get_udt_details(self.struct_udt)

        print(self.struct_tif.get_size(), self.struct_tif.get_type_name())

        self._size = self.struct_tif.get_size()

    def append(self, name, inf: ida_typeinf.tinfo_t):
        new_member = ida_typeinf.udm_t()
        new_member.name = name
        new_member.type = inf

        self.struct_tif.add_udm(new_member)
        self.struct_tif.save_type()
        self._size = self.struct_tif.get_size()

    def rename(self, new_name):
        self.struct_tif.rename_type(new_name)

    def size(self):
        self._size = self.struct_tif.get_size()
        return self._size

    def insert(self, offset, inf: ida_typeinf.tinfo_t):
        members = []
        cur_offset = 0x0
        struct_size = self.size()

    def clear(self):
        pass

    def set_cmt(self, cmt):
        self.struct_tif.set_type_cmt(cmt)

# class StructMember:
#     def __init__(self, struc_item: Struct, offset):
#         self.StructItem = struc_item
#         self.struct: idaapi.tinfo_t = struc_item.struct_tid
#         self.offset = offset
#         self.member_tid : idaapi.tinfo_t = self.struct.get_udm_tid(offset)
#         self.member_t: ida_struct.member_t = self.struct.get_udm()
#         self._name = ida_struct.get_member_name(self.member_t.id)
#         self._size = ida_struct.get_member_size(self.member_t)
#         self.type_t = ida_typeinf.tinfo_t()
#         ida_struct.get_member_tinfo(self.type_t, self.member_t)
#         self.cmt = ida_struct.get_member_cmt(self.member_t.id, True)
#
#     def set_cmt(self, cmt):
#         res = ida_struct.set_member_cmt(self.member_t, cmt, True)
#         print(f'set_cmt {cmt} : {res}')
#         return res
#
#     def get_cmt(self):
#         self.cmt = ida_struct.get_member_cmt(self.member_t.id, True)
#         return self.cmt
#
#     def size(self):
#         self._size = ida_struct.get_member_size(self.member_t)
#         return self._size
#
#     def set_name(self, new_name):
#         ida_struct.set_member_name(self.struct, self.offset, new_name)
#
#     def set_type(self, new_type):
#         ida_struct.set_member_tinfo(self.struct, self.member_t, self.offset, new_type, True)
