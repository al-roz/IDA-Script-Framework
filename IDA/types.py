import ida_bytes
import ida_idp
import ida_struct
import ida_typeinf
import idaapi
import idc

import Utils.structs
import IDA.bytes
import IDA.info

import AbstructAPI.types


def init_standard_types():
    pass


def get_type_flag(type: str):
    if type == 'BYTE':
        return idc.FF_BYTE
    if type == 'WORD':
        return idc.FF_WORD
    if type == 'DWORD':
        return idc.FF_DWORD
    if type == 'PVOID':
        if IDA.info.get_ptr_size() == 8:
            return idc.FF_QWORD
        else:
            return idc.FF_DWORD
    if type.index('char') != -1:
        return idc.FF_STRLIT
    return idc.FF_UNK


def get_str_type(type):
    if type == 'char':
        return idc.STRTYPE_C
    if type == 'wchar':
        return idc.STRTYPE_C_16
    if type == 'pascal char':
        return idc.STRTYPE_PASCAL
    if type == 'pascal wchar':
        return idc.STRTYPE_PASCAL_16

    return idc.STRTYPE_C


def create_type_info_by_str(type):
    type_info = ida_typeinf.tinfo_t()
    parsed = type_info.get_named_type(None, type)
    ida_typeinf.parse_decl(type_info, None, type, ida_typeinf.PT_TYP | ida_typeinf.PT_SIL)
    return type_info


def get_ptr_on_lib_func(func_name):
    t = idaapi.get_named_type(None, func_name, 0)
    func_tif = idaapi.tinfo_t()
    func_tif.deserialize(None, t[1], t[2])

    ptr_import_tif = idaapi.tinfo_t()
    ptr_import_tif.create_ptr(func_tif)


def change_member_to_ptr(struct_name, member_name):
    sid = idaapi.get_struc_id(struct_name)
    struct = idaapi.get_struc(sid)
    member = idaapi.get_member_by_name(struct, member_name)

    type_info = idaapi.tinfo_t()
    type_info.create_ptr(idaapi.tinfo_t(idaapi.BT_INT))


def create_struct(struct_name, fields: list[Utils.structs.Field]):
    fields = sorted(fields, key=lambda field: field.offset)
    struct_id = idc.add_struc(-1, struct_name, 0)

    if struct_id == idaapi.BADADDR:
        return False

    for field in fields:
        flag = get_type_flag(field.type)
        type = -1
        if flag == idc.FF_STRLIT:
            type = get_str_type(field.type)
        idc.add_struc_member(struct_id, field.name, field.offset, idc.FF_DATA | flag, type, field.size)

    return True


def apply_type_to_memory(addr, struct_name):
    sid = idaapi.get_struc_id(struct_name)
    struc = idaapi.get_struc(sid)
    struct_size = idaapi.get_struc_size(struc.id)
    idaapi.create_struct(addr, struct_size, sid, True)


def is_struct_exist(struct_name):
    sid = idaapi.get_struc_id(struct_name)
    return sid != idaapi.BADADDR


class Struct(AbstructAPI.types.Struct):
    def __init__(self, struct_name):
        self.sid = idaapi.get_struc_id(struct_name)
        if self.sid == idaapi.BADADDR:
            self.sid = idc.add_struc(-1, struct_name, 0)
        self.struc: ida_struct.struc_t = idaapi.get_struc(self.sid)
        self._size = idaapi.get_struc_size(self.struc.id)

    def append(self, name, inf: ida_typeinf.tinfo_t):
        res = ida_struct.add_struc_member(self.struc, name, idc.BADADDR, idaapi.FF_DATA, None, inf.get_size())
        if res == idaapi.STRUC_ERROR_MEMBER_OK:
            self._size = idaapi.get_struc_size(self.struc)
            cur_mem = idaapi.get_member_by_name(self.struc, name)
            idaapi.set_member_tinfo(self.struc, cur_mem, 0, inf, 0)

    def rename(self, new_name):
        ida_struct.set_struc_name(self.sid, new_name)

    def size(self):
        self._size = idaapi.get_struc_size(self.struc.id)
        return self._size

    def insert(self, offset, inf: ida_typeinf.tinfo_t):
        members = []
        cur_offset = 0x0
        struct_size = self.size()
        while cur_offset < struct_size:
            mem = StructMember(self.struc, cur_offset)
            print(mem.offset, mem._name, mem._size, mem.cmt, mem.type_t)
            cur_offset += mem._size

    def clear(self):
        ida_struct.del_struc_members(self.struc, 0, self.size())

    def set_cmt(self):
        ida_struct.set_struc_cmt()


class StructMember:
    def __init__(self, struc_item: Struct, offset):
        self.StructItem = struc_item
        self.struct: ida_struct.struc_t = struc_item.struc
        self.offset = offset
        self.member_t: ida_struct.member_t = ida_struct.get_member(self.struct, self.offset)
        self._name = ida_struct.get_member_name(self.member_t.id)
        self._size = ida_struct.get_member_size(self.member_t)
        self.type_t = ida_typeinf.tinfo_t()
        ida_struct.get_member_tinfo(self.type_t, self.member_t)
        self.cmt = ida_struct.get_member_cmt(self.member_t.id, True)

    def set_cmt(self, cmt):
        res = ida_struct.set_member_cmt(self.member_t, cmt, True)
        print(f'set_cmt {cmt} : {res}')
        return res

    def get_cmt(self):
        self.cmt = ida_struct.get_member_cmt(self.member_t.id, True)
        return self.cmt

    def size(self):
        self._size = ida_struct.get_member_size(self.member_t)
        return self._size

    def set_name(self, new_name):
        ida_struct.set_member_name(self.struct, self.offset, new_name)

    def set_type(self, new_type):
        ida_struct.set_member_tinfo(self.struct, self.member_t, self.offset, new_type, True)
