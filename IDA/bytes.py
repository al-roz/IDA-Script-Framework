import ida_ida
import idaapi


def read_ptr(addr):
    is_x64 = ida_ida.idainfo_is_64bit()
    if is_x64:
        return idaapi.get_qword(addr)
    else:
        return idaapi.get_dword(addr)


def read_byte(addr):
    return idaapi.get_byte(addr)


def read_word(addr):
    return idaapi.get_word(addr)


def read_dword(addr):
    return idaapi.get_dword(addr)


def read_qword(addr):
    return idaapi.get_qword(addr)


def create_name_to_addr(addr, name):
    idaapi.set_name(addr, name)


def make_ptr(addr):
    is_x64 = ida_ida.idainfo_is_64bit()
    if is_x64:
        return idaapi.create_qword(addr, 8, True)
    else:
        return idaapi.create_dword(addr, 4, True)
