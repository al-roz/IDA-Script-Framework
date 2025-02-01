import ida_ida
import idaapi
import ida_idaapi
import ida_loader
import idautils


def get_ptr_size():
    is_x64 = ida_ida.idainfo_is_64bit()
    if is_x64:
        return 8
    else:
        return 4


def get_file_path():
    inf: idaapi.idainfo = idaapi.get_inf_structure()
    path = ida_loader.get_path(ida_loader.PATH_TYPE_CMD)
    return path


def get_arh():
    return ida_ida.idainfo_is_64bit()


def get_file_type():
    return ida_loader.get_file_type_name()


def get_func_list():
    func_list = list(idautils.Functions())
    return func_list


def get_image_base():
    return idaapi.get_imagebase()
