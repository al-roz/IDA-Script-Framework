import IDA.types


def create_struct(struct_name, fields):
    return IDA.types.create_struct(struct_name, fields)


def get_ptr_on_lib_func(func_name):
    IDA.types.get_ptr_on_lib_func(func_name)


def apply_type_to_memory(addr, struct_name):
    IDA.types.apply_type_to_memory(addr, struct_name)


def is_struct_exist(struct_name):
    return IDA.types.is_struct_exist(struct_name)
