import IDA.bytes


def read_ptr(addr):
    return IDA.bytes.read_ptr(addr)


def read_byte(addr):
    return IDA.bytes.read_byte(addr)


def read_word(addr):
    return IDA.bytes.read_word(addr)


def read_dword(addr):
    return IDA.bytes.read_dword(addr)


def read_qword(addr):
    return IDA.bytes.read_qword(addr)


def create_name_to_addr(addr, name, force=False):
    if addr != 0 or force:
        IDA.bytes.create_name_to_addr(addr, name)


def make_ptr(addr):
    IDA.bytes.make_ptr(addr)
