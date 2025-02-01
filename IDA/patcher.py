import idaapi
import idc
import ida_hexrays


def nop_range(addr, size):
    for i in range(size):
        idc.patch_byte(addr + i, 0x90)


def decode_xor(addr: int, size: int, key):
    for i in range(size):
        cur_byte = idaapi.get_byte(addr + i)
        idc.patch_byte(addr + i, cur_byte ^ key[i % len(key)])
