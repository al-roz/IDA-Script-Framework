import logging

import ida_bytes
import ida_funcs
import ida_hexrays
import ida_ua
import idaapi
import idautils
import idc

from IDA import patcher

import IDA.bytes

import AbstructAPI.analyze


class OperandItem(AbstructAPI.analyze.OperandItem):

    def __init__(self, op):
        self.op: ida_ua.op_t = op

    def is_type(self, otype):
        return self.op.type == otype

    def is_reg(self, reg):
        return self.op.reg == reg


class InstructionItem(AbstructAPI.analyze.InstructionItem):
    __JMPS = [idaapi.NN_jmp, idaapi.NN_jmpfi, idaapi.NN_jmpni]
    __IF_JMPS = [idaapi.NN_ja, idaapi.NN_jae, idaapi.NN_jb, idaapi.NN_jbe, idaapi.NN_jcxz, idaapi.NN_jecxz,
                 idaapi.NN_jg, idaapi.NN_jge, idaapi.NN_jl, idaapi.NN_jle, idaapi.NN_jnb,
                 idaapi.NN_jnbe, idaapi.NN_jnc, idaapi.NN_jne, idaapi.NN_jng, idaapi.NN_jnge, idaapi.NN_jnl,
                 idaapi.NN_jnle, idaapi.NN_jno, idaapi.NN_jnp, idaapi.NN_jns, idaapi.NN_jnz, idaapi.NN_jo, idaapi.NN_jp,
                 idaapi.NN_jpe, idaapi.NN_jpo, idaapi.NN_js, idaapi.NN_jz, idaapi.NN_ja, idaapi.NN_jb]
    __CALLS = [idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni]

    def __init__(self, addr):
        self.insn_item: ida_ua.insn_t = ida_ua.insn_t()
        self.size = ida_ua.decode_insn(self.insn_item, addr)
        self.disasm = idc.generate_disasm_line(addr, 0)
        self.start_addr = addr
        self.end_addr = self.start_addr + self.size
        self.mnem = idc.print_insn_mnem(addr)
        self.inst_bytes = []
        self.original_bytes = []

        self.ops: list[OperandItem] = []
        self.ops_count = 0
        for op in self.insn_item.ops:
            if op.type != ida_ua.o_void:
                self.ops_count += 1
                self.ops.append(OperandItem(op))
            else:
                break

        for i in range(self.size):
            self.inst_bytes.append(IDA.bytes.read_byte(self.start_addr + i))

        for i in range(self.size):
            self.original_bytes.append(ida_bytes.get_original_byte(self.start_addr + i))

    def get_op_value(self, op_number):
        if op_number >= self.ops_count:
            logging.error('op number more then op counts')
            logging.error(self)
            return None

        return idc.get_operand_value(self.start_addr, op_number)

    def is_cf_change_jmp(self):
        if self.insn_item.itype in self.__JMPS:
            return True
        else:
            return False

    def is_cf_change_call(self):
        if self.insn_item.itype in self.__CALLS:
            return True
        else:
            return False

    def is_cf_change_if_jmp(self):
        if self.insn_item.itype in self.__IF_JMPS:
            return True
        else:
            return False

    def nop_this_instruction(self):
        patcher.nop_range(self.start_addr, self.size)
        for i in range(self.size):
            ida_ua.create_insn(self.start_addr + i, None)

    def is_itype(self, itype):
        return self.insn_item.itype == itype

    def op(self, number):
        return self.ops[number]

    def is_code(self):
        return ida_bytes.is_code(self.start_addr)

    def set_cmt(self,cmt):
        idaapi.set_cmt(self.start_addr, cmt, True)

    def get_cmt(self):
        return idaapi.get_cmt(self.start_addr,True)

    def make_instruction(self):
        cmt = self.get_cmt()
        cur_head = ida_bytes.get_item_head(self.start_addr)
        ida_bytes.del_items(cur_head)
        size = ida_ua.create_insn(self.start_addr, None)
        if cmt is not None:
            self.set_cmt(cmt)
        return size

    def __str__(self):
        return (f'ADDR : {hex(self.start_addr)}\n'
                f'---line : {self.disasm}\n'
                f'---operands count : {self.ops_count}\n'
                f'---size : {self.size}\n'
                f'___________________________________________'
                )

    def test(self):
        d: ida_ua.op_t = self.insn_item.ops[0]


class CFunctionItem(AbstructAPI.analyze.CFunctionItem):
    def __init__(self, addr):
        self.cfunc = ida_hexrays.decompile(addr)
        if self.cfunc is None:
            logging.error(f'CFunction item create error {hex(addr)}')

    def get_user_cmt(self):
        result: list[str] = []
        for cmt in self.cfunc.user_cmts:
            result.append(self.cfunc.get_user_cmt(cmt, 1))
        return result

    def set_user_cmt(self, addr, cmt):
        tl = idaapi.treeloc_t()
        tl.ea = addr
        tl.itp = idaapi.ITP_SEMI
        self.cfunc.set_user_cmt(tl, cmt)
        self.cfunc.save_user_cmts()
        self.cfunc.refresh_func_ctext()

    def get_ptr_on_func(self):
        tinfo = idaapi.tinfo_t()
        self.cfunc.get_func_type(tinfo)
        ptr_tif = idaapi.tinfo_t()
        ptr_tif.create_ptr(tinfo)
        return ptr_tif

    def test(self):
        ida_hexrays.treeloc_t()

        self.cfunc.refresh_func_ctext()


class FunctionItem(AbstructAPI.analyze.FunctionItem):
    def __init__(self, addr: int):
        self.func_item: ida_funcs.func_t = ida_funcs.get_func(addr)
        if self.func_item is None:
            logging.error(f'Function item create error {hex(addr)}')
            return

        self.start_addr = self.func_item.start_ea
        self.end_addr = self.func_item.end_ea
        self.name = ida_funcs.get_func_name(addr)

        self.insn_list: list[InstructionItem] = []
        for cur_insn in list(idautils.FuncItems(self.start_addr)):
            self.insn_list.append(InstructionItem(cur_insn))

    def get_list_call_cf_changed(self):
        result: list[InstructionItem] = []
        for cur_insn in self.insn_list:
            if cur_insn.is_cf_change_call():
                result.append(cur_insn)
        return result

    def get_list_jmp_cf_changed(self):
        result: list[InstructionItem] = []
        for cur_insn in self.insn_list:
            if cur_insn.is_cf_change_jmp():
                result.append(cur_insn)
        return result

    def get_list_data_insn(self):
        result: list[InstructionItem] = []
        for cur_insn in self.insn_list:
            if cur_insn.ops_count == 2 and cur_insn.op(1).is_type(ida_ua.o_mem):
                val = cur_insn.get_op_value(1)
                print(cur_insn)
        return result

    def get_list_str(self):
        result = []
        for ref in self.get_list_xref_from():
            str_type = idc.get_str_type(ref)
            if str_type is not None:
                size = ida_bytes.get_max_strlit_length(ref, str_type)
                result.append(str(ida_bytes.get_strlit_contents(ref, size, str_type)))
        return result

    def get_list_cmt(self):
        func_cmt = idc.get_func_cmt(self.start_addr, 1)
        asm_cmt = []
        for cur_ins in self.insn_list:
            cmt: str = idc.get_cmt(cur_ins.start_addr, 1)
            if cmt is not None:
                asm_cmt.append(cmt)
        decompile_cmt = self.get_decompile().get_user_cmt()
        return {'func_cmt': func_cmt, 'asm_cmt': asm_cmt, 'decompile_cmt': decompile_cmt}

    def get_function_info(self):
        cmt = self.get_list_cmt()
        funcs_list = self.get_list_call_cf_changed()
        jmps_list = self.get_list_jmp_cf_changed()
        strs = self.get_list_str()
        funcs = []
        for i in funcs_list:
            func_name = idc.get_name(i.get_op_value(0))
            if func_name != '':
                funcs.append(func_name)
            else:
                funcs.append(i.disasm)

        jmps = []
        for i in jmps_list:
            func_name = idc.get_name(i.get_op_value(0))
            if func_name != '':
                jmps.append(func_name)
            else:
                jmps.append(i.disasm)

        return {'calls': funcs, 'jmps': jmps, 'strs': strs, 'cmts': cmt}

    def get_list_xref_from(self):
        result = []
        for cur_insn in self.insn_list:
            refs = idautils.DataRefsFrom(cur_insn.start_addr)
            for ref in refs:
                result.append(ref)
        return result

    def get_decompile(self):
        return CFunctionItem(self.start_addr)

    def get_cmt(self):
        return idc.get_func_cmt(self.start_addr, 1)

    def set_cmt(self, cmt):
        return idc.set_func_cmt(self.start_addr, cmt, 1)

    def set_name(self, func_name):
        result = idc.set_name(self.start_addr, func_name, idc.SN_NOWARN)
        if result is False:
            for i in range(1, 1000):
                result = idc.set_name(self.start_addr, f'{func_name}_{i}', idc.SN_NOWARN)
                if result is True:
                    break
        return result

    def del_func(self):
        ida_funcs.del_func(self.start_addr)

    def set_func_end_addr(self, new_end_addr):
        ida_funcs.set_func_end(self.start_addr, new_end_addr)

    def append_func_tail(self, new_tail_start, new_tail_end):
        res = ida_funcs.append_func_tail(self.func_item, new_tail_start,new_tail_end)
        if res :
            self.set_func_end_addr(new_tail_end)
        return res



    def get_name(self):
        return idc.get_func_name(self.start_addr)

    def __str__(self):
        return (f'FUNC NAME: {self.name}\n'
                f'---start addr :  {hex(self.start_addr)}\n'
                f'---end addr :  {hex(self.end_addr)}\n'
                f'___________________________________________')
