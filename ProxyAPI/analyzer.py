import AbstructAPI.analyze
import IDA.analyzer


class OperandItem(AbstructAPI.analyze.OperandItem):
    def __init__(self, op):
        self.instance = IDA.analyzer.OperandItem(op)

    def is_type(self, otype):
        return self.instance.is_type(otype)

    def is_reg(self, reg):
        return self.instance.is_reg(reg)


class InstructionItem(AbstructAPI.analyze.InstructionItem):
    def __init__(self, addr):
        self.instance = IDA.analyzer.InstructionItem(addr)

    def get_op_value(self, op_number):
        return self.instance.get_op_value(op_number)

    def is_cf_change_jmp(self):
        return self.instance.is_cf_change_jmp()

    def is_cf_change_call(self):
        return self.instance.is_cf_change_call()

    def nop_this_instruction(self):
        self.instance.nop_this_instruction()

    def is_itype(self, itype):
        return self.instance.is_itype(itype)

    def op(self, number):
        return self.instance.op(number)

    def __str__(self):
        return self.instance.__str__()


class CFunctionItem(AbstructAPI.analyze.CFunctionItem):

    def __init__(self, addr):
        self.instance = IDA.analyzer.CFunctionItem(addr)

    def get_user_cmt(self):
        return self.instance.get_user_cmt()

    def set_user_cmt(self, addr, cmt):
        self.instance.set_user_cmt(addr, cmt)

    def get_ptr_on_func(self):
        return self.instance.get_ptr_on_func()


class FunctionItem(AbstructAPI.analyze.FunctionItem):

    def __init__(self, addr):
        self.instance = IDA.analyzer.FunctionItem(addr)

    def get_list_call_cf_changed(self):
        return self.instance.get_list_call_cf_changed()

    def get_list_jmp_cf_changed(self):
        return self.instance.get_list_jmp_cf_changed()

    def get_list_data_insn(self):
        return self.instance.get_list_data_insn()

    def get_decompile(self):
        return self.instance.get_decompile()

    def get_list_str(self):
        return self.instance.get_list_str()

    def get_list_cmt(self):
        return self.instance.get_list_cmt()

    def get_function_info(self):
        return self.instance.get_function_info()

    def get_list_xref_from(self):
        return self.instance.get_list_xref_from()

    def get_cmt(self):
        return self.instance.get_cmt()

    def set_cmt(self, cmt):
        return self.instance.set_cmt(cmt)

    def set_name(self, func_name):
        return self.instance.set_name(func_name, )

    def get_name(self):
        return self.instance.get_name()

    def __str__(self):
        return self.instance.__str__()
