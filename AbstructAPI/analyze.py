import abc


class OperandItem(metaclass=abc.ABCMeta):

    @abc.abstractmethod
    def is_type(self, otype):
        pass

    @abc.abstractmethod
    def is_reg(self, reg):
        pass


class CFunctionItem(metaclass=abc.ABCMeta):

    @abc.abstractmethod
    def get_user_cmt(self):
        pass

    @abc.abstractmethod
    def set_user_cmt(self, addr, cmt):
        pass

    @abc.abstractmethod
    def get_ptr_on_func(self):
        pass


class InstructionItem(metaclass=abc.ABCMeta):

    @abc.abstractmethod
    def get_op_value(self, op_number):
        pass

    @abc.abstractmethod
    def is_cf_change_jmp(self):
        pass

    @abc.abstractmethod
    def is_cf_change_call(self):
        pass

    @abc.abstractmethod
    def nop_this_instruction(self):
        pass

    @abc.abstractmethod
    def is_itype(self, itype):
        pass

    @abc.abstractmethod
    def op(self, number):
        pass

    @abc.abstractmethod
    def __str__(self):
        pass


class FunctionItem(metaclass=abc.ABCMeta):

    @abc.abstractmethod
    def get_list_call_cf_changed(self):
        pass

    @abc.abstractmethod
    def get_list_jmp_cf_changed(self):
        pass

    @abc.abstractmethod
    def get_list_data_insn(self):
        pass

    @abc.abstractmethod
    def get_list_str(self):
        pass

    @abc.abstractmethod
    def get_list_cmt(self):
        pass

    @abc.abstractmethod
    def get_function_info(self):
        pass

    @abc.abstractmethod
    def get_list_xref_from(self):
        pass

    @abc.abstractmethod
    def get_decompile(self):
        pass

    @abc.abstractmethod
    def get_cmt(self):
        pass

    @abc.abstractmethod
    def set_cmt(self, cmt):
        pass

    @abc.abstractmethod
    def set_name(self, func_name):
        pass

    @abc.abstractmethod
    def get_name(self):
        pass

    @abc.abstractmethod
    def __str__(self):
        pass
