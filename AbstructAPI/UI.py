import abc

import ida_kernwin


class View(metaclass=abc.ABCMeta):
    @staticmethod
    @abc.abstractmethod
    def set_color(addr, color):
        pass

    @staticmethod
    @abc.abstractmethod
    def highlight_control_flow_changed_insn(func_addr):
        pass

    @staticmethod
    @abc.abstractmethod
    def del_highlight(func_addr):
        pass


class ViewItem(metaclass=abc.ABCMeta):
    def __init__(self):
        pass


# class DialogItem(ida_kernwin.Form, metaclass=abc.ABCMeta):
#     def __init__(self, form, fields):
#         ida_kernwin.Form.__init__(form, fields)
