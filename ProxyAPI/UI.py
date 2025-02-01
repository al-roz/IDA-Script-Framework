import AbstructAPI.UI
import IDA.UI


class View(AbstructAPI.UI.View):
    __view_instance = IDA.UI.View

    @staticmethod
    def set_color(addr, color):
        View.__view_instance.set_color(addr, color)

    @staticmethod
    def highlight_control_flow_changed_insn(func_addr):
        View.__view_instance.highlight_control_flow_changed_insn(func_addr)

    @staticmethod
    def del_highlight(func_addr):
        View.__view_instance.del_highlight(func_addr)
