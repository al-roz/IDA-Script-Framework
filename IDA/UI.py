from cgitb import handler
from dataclasses import fields

import ida_lines
import idc
import ida_kernwin

from IDA.analyzer import FunctionItem

import AbstructAPI.UI


class View(AbstructAPI.UI.View):
    @staticmethod
    def set_color(addr, color):
        return idc.set_color(addr, idc.CIC_ITEM, color)

    @staticmethod
    def highlight_control_flow_changed_insn(func_addr):
        cur_func = FunctionItem(func_addr)
        for insn in cur_func.get_list_insn_control_flow_changed():
            View.set_color(insn.start_addr, 0xe4b8ff)

    @staticmethod
    def del_highlight(func_addr):
        cur_func = FunctionItem(func_addr)
        for i in cur_func.insn_list:
            View.set_color(i.start_addr, ida_lines.COLOR_CODE)


class ViewItem:
    def __init__(self):
        pass


class DialogItem:
    def __init__(self):
        self.form = ''
        self.form_name = None
        self.controls = {}
        self.fields = []
        self.instance: ida_kernwin.Form = None

    def _construct_form(self):
        self.form = """STARTITEM """ + '{id:' + self.fields[0] + '}\n'
        self.form += "BUTTON YES* Ok\n"
        self.form += "BUTTON CANCEL Cancel\n"
        self.form += f"{self.form_name}\n"
        for item in self.fields:
            self.form += f"<#{item} #{item}\: :" + "{" + item + "}>\n"

        print(self.form)

    def init(self):
        self._construct_form()
        self.instance = ida_kernwin.Form(form=self.form, controls=self.controls)

    def start(self):
        self.instance.Compile()
        return self.instance.Execute()

    def set_form_name(self, name):
        self.form_name = name

    def add_dir_input(self, field_name):
        self.fields.append(field_name)
        self.controls[field_name] = ida_kernwin.Form.DirInput(swidth=50)

    def add_string_input(self, field_name):
        self.fields.append(field_name)
        self.controls[field_name] = ida_kernwin.Form.StringInput(swidth=50)

    def add_numeric_input(self, field_name):
        self.fields.append(field_name)
        self.controls[field_name] = ida_kernwin.Form.NumericInput(swidth=50)

    def get_value(self, filed_name):
        return self.instance.__getattribute__(filed_name).value


class ActionHandlerItem:
    class ida_action(ida_kernwin.action_handler_t):
        def __init__(self, handler):
            ida_kernwin.action_handler_t.__init__(self)
            self.handler = handler

        def update(self, ctx):
            return ida_kernwin.AST_ENABLE_ALWAYS

        def activate(self, ctx):
            return self.handler()

    def __init__(self):
        self.name = ''
        self.handler = None
        self.shortcut = ''
        self.icon = -1
        self.result = None
        self.action_lable = ''

    def set_action_name(self, action_name):
        self.name = action_name

    def set_action_text(self, action_text):
        self.action_lable = action_text

    def set_handler(self, handler):
        self.handler = ActionHandlerItem.ida_action(handler)

    def set_shortcut(self, shortcut):
        self.shortcut = shortcut

    def set_icon(self, icon_data):
        pass

    def register_action(self):
        action_descriptor = ida_kernwin.action_desc_t(
            self.name,
            self.action_lable,
            self.handler,
            self.shortcut,
            self.name,
            self.icon
        )
        if ida_kernwin.register_action(action_descriptor):
            print(f"action {self.name} registered")
        else:
            print(f"action {self.name} didn't register")

    def activate(self, ctx):
        self.handler()
        return 0

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

    def attach_to_menu(self, menu):
        if ida_kernwin.attach_action_to_menu(menu, self.name, ida_kernwin.SETMENU_INS):
            print(f"{self.name} attached")
        else:
            print(f"{self.name} didn't attache")

    def attach_to_toolbar(self):
        pass


class MenuItem:
    def __init__(self):
        self.menu_name = ''

    def set_menu_name(self, name):
        self.menu_name = name

    def create_menu(self):
        ida_kernwin.create_menu(self.menu_name, f"&{self.menu_name}", "View")

    def add_action(self):
        pass
