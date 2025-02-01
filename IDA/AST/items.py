class CallArgument:
    def __init__(self, arg: ida_hexrays.carg_t):
        self.arg = arg

    def is_str(self):
        return self.arg.is_cstr()

    def is_num(self):
        return self.arg.op is ida_hexrays.cot_num

    def get_print_value(self):
        return ida_lines.tag_remove(self.arg.print1(None))

    def get_str_addr(self):
        return self.arg.obj_ea

    def get_parent_node(self):
        c = ida_hexrays.cfunc(self.arg.ea)
        print(c.body)



class ASTCallItem:
    def __init__(self, expr: ida_hexrays.cexpr_t):
        self.expr: ida_hexrays.cexpr_t = expr

        args: ida_hexrays.carglist_t = expr.a
        self.args: list[CallArgument] = []
        for arg in args:
            self.args.append(CallArgument(arg))

    def get_args_count(self):
        return len(self.args)

    def get_arg(self, number):
        return self.args[number]

    def get_called_addr(self):
        return self.expr.x.obj_ea

    def get_name(self):
        return idc.get_name(self.get_called_addr())

    def get_args(self):
        return self.args