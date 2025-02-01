import ida_hexrays
import ida_lines
import idc
import ida_pro


class StrItme:
    def __init__(self, addr=None, value=None, ea_type=None):
        self.addr = addr
        self.value = value
        self.ea_type = ea_type


class AsgItem:
    def __init__(self, expr: ida_hexrays.cexpr_t):
        self.asg_expr = expr

    def get_left(self):
        return self.asg_expr.x

    def get_right(self):
        return self.asg_expr.y


class VarItem:
    def __init__(self, var: ida_hexrays.cexpr_t):
        self.var = var
        self.var_ref: ida_hexrays.var_ref_t = self.var.v

    def get_asg_node(self):
        cfunc = ida_hexrays.decompile(self.var.ea)
        parent_exp: ida_hexrays.citem_t = cfunc.body.find_parent_of(self.var)

        while parent_exp is not None:
            if parent_exp.op == ida_hexrays.cot_asg:
                print('cur_asg:', hex(parent_exp.cexpr.obj_id))
                parent_var: ida_hexrays.var_ref_t = parent_exp.cexpr.x.v
                if parent_var is not None:
                    parent_var: ida_hexrays.var_ref_t
                    if parent_var.idx == self.var_ref.idx:
                        return AsgItem(parent_exp.cexpr)
            parent_exp = cfunc.body.find_parent_of(parent_exp)

        return None

    def foo(self):
        return self.var.obj_id


class CallArgument:
    def __init__(self, arg: ida_hexrays.carg_t):
        self.arg = arg
        self.sub_tree = SubCtreeVisitor()
        self.sub_tree.apply_to(self.arg, None)
        self.last: ida_hexrays.cexpr_t = self.sub_tree.collected_instructions[-1]

    def is_str(self):
        return self.last.is_cstr() or self.last.op == ida_hexrays.cot_str or self.last.op == ida_hexrays.cot_obj

    def is_num(self):
        return self.arg.op is ida_hexrays.cot_num

    def get_print_value(self):
        return ida_pro.str2user(ida_lines.tag_remove(self.arg.print1(None)))

    def to_str_item(self):
        if self.last.op == ida_hexrays.cot_obj:
            return StrItme(self.last.obj_ea, self.get_print_value(), ida_hexrays.cot_obj)
        if self.last.op == ida_hexrays.cot_str:
            return StrItme(self.last.ea, self.last.string, ida_hexrays.cot_str)
        return None

    def to_var_item(self):
        return VarItem(self.arg)


class ASTCallItem:
    def __init__(self, expr: ida_hexrays.cexpr_t):
        self.expr: ida_hexrays.cexpr_t = expr
        self.func: ida_hexrays.cexpr_t = expr.x

        args: ida_hexrays.carglist_t = expr.a
        self.args: list[CallArgument] = []
        for arg in args:
            self.args.append(CallArgument(arg))

    def get_args_count(self):
        return len(self.args)

    def get_arg(self, number):
        return self.args[number]

    def get_called_addr(self):
        return self.func.obj_ea

    def get_name(self):
        if self.func.op == ida_hexrays.cot_obj:
            return idc.get_name(self.get_called_addr())
        if self.func.op == ida_hexrays.cot_helper:
            return self.func.helper

    def get_args(self):
        return self.args


class ASTForItem:
    def __init__(self, expr: ida_hexrays.cfor_t):
        self.for_expr = expr
        sub_tree = SubCtreeVisitor()
        sub_tree.apply_to(self.for_expr.body, None)
        self.items: list[ida_hexrays.cexpr_t] = sub_tree.collected_instructions

    def get_init(self):
        return self.for_expr.init

    def get_step(self):
        return self.for_expr.step

    def get_end(self):
        return self.for_expr.expr

    def get_body(self):
        return self.for_expr.body


class CallCtreeVisitor(ida_hexrays.ctree_visitor_t):
    def __init__(self, cfunc: ida_hexrays.cfunc_t):
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
        self.cfunc = cfunc
        self.func_calls: list[ASTCallItem] = []

    def visit_expr(self, expr):
        if expr.op == ida_hexrays.cot_call:
            self.func_calls.append(ASTCallItem(expr))
        return 0

    def get_all_calls(self):
        self.func_calls.clear()
        self.apply_to(self.cfunc.body, None)
        return self.func_calls


class ForCtreeVisitor(ida_hexrays.ctree_visitor_t):
    def __init__(self, cfunc: ida_hexrays.cfunc_t):
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
        self.cfunc = cfunc
        self.func_fors: list[ASTForItem] = []

    # def visit_expr(self, expr):
    #     if expr.op == ida_hexrays.cit_for:
    #         print('asdasdads')
    #         self.func_fors.append(ASTForItem(expr))
    #     return 0

    def visit_insn(self, expr: ida_hexrays.cinsn_t):
        if expr.op == ida_hexrays.cit_for:
            print('asdasdads')
            self.func_fors.append(ASTForItem(expr.cfor))
        return 0

    def get_all_fors(self):
        self.func_fors.clear()
        self.apply_to(self.cfunc.body, None)
        return self.func_fors


class SubCtreeVisitor(ida_hexrays.ctree_visitor_t):
    def __init__(self):
        super(SubCtreeVisitor, self).__init__(ida_hexrays.CV_FAST)
        self.collected_instructions = []

    def visit_expr(self, expr):
        self.collected_instructions.append(expr)
        return 0


class FindInitVar(ida_hexrays.ctree_visitor_t):
    def __init__(self, var: ida_hexrays.cexpr_t):
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
        self.target_var = var
        self.init_expr: list[ida_hexrays.cexpr_t] = []

    def visit_expr(self, expr: ida_hexrays.cexpr_t):
        if expr.op == ida_hexrays.cot_asg:
            s = SubCtreeVisitor()
            s.apply_to(expr.x, None)
            inst_tree = s.collected_instructions
            last: ida_hexrays.cexpr_t = inst_tree[-1]
            if last.op == ida_hexrays.cot_var:
                if last.v.idx == self.target_var.v.idx:
                    self.init_expr.append(expr)
        return 0

# c = ida_hexrays.decompile(here())
# v = CallCtreeVisitor(c)
# calls = v.get_all_calls()
#
# for cur_call in calls:
#     print(cur_call.get_name(), hex(cur_call.get_called_addr()), cur_call.get_args_count())
#     args = cur_call.get_args()
#     for arg in args:
#         print(arg.get_print_value(), arg.is_str())
#         if arg.is_str():
#             str_obj = arg.to_str_item()
#             print(str_obj.value)
#     print('______________________')
#
# # f = ForCtreeVisitor(c)
# # fors = f.get_all_fors()
# #
# # for i in fors:
# #     print(i)
#
# #
# for cur_call in calls:
#     if cur_call.get_called_addr() == 0x140004008:
#         print(cur_call.get_name(), cur_call.get_called_addr(), cur_call.get_args_count())
#         arg = cur_call.get_arg(0)
#         var = arg.to_var_item()
#         print(var)
#         print(var.foo())
#         v : ida_hexrays.var_ref_t = var.var.get_v()
#         print(v.idx)
#         f = FindInitVar(var.var)
#         f.apply_to(c.body, None)
#         l = f.init_expr
#         print(l)
#         print(l[0].obj_id)
#         print(l[0].y.print1(None))
#         #print(asg.asg_expr.print1(None))
#         #print(hex(asg.asg_expr.obj_id))
#
# # c = ida_hexrays.decompile(here())
# # v = ForCtreeVisitor(c)
# # fors = v.get_all_fors()
# # print(fors)
# #
# # for i in fors:
# #     print(i.items)
#
