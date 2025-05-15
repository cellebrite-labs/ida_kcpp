import ida_hexrays
import ida_idaapi
import ida_idp
import ida_kernwin
import ida_moves
import ida_name
import ida_struct
import ida_typeinf
import idaapi

from . import logic, ui_utils, utils


class HexraysDoubleClickHook(ida_hexrays.Hexrays_Hooks):
    def __init__(self):
        super().__init__()
        self.vu = None

    def double_click(self, vu, shift):
        self.vu = vu
        if not (vu.item and vu.item.is_citem()):
            return 0
        result = logic.find_vtable_funcptr_from_expr(vu.item.e)
        if not result:
            return 0
        class_name, offset_in_vtable = result
        return jump_to_virtual_func(class_name, offset_in_vtable)


class VirtualFunctionChooser(ui_utils.Choose):
    def __init__(self, items):
        super().__init__("Choose a Virtual function...", items, [
            ["Class", 30 | self.CHCOL_PLAIN],
            ["Function name", 40 | self.CHCOL_FNAME],
            ["Address", 20 | self.CHCOL_HEX],
        ])


def jump_to_virtual_func(ancestor_name, offset_in_vtable):
    functions_table = logic.gather_funcs_from_descendants(ancestor_name, offset_in_vtable)
    vtable_func = ida_idaapi.BADADDR
    if not functions_table:
        return 0
    elif len(functions_table) == 1:
        _, vtable_func = functions_table[0]
    else:
        prepared_data = []
        functions_set = set()
        for class_name, virtual_func in functions_table:
            functions_set.add(virtual_func)
            virtual_func_formatted = "0x%016X" % virtual_func
            func_name = ida_name.get_ea_name(virtual_func)
            func_class_name, method_name = utils.parse_mangled_method_name(func_name)
            if func_class_name:
                func_name = func_class_name + "::" + method_name
            prepared_data.append((class_name, func_name, virtual_func_formatted))
        if len(functions_set) > 1:
            vf_chooser = VirtualFunctionChooser(prepared_data)
            chosen_vf = vf_chooser.show()
            if chosen_vf:
                _, _, vtable_func_formatted = chosen_vf
                vtable_func = int(vtable_func_formatted, 16)
        else:
            (vtable_func,) = functions_set
    if vtable_func != ida_idaapi.BADADDR:
        ida_kernwin.jumpto(vtable_func)
        return 1
    return 0


class VirtualFuncsSynchronizer(ida_idp.IDB_Hooks):
    def renamed(self, ea, new_name, local_name, old_name):
        if utils.is_func_start(ea):
            if "::" in new_name:
                self.unhook()
                class_name, method_name = new_name.split("::")
                full_name = utils.generate_method_name(class_name, method_name)
                utils.set_func_name(ea, full_name)
            else:
                class_name, method_name = utils.parse_mangled_method_name(new_name)
                if class_name is None:
                    # Case only actual method name was assigned without class prefix
                    if ea not in logic.vfunc_to_vmethod:
                        return
                    vfunc_metadata = logic.VFuncMetadata(*logic.vfunc_to_vmethod[ea])
                    class_name = vfunc_metadata.impl_class
                    method_name = new_name
                    full_name = utils.generate_method_name(class_name, method_name)
                    utils.set_func_name(ea, full_name)
                self.unhook()
            logic.virtual_method_renamed(ea, class_name, method_name)
            self.hook()
    
    # TODO: use lt_udm_renamed when porting to ida9
    def local_types_changed(self, ltc, ordinal, name):
        # There are two very annoying things about local_types_changed:
        #   1. the parameters tell you very little about WHAT changed.
        #      specifically, we can't really tell in which way a struct 
        #      was edited.
        #   2. this function hooks in exactly after the change starts
        #      but before it takes place. So for example if a member is
        #      modified by the user, the old name/type will still presist
        #      if this function tries to read them.
        # So in order to overcome these restrictions, we use
        # execute_ui_requests to perform the logic of this 
        # hook only AFTER the renaming/retyping takes place.
        # ...And instead of updating the functions that match
        # only the member that was modified, we update the matching
        # functions for EVERY member.
        if ltc != ida_idp.LTC_EDITED or not name.endswith("::vmethods"):
            return
        idaapi.execute_ui_requests([lambda: self._update_vmethods(name)])
    
    def _update_vmethods(self, name):
        sid = ida_struct.get_struc_id(name)
        sptr = ida_struct.get_struc(sid)
        self.unhook()
        class_name = name.split("::")[0]
        for mptr in sptr.members:
            vtable_offset = logic.find_own_vmethods_offset_in_vtable(class_name) + mptr.soff
            generic_method_name = f"method_{vtable_offset // 8}"
            logic.virtual_method_member_renamed(class_name, mptr.soff, generic_method_name)
        for mptr in sptr.members:
            member_name = ida_struct.get_member_name(mptr.id)
            logic.virtual_method_member_renamed(class_name, mptr.soff, member_name)    
            logic.virtual_method_member_prototype_changed(class_name, mptr)
        self.hook()
        
    def ti_changed(self, ea, ti_type, ti_fname):
        if not utils.is_func_start(ea):
            return
        tinfo = ida_typeinf.tinfo_t()
        tinfo.deserialize(None, ti_type, ti_fname, None)
        func_details = ida_typeinf.func_type_data_t()
        tinfo.get_func_details(func_details)
        self.unhook()
        logic.virtual_method_prototype_changed(ea, func_details)
        self.hook()


class StructsDoubleColonHooks(ida_kernwin.View_Hooks):
    def __init__(self):
        super(StructsDoubleColonHooks, self).__init__()
        self.selected_expr = None
        self.double_click_triggered = False

    def view_click(self, viewer, point):
        widget_type = ida_kernwin.get_widget_type(viewer)
        # Make sure the widget_type is of the Structures viewer
        if widget_type != 28:
            return
        if self.double_click_triggered:
            self.double_click_triggered = False
            return
        self.selected_expr = ui_utils.get_wrapped_word_from_viewer(viewer)

    def view_dblclick(self, viewer, point):
        widget_type = ida_kernwin.get_widget_type(viewer)
        # Make sure the widget_type is of the Structures viewer
        if widget_type != 28:
            return
        self.double_click_triggered = True
        if not self.selected_expr:
            return
        expr = self.selected_expr
        e = ida_moves.lochist_entry_t()
        if not ida_kernwin.get_custom_viewer_location(e, viewer):
            return
        place = e.place()
        if not place:
            return
        struct_place = place.as_structplace_t(place)

        if "::" in expr and " " not in expr:
            # Case click on struct type such as "OSObject::field"
            sid = ida_struct.get_struc_id(expr)
            if sid == ida_idaapi.BADADDR:
                return
            sidx = ida_struct.get_struc_idx(sid)
            if sid == ida_idaapi.BADADDR:
                return
            struct_place.idx = sidx
            struct_place.offset = 0
            e.set_place(struct_place)
            ida_kernwin.custom_viewer_jump(viewer, e)
            self.selected_expr = None
        else:
            sid = ida_struct.get_struc_by_idx(struct_place.idx)
            # Checking for a case click on vmethod
            if sid == ida_idaapi.BADADDR:
                return
            struct_name = ida_struct.get_struc_name(sid)
            if not struct_name.endswith("::vmethods"):
                return
            sptr = ida_struct.get_struc(sid)
            if not sptr:
                return
            member = ida_struct.get_member(sptr, struct_place.offset)
            name = ida_struct.get_member_name(member.id)
            if not name:
                return
            if name == expr:
                # clicked on method_x inside Y::vmethods
                class_name = "::".join(struct_name.split("::")[:-1])
                vmethod_offset_in_obj = logic.find_own_vmethods_offset_in_vtable(class_name) + struct_place.offset
                jump_to_virtual_func(class_name, vmethod_offset_in_obj)


def open_smart_xrefs():
    ea = ida_kernwin.get_screen_ea()
    vmethod_member_id = logic.get_member_id_for_vfunc(ea)
    if vmethod_member_id:
        ida_kernwin.open_xrefs_window(vmethod_member_id)
