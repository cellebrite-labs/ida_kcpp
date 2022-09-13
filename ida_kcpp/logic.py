import collections
import logging
import pathlib
import subprocess

import netnode

import ida_bytes
import ida_hexrays
import ida_idaapi
import ida_struct
import ida_typeinf
import ida_xref
from . import utils

initialized = False
logger = None
vfunc_to_vmethod = None
config = None
VFuncMetadata = collections.namedtuple('VFuncMetadata', ['impl_class', 'base_class', 'vmethod_offset', 'vtable_offset'])


def init_if_needed(only_collect=True):
    global initialized
    if initialized:
        return
    initialized = True

    # ida_kernelcache shall be imported on demand, otherwise it throws errors
    global ida_kernelcache
    import ida_kernelcache
    import ida_kernelcache.classes
    import ida_kernelcache.ida_utilities
    if only_collect:
        ida_kernelcache.collect_class_info()
    else:
        ida_kernelcache.kernelcache_process()

    global logger

    # Create a custom logger
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    # Create handlers
    c_handler = logging.StreamHandler()
    f_handler = logging.FileHandler('/tmp/ida_kcpp.log')
    c_handler.setLevel(logging.ERROR)
    f_handler.setLevel(logging.DEBUG)

    # Create formatters and add it to handlers
    c_format = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
    f_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    c_handler.setFormatter(c_format)
    f_handler.setFormatter(f_format)

    # Add handlers to the logger
    logger.addHandler(c_handler)
    logger.addHandler(f_handler)

    global vfunc_to_vmethod
    vfunc_to_vmethod = netnode.Netnode("$ ida_kcpp.vfunc_to_vmethod")

    global config
    config = netnode.Netnode("$ ida_kcpp.config")


def vfunc_metadata(func):
    def wrapper(ea, *args, **kwargs):
        if ea not in vfunc_to_vmethod:
            return
        vfunc_metadata = VFuncMetadata(*vfunc_to_vmethod[ea])
        return func(ea, vfunc_metadata, *args, **kwargs)
    return wrapper


def find_vtable_funcptr_from_expr(e):
    """Check if expr is from the form x->x::vtable->y::vmethods.methodz
    :returns x and absolute method offset inside x::vtable"""
    method_cand_expr = e
    if method_cand_expr.op != ida_hexrays.cot_memref:
        return
    offset = method_cand_expr.m  # method offset in y::vmethods
    vmethods_cand_expr = method_cand_expr.x
    if vmethods_cand_expr.op != ida_hexrays.cot_memptr:
        return
    if not str(vmethods_cand_expr.type).endswith("::vmethods"):  # check y::methods
        return
    offset += vmethods_cand_expr.m  # add y::methods offset in x::vtable
    vtable_cand_expr = vmethods_cand_expr.x
    if vtable_cand_expr.op != ida_hexrays.cot_memptr:
        return
    vtable_cand = utils.extract_struct_from_tinfo(vtable_cand_expr.type)
    vtable_cand_struc_name = ida_struct.get_struc_name(vtable_cand.id)
    if vtable_cand_struc_name.endswith("::vtable"):
        return vtable_cand_struc_name[:-len("::vtable")], offset


def get_func_in_vtable(class_info_or_name, offset_in_vtable):
    if isinstance(class_info_or_name, str):
        class_name = class_info_or_name
        if class_name not in ida_kernelcache.class_info:
            return ida_idaapi.BADADDR
        class_info = ida_kernelcache.class_info[class_name]
    elif isinstance(class_info_or_name, ida_kernelcache.classes.ClassInfo):
        class_info = class_info_or_name
    else:
        raise TypeError("class_info_or_name expected to be str or ClassInfo")
    if class_info.vtable:
        return ida_kernelcache.ida_utilities.read_word(class_info.vtable_methods + offset_in_vtable)
    return ida_idaapi.BADADDR


def gather_funcs_from_descendants(ancestor_classname, offset_in_vtable):
    funcs = []
    ancestor_virtual_func = get_func_in_vtable(ancestor_classname, offset_in_vtable)
    if ancestor_virtual_func != ida_idaapi.BADADDR and utils.is_func_start(ancestor_virtual_func):
        # TODO: can remove the check about 0 and try to hunt the problematic virtual table.
        funcs.append((ancestor_classname, ancestor_virtual_func))
    if ancestor_classname in ida_kernelcache.class_info:
        for descendant in ida_kernelcache.class_info[ancestor_classname].descendants():
            descendant_virtual_func = get_func_in_vtable(descendant, offset_in_vtable)
            if descendant_virtual_func != ida_idaapi.BADADDR and utils.is_func_start(descendant_virtual_func) != 0:
                # TODO: can remove the check about 0 and try to hunt the problematic virtual table.
                funcs.append((descendant.classname, descendant_virtual_func))
    return funcs


def perform_initial_sync(ui_update_func):
    fix_classes_vtables_top_down(ui_update_func)
    path = pathlib.Path(__file__)
    git_dir = path.parent.parent.absolute()
    hash_file = subprocess.check_output(['git', '-C', git_dir, 'rev-parse', 'HEAD']).decode('ascii').strip('\n')
    config["commit_hash"] = hash_file


@utils.batch_mode
def fix_classes_vtables_top_down(ui_update_func):
    parsed_classes = set()
    descendants = list(ida_kernelcache.class_info["OSObject"].descendants())
    descendants_len = len(descendants)
    for class_info in descendants:
        if class_info in parsed_classes:
            continue
        for class_info_to_fix in class_info.ancestors(inclusive=True):
            if class_info_to_fix in parsed_classes:
                continue
            try:
                ui_update_func(f"ida_kcpp: fixing classes vtables ({len(parsed_classes)}/{descendants_len})")
                fix_vtable(class_info_to_fix)
            except Exception as e:
                logger.warning(
                    f"Error in fixing {class_info_to_fix.classname} while iterating {class_info.classname} ancestors"
                )
            parsed_classes.add(class_info_to_fix)


def find_own_vmethods_offset_in_vtable(class_name):
    vtable_sptr = utils.get_sptr_by_name(class_name + "::vtable")
    if vtable_sptr is None:
        logger.warning(f"Couldn't find struc {class_name}::vtable")
        return
    offset = 0
    while offset != ida_idaapi.BADADDR and offset < ida_struct.get_struc_size(vtable_sptr):
        curr_vtable_member = ida_struct.get_member(vtable_sptr, offset)
        if not curr_vtable_member:
            logger.warning(f"Couldn't find struc member at {class_name}::vtable offset {offset}")
            return
        vmethods_sptr = utils.get_member_substruct(curr_vtable_member)
        if not vmethods_sptr:
            logger.warning(
                f"{class_name}::vtable can't find vmethods struct in offset {hex(offset)}"
            )
            return
        vmethods_name = ida_struct.get_struc_name(vmethods_sptr.id)
        if not vmethods_name.endswith("::vmethods"):
            logger.warning(
                f"{class_name}::vtable can't find vmethods struct in offset {hex(offset)}"
            )
            return
        if "".join(vmethods_name.split(":")[:-1]) == class_name:
            return offset
        offset = ida_struct.get_struc_next_offset(vtable_sptr, offset)
    return None


def extract_method_name(func_ea):
    impl_name = ida_kernelcache.ida_utilities.get_ea_name(func_ea)
    if impl_name == "___cxa_pure_virtual" or impl_name.startswith("nullsub"):
        return
    if ida_bytes.has_dummy_name(ida_bytes.get_flags(func_ea)):
        return
    mangled_class, method_name = utils.parse_mangled_method_name(impl_name)
    if not (mangled_class or method_name):
        return
    if method_name.startswith("method_") and method_name[len("method_"):].isnumeric():
        return
    return method_name


def find_vmethod_name_candidates(class_name, offset_in_vtable, member_name):
    all_impls = gather_funcs_from_descendants(class_name, offset_in_vtable)
    unique_impls = {}
    cands = []
    for imple_class_name, impl in all_impls:
        if impl not in unique_impls:
            unique_impls[impl] = imple_class_name
            method_name = extract_method_name(impl)
            if method_name and method_name != member_name:
                cands.append((method_name, impl))
    if not cands:
        return member_name, unique_impls, all_impls
    elif len(cands) > 1:
        logger.warning(f"More than one option to {class_name} offset {offset_in_vtable}")
        # TODO: handle this collision

    else:
        cand_name, cand = cands[0]
        if member_name.startswith("method_") and member_name[len("method_"):].isnumeric():
            return cand_name, unique_impls, all_impls
        else:
            logger.warning(f"Cand and not generic member name for {class_name} offset {offset_in_vtable}")
    return None, None, all_impls


def link_vfuncs_to_vmethod(class_name, offset_in_vmethods, offset_in_vtable, all_impls, vmethod_member_id):
    for impl_class_name, impl_ea in all_impls:
        if impl_ea not in vfunc_to_vmethod:
            vfunc_to_vmethod[impl_ea] = (impl_class_name, class_name, offset_in_vmethods, offset_in_vtable)
            ida_xref.add_dref(vmethod_member_id, impl_ea, ida_xref.dr_I | ida_xref.XREF_USER)


def fix_virtual_method(class_name, vmethods_sptr, vmethods_member, vmethods_offset, vmethods_offset_in_vtable):
    member_name = ida_struct.get_member_name(vmethods_member.id)
    offset_in_vtable = vmethods_offset + vmethods_offset_in_vtable
    chosen_method_name, unique_impls, all_impls = find_vmethod_name_candidates(class_name,
                                                                               offset_in_vtable, member_name)
    link_vfuncs_to_vmethod(class_name, vmethods_offset, offset_in_vtable, all_impls, vmethods_member.id)
    if not (chosen_method_name and unique_impls):
        return
    if chosen_method_name != member_name:
        ida_struct.set_member_name(vmethods_sptr, vmethods_member.soff, chosen_method_name)
    for impl, impl_class_name in unique_impls.items():
        full_name = utils.generate_method_name(impl_class_name, chosen_method_name)
        utils.set_func_name(impl, full_name)
        func_type = utils.decompile_and_update_this(impl, utils.get_typeinf_ptr(impl_class_name))
        if func_type and impl_class_name == class_name:
            func_ptr = utils.get_typeinf_ptr(func_type)
            ida_struct.set_member_tinfo(vmethods_sptr, vmethods_member, 0, func_ptr, ida_typeinf.TINFO_DEFINITE)


def fix_vtable(class_info):
    """This functions locates the ::vtable struct of given class_info and iterates by its vmethod structs over
    the actual vtable for'class_info'. Then it sets the name of every `dummy_function` to be a mangling of
    class name and function name according to the relevant vmethod. It also decompiles the function and sets its first
    argument to be `this` from the relevant type. Then, only in the vmethods struct of the class, it changes the
    type of the relevant vmethod member to be a funcptr to the decompiled function
    """
    class_name = class_info.classname
    vmethods_offset_in_vtable = find_own_vmethods_offset_in_vtable(class_name)
    if vmethods_offset_in_vtable is None:
        logger.warning(f"Couldn't find vmethod in vtable of {class_name}")
        return
    vmethods_sptr = utils.get_sptr_by_name(class_name + "::vmethods")
    if not vmethods_sptr:
        logger.warning("%s struct doesn't exist" % (class_name + "::vmethods"))
        return
    for vmethods_member, vmethods_offset in utils.iterate_struct_members(vmethods_sptr):
        fix_virtual_method(class_name, vmethods_sptr, vmethods_member, vmethods_offset, vmethods_offset_in_vtable)


@vfunc_metadata
def virtual_method_renamed(ea, vfunc_metadata, class_name, method_name):
    if vfunc_metadata.impl_class != class_name:
        logger.warning(f"Bad name case of {hex(ea)} from saved impl_class {vfunc_metadata.impl_class} to "
                       f"{class_name}::{method_name}")
    rename_virtual_method(vfunc_metadata.base_class, vfunc_metadata.vtable_offset, vfunc_metadata.vmethod_offset,
                          method_name)


def virtual_method_member_renamed(class_name, vmethod_offset, method_name):
    vtable_offset = find_own_vmethods_offset_in_vtable(class_name) + vmethod_offset
    rename_virtual_method(class_name, vtable_offset, vmethod_offset, method_name, set_member_name=False)


def rename_virtual_method(class_name, vtable_offset, vmethod_offset, method_name, set_member_name=True):
    if set_member_name:
        vmethod_sptr = utils.get_sptr_by_name(class_name + "::vmethods")
        ida_struct.set_member_name(vmethod_sptr, vmethod_offset, method_name)
    impls = gather_funcs_from_descendants(class_name, vtable_offset)
    changed_funcs = set()
    for _, impl_ea in impls:
        if impl_ea not in changed_funcs:
            impl_name = ida_kernelcache.ida_utilities.get_ea_name(impl_ea)
            impl_orig_class_name, impl_orig_method_name = utils.parse_mangled_method_name(impl_name)
            if not (impl_orig_method_name and impl_orig_class_name):
                continue
            utils.set_func_name(impl_ea, utils.generate_method_name(impl_orig_class_name, method_name))
            changed_funcs.add(impl_ea)


@vfunc_metadata
def virtual_method_prototype_changed(ea, vfunc_metadata, method_details):
    class_name = vfunc_metadata.base_class
    vtable_offset = vfunc_metadata.vtable_offset
    vmethods_offset = vfunc_metadata.vmethod_offset
    vmethods_sptr = utils.get_sptr_by_name(class_name + "::vmethods")
    vmethods_member = ida_struct.get_member(vmethods_sptr, vmethods_offset)
    function_tinfo = ida_typeinf.tinfo_t()
    new_details = utils.duplicate_details_with_this(method_details, utils.get_typeinf_ptr(class_name))
    function_tinfo.create_func(new_details)
    func_ptr = utils.get_typeinf_ptr(function_tinfo)
    ida_struct.set_member_tinfo(vmethods_sptr, vmethods_member, 0, func_ptr, ida_typeinf.TINFO_DEFINITE)
    propagate_vmethod_member_prototype_change(class_name, vtable_offset, method_details, ea)


def virtual_method_member_prototype_changed(class_name, mptr):
    method_details = ida_typeinf.func_type_data_t()
    funcptr = ida_typeinf.tinfo_t()
    if not ida_struct.get_member_tinfo(funcptr, mptr):
        return
    if not funcptr.is_funcptr():
        return
    func = funcptr.get_pointed_object()
    if not func.get_func_details(method_details):
        return
    vmethod_in_vtable = find_own_vmethods_offset_in_vtable(class_name)
    propagate_vmethod_member_prototype_change(class_name, mptr.soff + vmethod_in_vtable, method_details)


def propagate_vmethod_member_prototype_change(class_name, vtable_offset, method_details, ea=None):
    impls = gather_funcs_from_descendants(class_name, vtable_offset)
    changed_funcs = {ea}
    for impl_class_name, impl_ea in impls:
        if impl_ea not in changed_funcs:
            this_type = utils.get_typeinf_ptr(impl_class_name)
            if len(method_details) > 0:
                utils.update_func_details(impl_ea, utils.duplicate_details_with_this(method_details, this_type))
            changed_funcs.add(impl_ea)


@vfunc_metadata
def get_member_id_for_vfunc(ea, func_metadata):
    if utils.is_func_start(ea):
        sid = ida_struct.get_struc_id(func_metadata.base_class + "::vmethods")
        if sid is ida_idaapi.BADADDR:
            return
        sptr = ida_struct.get_struc(sid)
        if not sptr:
            return
        mid = ida_struct.get_member_id(sptr, func_metadata.vmethod_offset)
        if mid == ida_idaapi.BADADDR:
            return
        return mid
