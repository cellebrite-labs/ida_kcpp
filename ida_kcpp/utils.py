import logging
import re

import ida_bytes
import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_nalt
import ida_name
import ida_struct
import ida_typeinf
import idc


def batch_mode(func):
    def wrapper(*args, **kwargs):
        old_batch = idc.batch(1)
        try:
            return func(*args, **kwargs)
        finally:
            idc.batch(old_batch)

    return wrapper


def generate_method_name(classname, methodname):
    # the "_99" is a marker which IDA ignores and will let us identify self-generated mangled names
    return "__ZNK{}{}{}{}Ev_99".format(
        len(classname), classname, len(methodname), methodname
    )


def parse_mangled_method_name(mangled_name):
    demangled_name = idc.demangle_name(mangled_name, idc.get_inf_attr(idc.INF_LONG_DN))
    if not demangled_name:
        return None, None
    return re.match(r"(?:(.*)::)?(.*?)\(.*\)", demangled_name).groups()


# Functions below were copied from ida_medigate


def get_func_details(func_ea):
    tinfo = ida_typeinf.tinfo_t()
    ida_nalt.get_tinfo(tinfo, func_ea)
    if not tinfo.is_func():
        return None
    func_details = ida_typeinf.func_type_data_t()
    tinfo.get_func_details(func_details)
    return func_details


def update_func_details(func_ea, func_details):
    function_tinfo = ida_typeinf.tinfo_t()
    function_tinfo.create_func(func_details)
    if not ida_typeinf.apply_tinfo(func_ea, function_tinfo, ida_typeinf.TINFO_DEFINITE):
        return None
    return function_tinfo


def duplicate_details_with_this(method_details, this_type):
    new_method_details = ida_typeinf.func_type_data_t()
    new_method_details.retloc = method_details.retloc
    new_method_details.rettype = method_details.rettype
    new_method_details.stkargs = method_details.stkargs
    new_method_details.cc = method_details.cc
    if len(method_details) > 0:
        old_this_arg = method_details[0]
        new_arg = ida_typeinf.funcarg_t()
        new_arg.cmt = old_this_arg.cmt
        new_arg.name = old_this_arg.name
        new_arg.flags = old_this_arg.flags
        new_arg.argloc = old_this_arg.argloc
        new_arg.type = this_type
        new_method_details.push_back(new_arg)
        for i in range(1, method_details.size()):
            new_method_details.push_back(method_details[i])
    return new_method_details


def get_struc_from_tinfo(struct_tinfo):

    if ida_hexrays.init_hexrays_plugin() and (
        not (struct_tinfo.is_struct() or struct_tinfo.is_union())
    ):
        return None
    struct_id = ida_struct.get_struc_id(struct_tinfo.get_type_name())
    if struct_id == ida_idaapi.BADADDR:
        return None
    struct = ida_struct.get_struc(struct_id)
    return struct


def deref_tinfo(tinfo):
    pointed_obj = None
    if tinfo.is_ptr():
        pointed_obj = tinfo.get_pointed_object()
    return pointed_obj


def deref_struct_from_tinfo(tinfo):
    struct_tinfo = deref_tinfo(tinfo)
    if struct_tinfo is None:
        return None
    return get_struc_from_tinfo(struct_tinfo)


def extract_struct_from_tinfo(tinfo):
    struct = get_struc_from_tinfo(tinfo)
    if struct is None:
        struct = deref_struct_from_tinfo(tinfo)
    return struct


def decompile_and_update_this(func_ea, this_type=None):

    functype = None
    try:
        cfunc = ida_hexrays.decompile(func_ea)
        functype = cfunc.type
        func_details = ida_typeinf.func_type_data_t()
        functype.get_func_details(func_details)
        if func_details is None:
            return None
        if this_type:
            if len(func_details) > 0:
                func_details[0].name = "this"
                func_details[0].type = this_type
        functype = update_func_details(func_ea, func_details)
    except ida_hexrays.DecompilationFailure as e:
        logging.exception("Couldn't decompile 0x%x", func_ea)
    return functype


def get_sptr_by_name(struct_name):
    s_id = ida_struct.get_struc_id(struct_name)
    return ida_struct.get_struc(s_id)


def set_func_name(func_ea, func_name):
    counter = 0
    new_name = func_name
    while not ida_name.set_name(func_ea, new_name):
        new_name = func_name + "_%d" % counter
        counter += 1
    return new_name


def get_member_substruct(member):
    member_type = get_member_tinfo(member)
    if member_type is not None and member_type.is_struct():
        current_struct_id = ida_struct.get_struc_id(member_type.get_type_name())
        return ida_struct.get_struc(current_struct_id)
    elif member.flag & ida_bytes.FF_STRUCT == ida_bytes.FF_STRUCT:
        return ida_struct.get_sptr(member)
    return None


def get_member_tinfo(member, member_typeinf=None):
    if member_typeinf is None:
        member_typeinf = ida_typeinf.tinfo_t()
    ida_struct.get_member_tinfo(member_typeinf, member)
    return member_typeinf


def get_typeinf(typestr):
    tif = ida_typeinf.tinfo_t()
    tif.get_named_type(ida_typeinf.get_idati(), typestr)
    return tif


def get_typeinf_ptr(typeinf):
    old_typeinf = typeinf
    if isinstance(typeinf, str):
        typeinf = get_typeinf(typeinf)
    if typeinf is None:
        logging.warning("Couldn't find typeinf %s", old_typeinf or typeinf)
        return None
    tif = ida_typeinf.tinfo_t()
    tif.create_ptr(typeinf)
    return tif


def iterate_struct_members(sptr):
    offset = ida_struct.get_struc_first_offset(sptr)
    while offset != ida_idaapi.BADADDR and offset < ida_struct.get_struc_size(sptr):
        member = ida_struct.get_member(sptr, offset)
        yield member, offset
        offset = ida_struct.get_struc_next_offset(sptr, offset)


def is_func_start(ea):
    func = ida_funcs.get_func(ea)
    if func:
        return func.start_ea == ea
    return False
