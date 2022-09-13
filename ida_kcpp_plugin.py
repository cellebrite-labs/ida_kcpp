import logging

import ida_kernwin
import idaapi
from ida_kcpp import logic, ui, ui_utils


class KCPPPlugin(idaapi.plugin_t, idaapi.UI_Hooks):
    plugin_initialized = False
    flags = idaapi.PLUGIN_MOD | idaapi.PLUGIN_HIDE
    comment = "Add support for CPP navigating on top of ida_kernelcache"
    help = ""
    wanted_name = "Kernel Cache CPP"
    wanted_hotkey = ""

    def __init__(self):
        super().__init__()
        self.ui_hook = False
        self.activate_menu = None
        self.deactivate_menu = None
        self.kc_process_idb = None
        self.initial_sync_menu = None
        # Hook properties
        self.hexrays_hook = None
        self.virtual_synchronizer_hook = None
        self.structs_double_colon_hook = None
        # Hotkeys context
        self.vfunc_xref_hotkey = None

    def init(self):
        """plugin_t init() function"""
        # full name is something like "Apple XNU kernelcache for ARM64 (kernel + all kexts)"
        typename_markers = ("kernelcache", "arm64")
        typename = idaapi.get_file_type_name().lower()
        if any(word not in typename for word in typename_markers):
            logging.error(f"{self.wanted_name}: IDB deemed unsuitable (not an ARM64 kernelcache binary). Skipping...")
            return idaapi.PLUGIN_SKIP

        if not self.plugin_initialized:
            self.init_menu_items()

            self.ui_hook = True
            self.hook()
            logging.info(f"{self.wanted_name}: IDB deemed suitable. Initializing...")

        return idaapi.PLUGIN_KEEP

    def init_menu_items(self):
        self.kc_process_idb = ui_utils.MenuBase(self, self.process_kernelcache, "ida_kernelcache process kernel")
        self.activate_menu = ui_utils.MenuBase(self, self.activate_plugin, "Activate plugin")
        self.deactivate_menu = ui_utils.MenuBase(self, self.deactivate_plugin, "Deactivate plugin")
        self.initial_sync_menu = ui_utils.MenuBase(self, self.perform_initial_sync, "Perform initial sync")

    def run(self, arg=0):
        """plugin_t run() implementation"""
        return

    def term(self):
        """plugin_t term() implementation"""
        if self.ui_hook:
            self.unhook()
            self.ui_hook = False
        return

    def activate_hooks(self):
        if not self.hexrays_hook:
            self.hexrays_hook = ui.HexraysDoubleClickHook()
        self.hexrays_hook.hook()
        if not self.virtual_synchronizer_hook:
            self.virtual_synchronizer_hook = ui.VirtualFuncsSynchronizer()
        self.virtual_synchronizer_hook.hook()
        if not self.structs_double_colon_hook:
            self.structs_double_colon_hook = ui.StructsDoubleColonHooks()
        self.structs_double_colon_hook.hook()

    def deactivate_hooks(self):
        if self.hexrays_hook:
            self.hexrays_hook.unhook()
        if self.virtual_synchronizer_hook:
            self.virtual_synchronizer_hook.unhook()
        if self.structs_double_colon_hook:
            self.structs_double_colon_hook.unhook()

    def activate_plugin(self):
        logging.info("KernelCache CPP plugin was activated")
        logic.init_if_needed()
        self.activate_hooks()
        self.activate_menu.detach_from_menu()
        self.deactivate_menu.attach_to_menu()
        self.install_hotkeys()

    def deactivate_plugin(self):
        logging.info("KernelCache CPP plugin was deactivated")
        self.deactivate_hooks()
        self.deactivate_menu.detach_from_menu()
        self.activate_menu.attach_to_menu()
        self.uninstall_hotkeys()

    def install_hotkeys(self):
        self.vfunc_xref_hotkey = ida_kernwin.add_hotkey("CTRL+SHIFT+Y", ui.open_smart_xrefs)

    def uninstall_hotkeys(self):
        ida_kernwin.del_hotkey(self.vfunc_xref_hotkey)

    def perform_initial_sync(self):
        try:
            ida_kernwin.show_wait_box("Running initial sync...")
            logic.init_if_needed()
            logic.perform_initial_sync(ui_utils.update_wait_box)
        except Exception as e:
            logic.logger.exception("Exception in performinitial_sync")
        finally:
            ida_kernwin.hide_wait_box()

    def process_kernelcache(self):
        ida_kernwin.show_wait_box("ida_kernelcache is running...")
        try:
            logic.init_if_needed(only_collect=False)
        except Exception as e:
            logic.logger.exception("Exception in process_kernelcache")
        finally:
            ida_kernwin.hide_wait_box()

    def ready_to_run(self):
        """UI_Hooks function.
        Attaches actions to plugin in main menu.
        """
        self.kc_process_idb.attach_to_menu()
        self.initial_sync_menu.attach_to_menu()
        self.activate_menu.attach_to_menu()

        KCPPPlugin.plugin_initialized = True


def PLUGIN_ENTRY():
    return KCPPPlugin()
