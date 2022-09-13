import ida_kernwin
import ida_lines
import idc


class Choose(ida_kernwin.Choose):
    # Fix Choose.UI_Hooks_Trampoline to work with modal dialogs
    class UI_Hooks_Trampoline(ida_kernwin.Choose.UI_Hooks_Trampoline):
        def populating_widget_popup(self, form, popup_handle):
            chooser = self.v()
            if hasattr(chooser, "OnPopup") and callable(getattr(chooser, "OnPopup")):
                chooser.OnPopup(form, popup_handle)

    class chooser_handler_t(ida_kernwin.action_handler_t):
        def __init__(self, handler):
            super().__init__()
            self.handler = handler

        def activate(self, ctx):
            self.handler()
            return 1

        def update(self, ctx):
            return (
                ida_kernwin.AST_ENABLE_FOR_WIDGET
                if ida_kernwin.is_chooser_widget(ctx.widget_type)
                else ida_kernwin.AST_DISABLE_FOR_WIDGET
            )

    def __init__(self, title, items, columns):
        super().__init__(title, columns, flags=self.CH_RESTORE)

        self.items = items

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n]

    def show(self):
        selected = self.Show(modal=True)
        if selected < 0:
            return None
        return self.items[selected]


class MenuBase(ida_kernwin.action_handler_t):
    label = None
    shortcut = None
    tooltip = None
    icon = -1
    COUNTER = 0

    def __init__(self, plugin, callback, label):
        super().__init__()
        self.plugin = plugin
        self.label = label
        self.activate_callback = callback
        self.name = self.plugin.wanted_name + ":" + self.__class__.__name__ + str(self.COUNTER)
        MenuBase.COUNTER += 1
        self.register()

    def register(self):
        return ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                self.name,  # Name. Acts as an ID. Must be unique.
                self.label,  # Label. That's what users see.
                self,  # Handler. Called when activated, and for updating
                self.shortcut,  # shortcut,
                self.tooltip,  # tooltip
                self.icon,  # icon
            )
        )

    def unregister(self):
        """Unregister the action.
        After unregistering the class cannot be used.
        """
        ida_kernwin.unregister_action(self.__name__)

    def activate(self, ctx):
        self.activate_callback()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

    def path(self):
        return "Edit/Plugins/" + self.plugin.wanted_name + "/" + self.label

    def get_name(self):
        return self.name

    def attach_to_menu(self):
        ida_kernwin.attach_action_to_menu(self.path(), self.get_name(), ida_kernwin.SETMENU_APP)

    def detach_from_menu(self):
        ida_kernwin.detach_action_from_menu(self.path(), self.get_name())


def get_wrapped_word_from_viewer(viewer):
    line = ida_kernwin.get_custom_viewer_curline(viewer, False)
    line = ida_lines.tag_remove(line)
    place, x, y = ida_kernwin.get_custom_viewer_place(viewer, False)
    start = x
    while 0 < start < len(line) and line[start] not in (' ', '\t'):
        start -= 1
    end = x
    while 0 < end < len(line) and line[end] not in (' ', '\t'):
        end += 1
    return line[start + 1: end]


def update_wait_box(s):
    old_batch_mode = idc.batch(0)
    ida_kernwin.hide_wait_box()
    ida_kernwin.show_wait_box("HIDECANCEL\n" + s)
    idc.batch(old_batch_mode)
