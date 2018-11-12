#!/usr/bin/env python3
import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk

class PairingWindow(Gtk.Window):
    def __init__(self):
        Gtk.Window.__init__(self, title='SecureHID pairing')
        self.set_border_width(10)
        self.set_default_size(400, 100)

        self.vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)

        self.label = Gtk.Label()
        self.label.set_line_wrap(True)
        self.label.set_justify(Gtk.Justification.CENTER)
        self.label.set_markup('<b>Step 1</b>\n\nSearching for device')
        self.vbox.add(self.label)

        self.add(self.vbox)

if __name__ == '__main__':
    window = PairingWindow()
    window.connect('destroy', Gtk.main_quit)
    window.show_all()
    Gtk.main()

