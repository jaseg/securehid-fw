#!/usr/bin/env python3
import threading
import re

import serial
import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, Gdk, Pango, GLib

import hexnoise

class PairingWindow(Gtk.Window):
    def __init__(self, noise, debug=False):
        Gtk.Window.__init__(self, title='SecureHID pairing')
        self.noise = noise
        self.debug = debug

        self.set_border_width(10)
        self.set_default_size(600, 200)

        self.vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)

        self.label = Gtk.Label()
        self.label.set_line_wrap(True)
        self.label.set_justify(Gtk.Justification.CENTER)
        self.label.set_markup('<b>Step 1</b>\n\nContacting device...')
        self.vbox.pack_start(self.label, True, True, 0)

        self.entry = Gtk.Entry()
        self.entry.set_editable(False)
        self.vbox.pack_start(self.entry, True, True, 0)

        self.add(self.vbox)

        self.handshaker = threading.Thread(target=self.pair, daemon=True)
        self.handshaker.start()

    def pair(self):
        for i in range(10):
            try:
                self.run_handshake()
                break
            except hexnoise.ProtocolError as e:
                print(e)

    def run_handshake(self):
        binding_incantation = self.noise.channel_binding_incantation()
        GLib.idle_add(self.label.set_markup,
                f'<b>Step 2</b>\n\nPerform channel binding ritual.\n'
                f'Enter the following incantation, then press enter.\n'
                f'<b>{binding_incantation}</b>')
        
        def update_text(text):
            self.entry.set_text(text)
            self.entry.set_position(len(text))

            clean = lambda s: re.sub('[^a-z0-9-]', '', s.lower())
            if clean(binding_incantation).startswith(clean(text)):
                color = 0.9, 1.0, 0.9 # light red
            else:
                color = 1.0, 0.9, 0.9 # light green
            self.entry.override_background_color(Gtk.StateType.NORMAL, Gdk.RGBA(*color, 1.0))

        try:
            for user_input in self.noise.pairing_messages():
                GLib.idle_add(update_text, user_input)
            self.destroy()
        except noise.ProtocolError as e:
            GLib.idle_add(self.label.set_markup, f'<b>Error: {e}!</b>')


class StatusIcon(Gtk.StatusIcon):
    def __init__(self):
        Gtk.StatusIcon.__init__(self)
        self.set_tooltip_text('SecureHID connected')
        self.set_from_file('secureusb_icon.png')


def run_pairing_gui(serial, baudrate, debug=False):
    ser = serial.Serial(serial, baudrate)
    packetizer = hexnoise.Packetizer(serial, debug=debug)
    noise = hexnoise.NoiseEngine(packetizer, debug=debug)
    noise.perform_handshake()

    if not noise.paired:
        window = PairingWindow(noise, debug=debug)
        window.connect('destroy', Gtk.main_quit)
        window.show_all()
        Gtk.main()

    if self.noise.paired:
        input_runner = threading.Thread(target=noise.uinput_passthrough, daemon=True)
        input_runner.start()

        status_icon = StatusIcon()
        Gtk.main()

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('serial')
    parser.add_argument('baudrate')
    parser.add_argument('-d', '--debug', action='store_true')
    args = parser.parse_args()

    run_pairing_gui(args.serial, args.baudrate, args.debug)

