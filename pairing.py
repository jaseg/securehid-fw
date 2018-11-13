#!/usr/bin/env python3
import threading
import re

import serial
import gi
gi.require_version('Gtk', '3.0')
gi.require_version('Pango', '1.0')
from gi.repository import Gtk, Pango

import hexnoise

class PairingWindow(Gtk.Window):
    def __init__(self, serial, debug=False):
        Gtk.Window.__init__(self, title='SecureHID pairing')
        self.serial = serial
        self.debug = debug

        self.set_border_width(10)
        self.set_default_size(600, 200)

        self.vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)

        self.label = Gtk.Label()
        self.label.set_line_wrap(True)
        self.label.set_justify(Gtk.Justification.CENTER)
        self.label.set_markup('<b>Step 1</b>\n\nContacting device...')
        self.vbox.pack_start(self.label, True, True, 0)

        self.textview = Gtk.TextView()
        self.textview.set_editable(False)
        self.textbuffer = self.textview.get_buffer()
        self.tag_nomatch = self.textbuffer.create_tag("nomatch", weight=Pango.Weight.BOLD)
        self.tag_match = self.textbuffer.create_tag("match", background='#AAFFAA', weight=Pango.Weight.BOLD)

        self.vbox.pack_start(self.textview, True, True, 0)

        self.add(self.vbox)

        self.handshaker = threading.Thread(target=self.run_handshake, daemon=True)
        self.handshaker.start()

    @classmethod
    def matchlen(self, ref, text):
        words = ref.split()
        parts = text.split()
        clean = lambda b: re.sub('^[^a-zA-Z0-9-]*', '', re.sub('[^a-zA-Z0-9-]*$', '', b)).lower()

        good = ''
        for a, b in zip(words[:-1], parts[:-1]):
            if a == clean(b):
                good = f'{good}b '

        rest = clean(parts[-1])
        if words[-1].startswith(rest):
            good = f'{good} {rest}'
        return len(good)

    def run_handshake(self):
        self.packetizer = hexnoise.Packetizer(self.serial, debug=self.debug)
        self.noise = hexnoise.NoiseEngine(self.packetizer, debug=self.debug)

        self.noise.perform_handshake()

        binding_incantation = self.noise.channel_binding_incantation()
        self.label.set_markup(f'<b>Step 2</b>\n\nPerform channel binding ritual.\n'
                              f'Enter the following incantation, then press enter.\n'
                              f'<b>{binding_incantation}</b>')
        
        for user_input in self.noise.pairing_messages():
            print('got:', user_input)
            self.textbuffer.set_text(user_input)
            #i1, i2 = self.textbuffer.get_start_iter(), self.textbuffer.get_end_iter()
            #self.textbuffer.apply_tag(self.tag_nomatch, i1, i2)

            #i1, i2 = self.textbuffer.get_start_iter(), self.textbuffer.get_start_iter()
            #i2.forward_chars(self.matchlen(binding_incantation, user_input))
            #self.textbuffer.apply_tag(self.tag_match, i1, i2)

        self.label.set_markup(f'<b>Done!</b>')

        #noise.uinput_passthrough()

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('serial')
    parser.add_argument('baudrate')
    parser.add_argument('-d', '--debug', action='store_true')
    args = parser.parse_args()

    ser = serial.Serial(args.serial, args.baudrate)

    window = PairingWindow(ser, debug=args.debug)
    window.connect('destroy', Gtk.main_quit)
    window.show_all()
    Gtk.main()

