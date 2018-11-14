#!/usr/bin/env python3
import threading
import binascii
import re
import os
import time

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
        self.trusted = False

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

        self.confirm_button = Gtk.Button(label='Trust this device')
        self.confirm_button.connect('clicked', self.confirm_trust)
        self.confirm_button.set_sensitive(False)
        self.abort_button = Gtk.Button(label='Abort')
        self.abort_button.connect('clicked', lambda _foo: self.destroy())
        self.bbox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.bbox.pack_start(self.confirm_button, True, True, 0)
        self.bbox.pack_start(self.abort_button, True, True, 0)
        self.vbox.pack_start(self.bbox, True, True, 0)

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

            GLib.idle_add(self.finish_pairing)
        except hexnoise.ProtocolError as e:
            GLib.idle_add(self.label.set_markup, f'<b>Error: {e}</b>')

    def finish_pairing(self):
        self.label.set_markup(f'<b>Step 3</b>\n\nConfirm pairing.\n'
                f'In case the device did not sound an alarm just now, confirm pairing now using the button below.')
        self.confirm_button.set_sensitive(True)

    def confirm_trust(self, _foo):
        self.trusted = True
        self.destroy()


class StatusIcon(Gtk.StatusIcon):
    def __init__(self):
        Gtk.StatusIcon.__init__(self)
        self.set_tooltip_text('SecureHID connected')
        self.set_from_file('secureusb_icon.png')

def run_pairing_gui(port, baudrate, debug=False):
    XDG_CONFIG_HOME = os.environ.get('XDG_CONFIG_HOME') or os.path.join(os.path.expandvars('$HOME'), '.config', 'secure_hid')
    if not os.path.isdir(XDG_CONFIG_HOME):
        os.mkdir(XDG_CONFIG_HOME)

    private_key_file = os.path.join(XDG_CONFIG_HOME, 'host_key.pem')
    if not os.path.isfile(private_key_file):
        with open(private_key_file, 'w') as f:
            f.write(binascii.hexlify(hexnoise.NoiseEngine.generate_private_key_x25519()).decode())

    known_devices_file = os.path.join(XDG_CONFIG_HOME, 'known_devices')
    if not os.path.isfile(known_devices_file):
        with open(known_devices_file, 'w') as f:
            f.write('# This file contains the hex-encoded SHA-256 fingerprints of the X25519 keys of all trusted SecureHID devices\n')

    with open(private_key_file) as f:
        host_key_private = binascii.unhexlify(f.read())

    ser = serial.Serial(port, baudrate)
    packetizer = hexnoise.Packetizer(ser, debug=debug)
    noise = hexnoise.NoiseEngine(host_key_private, packetizer, debug=debug)
    noise.perform_handshake()
    print('Connected.')
    print('Device fingerprint:', noise.remote_fingerprint)

    if not noise.paired:
        window = PairingWindow(noise, debug=debug)
        window.connect('destroy', Gtk.main_quit)
        window.show_all()
        Gtk.main()

        if not window.trusted:
            raise SystemError('User abort')

        if not noise.paired:
            raise SystemError('Unknown noise error')

        with open(known_devices_file, 'a') as f:
            f.write(f'{noise.remote_fingerprint} # added {time.ctime()}\n')

    else:
        with open(known_devices_file) as f:
            known_devices = [ l.strip().partition('#')[0].strip() for l in f.readlines() if not l[0] == '#' ]

        if noise.remote_fingerprint not in known_devices:
            raise ValueError('Remote host is untrusted but seems to trust us.')

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

