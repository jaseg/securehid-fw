#!/usr/bin/env python3

import time
import string
import enum

from cobs import cobs

def _print_line(write, ts, line, width=16):
    h,m,s,ms = int(ts//3600), int((ts//60)%60), int(ts%60), int((ts%1.0) * 1000)
    timestamp = f'{h: 3d}:{m:02d}:{s:02d}:{ms:03d}'
    line = list(line) + [None]*(width-len(line))
    hexcol = '\033[0m' 
    col = lambda b, s: s if b != 0 else f'\033[91m{s}{hexcol}'
    hexfmt = '  '.join(
            ' '.join(col(b, f'{b:02x}') if b is not None else '  ' for b in line[i*8:i*8+8])
            for i in range(1 + (len(line)-1)//8))
    asciifmt = ''.join(chr(c) if c is not None and chr(c) in string.printable and c>=0x20 else '.' for c in line)
    write(f'\033[38;5;244m{timestamp}  {hexcol}{hexfmt}  \033[38;5;244m|\033[92m{asciifmt}\033[38;5;244m|\033[0m', flush=True, end='')

startup = time.time()

def hexdump(write, packet, width=16):
    ts = time.time()
    while len(packet) > width:
        chunk, packet = packet[:width], packet[width:]
        _print_line(write, ts-startup, chunk, width=width)
        write()
    _print_line(write, ts-startup, packet, width=width)
    write()

class PacketType(enum.Enum):
    _RESERVED = 0
    INITIATE_HANDSHAKE = 1
    HANDSHAKE = 2
    DATA = 3

class ReportType(enum.Enum):
    _RESERVED = 0
    KEYBOARD = 1
    MOUSE = 2
    PAIRING = 3 # keyboard in disguise

def send_packet(ser, pkt_type, data, width=16):
    print(f'\033[93mSending {len(data)} bytes, packet type {pkt_type.name} ({pkt_type.value})\033[0m')
    hexdump(print, data, width)
    data = bytes([pkt_type.value]) + data
    encoded = cobs.encode(data) + b'\0'
    ser.write(encoded)
    ser.flushOutput()

def receive_packet(ser, width=16):
    packet = ser.read_until(b'\0')
    data = cobs.decode(packet[:-1])
    #print(f'\033[93mReceived {len(data)} bytes\033[0m')
    #hexdump(print, data, width)
    return data[0], data[1:]

if __name__ == '__main__':
    import argparse
    import serial

    parser = argparse.ArgumentParser()
    parser.add_argument('serial')
    parser.add_argument('baudrate')
    parser.add_argument('-w', '--width', type=int, default=16, help='Number of bytes to display in one line')
    args = parser.parse_args()

    ser = serial.Serial(args.serial, args.baudrate)
    ser.write(b'\0') # COBS synchronization

    import uinput
    ALL_KEYS =  [ v for k, v in uinput.ev.__dict__.items() if k.startswith('KEY_') ]
    MODIFIERS = [
            uinput.ev.KEY_LEFTCTRL,
            uinput.ev.KEY_LEFTSHIFT,
            uinput.ev.KEY_LEFTALT,
            uinput.ev.KEY_LEFTMETA,
            uinput.ev.KEY_RIGHTCTRL,
            uinput.ev.KEY_RIGHTSHIFT,
            uinput.ev.KEY_RIGHTALT,
            uinput.ev.KEY_RIGHTMETA,
            ]
    map_modifiers = lambda x: [ mod for i, mod in enumerate(MODIFIERS) if x & (1<<i) ]
    import keymap
    map_regular = { v: getattr(uinput.ev, k) for k, v in keymap.__dict__.items() if k.startswith('KEY_') }
    map_regulars = lambda keycodes: [ map_regular[kc] for kc in keycodes if kc != 0 and kc in map_regular ]

    from noise.connection import NoiseConnection, Keypair
    from noise.exceptions import NoiseInvalidMessage

    STATIC_LOCAL = bytes([
        0xbb, 0xdb, 0x4c, 0xdb, 0xd3, 0x09, 0xf1, 0xa1,
        0xf2, 0xe1, 0x45, 0x69, 0x67, 0xfe, 0x28, 0x8c,
        0xad, 0xd6, 0xf7, 0x12, 0xd6, 0x5d, 0xc7, 0xb7,
        0x79, 0x3d, 0x5e, 0x63, 0xda, 0x6b, 0x37, 0x5b
        ])

    proto = NoiseConnection.from_name(b'Noise_XX_25519_ChaChaPoly_BLAKE2s')
    proto.set_as_initiator()
    proto.set_keypair_from_private_bytes(Keypair.STATIC, STATIC_LOCAL)
    proto.start_handshake()
    send_packet(ser, PacketType.INITIATE_HANDSHAKE, b'', args.width)
    print('Handshake started')

    while True:
        if proto.handshake_finished:
            break
        send_packet(ser, PacketType.HANDSHAKE, proto.write_message(), args.width)

        if proto.handshake_finished:
                break
        pkt_type, payload = receive_packet(ser, args.width)
        if pkt_type == PacketType.HANDSHAKE.value:
            proto.read_message(payload)
        else:
            print(f'Incorrect packet type {pkt_type}. Ignoring since this is only test code.')
    print('Handshake finished, handshake hash:')
    hexdump(print, proto.get_handshake_hash(), args.width)

    from nouns import NOUNS
    from adjectives import ADJECTIVES
    def map_bytes_to_incantation(data):
        elems = [ f'{ADJECTIVES[a]} {NOUNS[b]}' for a, b in zip(data[0::2], data[1::2]) ]
        nfirst = ", ".join(elems[:-1])
        return f'{nfirst} and {elems[-1]}'
    print('Handshake channel binding incantation:')
    hhash = proto.get_handshake_hash()
    print('    ' + map_bytes_to_incantation(hhash[:8       ]))
    print('    ' + map_bytes_to_incantation(hhash[ 8:16    ]))
    print('    ' + map_bytes_to_incantation(hhash[   16:24 ]))
    print('    ' + map_bytes_to_incantation(hhash[      24:]))

    old_kcs = set()
    def noise_rx(received, ui):
        global old_kcs

        data = proto.decrypt(received)
        #print('Decrypted data:')
        #hexdump(print, data, args.width)

        rtype, rlen, *report = data
        if rtype != 1 or rlen != 8:
            return

        modbyte, _reserved, *keycodes = report
        keys = map_modifiers(modbyte) + map_regulars(keycodes)
        print('Emitting:', keys)
        keyset = set(keys)

        for key in keyset - old_kcs:
            ui.emit(key, 1, syn=False)
        for key in old_kcs - keyset:
            ui.emit(key, 0, syn=False)
        ui.syn()

        old_kcs = keyset

    with uinput.Device(ALL_KEYS) as ui:
        while True:
            try:
                pkt_type, received = receive_packet(ser, args.width)
                if pkt_type != PacketType.DATA.value:
                    print(f'Unexpected packet type {pkt_type}. Ignoring.')
                    continue

                try:
                    noise_rx(received, ui)
                except NoiseInvalidMessage as e:
                    orig_n = proto.noise_protocol.cipher_state_decrypt.n
                    print('Invalid noise message', e)
                    for n in [orig_n+1, orig_n+2, orig_n+3]:
                        try:
                            proto.noise_protocol.cipher_state_decrypt.n = n
                            noise_rx(received, ui)
                            print(f'    Recovered. n={n}')
                            break
                        except NoiseInvalidMessage as e:
                            pass
                    else:
                        print('    Unrecoverable.')
                        proto.noise_protocol.cipher_state_decrypt.n = orig_n
            except Exception as e:
                print('Invalid framing:', e)

