#!/usr/bin/env python3

import time
import string

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

def send_packet(ser, data, width=16):
    print(f'\033[93mSending {len(data)} bytes\033[0m')
    hexdump(print, data, width)
    encoded = cobs.encode(data) + b'\0'
    ser.write(encoded)
    ser.flushOutput()

def receive_packet(ser, width=16):
    packet = ser.read_until(b'\0')
    data = cobs.decode(packet[:-1])
    print(f'\033[93mReceived {len(data)} bytes\033[0m')
    hexdump(print, data, width)
    return data

if __name__ == '__main__':
    import argparse
    import serial

    parser = argparse.ArgumentParser()
    parser.add_argument('serial')
    parser.add_argument('baudrate')
    parser.add_argument('-w', '--width', type=int, default=16, help='Number of bytes to display in one line')
    args = parser.parse_args()

    ser = serial.Serial(args.serial, args.baudrate)

    from noise.connection import NoiseConnection, Keypair

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
    print('Handshake started')

    while True:
        if proto.handshake_finished:
            break
        send_packet(ser, proto.write_message(), args.width)

        if proto.handshake_finished:
                break
        proto.read_message(receive_packet(ser, args.width))
    print('Handshake finished, handshake hash:')
    hexdump(print, proto.get_handshake_hash(), args.width)

    while True:
        data = proto.decrypt(receive_packet(ser, args.width))
        print('Decrypted data:')
        hexdump(print, data, args.width)

