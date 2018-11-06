#!/usr/bin/env python3

import time
import string

def _print_line(write, ts, line, width=16):
    h,m,s,ms = int(ts//3600), int((ts//60)%60), int(ts%60), int((ts%1.0) * 1000)
    timestamp = f'{h: 3d}:{m:02d}:{s:02d}:{ms:03d}'
    line = list(line) + [None]*(width-len(line))
    hexcol = '\033[94m' 
    col = lambda b, s: s if b != 0 else f'\033[91m{s}{hexcol}'
    hexfmt = '  '.join(
            ' '.join(col(b, f'{b:02x}') if b is not None else '  ' for b in line[i*8:i*8+8])
            for i in range(1 + (len(line)-1)//8))
    asciifmt = ''.join(chr(c) if c is not None and chr(c) in string.printable else '.' for c in line)
    write(f'\033[38;5;244m{timestamp}  {hexcol}{hexfmt}  \033[38;5;244m|\033[92m{asciifmt}\033[38;5;244m|\033[0m', flush=True, end='')

def hexcom(write, ser, width=16):
    current_line = b''
    start = time.time()
    while ser.is_open:
        data = ser.read_all() # non-blocking, flushes buffer
        if not data:
            data = ser.read(1) # blocking
        ts = time.time()

        current_line += data
        write('\033[2K\r', end='')
        while len(current_line) > width:
            chunk, current_line = current_line[:width], current_line[width:]
            _print_line(write, ts-start, chunk, width=width)
            write()
        _print_line(write, ts-start, current_line, width=width)

if __name__ == '__main__':
    import argparse
    import serial

    parser = argparse.ArgumentParser()
    parser.add_argument('serial')
    parser.add_argument('baudrate')
    parser.add_argument('-w', '--width', type=int, default=16, help='Number of bytes to display in one line')
    args = parser.parse_args()

    ser = serial.Serial(args.serial, args.baudrate)
    hexcom(print, ser, width=args.width)
