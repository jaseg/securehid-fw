
import string
import time

startup = time.time()

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

def hexdump(write, packet, width=16):
    ts = time.time()
    while len(packet) > width:
        chunk, packet = packet[:width], packet[width:]
        _print_line(write, ts-startup, chunk, width=width)
        write()
    _print_line(write, ts-startup, packet, width=width)
    write()

