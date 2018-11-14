#!/usr/bin/env python3

import time
import enum
import sys
from contextlib import contextmanager, suppress, wraps
import hashlib
import secrets

import serial
from cobs import cobs
import uinput
from noise.connection import NoiseConnection, Keypair
from noise.exceptions import NoiseInvalidMessage

import keymap
from hexdump import hexdump

class PacketType(enum.Enum):
    _RESERVED = 0
    INITIATE_HANDSHAKE = 1
    HANDSHAKE = 2
    DATA = 3
    COMM_ERROR = 4
    CRYPTO_ERROR = 5
    TOO_MANY_FAILS = 6

class ReportType(enum.Enum):
    _RESERVED = 0
    KEYBOARD = 1
    MOUSE = 2
    PAIRING_INPUT = 3
    PAIRING_SUCCESS = 4
    PAIRING_ERROR = 5
    PAIRING_START = 6

class ProtocolError(Exception):
    pass

class Packetizer:
    def __init__(self, serial, debug=False, width=16):
        self.ser, self.debug, self.width = serial, debug, width
        self.ser.write(b'\0') # COBS synchronization

    def send_packet(self, pkt_type, data):
        if self.debug:
            print(f'\033[93mSending {len(data)} bytes, packet type {pkt_type.name} ({pkt_type.value})\033[0m')
            hexdump(print, data, self.width)
        data = bytes([pkt_type.value]) + data
        encoded = cobs.encode(data) + b'\0'
        self.ser.write(encoded)
        self.ser.flushOutput()

    def receive_packet(self):
        packet = self.ser.read_until(b'\0')
        data = cobs.decode(packet[:-1])

        if self.debug:
            print(f'\033[93mReceived {len(data)} bytes\033[0m')
            hexdump(print, data, self.width)

        pkt_type, data = PacketType(data[0]), data[1:]
        if pkt_type is PacketType.COMM_ERROR:
            raise ProtocolError('Device-side serial communication error')
        elif pkt_type is PacketType.CRYPTO_ERROR:
            raise ProtocolError('Device-side cryptographic error')
        elif pkt_type is PacketType.TOO_MANY_FAILS:
            raise ProtocolError('Device reports too many failed handshake attempts')
        else:
            return pkt_type, data

class KeyMapper:
    Keycode = enum.Enum('Keycode', start=0, names='''
        KEY_NONE              _RESERVED_0x01  _RESERVED_0x02  _RESERVED_0x03  KEY_A               KEY_B           KEY_C            KEY_D
        KEY_E                 KEY_F           KEY_G           KEY_H           KEY_I               KEY_J           KEY_K            KEY_L
        KEY_M                 KEY_N           KEY_O           KEY_P           KEY_Q               KEY_R           KEY_S            KEY_T
        KEY_U                 KEY_V           KEY_W           KEY_X           KEY_Y               KEY_Z           KEY_1            KEY_2
        KEY_3                 KEY_4           KEY_5           KEY_6           KEY_7               KEY_8           KEY_9            KEY_0
        KEY_ENTER             KEY_ESC         KEY_BACKSPACE   KEY_TAB         KEY_SPACE           KEY_MINUS       KEY_EQUAL        KEY_LEFTBRACE
        KEY_RIGHTBRACE        KEY_BACKSLASH   KEY_HASH        KEY_SEMICOLON   KEY_APOSTROPHE      KEY_GRAVE       KEY_COMMA        KEY_DOT
        KEY_SLASH             KEY_CAPSLOCK    KEY_F1          KEY_F2          KEY_F3              KEY_F4          KEY_F5           KEY_F6
        KEY_F7                KEY_F8          KEY_F9          KEY_F10         KEY_F11             KEY_F12         KEY_SYSRQ        KEY_SCROLLLOCK
        KEY_PAUSE             KEY_INSERT      KEY_HOME        KEY_PAGEUP      KEY_DELETE          KEY_END         KEY_PAGEDOWN     KEY_RIGHT
        KEY_LEFT              KEY_DOWN        KEY_UP          KEY_NUMLOCK     KEY_KPSLASH         KEY_KPASTERISK  KEY_KPMINUS      KEY_KPPLUS
        KEY_KPENTER           KEY_KP1         KEY_KP2         KEY_KP3         KEY_KP4             KEY_KP5         KEY_KP6          KEY_KP7
        KEY_KP8               KEY_KP9         KEY_KP0         KEY_KPDOT       KEY_102ND           KEY_COMPOSE     KEY_POWER        KEY_KPEQUAL
        KEY_F13               KEY_F14         KEY_F15         KEY_F16         KEY_F17             KEY_F18         KEY_F19          KEY_F20
        KEY_F21               KEY_F22         KEY_F23         KEY_F24         KEY_OPEN            KEY_HELP        KEY_PROPS        KEY_FRONT
        KEY_STOP              KEY_AGAIN       KEY_UNDO        KEY_CUT         KEY_COPY            KEY_PASTE       KEY_FIND         KEY_MUTE
        KEY_VOLUMEUP          KEY_VOLUMEDOWN  _RESERVED_0x82  _RESERVED_0x83  _RESERVED_0x84      KEY_KPCOMMA     _RESERVED_0x86   KEY_RO
        KEY_KATAKANAHIRAGANA  KEY_YEN         KEY_HENKAN      KEY_MUHENKAN    KEY_KPJPCOMMA       _RESERVED_0x8D  _RESERVED_0x8E   _RESERVED_0x8F
        KEY_HANGEUL           KEY_HANJA       KEY_KATAKANA    KEY_HIRAGANA    KEY_ZENKAKUHANKAKU  _RESERVED_0x95  _RESERVED_0x96   _RESERVED_0x97
        _RESERVED_0x98        _RESERVED_0x99  _RESERVED_0x9A  _RESERVED_0x9B  _RESERVED_0x9C      _RESERVED_0x9D  _RESERVED_0x9E   _RESERVED_0x9F
        _RESERVED_0xA0        _RESERVED_0xA1  _RESERVED_0xA2  _RESERVED_0xA3  _RESERVED_0xA4      _RESERVED_0xA5  _RESERVED_0xA6   _RESERVED_0xA7
        _RESERVED_0xA8        _RESERVED_0xA9  _RESERVED_0xAA  _RESERVED_0xAB  _RESERVED_0xAC      _RESERVED_0xAD  _RESERVED_0xAE   _RESERVED_0xAF
        _RESERVED_0xB0        _RESERVED_0xB1  _RESERVED_0xB2  _RESERVED_0xB3  _RESERVED_0xB4      _RESERVED_0xB5  KEY_KPLEFTPAREN  KEY_KPRIGHTPAREN
        _RESERVED_0xB8        _RESERVED_0xB9  _RESERVED_0xBA  _RESERVED_0xBB  _RESERVED_0xBC      _RESERVED_0xBD  _RESERVED_0xBE   _RESERVED_0xBF
        _RESERVED_0xC0        _RESERVED_0xC1  _RESERVED_0xC2  _RESERVED_0xC3  _RESERVED_0xC4      _RESERVED_0xC5  _RESERVED_0xC6   _RESERVED_0xC7
        _RESERVED_0xC8        _RESERVED_0xC9  _RESERVED_0xCA  _RESERVED_0xCB  _RESERVED_0xCC      _RESERVED_0xCD  _RESERVED_0xCE   _RESERVED_0xCF
        _RESERVED_0xD0        _RESERVED_0xD1  _RESERVED_0xD2  _RESERVED_0xD3  _RESERVED_0xD4      _RESERVED_0xD5  _RESERVED_0xD6   _RESERVED_0xD7
        _RESERVED_0xD8        _RESERVED_0xD9  _RESERVED_0xDA  _RESERVED_0xDB  _RESERVED_0xDC      _RESERVED_0xDD  _RESERVED_0xDE   _RESERVED_0xDF
        _RESERVED_0xE0        _RESERVED_0xE1  _RESERVED_0xE2  _RESERVED_0xE3  _RESERVED_0xE4      _RESERVED_0xE5  _RESERVED_0xE6   _RESERVED_0xE7
        _RESERVED_0xE8        _RESERVED_0xE9  _RESERVED_0xEA  _RESERVED_0xEB  _RESERVED_0xEC      _RESERVED_0xED  _RESERVED_0xEE   _RESERVED_0xEF
        _RESERVED_0xF0        _RESERVED_0xF1  _RESERVED_0xF2  _RESERVED_0xF3  _RESERVED_0xF4      _RESERVED_0xF5  _RESERVED_0xF6   _RESERVED_0xF7
        _RESERVED_0xF8        _RESERVED_0xF9  _RESERVED_0xFA  _RESERVED_0xFB  _RESERVED_0xFC      _RESERVED_0xFD  _RESERVED_0xFE   _RESERVED_0xFF
        ''')

    MODIFIERS = [ uinput.ev.KEY_LEFTCTRL, uinput.ev.KEY_LEFTSHIFT, uinput.ev.KEY_LEFTALT, uinput.ev.KEY_LEFTMETA,
                  uinput.ev.KEY_RIGHTCTRL, uinput.ev.KEY_RIGHTSHIFT, uinput.ev.KEY_RIGHTALT, uinput.ev.KEY_RIGHTMETA ]

    ALL_KEYS =  [ v for k, v in uinput.ev.__dict__.items() if k.startswith('KEY_') ]
    REGULAR_MAP = { kc.value: getattr(uinput.ev, kc.name) for kc in Keycode if hasattr(uinput.ev, kc.name) }

    @classmethod
    def map_modifiers(kls, val):
        return [ mod for i, mod in enumerate(kls.MODIFIERS) if val & (1<<i) ]
    
    @classmethod
    def map_regulars(kls, keycodes):
        return [ kls.REGULAR_MAP[kc] for kc in keycodes if kc != 0 and kc in kls.REGULAR_MAP ]

class Magic:
    @classmethod
    def map_bytes_to_incantation(kls, data):
        elems = [ f'{kls.ADJECTIVES[a]} {kls.NOUNS[b]}' for a, b in zip(data[0::2], data[1::2]) ]
        nfirst = ", ".join(elems[:-1])
        return f'{nfirst} and {elems[-1]}'

    ADJECTIVES = '''
        wrathful      worthy         weird             warm             volatile     veiled      vacuous       useless
        upset         unsoiled       unsightly         unpronounceable  unfriendly   unfree      unfit         unfaithful
        unchaste      unbroken       unbound           unblessed        unbefitting  unaltered   unabused      unable
        ugly          tongued        thorny            thirsty          thick        terminal    ten-sided     teeming
        tangerine     taken          substantial       stupefying       stringy      strange     stillborn     sticky
        stagnant      spongy         sour              soul-destroying  smoldering   smitten     slain         six-sided
        shifting      shadowy        severed           seven-sided      serene       salty       rust-red      royal
        rotten        riddled        resentful         regrettable      reeking      rare        rank          rancid
        quiescent     putrid         putrid            putrescent       prehistoric  predatory   predaceous    porous
        poisonous     pierced        phlegmatic        petrifying       pessimal     pathetic    odorless      oddish
        obsessed      obscene        numb              nine-sided       nasty        mysterious  mute          musky
        morose        moribund       moldy             miasmic          material     many-lobed  malodorous    malign
        maimed        luminescent    low-cut           lousy            live         limp        lifeless      leering
        leaky         layered        latent            lackluster       jagged       irregular   iridescent    intangible
        infinite      inept          incomprehensible  in-between       improper     idle        hunted        hideous
        heavy         hairy          guilty            grotesque        grey         greedy      gory          gorgeous
        gooey         golden-brown   golden            ghastly          frostbitten  fresh-cut   freakish      frantic
        fossilized    formless       formidable        floccose         five-lobed   firstborn   filthy        fickle
        fetid         fertile        fearful           fatal            familiar     fallen      fallacious    faint
        faceless      extinct        esoteric          errant           emergent     elastic     eight-sided   eerie
        ebon          dysphoric      dying             dumb             dull-purple  dull        dull          dull
        dormant       doomed         disfigured        dirty            defenseless  deep-pink   deep          deconsecrated
        deathlike     deadly         dead              dark-blue        dark         curly       curious       cured
        cunning       crystalline    cryptic           crying           crumbly      crimson     crested       creepy
        crazy         corrupt        corporeal         contemptible     contained    concrete    cloudy        chopped
        chained       caustic        catholic          cathartic        captive      cancerous   cabalistic    burnt
        buoyant       bronze-red     bronze            broken           bright-red   breathless  bound         bound
        bottomless    bony           bodiless          blue-lilac       blue         bloody      bloodthirsty  bloodsucking
        bloodstained  bloodcurdling  blonde            blistered        blank        bitter      bilgy         bewitched
        befouled      beardless      bastardly         barbed           baleful      balding     awkward       awful
        atrocious     arcane         appalling         antic            anonymous    angry       ample         ambiguous
        amber-green   amber          aghast            activated        acidic       abused      abstruse      abject
        '''.split()

    NOUNS = '''
        yolk         writing        wrath      wound          worm              wings         whistle       watchdog
        waste        vomit          vermin     variation      underachievement  tusk          troll         trick
        transplant   transgression  tooth      tongue         tickle            tick          thorn         thistle
        thing        terror         tentacle   tease          surrender         surge         sucker        substance
        storm        stone          stew       stalk          squid             sprout        sponge        spill
        spider       sphere         spectacle  speck          spawn             soul          solution      snout
        snake        smell          sloth      slime          slice             sleeper       slave         sinew
        shell        shape          seizure    seed           schism            scam          scale         sainthood
        root         robe           roach      rinse          remains           relay         rejuvenation  realization
        reaction     ransom         pupa       pride          prey              predator      potion        pornography
        polyp        plum           pleasure   pitch          pigeon            phenomenon    pest          periwinkle
        percolation  parasite       pair       oyster         orphan            orgasm        organism      orchid
        object       nail           mushroom   murder         mucus             movement      mother        mold
        mist         mildew         metal      mesh           meddling          mayhem        masterpiece   masonry
        mask         manhood        maggot     lust           loop              living_thing  liquor        liquid
        lining       laceration     knife      kitten         kiss              jumper        jest          instrument
        injustice    injury         influence  indulgence     incursion         impulse       imago         hound
        horn         hook           hoof       heirloom       heart             hawk          hare          hair
        gulp         guardian       grass      goat           gnat              gluttony      glowworm      gasp
        game         fusion         fungus     frustration    frog              foul          foot          food
        fog          foal           fluke      fluff          flower            flicker       flea          flattery
        flask        flare          firefly    finger         filtration        female        feeder        feather
        fart         fang           failure    face           fabrication       extract       exodus        evil
        envy         enema          embryo     egress         echo              eater         ear           dwarf
        dust         drop           draft      domestication  distortion        dew           depravity     deity
        death        daughter       dash       dagger         culture           crutch        crow          critter
        creeper      creation       crab       corruption     cocoon            claw          chip          child
        cell         catch          carving    carrot         carnival          cancer        butterfly     burn
        buildup      brush          brew       bottle         boot              book          bone          blunder
        blot         blood          blink      bite           bird              benthos       beak          basket
        bark         ball           baby       axolotl        ashes             artifact      arson         armor
        apparition   antenna        alms       alienation     advent            adornment     abomination   abandonment
        '''.split()

class NoiseEngine:
    def __init__(self, host_key, packetizer, debug=False):
        self.debug = debug
        self.packetizer = packetizer
        self.static_local = host_key
        self.proto = NoiseConnection.from_name(b'Noise_XX_25519_ChaChaPoly_BLAKE2s')
        self.proto.set_as_initiator()
        self.proto.set_keypair_from_private_bytes(Keypair.STATIC, self.static_local)
        self.proto.start_handshake()
        self.handshake = self.proto.noise_protocol.handshake_state # save for later because someone didn't think
        self.paired = False
        self.connected = False

    @property
    def remote_fingerprint(self):
        ''' Return the SHA-256 hash of the remote static key (rs). This can be used to fingerprint the remote party. '''
        return hashlib.sha256(self.handshake.rs.public_bytes).hexdigest()

    @classmethod
    def generate_private_key_x25519(kls):
        # This is taken from noise-c's reference implementation. This would not be needed had not cryptography/hazmat
        # decided noone would ever need serialized x25519 private keys and noiseprotocol stopped just short of implementing
        # key generation (who'd need that anyway, amiright?) -.-
        key = list(secrets.token_bytes(32))
        key[0] &= 0xF8
        key[31] = (key[31] & 0x7F) | 0x40
        return bytes(key)

    @wraps(print)
    def debug_print(self, *args, **kwargs):
        if self.debug:
            print(*args, **kwargs)

    def perform_handshake(self):
        self.packetizer.send_packet(PacketType.INITIATE_HANDSHAKE, b'')
        self.debug_print('Handshake started')

        while True:
            if self.proto.handshake_finished:
                break
            self.packetizer.send_packet(PacketType.HANDSHAKE, self.proto.write_message())

            if self.proto.handshake_finished:
                    break
            pkt_type, payload = self.packetizer.receive_packet()
            if pkt_type is PacketType.HANDSHAKE:
                self.proto.read_message(payload)
            else:
                raise ProtocolError(f'Incorrect packet type {pkt_type}. Ignoring since this is only test code.')

        msg_type, payload = self.packetizer.receive_packet()
        rtype, data = self._decrypt(payload)
        if rtype is ReportType.PAIRING_SUCCESS:
            self.connected, self.paired = True, True
        elif rtype is ReportType.PAIRING_START:
            self.connected, self.paired = True, False
        else:
            self.connected, self.paired = True, False
            raise UserWarning(f'Unexpected record type {rtype} in {msg_type} packet. Ignoring.')

        if self.debug:
            print('Handshake finished, handshake hash:')
            hexdump(print, self.proto.get_handshake_hash())

    def channel_binding_incantation(self):
        hhash = self.proto.get_handshake_hash()
        return '\n'.join(Magic.map_bytes_to_incantation(hhash[i:i+8]) for i in range(0, 16, 8))

    def receive_loop(self):
        while True:
            try:
                pkt_type, received = self.packetizer.receive_packet()
            except Exception as e:
                self.debug_print('Invalid framing:', e)

            if pkt_type is not PacketType.DATA:
                raise UserWarning(f'Unexpected packet type {pkt_type}. Ignoring.')
                continue

            rtype, data = self._decrypt(received)
            if self.debug:
                print(f'Decrypted packet {rtype} ({rtype.value}):')
                hexdump(print, data)
            yield rtype, data

    def _decrypt(self, received):
        try:
            data = self.proto.decrypt(received)
            return ReportType(data[0]), data[1:]

        except NoiseInvalidMessage as e:
            self.debug_print('Invalid noise message', e)
            for i in range(3):
                with self._nonce_lookahead() as set_nonce:
                    set_nonce(i)
                    data = self.proto.decrypt(received)
                    return ReportType(data[0]), data[1:]
            else:
                self.debug_print('    Unrecoverable.')
                raise e
            self.debug_print(f'    Recovered. n={n}')

    @contextmanager
    def _nonce_lookahead(self):
        nold = self.proto.noise_protocol.cipher_state_decrypt.n
        def setter(n):
            self.proto.noise_protocol.cipher_state_decrypt.n = nold + n

        with suppress(NoiseInvalidMessage):
            yield setter

        self.proto.noise_protocol.cipher_state_decrypt.n = nold

    def pairing_messages(self):
        user_input = ''
        for msg_type, payload in self.receive_loop():
            if msg_type is ReportType.PAIRING_INPUT:
                ch = chr(payload[0])
                if ch == '\b':
                    user_input = user_input[:-1]
                else:
                    user_input += ch
                yield user_input

            elif msg_type is ReportType.PAIRING_SUCCESS:
                self.paired = True
                break

            elif msg_type is ReportType.PAIRING_ERROR:
                raise ProtocolError('Device-side pairing error') # FIXME find better exception subclass here

            else:
                raise ProtocolError('Invalid report type')

    def uinput_passthrough(self):
        with uinput.Device(KeyMapper.ALL_KEYS) as ui:
            old_kcs = set()
            for msg_type, payload in self.receive_loop():
                report_len, *report = payload
                if report_len != 8:
                    raise ValueError('Unsupported report length', report_len)

                if msg_type is ReportType.KEYBOARD:
                    modbyte, _reserved, *keycodes = report
                    import binascii
                    keys = { *KeyMapper.map_modifiers(modbyte), *KeyMapper.map_regulars(keycodes) }
                    if self.debug:
                        print('Emitting:', keys)

                    for key in keys - old_kcs:
                        ui.emit(key, 1, syn=False)
                    for key in old_kcs - keys:
                        ui.emit(key, 0, syn=False)
                    ui.syn()
                    old_kcs = keys

                elif msg_type is ReportType.MOUSE:
                    # FIXME unhandled
                    pass

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('serial')
    parser.add_argument('baudrate')
    parser.add_argument('-w', '--width', type=int, default=16, help='Number of bytes to display in one line')
    parser.add_argument('-d', '--debug', action='store_true')
    args = parser.parse_args()

    ser = serial.Serial(args.serial, args.baudrate)
    packetizer = Packetizer(ser, debug=args.debug, width=args.width)
    noise = NoiseEngine(packetizer, debug=args.debug)
    noise.perform_handshake()

    print('Handshake channel binding incantation:')
    print(noise.channel_binding_incantation())

    for user_input in noise.pairing_messages():
        if not args.debug:
            print('\033[2K\r', end='')
        print('Pairing input:', user_input, end='' if not args.debug else '\n', flush=True)
    print()
    print('Pairing success')

    noise.uinput_passthrough()
