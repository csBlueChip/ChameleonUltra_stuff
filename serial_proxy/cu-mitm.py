#!/usr/bin/env python3
"""

	W   W   A   RRRR N  N III N  N GGGG
	W   W  A A  R  R NN N  I  NN N G
	W W W  AAA  RRRR N NN  I  N NN G GG    THIS IS AI SLOP
	W W W A   A R R  N  N  I  N  N G  G
	 WWW  A   A R  R N  N III N  N GGGG

	This was knocked out by Claude
	I have done some basic hand holding
	But I have NOT done things like verify all the lookup tables

	It was created with a specific purpose in mind
	and is shared on the off-chance that it might be of help to someone else

	It comes with NO promises or assurances!
	But it has helped me work out what I wanted to know.

	BC

serial_sniff.py — PTY proxy sniffer for serial ports, with Chameleon Ultra protocol decoder.

Usage:
    python3 serial_sniff.py [OPTIONS] [PORT]

Options:
    -p, --port      Real serial port (default: /dev/ttyACM0)
    -b, --baud      Baud rate (default: 115200)
    -l, --log       Log file path (default: serial_sniff.log, use - for stdout only)
    --no-color      Disable ANSI color output
    --no-decode     Disable Chameleon Ultra protocol decoding
    --width         Bytes per hexdump row (default: 16)

Connect your app to the PTY path printed at startup instead of the real port.
Press Ctrl+C to stop.
"""

import argparse
import os
import pty
import select
import serial
import struct
import sys
import time
import tty
from datetime import datetime


# ---------------------------------------------------------------------------
# ANSI colors
# ---------------------------------------------------------------------------
class C:
    TX     = "\033[1;32m"   # green  — PC → device
    RX     = "\033[1;36m"   # cyan   — device → PC
    META   = "\033[1;33m"   # yellow — open/close/info
    DECODE = "\033[1;35m"   # magenta — decoded frame fields
    VAL    = "\033[1;33m"   # yellow — extracted payload values
    OK     = "\033[1;32m"   # green  — [OK]
    LRC2   = "\033[1;34m"   # bright blue — opcodes covered by LRC2
    BGBLU  = "\033[1;37;44m" # white on blue background — PTY path
    WARN   = "\033[1;35m"   # bright magenta — expected ...
    ERR    = "\033[1;31m"   # red — decode errors
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"


# ---------------------------------------------------------------------------
# Chameleon Ultra protocol decoder
# ---------------------------------------------------------------------------

SOF  = 0x11
LRC1 = 0xEF
FRAME_HEADER_LEN = 10   # SOF LRC1 CMD[2] STATUS[2] LEN[2] LRC2  (+LRC3 at end)

# STATUS is a 1-byte value in the high byte of the 2-byte STATUS field.
# Commands always send 0x0000 (no status). Responses carry status in byte[0].
STATUS_CODES = {
    0x00: "HF_TAG_OK",
    0x01: "HF_TAG_NO",
    0x02: "HF_ERR_STAT",
    0x03: "HF_ERR_CRC",
    0x04: "HF_COLLISION",
    0x05: "HF_ERR_BCC",
    0x06: "MF_ERR_AUTH",
    0x07: "HF_ERR_PARITY",
    0x08: "HF_ERR_ATS",
    0x40: "LF_TAG_OK",
    0x41: "LF_TAG_NO_FOUND",
    0x60: "PAR_ERR",
    0x66: "DEVICE_MODE_ERROR",
    0x67: "INVALID_CMD",
    0x68: "SUCCESS",
    0x69: "NOT_IMPLEMENTED",
    0x70: "FLASH_WRITE_FAIL",
    0x71: "FLASH_READ_FAIL",
    0x72: "INVALID_SLOT_TYPE",
}

COMMANDS = {
    # Hardware / device management
    1000: "GET_APP_VERSION",
    1001: "CHANGE_DEVICE_MODE",
    1002: "GET_DEVICE_MODE",
    1003: "SET_ACTIVE_SLOT",
    1004: "SET_SLOT_TAG_TYPE",
    1005: "SET_SLOT_DATA_DEFAULT",
    1006: "SET_SLOT_ENABLE",
    1007: "SET_SLOT_TAG_NICK",
    1008: "GET_SLOT_TAG_NICK",
    1009: "SLOT_DATA_CONFIG_SAVE",
    1010: "ENTER_BOOTLOADER",
    1011: "GET_DEVICE_CHIP_ID",
    1012: "GET_DEVICE_ADDRESS",
    1013: "SAVE_SETTINGS",
    1014: "RESET_SETTINGS",
    1015: "SET_ANIMATION_MODE",
    1016: "GET_ANIMATION_MODE",
    1017: "GET_GIT_VERSION",
    1018: "GET_ACTIVE_SLOT",
    1019: "GET_SLOT_INFO",
    1020: "WIPE_FDS",
    1021: "DELETE_SLOT_TAG_NICK",
    1023: "GET_ENABLED_SLOTS",
    1024: "DELETE_SLOT_SENSE_TYPE",
    1025: "GET_BATTERY_INFO",
    1026: "GET_BUTTON_PRESS_CONFIG",
    1027: "SET_BUTTON_PRESS_CONFIG",
    1028: "GET_LONG_BUTTON_PRESS_CONFIG",
    1029: "SET_LONG_BUTTON_PRESS_CONFIG",
    1030: "SET_BLE_PAIRING_KEY",
    1031: "GET_BLE_PAIRING_KEY",
    1032: "DELETE_ALL_BLE_BONDS",
    1033: "GET_DEVICE_MODEL",
    1034: "GET_DEVICE_SETTINGS",
    1035: "GET_DEVICE_CAPABILITIES",
    1036: "GET_BLE_PAIRING_ENABLE",
    1037: "SET_BLE_PAIRING_ENABLE",
    # HF
    2000: "HF14A_SCAN",
    2001: "MF1_DETECT_SUPPORT",
    2002: "MF1_DETECT_PRNG",
    2003: "MF1_STATIC_NESTED_ACQUIRE",
    2004: "MF1_DARKSIDE_ACQUIRE",
    2005: "MF1_DETECT_NT_DIST",
    2006: "MF1_NESTED_ACQUIRE",
    2007: "MF1_AUTH_ONE_KEY_BLOCK",
    2008: "MF1_READ_ONE_BLOCK",
    2009: "MF1_WRITE_ONE_BLOCK",
    2010: "HF14A_RAW",
    2011: "MF1_MANIPULATE_VALUE_BLOCK",
    2012: "MF1_CHECK_KEYS_OF_SECTORS",
    # LF
    3000: "EM410X_SCAN",
    3001: "EM410X_WRITE_TO_T55XX",
    3002: "HIDPROX_SCAN",
    3003: "HIDPROX_WRITE_TO_T55XX",
    # Emulator
    4000: "MF1_WRITE_EMU_BLOCK_DATA",
    4001: "HF14A_SET_ANTI_COLL_DATA",
    4004: "MF1_SET_DETECTION_ENABLE",
    4005: "MF1_GET_DETECTION_COUNT",
    4006: "MF1_GET_DETECTION_LOG",
    4007: "MF1_GET_DETECTION_ENABLE",
    4008: "MF1_READ_EMU_BLOCK_DATA",
    4009: "MF1_GET_EMULATOR_CONFIG",
    4010: "MF1_GET_GEN1A_MODE",
    4011: "MF1_SET_GEN1A_MODE",
    4012: "MF1_GET_GEN2_MODE",
    4013: "MF1_SET_GEN2_MODE",
    4014: "MF1_GET_BLOCK_ANTI_COLL_MODE",
    4015: "MF1_SET_BLOCK_ANTI_COLL_MODE",
    4016: "MF1_GET_WRITE_MODE",
    4017: "MF1_SET_WRITE_MODE",
    4018: "HF14A_GET_ANTI_COLL_DATA",
    4019: "MF0_NTAG_GET_UID_MAGIC_MODE",
    4020: "MF0_NTAG_SET_UID_MAGIC_MODE",
    4021: "MF0_NTAG_READ_EMU_PAGE_DATA",
    4022: "MF0_NTAG_WRITE_EMU_PAGE_DATA",
    4023: "MF0_NTAG_GET_VERSION_DATA",
    4024: "MF0_NTAG_SET_VERSION_DATA",
    4025: "MF0_NTAG_GET_SIGNATURE_DATA",
    4026: "MF0_NTAG_SET_SIGNATURE_DATA",
    4027: "MF0_NTAG_GET_COUNTER_DATA",
    4028: "MF0_NTAG_SET_COUNTER_DATA",
    4029: "MF0_NTAG_RESET_AUTH_CNT",
    4030: "MF0_NTAG_GET_PAGE_COUNT",
    # Device management (continued)
    1038: "GET_ALL_SLOT_NICKS",
    1039: "GET_SLEEP_TIMEOUT",
    1040: "SET_SLEEP_TIMEOUT",
    # HF (continued)
    2013: "MF1_HARDNESTED_ACQUIRE",
    2014: "MF1_ENC_NESTED_ACQUIRE",
    2015: "MF1_CHECK_KEYS_ON_BLOCK",
    2016: "HF14A_SCAN_KEEP",
    2017: "HF14A_AUTH_TRACE",
    2020: "HF14A_SNIFF",
    2200: "HF14A_GET_CONFIG",
    2201: "HF14A_SET_CONFIG",
    # LF (continued)
    3004: "VIKING_SCAN",
    3005: "VIKING_WRITE_TO_T55XX",
    3006: "EM410X_ELECTRA_WRITE_TO_T55XX",
    3009: "ADC_GENERIC_READ",
    3010: "IOPROX_SCAN",
    3011: "IOPROX_WRITE_TO_T55XX",
    3012: "IOPROX_DECODE_RAW",
    3013: "IOPROX_COMPOSE_ID",
    3014: "PAC_SCAN",
    3015: "PAC_WRITE_TO_T55XX",
    3016: "LF_T55XX_WRITE",
    3018: "IDTECK_WRITE_TO_T55XX",
    3019: "JABLOTRON_SCAN",
    3020: "JABLOTRON_WRITE_TO_T55XX",
    3030: "EM4X05_SCAN",
    3031: "LF_SNIFF",
    3032: "EM4X05_READSNIFF",
    # Emulator (continued)
    4031: "MF0_NTAG_GET_WRITE_MODE",
    4032: "MF0_NTAG_SET_WRITE_MODE",
    4033: "MF0_NTAG_SET_DETECTION_ENABLE",
    4034: "MF0_NTAG_GET_DETECTION_COUNT",
    4035: "MF0_NTAG_GET_DETECTION_LOG",
    4036: "MF0_NTAG_GET_DETECTION_ENABLE",
    4037: "MF0_NTAG_GET_EMULATOR_CONFIG",
    4038: "MF1_SET_FIELD_OFF_DO_RESET",
    4039: "MF1_GET_FIELD_OFF_DO_RESET",
    4040: "MF1_GET_PRNG_TYPE",
    4041: "MF1_SET_PRNG_TYPE",
    # LF emulator
    5000: "EM410X_SET_EMU_ID",
    5001: "EM410X_GET_EMU_ID",
    5002: "HIDPROX_SET_EMU_ID",
    5003: "HIDPROX_GET_EMU_ID",
    5004: "VIKING_SET_EMU_ID",
    5005: "VIKING_GET_EMU_ID",
    5006: "PAC_SET_EMU_ID",
    5007: "PAC_GET_EMU_ID",
    5008: "IOPROX_SET_EMU_ID",
    5009: "IOPROX_GET_EMU_ID",
    5010: "JABLOTRON_SET_EMU_ID",
    5011: "JABLOTRON_GET_EMU_ID",
    5012: "IDTECK_SET_EMU_ID",
    5013: "IDTECK_GET_EMU_ID",
    # ISO14443-4 T=CL
    6000: "HF14A_4_APDU_RECV",
    6001: "HF14A_4_APDU_SEND",
    6002: "HF14A_4_SET_ANTI_COLL",
    6003: "HF14A_4_STATIC_RESP",
    6004: "HF14A_4_READER_APDU",
    6005: "HF14A_4_EMV_SCAN",
}

DEVICE_MODES    = {0: "EMULATOR", 1: "READER"}
DEVICE_MODELS   = {0: "Ultra", 1: "Lite"}
ANIMATION_MODES = {0: "NONE", 1: "MINIMAL", 2: "FULL"}
SENSE_TYPES     = {0: "HF", 1: "LF"}
MF1_KEY_TYPES   = {0x60: "KEY_A", 0x61: "KEY_B"}
WRITE_MODES     = {0: "NORMAL", 1: "DENIED", 2: "DECEIVE", 3: "SHADOW"}
PRNG_TYPES      = {0: "STATIC", 1: "WEAK", 2: "HARD"}

TAG_TYPES = {
    0x0000: "UNDEFINED",
    0x0001: "EM410X",
    0x0002: "MIFARE_Mini",
    0x0003: "MIFARE_1K",
    0x0004: "MIFARE_2K",
    0x0005: "MIFARE_4K",
    0x0006: "MIFARE_UL",
    0x0007: "MIFARE_UL_EV1_80",
    0x0008: "MIFARE_UL_EV1_164",
    0x0009: "NTAG_210",
    0x000A: "NTAG_212",
    0x000B: "NTAG_213",
    0x000C: "NTAG_215",
    0x000D: "NTAG_216",
    0x000E: "MF_DESFIRE",
    0x000F: "MF_DESFIRE_EV1_2K",
    0x0010: "MF_DESFIRE_EV1_4K",
    0x0011: "MF_DESFIRE_EV1_8K",
    0x0012: "MF_DESFIRE_EV2_2K",
    0x0013: "MF_DESFIRE_EV2_4K",
    0x0014: "MF_DESFIRE_EV2_8K",
    0x07D0: "HID_PROX",
}

# ISO14443A / MIFARE / NTAG command bytes sent in HF14A_RAW tx_data
ISO14443A_CMDS = {
    # ISO14443-3 Type A
    0x26: ("REQA",          None),
    0x52: ("WUPA",          None),
    0x50: ("HLTA",          "args: none (2-byte cmd, no data)"),
    0x93: ("SEL_CL1",       "args: NVB[1] + UID-CLn[0-4] + BCC"),
    0x95: ("SEL_CL2",       "args: NVB[1] + UID-CLn[0-4] + BCC"),
    0x97: ("SEL_CL3",       "args: NVB[1] + UID-CLn[0-4] + BCC"),
    0xE0: ("RATS",          "args: PARAM[1] (FSD/CID)"),
    0xC2: ("PPS",           "args: PPS0[1]"),
    0xCA: ("DESELECT",      None),
    # MIFARE Classic
    0x60: ("MF_AUTH_KEY_A/GET_VERSION", "args: block[1] for MF auth -or- none for NTAG GET_VERSION"),
    0x61: ("MF_AUTH_KEY_B", "args: block[1]  →  then 3-pass crypto1 auth"),
    0x30: ("MF_READ",       "args: block[1]  →  16 bytes"),
    0xA0: ("MF_WRITE",      "args: block[1]  →  ACK, then 16 bytes data"),
    0xA2: ("MF_UL_WRITE",   "args: page[1] + data[4]"),
    0xC0: ("MF_DECREMENT",  "args: block[1] + value[4]"),
    0xC1: ("MF_INCREMENT",  "args: block[1] + value[4]"),
    0xC2: ("MF_RESTORE/PPS", "args: block[1] for MF restore -or- PPS0[1] for ISO14443-4"),
    0xB0: ("MF_TRANSFER",   "args: block[1]"),
    # MIFARE Ultralight / NTAG
    0x3A: ("MF_FAST_READ",  "args: start_page[1] + end_page[1]  →  pages"),
    0x1B: ("PWD_AUTH",      "args: password[4]  →  PACK[2]"),
    0x3C: ("READ_SIG",      "args: addr[1]=0x00  →  sig[32]"),
    0x1A: ("UL_C_AUTH1",    "args: none  →  ekRndB[9]"),
    0xAF: ("UL_C_AUTH2",    "args: ekRndA[17]  →  ok/err"),
    # DESFire
    0x90: ("DESFIRE_WRAPPED", "args: INS[1] + data...  (ISO7816 wrapped)"),
    # Generic
    0x02: ("T=CL_BLOCK",    "args: PCB + data  (ISO14443-4 I-block)"),
    0x03: ("T=CL_BLOCK",    "args: PCB + data  (ISO14443-4 I-block)"),
}


def annotate_iso14443a(data: bytes) -> str:
    """Return a human-readable annotation for raw ISO14443A tx bytes."""
    if not data:
        return data.hex()
    cmd_byte = data[0]
    args = data[1:]
    entry = ISO14443A_CMDS.get(cmd_byte)
    if not entry:
        return data.hex()
    name, _ = entry
    base = f"0x{cmd_byte:02x}:{name}"

    # Per-command argument decoding
    if cmd_byte in (0x60, 0x61) and len(args) >= 1:   # MF_AUTH_KEY_A/B: block
        base += f"  block=0x{args[0]:02x}({args[0]})"
    elif cmd_byte == 0x30 and len(args) >= 1:          # MF_READ: page
        base += f"  page=0x{args[0]:02x}({args[0]})"
    elif cmd_byte == 0x3A and len(args) >= 2:          # FAST_READ: start, end
        base += f"  start=0x{args[0]:02x}({args[0]}) end=0x{args[1]:02x}({args[1]})"
    elif cmd_byte == 0xA0 and len(args) >= 1:          # MF_WRITE: block
        base += f"  block=0x{args[0]:02x}({args[0]})"
    elif cmd_byte == 0xA2 and len(args) >= 1:          # MF_UL_WRITE: page + data
        base += f"  page=0x{args[0]:02x}({args[0]})"
        if len(args) >= 5:
            base += f"  data={args[1:5].hex()}"
    elif cmd_byte == 0x1B and len(args) >= 4:          # PWD_AUTH: password
        base += f"  pwd={args[:4].hex()}"
    elif cmd_byte == 0x50:                             # HLTA: no args
        pass
    elif cmd_byte == 0xE0 and len(args) >= 1:          # RATS: PARAM byte
        fsdi = (args[0] >> 4) & 0x0F
        cid  = args[0] & 0x0F
        base += f"  FSDI={fsdi} CID={cid}"
    elif cmd_byte in (0x93, 0x95, 0x97) and len(args) >= 1:  # SEL: NVB
        base += f"  NVB=0x{args[0]:02x}"
        if len(args) > 1:
            base += f"  data={args[1:].hex()}"
    elif len(args) > 0:
        base += f"  args={args.hex()}"

    return base



def annotate_iso14443a_response(data: bytes) -> str:
    """Annotate raw ISO14443A card response bytes."""
    if not data:
        return data.hex()
    b0 = data[0]

    # Single-byte responses
    SINGLE = {
        0x0A: "ACK",
        0x00: "NAK(0) - invalid operation",
        0x01: "NAK(1) - CRC/parity error",
        0x04: "NAK(4) - auth/counter error",
        0x05: "NAK(5) - no write access / eeprom error",
    }
    if len(data) == 1 and b0 in SINGLE:
        return f"0x{b0:02x}:{SINGLE[b0]}"

    # ATQA: 2 bytes returned from REQA/WUPA
    if len(data) == 2:
        return f"0x{b0:02x} {data[1]:02x} (ATQA)"

    # SAK: 1 or 3 bytes after SELECT
    if len(data) == 3 and data[1] == 0x28:
        return f"0x{b0:02x}:SAK (ISO14443-4 compliant) + {data[1:].hex()}"

    # PACK: 2 bytes after PWD_AUTH success
    if len(data) == 2:
        return f"0x{b0:02x}{data[1]:02x}:PACK (pwd auth ack)"

    # ATS: starts with length byte TL
    if len(data) >= 2 and b0 == len(data):
        return f"ATS[{b0}]: {data.hex()}"

    # NXP GET_VERSION response: 8 bytes, byte0=0x00, byte1=0x04 (NXP vendor)
    if len(data) == 8 and b0 == 0x00 and data[1] == 0x04:
        prod = {0x03: "MIFARE_UL", 0x04: "NTAG"}.get(data[2], f"0x{data[2]:02x}")
        return f"GET_VERSION rsp: vendor=NXP prod={prod} v{data[4]}.{data[5]} size=0x{data[6]:02x} proto=0x{data[7]:02x} | {data.hex()}"

    # NDEF/capability container starts with E1
    if b0 == 0xE1:
        return f"NDEF CC: {data.hex()}"

    # DESFire status trailers
    DESFIRE_STATUS = {0x90: "ok", 0xAF: "more data", 0x6A: "err:no such file", 0x91: "err"}
    if b0 in DESFIRE_STATUS and len(data) >= 2:
        return f"{data[:-2].hex()} | SW={data[-2]:02x}{data[-1]:02x}:{DESFIRE_STATUS.get(data[-2], '?')}"

    return data.hex()



def lrc(data: bytes) -> int:
    """8-bit two's complement of sum of bytes mod 256."""
    return (-sum(data)) & 0xFF


# Each decode entry: (offset, raw_bytes, label, highlight, value)
# label  = field name, e.g. "version_major"
# value  = extracted value string, e.g. "2"  (coloured separately)
# highlight = True for payload fields
DecodeEntry = tuple


def bstr(b: bytes) -> str:
    """Compact hex string for a byte sequence."""
    return " ".join(f"{x:02x}" for x in b)


def render_decode(entries: list[DecodeEntry], use_color: bool = False) -> list[str]:
    """
    Format decode entries as disassembler-style lines.
    label : value   (colon separator; value highlighted in yellow)
    [OK]  in green, "expected 0xNN" in bright magenta.
    Entries with raw=None are blank-line markers (inserted by decode_frame).
    """
    if not entries:
        return []
    real = [e for e in entries if e[1] is not None]
    if not real:
        return []
    max_bytes = max(len(e[1]) for e in real)
    BYTE_COL = min(max_bytes, 8) * 3 + 2
    result = []
    for entry in entries:
        if entry[1] is None:
            continue
        offset    = entry[0]
        raw       = entry[1]
        label     = entry[2]
        highlight = entry[3] if len(entry) > 3 else False
        value     = entry[4] if len(entry) > 4 else None
        opcode_zone = entry[5] if len(entry) > 5 else None
        if len(raw) > 8:
            byte_str = f"[{bstr(raw[:8])} ...]"
        else:
            byte_str = f"[{bstr(raw)}]"
        byte_str = byte_str.ljust(BYTE_COL)
        if use_color and opcode_zone == "lrc2":
            byte_str = C.LRC2 + byte_str + C.RESET
        if highlight and value is not None:
            if use_color:
                # colour [OK] green, "expected …" magenta, anything else yellow
                if value == "[OK]":
                    val_str = f"{C.OK}{value}{C.RESET}"
                elif value.startswith("expected "):
                    val_str = f"{C.WARN}{value}{C.RESET}"
                else:
                    val_str = f"{C.VAL}{value}{C.RESET}"
                desc = f"{label} : {val_str}" if label else val_str
            else:
                desc = f"{label} : {value}" if label else value
        else:
            # Non-highlighted label — but still colour [OK]/expected substrings
            if use_color:
                desc = label.replace("[OK]", f"{C.OK}[OK]{C.RESET}")
                desc = desc.replace("expected ", f"{C.WARN}expected ")
                # close WARN colour if it was opened
                if f"{C.WARN}expected " in desc and C.RESET not in desc.split(f"{C.WARN}expected ")[-1]:
                    desc += C.RESET
            else:
                desc = label
        result.append(f"  {offset:04x}: {byte_str} - {desc}")
    return result

def decode_frame(frame: bytes, is_response: bool) -> list[DecodeEntry]:
    """
    Decode a complete Chameleon Ultra frame into (offset, bytes, description) entries.
    frame must start at SOF.
    """
    b = frame
    entries: list[DecodeEntry] = []

    # --- Fixed header ---
    # (label, highlight, value) — value is coloured, label is plain
    def hdr(offset, raw, label, value):
        entries.append((offset, raw, label, True, str(value)))

    # SOF/LRC are fixed opcodes — no extracted value, no highlight
    entries.append((0x00, b[0:1], "SOF", False))
    entries.append((0x01, b[1:2], "LRC1{00}[1] [OK]", False))

    cmd         = struct.unpack(">H", b[2:4])[0]
    status_byte = b[5]   # low byte; b[4] is always 0x00 padding
    dlen        = struct.unpack(">H", b[6:8])[0]
    lrc2        = b[8]

    cmd_name  = COMMANDS.get(cmd, f"CMD_0x{cmd:04x}")
    direction = "RSP" if is_response else "CMD"

    # CMD: 0x<hex> (<decimal>:<name>) [DIR]
    entries.append((0x02, b[2:4], "CMD",    True, f"0x{cmd:04x} ({cmd:d}:{cmd_name})", "lrc2"))

    # STATUS: 0x<hex> (<decimal>:<lookup>)  — response only gets lookup
    status_word = struct.unpack(">H", b[4:6])[0]
    if is_response:
        status_str = STATUS_CODES.get(status_byte, None)
        status_val = f"0x{status_word:04x} ({status_word:d}" + (f":{status_str})" if status_str else ")")
    else:
        status_val = f"0x{status_word:04x} ({status_word:d})"
    entries.append((0x04, b[4:6], "STS", True, status_val, "lrc2"))

    # LEN: 0x<hex> (<decimal>)
    entries.append((0x06, b[6:8], "LEN", True, f"0x{dlen:04x} ({dlen:d})", "lrc2"))

    expected_lrc2 = lrc(b[2:8])
    lrc2_ok   = lrc2 == expected_lrc2
    lrc2_note = "[OK]" if lrc2_ok else f"expected 0x{expected_lrc2:02x}"
    entries.append((0x08, b[8:9], f"LRC2{{02..07}}[6] {lrc2_note}", False, None, "lrc2"))

    data = bytes(b[9:9+dlen])
    lrc3 = b[9+dlen]

    # --- Payload ---
    payload_entries = decode_payload(cmd, data, is_response, base_offset=9)
    if payload_entries:
        entries.extend(payload_entries)
    elif dlen > 0:
        entries.append((0x09, data, "DATA", True, f"0x{dlen:04x} ({dlen:d} bytes)"))

    # --- LRC3 ---
    expected_lrc3 = lrc(data) if data else 0x00
    lrc3_ok   = lrc3 == expected_lrc3
    lrc3_note = "[OK]" if lrc3_ok else f"expected 0x{expected_lrc3:02x}"
    lrc3_range = f"09..{9 + dlen - 1:02x}" if dlen > 0 else "empty"
    entries.append((9 + dlen, b[9+dlen:9+dlen+1], f"LRC3{{{lrc3_range}}}[{dlen}] {lrc3_note}", False))

    return entries


def decode_payload(cmd: int, data: bytes, is_response: bool,
                   base_offset: int = 9) -> list[DecodeEntry]:
    """
    Return (offset, raw_bytes, description) entries for the DATA field only.
    base_offset is the offset of data[0] within the full frame.
    """
    o = base_offset   # running offset within the full frame
    E: list[DecodeEntry] = []

    def add(n: int, label: str, value):
        nonlocal o
        E.append((o, data[o - base_offset: o - base_offset + n], label, True, str(value)))
        o += n

    d = data   # shorthand

    if not is_response:
        # ================================================================
        # Commands PC → device
        # ================================================================
        if cmd == 1001 and len(d) >= 1:
            add(1, "mode", f"0x{d[0]:02x} ({DEVICE_MODES.get(d[0], '?')})")
        elif cmd == 1003 and len(d) >= 1:
            add(1, "slot", d[0])
        elif cmd in (1004, 1005) and len(d) >= 3:
            add(1, "slot", d[0])
            tag = struct.unpack(">H", d[1:3])[0]
            add(2, "tag_type", f"0x{tag:04x} ({TAG_TYPES.get(tag, '?')})")
        elif cmd == 1006 and len(d) >= 3:
            add(1, "slot", d[0])
            add(1, "sense", f"0x{d[1]:02x} ({SENSE_TYPES.get(d[1], '?')})")
            add(1, "enable", bool(d[2]))
        elif cmd == 1007 and len(d) >= 2:
            add(1, "slot", d[0])
            add(1, "sense", f"{d[1]}:{SENSE_TYPES.get(d[1], d[1])}")
            name = d[2:].decode("utf-8", errors="replace")
            add(len(d) - 2, "name", f"'{name}'")
        elif cmd == 1008 and len(d) >= 2:
            add(1, "slot", d[0])
            add(1, "sense", f"{d[1]}:{SENSE_TYPES.get(d[1], d[1])}")
        elif cmd == 1015 and len(d) >= 1:
            add(1, "animation_mode", f"0x{d[0]:02x} ({ANIMATION_MODES.get(d[0], '?')})")
        elif cmd in (1026, 1028) and len(d) >= 1:
            add(1, "button", f"'{chr(d[0])}'")
        elif cmd in (1027, 1029) and len(d) >= 2:
            add(1, "button", f"'{chr(d[0])}'")
            add(1, "function", f"0x{d[1]:02x}")
        elif cmd == 1030 and len(d) >= 6:
            add(6, "ble_key", f"'{d[:6].decode('ascii', errors='replace')}'")
        elif cmd == 1036 and len(d) >= 1:
            add(1, "ble_pairing", bool(d[0]))
        elif cmd == 1037 and len(d) >= 1:
            add(1, "ble_pairing", bool(d[0]))
        elif cmd in (2007, 2008) and len(d) >= 8:
            add(1, "key_type", f"0x{d[0]:02x} ({MF1_KEY_TYPES.get(d[0], '?')})")
            add(1, "block", d[1])
            add(6, "key", d[2:8].hex())
        elif cmd == 2009 and len(d) >= 24:
            add(1, "key_type", f"0x{d[0]:02x}:{MF1_KEY_TYPES.get(d[0], '?')}")
            add(1, "block", d[1])
            add(6, "key", d[2:8].hex())
            add(16, "block_data", d[8:24].hex())
        elif cmd == 2010 and len(d) >= 5:
            # options bitfield (MSB first): activate_rf|wait_resp|append_crc|auto_sel|keep_rf|chk_crc|rsvd[2]
            opts = d[0]
            flags = []
            if opts & 0x80: flags.append("activate_rf")
            if opts & 0x40: flags.append("wait_resp")
            if opts & 0x20: flags.append("append_crc")
            if opts & 0x10: flags.append("auto_sel")
            if opts & 0x08: flags.append("keep_rf")
            if opts & 0x04: flags.append("chk_crc")
            add(1, "opt", f"0x{opts:02x} ({','.join(flags) if flags else 'none'})")
            timeout_ms = struct.unpack(">H", d[1:3])[0]
            add(2, "tmo", f"0x{timeout_ms:04x} ({timeout_ms}ms)")
            bitlen = struct.unpack(">H", d[3:5])[0]
            byte_len = (bitlen + 7) // 8
            add(2, "len", f"0x{bitlen:04x} ({bitlen} bits = {byte_len} bytes)")
            if len(d) > 5:
                add(len(d) - 5, "txd", annotate_iso14443a(d[5:]))
        elif cmd == 4006 and len(d) >= 4:
            idx = struct.unpack(">I", d[:4])[0]
            add(4, "index", idx)
        elif cmd == 4008 and len(d) >= 2:
            add(1, "block_start", d[0])
            add(1, "count", d[1])
        elif cmd == 5000 and len(d) >= 5:
            add(5, "em410x_id", d[:5].hex())

    else:
        # ================================================================
        # Responses device → PC
        # ================================================================
        if cmd == 1000 and len(d) >= 2:
            add(1, "version_major", d[0])
            add(1, "version_minor", d[1])
        elif cmd == 1002 and len(d) >= 1:
            add(1, "mode", f"{d[0]}:{DEVICE_MODES.get(d[0], f'0x{d[0]:02x}')}")
        elif cmd == 1011 and len(d) >= 8:
            add(8, "chip_id", d[:8].hex())
        elif cmd == 1012 and len(d) >= 6:
            addr = ":".join(f"{x:02x}" for x in d[:6])
            add(6, "ble_addr", addr)
        elif cmd == 1016 and len(d) >= 1:
            add(1, "animation_mode", f"{d[0]}:{ANIMATION_MODES.get(d[0], d[0])}")
        elif cmd == 1017:
            add(len(d), "git_version", f"'{d.decode('utf-8', errors='replace')}'")
        elif cmd == 1018 and len(d) >= 1:
            add(1, "active_slot", d[0])
        elif cmd == 1019 and len(d) >= 32:
            for slot in range(8):
                hf = struct.unpack(">H", d[slot*4:slot*4+2])[0]
                lf_val = struct.unpack(">H", d[slot*4+2:slot*4+4])[0]
                add(2, f"slot[{slot}].hf_type", f"0x{hf:04x} ({TAG_TYPES.get(hf, '?')})")
                add(2, f"slot[{slot}].lf_type", f"0x{lf_val:04x} ({TAG_TYPES.get(lf_val, '?')})")
        elif cmd == 1023 and len(d) >= 16:
            for slot in range(8):
                add(1, f"slot[{slot}].hf_enabled", bool(d[slot*2]))
                add(1, f"slot[{slot}].lf_enabled", bool(d[slot*2+1]))
        elif cmd == 1025 and len(d) >= 3:
            voltage = struct.unpack(">H", d[0:2])[0]
            add(2, "voltage", f"{voltage} mV")
            add(1, "percentage", f"{d[2]}%")
        elif cmd == 1031 and len(d) >= 6:
            add(6, "ble_key", f"'{d[:6].decode('ascii', errors='replace')}'")
        elif cmd == 1033 and len(d) >= 1:
            add(1, "model", f"0x{d[0]:02x} ({DEVICE_MODELS.get(d[0], '?')})")
        elif cmd == 1034 and len(d) >= 14:
            add(1, "settings_version", d[0])
            add(1, "animation_mode", f"0x{d[1]:02x} ({ANIMATION_MODES.get(d[1], '?')})")
            add(1, "btn_press_A", f"0x{d[2]:02x}")
            add(1, "btn_press_B", f"0x{d[3]:02x}")
            add(1, "btn_long_press_A", f"0x{d[4]:02x}")
            add(1, "btn_long_press_B", f"0x{d[5]:02x}")
            add(1, "ble_pairing_enable", bool(d[6]))
            add(6, "ble_pairing_key", f"'{d[7:13].decode('ascii', errors='replace')}'")
        elif cmd == 1035:
            count = len(d) // 2
            for i in range(count):
                cid = struct.unpack(">H", d[i*2:i*2+2])[0]
                name = COMMANDS.get(cid, "UNKNOWN")
                add(2, f"capability[{i:3d}]", f"0x{cid:04x} ({cid:d}:{name})")
        elif cmd == 1036 and len(d) >= 1:
            add(1, "ble_pairing", f"0x{d[0]:02x} ({'enabled' if d[0] else 'disabled'})")
        elif cmd == 2000:
            pos = 0
            tag_num = 0
            while pos < len(d):
                uid_len = d[pos]
                add(1, f"tag[{tag_num}].uid_len", uid_len)
                if pos + uid_len > len(d): break
                add(uid_len, f"tag[{tag_num}].uid", d[pos:pos+uid_len].hex())
                pos = o - base_offset
                if pos + 4 > len(d): break
                add(2, f"tag[{tag_num}].atqa", d[pos:pos+2].hex())
                pos = o - base_offset
                add(1, f"tag[{tag_num}].sak", f"0x{d[pos]:02x}")
                pos = o - base_offset
                ats_len = d[pos]
                add(1, f"tag[{tag_num}].ats_len", ats_len)
                pos = o - base_offset
                if ats_len:
                    add(ats_len, f"tag[{tag_num}].ats", d[pos:pos+ats_len].hex())
                pos = o - base_offset
                tag_num += 1
        elif cmd == 2001 and len(d) >= 1:
            add(1, "mf1_supported", bool(d[0]))
        elif cmd == 2002 and len(d) >= 1:
            add(1, "prng_type", f"0x{d[0]:02x} ({PRNG_TYPES.get(d[0], '?')})")
        elif cmd == 2008 and len(d) >= 16:
            add(16, "block_data", d[:16].hex())
        elif cmd == 2010:
            if len(d) > 0:
                raw_d = d[:]
                annotated = annotate_iso14443a_response(raw_d)
                # split into 4-byte chunks if > 4 bytes
                if len(raw_d) <= 4:
                    add(len(raw_d), "", annotated)
                else:
                    # first chunk gets the annotation, rest are plain hex
                    pos = 0
                    chunk_num = 0
                    while pos < len(raw_d):
                        chunk = raw_d[pos:pos+4]
                        add(len(chunk), "", chunk.hex())
                        pos += 4
                        chunk_num += 1
        elif cmd == 3000 and len(d) >= 5:
            add(5, "em410x_id", d[:5].hex())
        elif cmd == 4005 and len(d) >= 4:
            count = struct.unpack(">I", d[:4])[0]
            add(4, "detection_count", count)
        elif cmd in (4007, 4010, 4012, 4014, 4019) and len(d) >= 1:
            add(1, "enabled", bool(d[0]))
        elif cmd == 4009 and len(d) >= 5:
            add(1, "detection", bool(d[0]))
            add(1, "gen1a_mode", bool(d[1]))
            add(1, "gen2_mode", bool(d[2]))
            add(1, "block_anti_coll_mode", bool(d[3]))
            add(1, "write_mode", f"0x{d[4]:02x} ({WRITE_MODES.get(d[4], '?')})")
        elif cmd == 4016 and len(d) >= 1:
            add(1, "write_mode", f"0x{d[0]:02x} ({WRITE_MODES.get(d[0], '?')})")
        elif cmd == 4018 and len(d) >= 1:
            uid_len = d[0]
            add(1, "uid_len", uid_len)
            add(uid_len, "uid", d[1:1+uid_len].hex())
            pos = o - base_offset
            add(2, "atqa", d[pos:pos+2].hex())
            pos = o - base_offset
            add(1, "sak", f"0x{d[pos]:02x}")
        elif cmd == 5001 and len(d) >= 5:
            add(5, "em410x_id", d[:5].hex())

    return E


class FrameBuffer:
    """
    Reassembles Chameleon Ultra frames from a stream of bytes.
    Yields decoded frame entries per complete frame found.
    """
    def __init__(self, is_response: bool):
        self.buf = bytearray()
        self.is_response = is_response
        self.stream_offset = 0   # raw bytes received so far (for hexdump numbering)

    def feed(self, data: bytes) -> list[list[DecodeEntry]]:
        self.buf.extend(data)
        results = []
        while True:
            entries, consumed = self._try_parse()
            if entries is None:
                break
            self.buf = self.buf[consumed:]
            results.append(entries)
        return results

    def _try_parse(self):
        b = self.buf

        # Hunt for SOF
        while len(b) >= 2 and not (b[0] == SOF and b[1] == LRC1):
            b = b[1:]
            self.buf = b

        if len(b) < FRAME_HEADER_LEN:
            return None, 0

        dlen  = struct.unpack(">H", b[6:8])[0]
        total = FRAME_HEADER_LEN + dlen

        if len(b) < total:
            return None, 0

        frame   = bytes(b[:total])
        entries = decode_frame(frame, self.is_response)
        return entries, total


# ---------------------------------------------------------------------------
# Hex dump
# ---------------------------------------------------------------------------

def hexdump(data: bytes, width: int = 16, start_offset: int = 0) -> list[str]:
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hex_part   = " ".join(f"{b:02x}" for b in chunk)
        hex_part   = hex_part.ljust(width * 3 - 1)
        ascii_part = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        lines.append(f"  {start_offset + i:04x}  {hex_part}  |{ascii_part}|")
    return lines


def gap_line(elapsed: float, use_color: bool) -> str:
    """Return a timed gap separator line."""
    try:
        cols = os.get_terminal_size().columns
    except OSError:
        cols = 80
    label = f" {elapsed:.3f}s "
    dashes = max(0, cols - len(label) - 2)
    left   = dashes // 2
    right  = dashes - left
    line   = "\u2500" * left + label + "\u2500" * right
    if use_color:
        return C.META + line + C.RESET + "\n"
    return line + "\n"


def format_block(direction: str, data: bytes, color: str, use_color: bool,
                 width: int, frames: list, start_offset: int = 0) -> str:
    """
    Render one TX/RX block:
      - header + hexdump  (in TX/RX color, numbered from start_offset)
      - disassembler decode for each complete frame found (in DECODE color)
    """
    ts    = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    label = f"[{ts}] {direction}  ({len(data)} bytes)"
    dump_lines = [label] + hexdump(data, width, start_offset)

    dec_lines: list[str] = []
    for frame_entries in frames:
        dec_lines.extend(render_decode(frame_entries, use_color))
        dec_lines.append("")   # blank line between frames

    if use_color:
        hex_block  = color + "\n".join(dump_lines) + C.RESET
        if dec_lines:
            colored = [C.DECODE + line + C.RESET if line else "" for line in dec_lines]
            return hex_block + "\n" + "\n".join(colored) + "\n"
        return hex_block + "\n\n"
    else:
        if dec_lines:
            return "\n".join(dump_lines) + "\n" + "\n".join(dec_lines) + "\n"
        return "\n".join(dump_lines) + "\n\n"


# ---------------------------------------------------------------------------
# Main sniffer loop
# ---------------------------------------------------------------------------

def sniff(port: str, baud: int, logfile, use_color: bool, width: int, decode: bool, gap_delay: float = 0.3):
    ser = serial.Serial(port, baud, timeout=0)

    master_fd, slave_fd = pty.openpty()
    slave_path = os.ttyname(slave_fd)
    tty.setraw(master_fd)

    tx_buf = FrameBuffer(is_response=False)
    rx_buf = FrameBuffer(is_response=True)

    def emit(text):
        sys.stdout.write(text)
        sys.stdout.flush()
        if logfile:
            logfile.write(text)
            logfile.flush()

    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    meta_color = C.META if use_color else ""
    reset      = C.RESET if use_color else ""
    emit(f"{meta_color}[{ts}] OPEN  real={port} @ {baud}  pty={slave_path}{reset}\n")
    emit(f"{meta_color}[{ts}] Connect your app to:  {reset}{C.BGBLU} {slave_path} {reset}\n\n")

    fds = [master_fd, ser.fd]
    last_packet_time: float = 0.0

    try:
        while True:
            readable, _, _ = select.select(fds, [], [], 0.1)
            for fd in readable:
                if fd == master_fd:
                    raw = os.read(master_fd, 4096)
                    if raw:
                        ser.write(raw)
                        now = time.monotonic()
                        if gap_delay > 0 and last_packet_time and (now - last_packet_time) >= gap_delay:
                            emit(gap_line(now - last_packet_time, use_color))
                        last_packet_time = now
                        offset_before = tx_buf.stream_offset
                        frames = tx_buf.feed(raw) if decode else []
                        tx_buf.stream_offset += len(raw)
                        emit(format_block("TX →", raw, C.TX, use_color, width, frames, offset_before))

                elif fd == ser.fd:
                    raw = ser.read(ser.in_waiting or 1)
                    if raw:
                        os.write(master_fd, raw)
                        now = time.monotonic()
                        if gap_delay > 0 and last_packet_time and (now - last_packet_time) >= gap_delay:
                            emit(gap_line(now - last_packet_time, use_color))
                        last_packet_time = now
                        offset_before = rx_buf.stream_offset
                        frames = rx_buf.feed(raw) if decode else []
                        rx_buf.stream_offset += len(raw)
                        emit(format_block("← RX", raw, C.RX, use_color, width, frames, offset_before))

    except KeyboardInterrupt:
        pass
    finally:
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        emit(f"\n{meta_color}[{ts}] CLOSE{reset}\n")
        ser.close()
        os.close(master_fd)
        os.close(slave_fd)


def main():
    ap = argparse.ArgumentParser(description="Serial sniffer with Chameleon Ultra decoder")
    ap.add_argument("port",         nargs="?", default="/dev/ttyACM0",
                    help="Serial port (default: /dev/ttyACM0)")
    ap.add_argument("-p", "--port", dest="port_flag", default=None)
    ap.add_argument("-b", "--baud",     default=115200, type=int)
    ap.add_argument("-l", "--log",      default="serial_sniff.log",
                    help="Log file, or '-' for stdout only")
    ap.add_argument("--no-color",       action="store_true")
    ap.add_argument("--no-decode",      action="store_true",
                    help="Disable Chameleon Ultra protocol decoding")
    ap.add_argument("--gap",            default=0.3, type=float, metavar="SECS",
                    help="Draw separator line after this many seconds of silence (0=off, default=0.3)")
    ap.add_argument("--width",          default=16, type=int)
    args = ap.parse_args()

    port = args.port_flag or args.port

    use_color = not args.no_color and sys.stdout.isatty()

    logfile = None
    if args.log and args.log != "-":
        logfile = open(args.log, "a")

    try:
        sniff(port, args.baud, logfile, use_color, args.width, not args.no_decode, args.gap)
    finally:
        if logfile:
            logfile.close()


if __name__ == "__main__":
    main()
