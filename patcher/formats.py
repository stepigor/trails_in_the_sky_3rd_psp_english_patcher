"""Bounded readers for ISO9660 and Falcom archive/script formats.

CCLM/data.lst/FALCOM3 reference: uyjulian's MIT-licensed format extractor:
https://gist.github.com/uyjulian/b596c978da0c1031047e124eaf5d4f84
ED6 header layout reference: Aureole-Suite/Calmare.
"""
from dataclasses import dataclass
from pathlib import Path
import hashlib
import struct


class FormatError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise FormatError(message)


def u16(data, pos=0):
    require(0 <= pos <= len(data) - 2, "Truncated u16")
    return struct.unpack_from("<H", data, pos)[0]


def u32(data, pos=0):
    require(0 <= pos <= len(data) - 4, "Truncated u32")
    return struct.unpack_from("<I", data, pos)[0]


def sha256_file(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(4 * 1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


@dataclass(frozen=True)
class IsoEntry:
    path: str
    lba: int
    size: int
    directory: bool
    record_offset: int = 0


class Iso9660:
    """Small bounded reader for ordinary, single-extent ISO9660 files."""
    sector = 2048

    def __init__(self, path):
        self.path = Path(path)
        self.size = self.path.stat().st_size
        pvd = None
        for lba in range(16, min(self.size // self.sector, 256)):
            block = self.read(lba, self.sector)
            require(block[1:6] == b"CD001" and block[6] == 1,
                    "Not an ordinary ISO9660 volume")
            if block[0] == 1:
                pvd = block
            if block[0] == 255:
                break
        require(pvd is not None, "Missing primary volume descriptor")
        require(u16(pvd, 128) == self.sector, "Unsupported ISO sector size")
        root = self.record(pvd[156:190], "")
        self.entries = {}
        self._walk(root, set())

    def read(self, lba, size):
        offset = lba * self.sector
        require(lba >= 0 and size >= 0 and offset + size <= self.size,
                "ISO extent outside the image")
        with self.path.open("rb") as f:
            f.seek(offset)
            data = f.read(size)
        require(len(data) == size, "Short ISO read")
        return data

    def record(self, data, path, record_offset=0):
        require(len(data) >= 34 and data[0] >= 34, "Short directory record")
        lba, size = u32(data, 2), u32(data, 10)
        require(lba == int.from_bytes(data[6:10], "big") and
                size == int.from_bytes(data[14:18], "big"),
                "ISO endian copies disagree")
        require(not data[25] & 0x80, "Multi-extent ISO files are unsupported")
        return IsoEntry(path, lba, size, bool(data[25] & 2), record_offset)

    def _walk(self, entry, seen):
        require((entry.lba, entry.size) not in seen, "ISO directory cycle")
        seen = seen | {(entry.lba, entry.size)}
        require(len(seen) <= 32, "Excessive ISO directory depth")
        data = self.read(entry.lba, entry.size)
        pos = 0
        while pos < len(data):
            length = data[pos]
            if not length:
                pos = (pos // self.sector + 1) * self.sector
                continue
            require(length >= 34 and pos + length <= len(data),
                    "Invalid ISO directory record length")
            absolute_offset = entry.lba * self.sector + pos
            record = data[pos:pos + length]
            pos += length
            n = record[32]
            require(33 + n <= len(record), "Truncated ISO filename")
            raw = record[33:33 + n]
            if raw in (b"\0", b"\1"):
                continue
            name = raw.decode("ascii").split(";", 1)[0]
            require(name not in ("", ".", "..") and "/" not in name,
                    "Invalid ISO filename")
            path = (entry.path + "/" + name).lstrip("/")
            child = self.record(record, path, absolute_offset)
            require(path not in self.entries, "Duplicate ISO path")
            self.entries[path] = child
            if child.directory:
                self._walk(child, seen)

    def get(self, path):
        entry = self.entries[path]
        require(not entry.directory, "Expected file, got directory")
        return self.read(entry.lba, entry.size)


def data_list(data):
    """Return logical Falcom paths, sizes and absolute ISO LBAs."""
    require(len(data) >= 0x400 and u32(data) == len(data), "Invalid data.lst size")
    extensions = [data[i:i+4].rstrip(b"\0") for i in range(4, 0x400, 4)]
    pos, rows = 0x400, []

    def walk(prefix, count=None, depth=0):
        nonlocal pos
        require(depth < 32, "Excessive data.lst depth")
        total = 0
        while pos < len(data) and (count is None or total < count):
            require(pos + 16 <= len(data), "Truncated data.lst record")
            record_pos = pos
            name = data[pos:pos+8].rstrip(b"\0").decode("ascii")
            size = u32(data, pos + 8)
            lba = int.from_bytes(data[pos+12:pos+15], "little")
            ext = data[pos+15]
            pos += 16
            total += 1  # Directory counts include descendant directory records.
            if ext == 0:
                total += walk(prefix + name + "/", size, depth + 1)
            else:
                require(1 <= ext <= len(extensions) and extensions[ext-1],
                        "Invalid data.lst extension")
                suffix = extensions[ext-1].decode("ascii")
                rows.append({"path": (prefix + name + "." + suffix).lstrip("/"),
                             "size": size, "lba": lba, "record_pos": record_pos})
        require(count is None or total == count, "data.lst child count mismatch")
        return total
    walk("")
    require(pos == len(data), "data.lst trailing bytes")
    return rows


@dataclass(frozen=True)
class CclmMember:
    name: str
    offset: int
    size: int
    raw_size: int

    def read(self, archive):
        data = archive[self.offset:self.offset+self.size]
        if self.raw_size and self.raw_size != self.size:
            return falcom3(data, self.raw_size)
        return data


def cclm_members(data):
    require(len(data) >= 16, "Truncated CCLM header")
    n = u32(data)
    require(n and data[:4] * 4 == data[:16] and 16 + 32*n <= len(data),
            "Invalid CCLM header")
    rows = []
    for i in range(n):
        p = 16 + 32*i
        name = data[p:p+16].split(b"\0", 1)[0].decode("ascii")
        offset, size, raw, reserved = struct.unpack_from("<IIII", data, p+16)
        require(name and "/" not in name and "\\" not in name and name not in (".", ".."),
                "Invalid CCLM member name")
        require(not reserved and offset >= 16 + 32*n and offset + size <= len(data),
                "Invalid CCLM member range")
        rows.append(CclmMember(name, offset, size, raw))
    return rows


def bz_zero(data, limit=65536):
    """Bounded Falcom BZ method zero decoder (not Python bz2)."""
    require(len(data) >= 2 and data[0] == 0, "Unsupported Falcom BZ method")
    pos, flags, bits = 2, data[1], 8
    out = bytearray()

    def byte():
        nonlocal pos
        require(pos < len(data), "Truncated BZ stream")
        v = data[pos]
        pos += 1
        return v

    def bit():
        nonlocal flags, bits
        if not bits:
            flags = byte() | byte() << 8
            bits = 16
        v = flags & 1
        flags >>= 1
        bits -= 1
        return v

    def number(n):
        v = 0
        for _ in range(n):
            v = v * 2 + bit()
        return v

    def put(value, count=1):
        require(len(out) + count <= limit, "BZ output exceeds declared bounds")
        out.extend(bytes([value]) * count)

    def copy(distance):
        require(0 < distance <= len(out), "Invalid BZ backreference")
        length = 2
        while length < 6:
            if bit():
                break
            length += 1
        if length == 6:
            length = number(3) + 6 if bit() else byte() + 14
        require(len(out) + length <= limit, "BZ copy exceeds bounds")
        for _ in range(length):
            out.append(out[-distance])

    while True:
        if not bit():
            put(byte())
        elif not bit():
            copy(byte())
        else:
            high = number(5)
            low = byte()
            if high:
                copy(high << 8 | low)
            elif low > 2:
                copy(low)
            elif low == 0:
                return bytes(out)
            else:
                long_run = bit()
                count = number(4)
                if long_run:
                    count = count << 8 | byte()
                put(byte(), count + 14)


def falcom3(data, expected=None):
    require(len(data) >= 12, "Truncated FALCOM3 header")
    size, raw_size, blocks = struct.unpack_from("<III", data)
    require(not size & 0x80000000, "High-bit FALCOM3 method is unsupported")
    require(size + 4 == len(data), "FALCOM3 stored size mismatch")
    require(raw_size <= 64 * 1024 * 1024 and blocks <= len(data)//3,
            "Unreasonable FALCOM3 allocation")
    require(expected is None or raw_size == expected, "FALCOM3 raw size mismatch")
    pos, out = 12, bytearray()
    for i in range(blocks):
        length = u16(data, pos)
        require(length >= 4 and pos + length <= len(data), "Invalid FALCOM3 block")
        out.extend(bz_zero(data[pos+2:pos+length], min(65536, raw_size-len(out))))
        pos += length
        if len(out) == raw_size:
            break
        require(pos < len(data) and data[pos] == 1 and i + 1 < blocks,
                "Missing FALCOM3 continuation")
        pos += 1
    require(len(out) == raw_size, "FALCOM3 decompressed size mismatch")
    return bytes(out)


def pc_ed6(data):
    """PC ED6 is a sequence of BZ chunks, without the PSP FALCOM3 header."""
    pos, out = 0, bytearray()
    while True:
        size = u16(data, pos)
        require(size >= 4 and pos + size < len(data), "Invalid PC ED6 chunk")
        out.extend(bz_zero(data[pos+2:pos+size]))
        pos += size
        more = data[pos]
        pos += 1
        require(len(out) <= 64 * 1024 * 1024, "Oversize PC ED6 data")
        if not more:
            require(pos == len(data), "Trailing PC ED6 data")
            return bytes(out)


def ed6_header(data):
    """Validate header and function pointers; does NOT validate bytecode."""
    require(len(data) >= 0x64, "Truncated ED6 header")
    strings, code_start, table, table_size = (u16(data, 0x5a), u32(data, 0x5c),
                                             u16(data, 0x60), u16(data, 0x62))
    require(table_size % 2 == 0 and 0x64 <= code_start <= table and
            table + table_size <= strings < len(data), "Invalid ED6 sections")
    require(data[strings:strings+10] == b"@FileName\0", "Missing ED6 string marker")
    funcs = [u16(data, p) for p in range(table, table+table_size, 2)]
    require(all(code_start <= f < table for f in funcs), "ED6 function out of bounds")
    require(not funcs or funcs[0] == code_start, "ED6 first function mismatch")
    return {"size": len(data), "function_count": len(funcs),
            "code_start": code_start, "function_table": table,
            "string_table": strings, "address_bits": 16,
            "bytecode_validated": False}
