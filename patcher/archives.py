"""Read local PC members, compress PSP resources and write a new ISO."""
from pathlib import Path
from functools import lru_cache
import shutil
import struct
from formats import Iso9660,cclm_members,data_list,pc_ed6,require,falcom3


def pc_file(root, archive, name):
    index = (Path(root)/(archive+'.dir')).read_bytes()
    require(index[:8] == b'LB DIR\x1a\0', 'Wrong PC archive index')
    count = struct.unpack_from('<Q', index, 8)[0]
    require(16+36*count <= len(index), 'Truncated PC index')
    rows = []
    for i in range(count):
        p = 16+36*i
        raw_name = index[p:p+12].decode('cp932').rstrip('\0 ')
        stem, _, ext = raw_name.partition('.')
        normal = stem.rstrip().lower()+'.'+ext.rstrip().lower()
        if normal == name.lower():
            size, offset = struct.unpack_from('<I', index, p+16)[0], struct.unpack_from('<I', index, p+32)[0]
            if size:
                rows.append((size, offset))
    require(len(rows) == 1, 'Missing or duplicate PC donor member')
    size, offset = rows[0]
    with (Path(root)/(archive+'.dat')).open('rb') as f:
        f.seek(offset)
        data = f.read(size)
    require(len(data) == size, 'Short PC donor read')
    return pc_ed6(data)


def bz_literals(payload):
    data = bytearray([0, 0])
    pos, used, capacity = 1, 0, 8

    def bit(value):
        nonlocal pos, used, capacity
        if used == capacity:
            pos, used, capacity = len(data), 0, 16
            data.extend(b'\0\0')
        if value:
            data[pos+used//8] |= 1 << (used % 8)
        used += 1

    for value in payload:
        bit(0)
        data.append(value)
    for value in [1, 1, 0, 0, 0, 0, 0]:
        bit(value)
    data.append(0)
    return bytes(data)


def bz_compress(payload):
    """Bounded BZ method-zero writer with runs and 8 KiB backreferences."""
    payload=bytes(payload)
    data=bytearray([0,0]);flagpos=1;used=0;capacity=8
    def bit(value):
        nonlocal flagpos,used,capacity
        if used==capacity:flagpos=len(data);data.extend(b'\0\0');used=0;capacity=16
        if value:data[flagpos+used//8]|=1<<(used%8)
        used+=1
    def number(value,n):
        for shift in range(n-1,-1,-1):bit((value>>shift)&1)
    def length(n):
        for value in range(2,6):
            if n==value:bit(1);return
            bit(0)
        if n<=13:bit(1);number(n-6,3)
        else:bit(0);data.append(n-14)
    recent={};p=0
    while p<len(payload):
        run=1
        while run<min(4109,len(payload)-p) and payload[p+run]==payload[p]:run+=1
        take=1
        if run>=30:
            bit(1);bit(1);number(0,5);data.append(1);n=run-14
            bit(n>15);number(n>>8 if n>15 else n,4)
            if n>15:data.append(n&255)
            data.append(payload[p]);take=run
        else:
            best,distance=0,0;key=payload[p:p+3]
            for previous in reversed(recent.get(key,[])):
                d=p-previous
                if d>8191:break
                n=0
                while n<min(269,len(payload)-p) and payload[previous+n]==payload[p+n]:n+=1
                if n>best:best,distance=n,d
                if best==269:break
            if best>=3:
                bit(1)
                if distance<=255:bit(0);data.append(distance)
                else:bit(1);number(distance>>8,5);data.append(distance&255)
                length(best);take=best
            else:bit(0);data.append(payload[p])
        for q in range(p,p+take):
            key=payload[q:q+3]
            if len(key)==3:
                history=recent.setdefault(key,[]);history.append(q)
                if len(history)>64:del history[:-64]
        p+=take
    bit(1);bit(1);number(0,5);data.append(0)
    return bytes(data)


def encode_falcom3(payload,compress=False):
    return _encode_falcom3(bytes(payload),compress)


@lru_cache(maxsize=1024)
def _encode_falcom3(payload,compress=False):
    chunks = [payload[i:i+32768] for i in range(0, len(payload), 32768)]
    require(chunks, 'Empty FALCOM3 payload unsupported')
    blocks = []
    for i, chunk in enumerate(chunks):
        bz = bz_compress(chunk) if compress else bz_literals(chunk)
        blocks.append(struct.pack('<H', len(bz)+2)+bz+bytes([int(i+1 < len(chunks))]))
    body = b''.join(blocks)
    result = struct.pack('<III', len(body)+8, len(payload), len(chunks))+body
    require(falcom3(result, len(payload)) == payload, 'Compression round trip failed')
    return result


def repack_cclm(archive, replacements, additions=None,compress=False):
    """Preserve original compressed members, replace selected ones, add new members."""
    additions=additions or {}
    members=cclm_members(archive)
    existing={m.name for m in members}
    require(set(replacements)<=existing,'Missing CCLM replacement member')
    require(not (set(additions)&existing),'New CCLM member already exists')
    entries=[]
    for m in members:
        if m.name in replacements:
            raw=replacements[m.name];payload=encode_falcom3(raw,compress);raw_size=len(raw)
        else:
            payload=archive[m.offset:m.offset+m.size];raw_size=m.raw_size
        entries.append((m.name,payload,raw_size))
    for name,raw in sorted(additions.items()):
        require(len(name.encode('ascii'))<=16,'CCLM name too long')
        entries.append((name,encode_falcom3(raw,compress),len(raw)))
    count=len(entries);offset=16+32*count
    header=bytearray(struct.pack('<IIII',count,count,count,count));payloads=[]
    for name,payload,raw_size in entries:
        header.extend(name.encode('ascii').ljust(16,b'\0'))
        header.extend(struct.pack('<IIII',offset,len(payload),raw_size,0))
        payloads.append(payload);offset+=len(payload)
    out=bytes(header)+b''.join(payloads)
    checked=cclm_members(out)
    check={m.name:m for m in checked}
    for name,raw in {**replacements,**additions}.items():
        require(check[name].read(out)==raw,'Repacked CCLM member differs')
    for m,c in zip(members,checked):
        if m.name not in replacements:
            require(c.name==m.name and out[c.offset:c.offset+c.size]==archive[m.offset:m.offset+m.size] and c.raw_size==m.raw_size,
                    'Untouched compressed CCLM member changed')
    return out


def append_iso_files(source, output, replacements):
    iso = Iso9660(source)
    output = Path(output)
    require(not output.exists() and output.resolve() != Path(source).resolve(), 'Output must be a new file')
    logical_entry = iso.entries['PSP_GAME/USRDIR/data.lst']
    logical_bytes = bytearray(iso.get(logical_entry.path))
    logical = data_list(logical_bytes)
    shutil.copyfile(source, output)
    with output.open('r+b') as f:
        for path, data in sorted(replacements.items()):
            old = iso.entries[path]
            matches = [r for r in logical if r['lba'] == old.lba and r['size'] == old.size]
            require(len(matches) == 1 or (not matches and not path.startswith('PSP_GAME/USRDIR/data_3rd/')),
                    'Missing or ambiguous logical extent')
            f.seek(0, 2)
            pad = (-f.tell()) % 2048
            f.write(b'\0'*pad)
            lba = f.tell()//2048
            require(lba < 1<<24, 'Falcom 24-bit LBA overflow')
            f.write(data)
            f.write(b'\0'*((-len(data)) % 2048))
            f.seek(old.record_offset+2)
            f.write(struct.pack('<I', lba)+struct.pack('>I', lba))
            f.seek(old.record_offset+10)
            f.write(struct.pack('<I', len(data))+struct.pack('>I', len(data)))
            if matches:
                p = matches[0]['record_pos']
                struct.pack_into('<I', logical_bytes, p+8, len(data))
                logical_bytes[p+12:p+15] = lba.to_bytes(3, 'little')
        f.seek(logical_entry.lba*2048)
        f.write(logical_bytes)
        f.seek(0, 2)
        volume_size = f.tell()//2048
        for lba in range(16, 256):
            f.seek(lba*2048)
            descriptor = f.read(7)
            require(descriptor[1:6] == b'CD001', 'Missing ISO descriptor')
            if descriptor[0] in (1, 2):
                f.seek(lba*2048+80)
                f.write(struct.pack('<I', volume_size)+struct.pack('>I', volume_size))
            if descriptor[0] == 255:
                break
    rebuilt = Iso9660(output)
    for path, data in replacements.items():
        require(rebuilt.get(path) == data, 'ISO file readback differs')
    extents = {(e.lba, e.size) for e in rebuilt.entries.values() if not e.directory}
    require(all((r['lba'], r['size']) in extents for r in data_list(rebuilt.get(logical_entry.path))),
            'ISO logical index verification failed')
