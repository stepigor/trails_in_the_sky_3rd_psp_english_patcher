"""PSMF packet writer with native per-access-unit index tables.

Annex-B and timestamp helpers adapted from TotalKommando/psp-media-toolkit,
Copyright (c) 2026 Total Kommando, MIT. See third-party/pspmedia-LICENSE.
Container templates are read locally from the user's original PSP movie.
"""
import bisect
import struct
from formats import require


def split_nals(es):
    """Annex-B split; returns list of (start_code_len, nal_bytes)."""
    out, i, n = [], 0, len(es)
    starts = []
    while True:
        j = es.find(b'\x00\x00\x01', i)
        if j < 0:
            break
        sc = 4 if j > 0 and es[j - 1] == 0 else 3
        starts.append((j - (sc - 3), j + 3))
        i = j + 3
    for k, (st, body) in enumerate(starts):
        end = starts[k + 1][0] if k + 1 < len(starts) else n
        out.append((body - st, es[body:end]))
    return out


def split_aus(es, drop_sei_types=(5,), drop_nal_types=(12,)):
    """Split raw ES into access units at AUDs, cleaning unwanted NALs.
    Returns list of (au_bytes, is_idr)."""
    aus, cur, cur_idr = [], bytearray(), False

    def flush():
        nonlocal cur, cur_idr
        if cur:
            aus.append((bytes(cur), cur_idr))
        cur, cur_idr = bytearray(), False

    for sclen, nal in split_nals(es):
        t = nal[0] & 0x1F
        if t == 9:
            flush()
        if t in drop_nal_types:
            continue
        if t == 6 and len(nal) > 1 and nal[1] in drop_sei_types:
            continue
        cur += (b'\x00\x00\x00\x01' if sclen == 4 else b'\x00\x00\x01') + nal
        if t == 5:
            cur_idr = True
    flush()
    require(aus and aus[0][1], 'Encoded stream does not start with IDR')
    return aus


def scr_bytes(v27):
    base, ext = divmod(v27, 300)
    b = [0] * 6
    b[0] = 0x44 | ((base >> 27) & 0x38) | ((base >> 28) & 0x03)
    b[1] = (base >> 20) & 0xFF
    b[2] = ((base >> 12) & 0xF8) | 0x04 | ((base >> 13) & 0x03)
    b[3] = (base >> 5) & 0xFF
    b[4] = ((base << 3) & 0xF8) | 0x04 | ((ext >> 7) & 0x03)
    b[5] = ((ext << 1) & 0xFE) | 0x01
    return bytes(b)


def pts_field(prefix, v):
    return bytes([prefix | ((v >> 29) & 0x0E) | 1,
                  (v >> 22) & 0xFF, ((v >> 14) & 0xFE) | 1,
                  (v >> 7) & 0xFF, ((v << 1) & 0xFE) | 1])


def packets(data):
    p=int.from_bytes(data[8:12],'big');require(p==2048,'Unexpected PSMF offset')
    while p<len(data):
        require(data[p:p+3]==b'\0\0\1','MPEG packet boundary missing')
        kind=data[p+3]
        size=14+(data[p+13]&7) if kind==0xba else (4 if kind==0xb9 else 6+int.from_bytes(data[p+4:p+6],'big'))
        require(size>0 and p+size<=len(data),'Truncated MPEG packet')
        yield kind,data[p:p+size];p+=size


def inspect(data):
    es=bytearray();indexes=[];system=None;pack_header=None
    for kind,payload in packets(data):
        if kind==0xba and pack_header is None:pack_header=payload
        elif kind==0xbb and system is None:system=payload
        elif kind==0xbf:
            b=payload[6:];require(b[:2]==b'\x01\xe0' and len(b)>=18,'Unsupported AVC AU index')
            n=int.from_bytes(b[16:18],'big');require(len(b)==18+4*n,'Invalid AU table length');indexes.append(b)
        elif kind==0xe0:es.extend(payload[9+payload[8]:])
        else:require(kind in (0xba,0xbb,0xbe,0xb9),'Unexpected stream in video-only PSMF')
    require(system and pack_header,'MPEG templates missing')
    return bytes(es),indexes,system,pack_header


def indexed_layout(original):
    es,indexes,system,header=inspect(original);require(indexes,'Original AU indexes missing')
    aus=split_aus(es,drop_sei_types=(),drop_nal_types=());sizes=[len(a) for a,_ in aus];cursor=0
    for b in indexes:
        n=int.from_bytes(b[16:18],'big');table=[int.from_bytes(b[20+4*i:22+4*i],'big') for i in range(n)]
        require(table==sizes[cursor:cursor+n],'Original AU index disagrees with AVC data');cursor+=n
    require(cursor==len(aus),'Original AU indexes do not cover all frames')
    return aus,indexes,system,header


def mux(original,es):
    original_aus,indexes,system,header=indexed_layout(original)
    aus=split_aus(es);require(len(aus)==len(original_aus),'Encoded frame count changed')
    require([i for i,(_,idr) in enumerate(aus) if idr]==[i for i,(_,idr) in enumerate(original_aus) if idr],'IDR positions changed')
    start=int.from_bytes(original[0x54:0x5a],'big');end=int.from_bytes(original[0x5a:0x60],'big')
    require(start==90000 and end-start==len(aus)*3003,'Unexpected original video clock')
    buffer=int.from_bytes(original[0x84:0x86],'big');pstd=bytes([0x1e,0x40|(buffer>>8),buffer&255])
    stream=bytearray();base=0;last_stamp=-100;last_scr=-1
    for index in indexes:
        count=int.from_bytes(index[16:18],'big');group=aus[base:base+count];offsets=[];total=0
        table=bytearray(index)
        for i,(au,_) in enumerate(group):
            require(0<len(au)<=65535,'AVC AU exceeds 16-bit index')
            offsets.append(total);total+=len(au);struct.pack_into('>H',table,20+4*i,len(au))
        elementary=b''.join(a for a,_ in group);pos=0;first=True
        while pos<len(elementary):
            prefix=bytearray(header)
            if first:prefix.extend(system);prefix.extend(b'\0\0\1\xbf'+struct.pack('>H',len(table))+table)
            space=2048-len(prefix);available=space-22
            k=bisect.bisect_left(offsets,pos)
            stamp=first or (k<len(group) and offsets[k]<pos+available and base+k>=last_stamp+16)
            extra=13 if first else (10 if stamp else 0);amount=min(len(elementary)-pos,space-9-extra)
            wanted=k+16 if stamp else last_stamp+16-base
            if 0<=wanted<len(group) and pos<offsets[wanted]<pos+amount:amount=offsets[wanted]-pos
            k=bisect.bisect_left(offsets,pos);pes_header=b'';flags=0
            if stamp:
                require(k<len(group) and offsets[k]<pos+amount,'Timestamp has no corresponding AU')
                pts=start+(base+k)*3003;pes_header=pts_field(0x30,pts)+pts_field(0x10,pts-3003);flags=0xc0;last_stamp=base+k
                if first:pes_header+=pstd;flags|=1
            leftover=space-9-extra-amount;stuff=leftover if 0<leftover<6 else 0
            prefix.extend(b'\0\0\1\xe0'+struct.pack('>H',3+extra+stuff+amount)+bytes([0x81,flags,extra+stuff])+pes_header+b'\xff'*stuff+elementary[pos:pos+amount])
            leftover-=stuff
            if leftover:prefix.extend(b'\0\0\1\xbe'+struct.pack('>H',leftover-6)+b'\xff'*(leftover-6))
            require(len(prefix)==2048,'MPEG sector size changed')
            frame=max(0,bisect.bisect_right(offsets,pos)-1)
            scr=((start+(base+frame)*3003-3003-76850)*300+(pos-offsets[frame])*3003*300//len(group[frame][0]))
            scr=max(scr,last_scr+1);prefix[4:10]=scr_bytes(scr);last_scr=scr
            stream.extend(prefix);pos+=amount;first=False
        base+=count
    result=bytearray(original[:2048]);struct.pack_into('>I',result,12,len(stream));result.extend(stream)
    recovered,rebuilt,_,_=inspect(result);expected=b''.join(a for a,_ in aus)
    require(recovered==expected,'PSMF mux changed AVC bytes')
    decoded=split_aus(recovered,drop_sei_types=(),drop_nal_types=());cursor=0
    for b in rebuilt:
        n=int.from_bytes(b[16:18],'big');sizes=[int.from_bytes(b[20+4*i:22+4*i],'big') for i in range(n)]
        require(sizes==[len(a) for a,_ in decoded[cursor:cursor+n]],'Rebuilt AU index is inconsistent');cursor+=n
    require(cursor==len(aus),'Rebuilt index coverage incomplete')
    return bytes(result),dict(frames=len(aus),au_indexes=len(indexes),hardware_tested=False,format='native_AU_indexed_PSMF_v2')
