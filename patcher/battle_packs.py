"""PSP runtime monster streams and system-texture packs, without game assets."""
import struct
import textwrap
from formats import require,u32
from battle_text import parse_tail
from scena import Script


def records(data,terminator_words):
    end=len(data)-4*terminator_words
    require(end>=0 and data[end:]==b'\xff'*(4*terminator_words),'Monster pack terminator differs')
    p=0;rows=[]
    while p<end:
        require(p+8<=end,'Truncated monster pack record')
        fid,size=struct.unpack_from('<II',data,p);p+=8
        require(0x300000<=fid<=0x30ffff and p+size<=end,'Invalid monster pack record')
        rows.append((fid,data[p:p+size]));p+=size
    require(p==end,'Monster pack boundary differs')
    return rows


def repack_records(data,terminator_words,transform):
    before=records(data,terminator_words);out=bytearray();changed=0
    expected=[]
    for fid,old in before:
        new=transform(fid,old);expected.append((fid,new));changed+=new!=old
        out.extend(struct.pack('<II',fid,len(new)));out.extend(new)
    out.extend(b'\xff'*(4*terminator_words));result=bytes(out)
    require(records(result,terminator_words)==expected,'Monster pack readback differs')
    return result,dict(records=len(before),changed_records=changed)


def pkc_members(data):
    require(data[-4:]==bytes(4),'System texture terminator differs')
    p=0;rows=[]
    while p<len(data)-4:
        require(p+36<=len(data)-4,'Truncated system texture header')
        size=u32(data,p);header=data[p:p+36];name=header[4:].split(b'\0')[0].decode('ascii')
        require(size and p+36+size<=len(data)-4,'System texture exceeds pack')
        rows.append((name,header,data[p+36:p+36+size]));p+=36+size
    require(p==len(data)-4 and len({n for n,_,_ in rows})==len(rows),'System texture directory invalid')
    return rows


def repack_pkc(data,replacements):
    rows=pkc_members(data);require(set(replacements)<={n for n,_,_ in rows},'Packed texture missing')
    out=bytearray()
    for name,header,old in rows:
        new=replacements.get(name,old);out.extend(struct.pack('<I',len(new))+header[4:]);out.extend(new)
    out.extend(bytes(4));result=bytes(out);after=pkc_members(result)
    for (name,header,old),(nn,hh,new) in zip(rows,after):
        require(name==nn and header[4:]==hh[4:] and new==replacements.get(name,old),'System texture readback differs')
    return result


def replace_tail(data,count_offset,values):
    before,trailer,spans=parse_tail(data,count_offset,True)
    require(len(values)==len(spans),'Monster field count differs')
    out=Script._edit(data,0,len(data),[(a,b,v) for (a,b),v in zip(spans,values)])
    after,new_trailer,new_spans=parse_tail(out,count_offset,True)
    require(data[:count_offset+1]==out[:count_offset+1] and [r[0] for r in before]==[r[0] for r in after]
            and trailer==new_trailer and data[spans[-1][1]:]==out[new_spans[-1][1]:], 'Monster parameters changed')
    return out


def description(data,count_offset,override=None):
    _,_,spans=parse_tail(data,count_offset,True);values=[data[a:b] for a,b in spans]
    text=(override if override is not None else values[-1]).rstrip(b'\0').decode('cp932')
    lines=textwrap.wrap(text.replace('\\n',' '),width=22,break_long_words=False,break_on_hyphens=True)
    require(len(lines)<=5 and all(len(s)<=22 for s in lines),'Monster description exceeds PSP panel')
    values[-1]='\\n'.join(lines).encode('cp932')+b'\0'
    return replace_tail(data,count_offset,values)


def translate_copy(data,original,translated,count_offset,approved_differences=()):
    _,_,source=parse_tail(original,count_offset,True);_,_,target=parse_tail(translated,count_offset,True)
    _,_,variant=parse_tail(data,count_offset,True)
    require(len(source)==len(variant)==len(target),'Bestiary variant field count differs')
    differences=[i for i,((a,b),(c,d)) in enumerate(zip(source,variant)) if original[a:b]!=data[c:d]]
    require(differences==list(approved_differences),'Unexpected bestiary variant text')
    return replace_tail(data,count_offset,[translated[a:b] for a,b in target])
