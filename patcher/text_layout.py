"""Conservative PSP dialogue wrapping, preserving text and inline controls."""
import re
from formats import require


TAG=re.compile(rb'#-?\d+[A-Za-z]')


def atoms(data):
    p=0
    while p<len(data):
        v=data[p];end=p+1;width=1
        if v==7:end=p+2;width=0
        elif v==31:end=p+3;width=24
        elif v==35:
            tag=TAG.match(data,p)
            if tag:end=tag.end();width=0
        elif 0x81<=v<=0x9f or 0xe0<=v<=0xfc:end=p+2;width=2
        elif v<32:width=0
        require(end<=len(data),'Truncated dialogue control')
        yield data[p:end],width;p=end


def reflow(data,spoken=False):
    require(data.endswith(b'\0'),'Dialogue terminator missing')
    tokens=list(atoms(data))
    portrait=spoken or any(re.fullmatch(rb'#\d+F',a) for a,_ in tokens)
    sizes=[int(a[1:-1]) for a,_ in tokens if re.fullmatch(rb'#[1-5]S',a)]
    scale=max([1]+[(n+1)/2 for n in sizes]);limit=int((50 if portrait else 62)/scale)
    rows_max=2 if scale>1.5 else 3
    out=bytearray();line=[];width=0;rows=1;added_pages=0
    def flush():
        nonlocal line,width
        out.extend(b''.join(a for a,w in line));line=[];width=0
    def newline():
        nonlocal rows,added_pages
        if rows>=rows_max:out.extend(b'\x02\x03');rows=1;added_pages+=1
        else:out.append(1);rows+=1
    for raw,w in tokens:
        if raw in (b'\0',b'\x02',b'\x03'):
            flush();out.extend(raw);rows=1;continue
        if raw==b'\x01':flush();newline();continue
        line.append((raw,w));width+=w
        if width<=limit:continue
        spaces=[i for i,(a,_) in enumerate(line[:-1]) if a==b' ']
        if spaces:
            i=spaces[-1];tail=line[i+1:];head=line[:i]
        else:head=line[:-1];tail=line[-1:]
        out.extend(b''.join(a for a,_ in head));newline();line=tail;width=sum(w for _,w in line)
    flush();result=bytes(out)
    # Wrapping may alter whitespace and pagination, never printable words,
    # byte-pair glyphs, face/font/style codes, color operands or item IDs.
    def significant(value):return b''.join(a for a,_ in atoms(value) if a not in (b' ',b'\x01',b'\x02',b'\x03'))
    require(significant(result)==significant(data),'Dialogue wrapping changed content')
    return result,dict(changed=result!=data,added_pages=added_pages,columns=limit)
