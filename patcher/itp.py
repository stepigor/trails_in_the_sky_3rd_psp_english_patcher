"""Read old indexed Falcom ITP textures for local visual inspection.

Format facts: Aureole-Suite/Cradle's ITP reader. This implementation supports
the AFastMode2 literal-nibble variant and refuses undocumented subformats.
"""
import struct
from formats import require,u32,falcom3


def decode(data):
    if u32(data)==1006:return decode_ccpi(data)
    kind,width,height=struct.unpack_from('<III',data)
    require(kind in (1002,1004,1005),'Unsupported indexed ITP variant')
    require(width%16==0 and height%8==0 and width*height<=4096*4096,'Invalid ITP dimensions')
    p=12
    if kind==1002:count=256
    else:count=u32(data,p);p+=4
    require(0<count<=256,'Invalid ITP palette length')
    def compressed():
        nonlocal p
        size=u32(data,p)+4;require(p+size<=len(data),'ITP compressed field exceeds file')
        result=falcom3(data[p:p+size]);p+=size;return result
    palette=compressed();require(len(palette)==4*count,'ITP palette size mismatch')
    colors=[];previous=0
    for (value,) in struct.iter_unpack('<I',palette):
        if kind==1005:value=(value+previous)&0xffffffff
        previous=value;colors.append(value.to_bytes(4,'little'))
    if kind==1005:
        packed_size=u32(data,p);p+=4;raw=compressed();require(len(raw)==packed_size,'AFast data size mismatch')
        tiles=(width//16)*(height//8);header=tiles//2
        ncolors=[n+1 if n else 0 for v in raw[:header] for n in (v>>4,v&15)]
        color_end=header+sum(ncolors);palette_indices=raw[header:color_end];cursor=color_end
        require(raw[cursor]==0,'Unsupported AFastMode2 encoding');cursor+=1;ci=0;pixels=bytearray()
        for n in ncolors:
            if not n:pixels.extend(bytes(128));continue
            local=palette_indices[ci:ci+n];ci+=n
            require(cursor+64<=len(raw),'Truncated AFast tile')
            for v in raw[cursor:cursor+64]:
                require(v>>4<n and v&15<n,'AFast palette index overflow')
                pixels.extend((local[v>>4],local[v&15]))
            cursor+=64
        require(cursor==len(raw) and ci==len(palette_indices),'Trailing AFast data')
    else:pixels=compressed()
    require(p==len(data) and len(pixels)==width*height,'ITP raster size mismatch')
    rgba=bytearray(width*height*4)
    if kind==1002:
        for i,value in enumerate(pixels):rgba[4*i:4*i+4]=colors[value]
    else:
        tile=0
        for top in range(0,height,8):
            for left in range(0,width,16):
                for y in range(8):
                    for x in range(16):
                        target=((top+y)*width+left+x)*4
                        rgba[target:target+4]=colors[pixels[tile+y*16+x]]
                tile+=128
    return width,height,bytes(rgba)


def decode_ccpi(data):
    require(data[8:12]==b'CCPI','Missing CCPI signature')
    version,count,cx,cy,width,height,flags=struct.unpack_from('<HHBBHHH',data,12)
    require(version in (6,7) and not flags&512,'Unsupported CCPI palette')
    cw,ch=1<<cx,1<<cy
    raw=falcom3(data[24:]) if flags&0x8000 else data[24:]
    require(len(raw)==u32(data,4)-16 and count<=256,'CCPI payload size mismatch')
    colors=[raw[4*i:4*i+4] for i in range(count)];p=4*count;pixels=bytearray(width*height)
    def byte():
        nonlocal p
        require(p<len(raw),'Truncated CCPI chunk');v=raw[p];p+=1;return v
    for top in range(0,height,ch):
        for left in range(0,width,cw):
            w,h=min(cw,width-left),min(ch,height-top);n=byte();tiles=[]
            for i in range(n):tiles.append(tuple(byte() for _ in range(4)))
            for a,b,c,d in list(tiles):tiles.append((b,a,d,c))
            tiles=tiles[:256]
            for a,b,c,d in list(tiles):tiles.append((c,d,a,b))
            tiles=tiles[:256];chunk=bytearray();last=0
            while len(chunk)<w*h:
                v=byte()
                if v==255:chunk.extend(bytes(tiles[last])*byte())
                else:
                    require(v<len(tiles),'CCPI tile index outside dictionary');last=v;chunk.extend(tiles[v])
            require(len(chunk)==w*h,'CCPI chunk output overflow')
            k=0
            for y in range(0,h,2):
                for x in range(0,w,2):
                    for yy,xx in [(0,0),(0,1),(1,0),(1,1)]:pixels[(top+y+yy)*width+left+x+xx]=chunk[k];k+=1
    require(p==len(raw),'Trailing CCPI data')
    return width,height,b''.join(colors[i] for i in pixels)
