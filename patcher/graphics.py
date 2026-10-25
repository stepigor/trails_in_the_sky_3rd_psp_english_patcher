"""Repack the existing PC English logo into the PSP title-model texture atlas.

The original PSP mesh, atlas dimensions, palette, and every other texture stay
intact. This is deterministic local asset conversion; no images are distributed.
"""
import struct
from formats import require,u32,falcom3
from archives import encode_falcom3
from itp import decode


def decode_ch(data,width,mode):
    """Decode local Windows BGRA/16-bit textures without shipping their pixels."""
    from PIL import Image
    stride=4 if mode==8888 else 2
    require(len(data)%(width*stride)==0,'Invalid PC raster dimensions')
    height=len(data)//(width*stride)
    if mode==8888:return Image.frombytes('RGBA',(width,height),data,'raw','BGRA')
    require(mode in (1555,4444),'Unsupported PC pixel format')
    out=bytearray()
    for (v,) in struct.iter_unpack('<H',data):
        if mode==4444:out.extend(((v>>8&15)*17,(v>>4&15)*17,(v&15)*17,(v>>12&15)*17))
        else:out.extend(((v>>10&31)*255//31,(v>>5&31)*255//31,(v&31)*255//31,(v>>15)*255))
    return Image.frombytes('RGBA',(width,height),bytes(out))


def indexed_image(image):
    from PIL import Image
    q=image.convert('RGBA').quantize(colors=256,method=Image.Quantize.FASTOCTREE,dither=Image.Dither.NONE)
    palette=bytes(q.getpalette('RGBA'))
    return pack_indexed(*image.size,palette,q.tobytes())


def convert_texture(original,donor,recipe,pc_exe=b''):
    from PIL import Image,ImageDraw,ImageFont,ImageEnhance,ImageFilter
    width,height,rgba=decode(original)
    target=Image.frombytes('RGBA',(width,height),rgba)
    if donor and recipe.get('dds'):
        require(donor[:4]==b'DDS ' and u32(donor,4)==124 and u32(donor,88)==16,'Unsupported DDS donor')
        masks={1555:(0x7c00,0x3e0,0x1f,0x8000),4444:(0xf00,0xf0,0xf,0xf000)}
        require(struct.unpack_from('<4I',donor,92)==masks.get(recipe['mode']),'Unsupported DDS masks')
        source=decode_ch(donor[128:],recipe['source_width'],recipe['mode'])
    else:source=decode_ch(donor,recipe['source_width'],recipe['mode']) if donor else None
    if recipe.get('color_key'):
        key=tuple(recipe['color_key']);source.putdata([p[:3]+(0,) if p[:3]==key else p for p in source.getdata()])
    if recipe.get('clear'):target=Image.new('RGBA',(width,height),tuple(recipe['clear']))
    for operation in recipe.get('rectangles',[]):
        a,b=operation['source'],operation['destination']
        require(0<=a[0]<a[2]<=source.width and 0<=a[1]<a[3]<=source.height,'PC crop exceeds raster')
        require(0<=b[0]<b[2]<=width and 0<=b[1]<b[3]<=height,'PSP crop exceeds raster')
        image=source.crop(a)
        if operation.get('contrast'):image=ImageEnhance.Contrast(image).enhance(operation['contrast'])
        image=image.resize((b[2]-b[0],b[3]-b[1]),Image.Resampling.LANCZOS)
        if operation.get('sharpen'):image=image.filter(ImageFilter.UnsharpMask(radius=.65,percent=operation['sharpen'],threshold=2))
        target.paste(image,(b[0],b[1]))
    for operation in recipe.get('overlays',[]):
        draw=ImageDraw.Draw(target)
        if 'box' in operation:draw.rectangle(operation['box'],fill=tuple(operation['fill']))
        if 'parts' not in operation:continue
        text=b''.join(pc_exe[p:p+n] for p,n in operation['parts']).decode('ascii')
        size=operation.get('size',12);font=None
        for path in ['/System/Library/Fonts/Supplemental/Arial.ttf','C:/Windows/Fonts/arial.ttf','/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf']:
            try:font=ImageFont.truetype(path,size);break
            except OSError:pass
        if font is None:font=ImageFont.load_default()
        lines=text.split('\n');spacing=operation.get('spacing',size+4)
        x,y=operation['position'];color=tuple(operation.get('color',[255,255,255,255]))
        for line in lines:
            box=draw.textbbox((0,0),line,font=font);w=box[2]-box[0]
            limit=operation.get('width',width-x)
            require(w<=limit,'English graphic label exceeds allocated width')
            xx=x+(limit-w)//2 if operation.get('center') else x
            draw.text((xx,y),line,font=font,fill=color,stroke_width=operation.get('stroke',0),stroke_fill=(0,0,0,255));y+=spacing
    return indexed_image(target)


def pack_indexed(width,height,palette,pixels):
    require(len(palette)%4==0 and len(pixels)==width*height,'Invalid indexed texture')
    swizzled=bytearray()
    for top in range(0,height,8):
        for left in range(0,width,16):
            for y in range(8):swizzled.extend(pixels[(top+y)*width+left:(top+y)*width+left+16])
    result=struct.pack('<IIII',1004,width,height,len(palette)//4)+encode_falcom3(palette,compress=True)+encode_falcom3(swizzled,compress=True)
    require(decode(result)[:2]==(width,height),'Repacked texture dimensions changed')
    return result


def convert_logo(texture,pc,source_width,source_rect,destination_rects):
    require(u32(texture)==1004,'Expected indexed PSP title atlas')
    width,height,rgba=decode(texture);size=u32(texture,16)+4;palette=falcom3(texture[16:16+size])
    colors=[tuple(palette[p:p+4]) for p in range(0,len(palette),4)];lookup={v:i for i,v in enumerate(colors)}
    pixels=bytearray(lookup[tuple(rgba[i:i+4])] for i in range(0,len(rgba),4));cache={}
    premultiplied=[(r*a,g*a,b*a,255*a) for r,g,b,a in colors]
    def nearest(color):
        if color not in cache:
            r,g,b,a=color;target=(r*a,g*a,b*a,255*a)
            cache[color]=min(range(len(colors)),key=lambda i:sum((x-y)**2*(2 if j==3 else 1) for j,(x,y) in enumerate(zip(target,premultiplied[i]))))
        return cache[color]
    def source(x,y):
        value=int.from_bytes(pc[2*(y*source_width+x):2*(y*source_width+x)+2],'little')
        return ((value>>8&15)*17,(value>>4&15)*17,(value&15)*17,(value>>12&15)*17)
    x0,y0,x1,y1=source_rect;sw,sh=x1-x0,y1-y0
    require(0<=x0<x1<=source_width and 0<=y0<y1 and 2*source_width*y1<=len(pc),'PC logo crop exceeds donor')
    transparent=nearest((0,0,0,0))
    for left,top,right,bottom in destination_rects:
        require(0<=left<right<=width and 0<=top<bottom<=height,'Logo rectangle exceeds PSP atlas')
        for y in range(top,bottom):pixels[y*width+left:y*width+right]=bytes([transparent])*(right-left)
        scale=min((right-left)/sw,min(96,bottom-top)/sh);dw,dh=max(1,round(sw*scale)),max(1,round(sh*scale))
        dx,dy=left+((right-left)-dw)//2,top
        for y in range(dh):
            sy=min(sh-1,(y+.5)*sh/dh-.5);iy=max(0,int(sy));fy=max(0,sy-iy)
            for x in range(dw):
                sx=min(sw-1,(x+.5)*sw/dw-.5);ix=max(0,int(sx));fx=max(0,sx-ix)
                samples=[source(x0+xx,y0+yy) for yy,xx in [(iy,ix),(iy,min(ix+1,sw-1)),(min(iy+1,sh-1),ix),(min(iy+1,sh-1),min(ix+1,sw-1))]]
                weights=[(1-fx)*(1-fy),fx*(1-fy),(1-fx)*fy,fx*fy]
                color=tuple(round(sum(c[k]*w for c,w in zip(samples,weights))) for k in range(4))
                pixels[(dy+y)*width+dx+x]=nearest(color)
    return pack_indexed(width,height,palette,pixels)


def title_model(model,pc,recipe):
    out=bytearray();p=0;count=0
    while p<len(model):
        require(p+8<=len(model),'Truncated IT3 chunk header')
        kind=model[p:p+4];size=u32(model,p+4);end=p+8+size
        require(end<=len(model),'IT3 chunk exceeds file')
        payload=model[p+8:end]
        if kind==b'TEXI' and payload[:32].split(b'\0')[0].decode('ascii')==recipe['texture_name']:
            image=convert_logo(payload[36:],pc,recipe['source_width'],recipe['source_rect'],recipe['destination_rects'])
            payload=payload[:36]+image;count+=1
        out.extend(kind+struct.pack('<I',len(payload))+payload);p=end
    require(count==1,'Title logo atlas missing or duplicated')
    return bytes(out)


def png_logo(original,donor,recipe,pc_exe):
    """Create local XMB artwork from the same verified English logo donor."""
    import io
    from PIL import Image,ImageDraw,ImageFont
    size=Image.open(io.BytesIO(original)).size
    require(list(size)==recipe['dimensions'],'XMB image dimensions changed')
    target=Image.new('RGBA',size,tuple(recipe['background']))
    logo=decode_ch(donor,recipe['source_width'],4444).crop(recipe['source_rect'])
    x,y,right,bottom=recipe['destination'];scale=min((right-x)/logo.width,(bottom-y)/logo.height)
    logo=logo.resize((round(logo.width*scale),round(logo.height*scale)),Image.Resampling.LANCZOS)
    target.alpha_composite(logo,(x+(right-x-logo.width)//2,y+(bottom-y-logo.height)//2))
    if recipe.get('caption'):
        text=b''.join(pc_exe[p:p+n] for p,n in recipe['caption']).decode('ascii')
        font=None
        for path in ['/System/Library/Fonts/Supplemental/Arial.ttf','C:/Windows/Fonts/arial.ttf','/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf']:
            try:font=ImageFont.truetype(path,16);break
            except OSError:pass
        font=font or ImageFont.load_default();draw=ImageDraw.Draw(target);box=draw.textbbox((0,0),text,font=font)
        require(box[2]-box[0]<size[0],'XMB caption exceeds image')
        draw.text(((size[0]-(box[2]-box[0]))//2,150),text,font=font,fill=(235,239,244,255),stroke_width=1,stroke_fill=(12,24,34,255))
    output=io.BytesIO();target.save(output,format='PNG',compress_level=9);return output.getvalue()
