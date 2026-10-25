"""Fit chapter and door journal prose to the PSP's fixed text columns."""
import struct
from formats import require
from text_layout import atoms


def significant(data):
    return b''.join(raw for raw,_ in atoms(data) if raw not in (b' ',b'\x01'))


def column_text(data,columns,hanging=0,join_lines=True):
    require(data.endswith(b'\0') and columns>hanging,'Invalid journal column')
    tokens=list(atoms(data[:-1]));lines=[[]]
    for token in tokens:
        if token[0]==b'\x01':lines.append([])
        else:lines[-1].append(token)
    def nonblank(line):return any(width and raw!=b' ' for raw,width in line)
    # Existing single line breaks reflect the wider PC layout. Blank lines
    # separate paragraphs and must retain their position and style controls.
    paragraphs=[];pending=[]
    for line in lines:
        if nonblank(line):
            if pending and not join_lines:paragraphs.append((pending,True));pending=[]
            if pending:pending.append((b' ',1))
            pending.extend(line)
        else:
            if pending:paragraphs.append((pending,True));pending=[]
            paragraphs.append((line,False))
    if pending:paragraphs.append((pending,True))
    output=[]
    for paragraph,wrap in paragraphs:
        if not wrap:output.append(b''.join(raw for raw,_ in paragraph));continue
        line=[];width=0;continuation=False
        def emit():
            prefix=b' '*hanging if continuation else b''
            return prefix+b''.join(raw for raw,_ in line)
        for raw,w in paragraph:
            if not line and raw==b' ':continue
            line.append((raw,w));width+=w
            limit=columns-(hanging if continuation else 0)
            if width<=limit:continue
            spaces=[i for i,(v,_) in enumerate(line[:-1]) if v==b' ']
            if spaces:
                cut=spaces[-1];tail=line[cut+1:];line=line[:cut]
            else:tail=line[-1:];line=line[:-1]
            require(line,'Inline journal glyph exceeds column')
            output.append(emit());continuation=True;line=tail;width=sum(x for _,x in line)
        output.append(emit())
    result=b'\x01'.join(output)+b'\0'
    require(significant(result)==significant(data),'Journal wrapping changed text or inline controls')
    require(all(sum(w for _,w in atoms(line))<=columns for line in output),'Journal column still overflows')
    return result


def main_quest_fields(identity,fields):
    if not 40<=identity<=64:return fields
    require(len(fields)==18 and b'[Writer]' in fields[1],'Unknown main-quest layout')
    return [fields[0],column_text(fields[1],31)]+[column_text(f,36,2) for f in fields[2:]]


DOOR_COLUMNS={2:28,3:28,4:30,5:34,6:34,7:34}


def door_quest_fields(identity,fields):
    if not 1<=identity<=36 or not fields[0].strip(b' \x01\0'):return fields
    require(len(fields)==18,'Unknown door journal layout')
    result=list(fields)
    for i,width in DOOR_COLUMNS.items():
        # Bonus lines can list separate rewards. Keep those item boundaries.
        result[i]=column_text(fields[i],width,join_lines=i!=7)
    if result[4].strip(b' \x01\0'):
        # PSP draws the Riddle heading on the first line of this field.
        # The PC renderer puts it elsewhere and omits this reserved line.
        result[4]=b'\x01'+result[4]
    for i,limit in [(2,2),(3,2),(4,10)]:
        require(len(result[i][:-1].split(b'\x01'))<=limit,'Door field exceeds its vertical allocation')
    require(all(significant(a)==significant(b) for a,b in zip(fields,result)),
            'Door layout changed words or inline controls')
    return result


# Five immediate operands in the door-only drawing branch of ULJM05353 1.01.
# File offset = PRX virtual address + 0xc0. No branches or addresses change.
DOOR_DRAW_WORDS=[
    (0xfc4e4+0xc0,0x2402000b,0x24020009), # left line pitch: 11 -> 9
    (0xfc584+0xc0,0x2406005e,0x24060056), # Place heading: y94 -> y86
    (0xfc5ac+0xc0,0x24060069,0x24060061), # Place value: y105 -> y97
    (0xfc5e0+0xc0,0x2406007c,0x24060077), # Riddle heading: y124 -> y119
    (0xfc614+0xc0,0x2406007d,0x24060078), # Riddle field: y125 -> y120
]


def apply_door_layout(boot):
    out=bytearray(boot)
    for offset,before,after in DOOR_DRAW_WORDS:
        require(offset+4<=len(out) and struct.unpack_from('<I',out,offset)[0]==before,
                'Unexpected PSP door drawing instruction')
        struct.pack_into('<I',out,offset,after)
    return bytes(out)


# Chapter-only upper rule, between Writer and the first description paragraph.
# Keep all text positions and the lower rule unchanged, including long entries.
CHAPTER_SEPARATOR_WORD=(0xfc338+0xc0,0x24060054,0x2406004c) # y84 -> y76


def apply_chapter_separator(boot):
    offset,before,after=CHAPTER_SEPARATOR_WORD
    require(offset+4<=len(boot) and struct.unpack_from('<I',boot,offset)[0]==before,
            'Unexpected PSP chapter separator instruction')
    out=bytearray(boot);struct.pack_into('<I',out,offset,after)
    return bytes(out)
