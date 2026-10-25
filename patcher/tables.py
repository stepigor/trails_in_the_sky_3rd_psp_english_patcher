"""Text-only rebuilds of known ED6 tables, retaining PSP numeric records."""
from dataclasses import dataclass
import struct
from formats import require,u16


@dataclass
class Row:
    index: int
    identity: int
    start: int
    end: int
    prefix: bytes
    fields: list


# (pointer-table style, fixed prefix, pointer offsets, identity width)
LAYOUTS={
    't_ittxt._dt':('plain',8,[4,6],4),
    't_ittxt2._dt':('plain',8,[4,6],4),
    't_magic._dt':('plain',32,[28,30],2),
    't_cook2._dt':('plain',46,[42,44],2),
    't_name._dt':('name',34,[32],2),
    't_memo._dt':('plain',6,[4],2),
    't_quest._dt':('plain',None,None,2),
    **{f't_quiz{i:02d}._dt':('plain',16,[4,6,8,10,12,14],2) for i in range(1,5)},
}


def text_end(data,start,limit=None):
    limit=len(data) if limit is None else limit
    p=start
    while p<limit:
        ch=data[p];p+=1
        if ch==0:return p
        if ch==7:p+=1
        elif ch==0x1f:p+=2
    raise ValueError('Unterminated table text')


def row_table(data,name):
    style,fixed,pfields,idwidth=LAYOUTS[name]
    if style=='plain':
        offset=0;count=u16(data)//2
        require(count>0 and count*2==u16(data),'Invalid table pointer count')
    elif style=='name':
        offset=2;count=(u16(data,2)-2)//2
        require(count>0 and 2+count*2==u16(data,2),'Invalid character-name table')
    header=offset+count*2
    pointers=[u16(data,offset+2*i) for i in range(count)]
    require(all(header<=p<len(data) for p in pointers),'Table record outside file')
    ends={a:b for a,b in zip(sorted(set(pointers)),sorted(set(pointers))[1:]+[len(data)])}
    rows=[]
    for i,start in enumerate(pointers):
        end=ends[start]
        if name=='t_quest._dt':
            first=u16(data,start+18)
            require(start+20<=first<=end and (first-start-18)%2==0,'Invalid quest text pointers')
            fields=list(range(18,first-start,2));size=first-start
        else:fields=pfields;size=fixed
        require(start+size<=end,'Truncated table row')
        targets=[u16(data,start+p) for p in fields]
        require(targets and targets[0]==start+size and targets==sorted(targets) and
                all(start+size<=p<end for p in targets),'Invalid table text span')
        # Some records point into the middle of another string (a suffix),
        # rather than storing disjoint strings. Resolve each C string itself.
        texts=[]
        for a in targets:
            texts.append(data[a:text_end(data,a,end)])
        rows.append(Row(i,int.from_bytes(data[start:start+idwidth],'little'),start,end,data[start:start+size],texts))
    return offset,rows


def transplant_rows(psp,pc,name,row_mapping=None,field_overrides=None):
    offset,source=row_table(psp,name);_,donor=row_table(pc,name)
    by_id={r.identity:r for r in donor}
    require(len(by_id)==len(donor),'Duplicate donor table identities')
    out=bytearray(psp[:offset]+bytes(2*len(source)));changed=0;mapping=[]
    for row in source:
        identity=row_mapping.get(row.identity,row.identity) if row_mapping else row.identity
        require(identity in by_id or field_overrides and row.identity in field_overrides,f'PC table missing record {name}:{identity}')
        other=by_id.get(identity,row)
        if field_overrides and row.identity in field_overrides:
            other=Row(other.index,other.identity,other.start,other.end,other.prefix,field_overrides[row.identity])
        require(len(row.fields)==len(other.fields),f'Table field-count mismatch {name}:{row.identity}')
        prefix=bytearray(row.prefix)
        if name.startswith('t_quiz'):
            # The correct-choice index belongs to the localized question/options.
            prefix[2:4]=other.prefix[2:4]
        if name=='t_quest._dt':positions=list(range(18,len(prefix),2))
        else:positions=LAYOUTS[name][2]
        start=len(out);cursor=start+len(prefix)
        require(start<65536,'Table record pointer overflow')
        struct.pack_into('<H',out,offset+2*row.index,start)
        for p,text in zip(positions,other.fields):
            require(cursor<65536,'Table text pointer overflow')
            struct.pack_into('<H',prefix,p,cursor);cursor+=len(text)
        out.extend(prefix);out.extend(b''.join(other.fields))
        changed+=sum(a!=b for a,b in zip(row.fields,other.fields))
        mapping.append({'psp_record':row.identity,'pc_record':other.identity,'fields':len(row.fields)})
    # Re-read to verify pointers and retained non-text PSP record bytes.
    _,rebuilt=row_table(bytes(out),name)
    for before,after in zip(source,rebuilt):
        a,b=bytearray(before.prefix),bytearray(after.prefix)
        positions=list(range(18,len(a),2)) if name=='t_quest._dt' else LAYOUTS[name][2]
        for p in positions:a[p:p+2]=b'\0\0';b[p:p+2]=b'\0\0'
        if name.startswith('t_quiz'):a[2:4]=b[2:4]
        require(a==b,'Non-text PSP table bytes changed')
    return bytes(out),{'records':len(source),'changed_fields':changed,'mapping':mapping}


def string_array(data):
    count=u16(data);header=2+2*count
    require(header<=len(data),'Truncated counted string table')
    fields=[]
    for i in range(count):
        pos=u16(data,2+2*i);require(header<=pos<len(data),'String-array pointer outside file')
        end=data.find(b'\0',pos);require(end>=pos,'Unterminated counted string')
        fields.append(data[pos:end+1])
    return fields


def transplant_string_array(psp,pc):
    old,new=string_array(psp),string_array(pc)
    require(len(old)==len(new),'String-array identity count differs')
    out=bytearray(struct.pack('<H',len(old))+bytes(2*len(old)));seen={}
    for i,text in enumerate(new):
        if text not in seen:seen[text]=len(out);out.extend(text)
        require(seen[text]<65536,'String-array pointer overflow')
        struct.pack_into('<H',out,2+2*i,seen[text])
    require(string_array(bytes(out))==new,'Rebuilt counted strings differ')
    return bytes(out),{'records':len(old),'changed_fields':sum(a!=b for a,b in zip(old,new))}


def transplant_fish(psp,pc):
    # Four numeric arrays end at 3942; 26 species descriptions follow them.
    roots_a=[u16(psp,p) for p in range(0,10,2)]
    roots_b=[u16(pc,p) for p in range(0,10,2)]
    require(roots_a[:4]==roots_b[:4]==[10,1570,2494,2942],'Unknown fishing layout')
    prefix=bytearray(psp[:3942]);other=bytearray(pc[:3942])
    for x in (8,*[12+60*i for i in range(26)]):prefix[x:x+2]=other[x:x+2]=b'\0\0'
    require(prefix==other,'Fishing numeric parameters differ unexpectedly')
    out=bytearray(psp[:3942])
    for i in range(26):
        require(u16(psp,10+60*i)==u16(pc,10+60*i)==i,'Fishing species identity mismatch')
        p=12+60*i;q=u16(pc,p);text=pc[q:text_end(pc,q,roots_b[4])]
        struct.pack_into('<H',out,p,len(out));out.extend(text)
    # Last section is an indexed array of fishing dialogue, with suffix aliases.
    start=len(out);struct.pack_into('<H',out,8,start)
    ca=(u16(psp,roots_a[4])-roots_a[4])//2;cb=(u16(pc,roots_b[4])-roots_b[4])//2
    require(ca==cb==80,'Fishing dialogue count mismatch')
    out.extend(bytes(2*ca));seen={}
    for i in range(ca):
        q=u16(pc,roots_b[4]+2*i);text=pc[q:text_end(pc,q)]
        if text not in seen:seen[text]=len(out);out.extend(text)
        require(seen[text]<65536,'Fishing pointer overflow')
        struct.pack_into('<H',out,start+2*i,seen[text])
    return bytes(out),{'species':26,'dialogue_entries':80}


def transplant_chain(psp,pc):
    require([u16(psp,p) for p in (0,2,4)]==[8,32,56] and [u16(pc,p) for p in (0,2,4)]==[8,32,56],'Unknown chain layout')
    out=bytearray(psp[:376]);a=bytearray(psp[:376]);b=bytearray(pc[:376])
    for p in (6,*range(56,376,8)):a[p:p+2]=b[p:p+2]=b'\0\0'
    require(a==b,'Chain numeric parameters differ unexpectedly')
    for p in range(56,376,8):
        x,y=u16(psp,p),u16(pc,p);q=u16(pc,y)
        require(q==y+8 and u16(psp,x)==x+8,'Unknown chain label record')
        prefix=bytearray(psp[x:x+8]);struct.pack_into('<H',prefix,0,len(out)+8)
        struct.pack_into('<H',out,p,len(out));out.extend(prefix);out.extend(pc[q:text_end(pc,q,u16(pc,6))])
    start=len(out);struct.pack_into('<H',out,6,start);out.extend(bytes(40))
    la,lb=u16(psp,6),u16(pc,6)
    require(u16(psp,la)==la+40 and u16(pc,lb)==lb+40,'Unknown chain quote count')
    for i in range(20):
        x,y=u16(psp,la+2*i),u16(pc,lb+2*i);q=u16(pc,y)
        prefix=bytearray(psp[x:x+8]);struct.pack_into('<H',prefix,0,len(out)+8)
        struct.pack_into('<H',out,start+2*i,len(out));out.extend(prefix);out.extend(pc[q:text_end(pc,q)])
    require(len(out)<65536,'Chain pointer overflow')
    return bytes(out),{'chain_labels':40,'character_quotes':20}


def transplant_memo(psp,pc,pc_items):
    # PSP splits notebook topics into more fixed pages than PC. Keep the PSP
    # topic identities; generate page numbers from the donor's heading stem.
    _,rows=row_table(pc,'t_memo._dt');donor={r.identity:r.fields[0] for r in rows}
    overrides={};mapping={0:0,4:3,7:5,13:8,23:13,30:30,32:32,33:33,36:37,37:38,38:39,39:40,52:52,54:54,55:55,57:57,59:59,61:61,65:66,999:999}
    def heading(source,index):return donor[source].rstrip(b'\0').rsplit(b' ',1)[0]+b' '+str(index).encode()+b'\0'
    for ids,source in [([1,2,3],1),([5,6],4),([8,9],6),([10,11,12],7),([14,15],9),([17,18],10),([19,20],11),([21,22],12),([24,25],14)]:
        stem=donor[source].rstrip(b'\0')
        if source==1:stem=stem.rsplit(b' ',1)[0]
        for i,identity in enumerate(ids,1):overrides[identity]=[stem+b' '+str(i).encode()+b'\0']
    for i,identity in enumerate([28,29]+list(range(70,78)),1):overrides[identity]=[heading(15,i)]
    for i,identity in enumerate(range(78,92),1):overrides[identity]=[heading(21,i)]
    _,items=row_table(pc_items,'t_ittxt._dt');overrides[16]=[next(r.fields[0] for r in items if r.identity==527)]
    # These two page headings and the extra PSP counter have no PC counterpart.
    # The labels are newly authored adapter UI, not extracted game resources.
    overrides[26]=[b'Shortcuts 1\0'];overrides[27]=[b'Shortcuts 2\0'];overrides[40]=[b'Defeats:\0']
    overrides[63]=[donor[63].rstrip(b'\0')+b' '+donor[64]]
    _,source=row_table(psp,'t_memo._dt')
    for row in source:
        if row.identity not in overrides and row.identity not in mapping:
            # All remaining original fields are blank separators.
            require(not row.fields[0].decode('cp932').strip('\0 \u3000'),'Unexpected untranslated notebook heading')
            overrides[row.identity]=[b' \0']
    return transplant_rows(psp,pc,'t_memo._dt',mapping,overrides)


def transplant_quests(psp,pc):
    from journal_layout import main_quest_fields,door_quest_fields,DOOR_COLUMNS
    _,rows=row_table(pc,'t_quest._dt')
    overrides={r.identity:main_quest_fields(r.identity,r.fields) for r in rows if 40<=r.identity<=64}
    doors={r.identity:door_quest_fields(r.identity,r.fields) for r in rows
           if 1<=r.identity<=36 and r.fields[0].strip(b' \x01\0')}
    overrides.update(doors)
    result,info=transplant_rows(psp,pc,'t_quest._dt',field_overrides=overrides)
    info.update(main_quests_reflowed=len(overrides)-len(doors),left_columns=31,right_columns=36,
                door_records_reflowed=len(doors),door_column_limits=DOOR_COLUMNS)
    return result,info
