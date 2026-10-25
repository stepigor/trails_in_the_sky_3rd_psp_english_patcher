"""Split oversized ED6 scripts using the engine's existing include/call mechanism.

Old function numbers remain stable: a moved function becomes a Call/Return stub.
No executable modification, wide-address extension or debugger text injection.
"""
import bisect
import struct
from dataclasses import dataclass

from formats import require,u16
from scena import Script


@dataclass
class Fragment:
    old_start: int
    old_end: int
    edits: list
    data: bytes

    def local(self, offset):
        require(self.old_start<=offset<=self.old_end,'Pointer outside function fragment')
        delta=0
        for a,b,v in self.edits:
            require(not a<offset<b,'Pointer into translated field')
            if b<=offset:delta+=len(v)-(b-a)
        return offset-self.old_start+delta


def split_script(script, replacements, moved, parent_id, bank_id, bank_name,
                 self_slot=0, include_roster=None):
    n=len(script.funcs);moved=set(moved)
    require(moved and all(0<=i<n for i in moved),'Invalid moved-function set')
    includes=list(include_roster or struct.unpack_from('<8I',script.data,0x20))
    require(includes[self_slot] in (0xffffffff,parent_id),'Self slot belongs to another scenario')
    includes[self_slot]=parent_id
    free=next((i for i,v in enumerate(includes) if v==0xffffffff and i!=self_slot),None)
    require(free is not None,'No free include slot for split script')
    # Call operands use the roster index directly. Slot zero is the root;
    # auxiliary files use their global index, not an index relative to a file.
    link=free
    require(not any(scene==link for _,scene,_ in script.function_refs),'Unused include slot has callers')
    allowed={(s.start,s.end) for s in script.texts+script.string_spans}
    require(all((a,b) in allowed for a,b,_ in replacements),'Replacement is not a known field')
    replacements=sorted(replacements)
    require(all(replacements[i][1]<=replacements[i+1][0] for i in range(len(replacements)-1)), 'Overlapping replacements')
    table=script.header['function_table'];strings=script.header['string_table']
    fragments=[]
    for i,start in enumerate(script.funcs):
        end=script.funcs[i+1] if i+1<n else table
        edits=[(a,b,v) for a,b,v in replacements if start<=a<b<=end]
        data=script._edit(script.data,start,end,edits)
        fragments.append(Fragment(start,end,edits,data))
    name_edits=[(a,b,v) for a,b,v in replacements if a>=strings]
    names=script._edit(script.data,strings,len(script.data),name_edits)

    def owner(address):
        i=bisect.bisect_right(script.funcs,address)-1
        require(i>=0 and address<table,'Branch outside function region')
        return i

    for pos,target in script.labels:
        require((owner(pos) in moved)==(owner(target) in moved),
                'Cross-function branch crosses a bank boundary')

    def emit(bank):
        prefix=bytearray(script.data[:script.header['code_start']])
        ii=includes.copy();ii[free]=bank_id
        struct.pack_into('<8I',prefix,0x20,*ii)
        if bank:
            location=(bank_name.upper()+'.x').encode('ascii')
            require(len(location)<=14,'Bank name too long')
            prefix[10:24]=location.ljust(14,b'\0')
        chunks=[];starts=[];cursor=len(prefix)
        for i,frag in enumerate(fragments):
            starts.append(cursor)
            if bank:
                data=bytearray(frag.data if i in moved else b'\x01')
            else:
                data=bytearray(b'\x05'+bytes([link])+struct.pack('<H',i)+b'\x01' if i in moved else frag.data)
            chunks.append(data);cursor+=len(data)
        function_table=cursor;string_table=cursor+2*n
        require(string_table<65536 and max(starts)<65536,'Split bank still exceeds 16-bit region')
        for i,frag in enumerate(fragments):
            if (i in moved)!=bank:continue
            chunk=chunks[i]
            for pos,target in script.labels:
                if frag.old_start<=pos<frag.old_end:
                    dest=owner(target)
                    value=starts[dest]+fragments[dest].local(target)
                    require(value<65536,'Bank label overflow')
                    struct.pack_into('<H',chunk,frag.local(pos),value)
            for pos,start,end in script.lengths:
                if frag.old_start<=pos<frag.old_end:
                    length=frag.local(end)-frag.local(start)
                    require(length<256,'Fork length overflow in bank')
                    chunk[frag.local(pos)]=length
        struct.pack_into('<H',prefix,0x5a,string_table)
        struct.pack_into('<H',prefix,0x60,function_table)
        result=bytes(prefix)+b''.join(chunks)+struct.pack('<'+'H'*n,*starts)+names
        parsed=Script(result)
        require(len(parsed.funcs)==n,'Function count changed while splitting')
        return result,parsed
    main,pmain=emit(False);bank,pbank=emit(True)
    # Every externally visible function number remains callable in the parent.
    for i in moved:
        rows=pmain.functions[i]
        require(len(rows)==2 and rows[0]['opcode']==5 and rows[1]['opcode']==1,'Invalid parent stub')
        require(rows[0]['function_refs'][0][1:]==(link,i),'Stub points to wrong bank function')
    return main,bank,{'include_slot':link,'moved_functions':sorted(moved),'main_size':len(main),'bank_size':len(bank)}
