"""Transfer local PC battle speech using verified numeric source references.

The recipe records text spans and 16-bit relocation fields, not game text or
instructions. Every other PSP byte, including effects and timing, is preserved.
"""
import bisect
import hashlib
import struct
from formats import require,u16
from scena import Script


def transplant(source,donor,recipe):
    require(hashlib.sha256(source).hexdigest()==recipe['psp_sha256'],'Battle speech PSP source mismatch')
    require(hashlib.sha256(donor).hexdigest()==recipe['pc_sha256'],'Battle speech PC source mismatch')
    edits=[];previous=0
    for a,b,c,d in recipe['fields']:
        require(previous<=a<b<=len(source) and 0<=c<d<=len(donor),'Invalid or overlapping battle speech span')
        old,new=source[a:b],donor[c:d]
        require(old.endswith(b'\0') and b'\0' not in old[:-1] and new.endswith(b'\0') and b'\0' not in new[:-1],
                'Battle speech must be a single terminated string')
        require(len(new)<=64,'Battle speech exceeds the PSP text buffer')
        edits.append((a,b,new));previous=b
    require(edits,'Empty battle speech recipe')
    ends=[b for a,b,v in edits];deltas=[0]
    for a,b,v in edits:deltas.append(deltas[-1]+len(v)-(b-a))
    def relocated(offset):
        require(0<=offset<=len(source),'Battle speech address out of range')
        i=bisect.bisect_right(ends,offset)
        require(i==len(edits) or not edits[i][0]<offset<edits[i][1],'Battle speech address points inside text')
        result=offset+deltas[i]
        require(0<=result<=0xffff,'Battle speech 16-bit address overflow')
        return result
    require(len(source)+deltas[-1]<=0xffff,'Battle speech file exceeds 16-bit address range')
    pointers=recipe['pointers']
    require(pointers==sorted(set(pointers)),'Duplicate or unordered battle speech relocations')
    expected=[];previous=-2
    for position in pointers:
        require(previous+2<=position and position+2<=len(source),'Overlapping or truncated battle speech relocation')
        require(all(position+2<=a or b<=position for a,b,v in edits),'Battle speech relocation overlaps text')
        target=u16(source,position)
        require(target<len(source) and all(not a<=target<b for a,b,v in edits),'Battle speech target points into text')
        value=relocated(target)
        expected.append((relocated(position),value,position,struct.pack('<H',value)))
        previous=position
    result=Script._edit(source,0,len(source),edits+[(p,p+2,v) for _,_,p,v in expected])
    for position,target,_,_ in expected:require(u16(result,position)==target,'Battle speech relocated target differs')
    for a,b,value in edits:
        start=relocated(a);require(result[start:start+len(value)]==value,'Battle speech readback differs')
    # Remove the only permitted changes and compare every remaining source byte.
    old_removed=[(a,b,b'') for a,b,v in edits]+[(p,p+2,b'') for p in pointers]
    new_removed=[(relocated(a),relocated(a)+len(v),b'') for a,b,v in edits]+[(p,p+2,b'') for p,_,_,_ in expected]
    require(Script._edit(source,0,len(source),old_removed)==Script._edit(result,0,len(result),new_removed),
            'Non-text battle speech data changed')
    return result
