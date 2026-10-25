"""Transfer monster/craft text while preserving PSP parameters."""
import hashlib
from formats import require
from scena import Script


def parse_tail(data,count_offset,allow_trailing=False):
    count=data[count_offset];require(1<=count<=32,'Invalid monster craft count')
    p=count_offset+1;records=[];texts=[]
    def string():
        nonlocal p
        end=data.find(b'\0',p);require(end>=p,'Unterminated monster field')
        value=data[p:end+1];value.decode('cp932')
        require(all(c>=32 or c==0 for c in value),'Control byte in plain monster field')
        span=(p,end+1);p=end+1;texts.append(span);return span
    for i in range(count):
        require(p+28<=len(data),'Truncated monster craft record')
        prefix=data[p:p+28];p+=28
        a=string();b=string();records.append((prefix,a,b))
    require(p+4<=len(data),'Truncated monster trailer')
    trailer=data[p:p+4];p+=4;name=string();description=string()
    require(allow_trailing or p==len(data),'Unparsed monster tail')
    return records,trailer,texts


def transplant(a,b,entry):
    p=entry['count_offset'];ar,at,af=parse_tail(a,p,True);br,bt,bf=parse_tail(b,p,True)
    require(len(ar)==len(br) and af==[tuple(v) for v in entry['psp_spans']] and bf==[tuple(v) for v in entry['pc_spans']], 'Monster recipe layout mismatch')
    out=bytearray(a[:p+1])
    for (prefix,_,_),(_,x,y) in zip(ar,br):out.extend(prefix);out.extend(b[x[0]:x[1]]);out.extend(b[y[0]:y[1]])
    out.extend(at)
    for x,y in bf[-2:]:out.extend(b[x:y])
    out.extend(a[af[-1][1]:])
    rr,rt,rf=parse_tail(bytes(out),p,True)
    require([x[0] for x in rr]==[x[0] for x in ar] and rt==at and out[:p+1]==a[:p+1], 'Monster numeric data changed')
    require(out[rf[-1][1]:]==a[af[-1][1]:],'Monster trailing numeric data changed')
    return bytes(out)


def transplant_variant(a,donors,entry):
    p=entry['count_offset'];before,trailer,spans=parse_tail(a,p,True)
    require([tuple(f['psp_span']) for f in entry['fields']]==spans,'Variant field list differs')
    edits=[]
    for f in entry['fields']:
        donor=donors(f['pc_member']);require(hashlib.sha256(donor).hexdigest()==f['pc_sha256'],'Variant donor hash mismatch')
        x,y=f['pc_span'];start,end=f['psp_span'];edits.append((start,end,donor[x:y]))
    out=Script._edit(a,0,len(a),edits);after,tail,new_spans=parse_tail(out,p,True)
    require(out[:p+1]==a[:p+1] and [r[0] for r in before]==[r[0] for r in after] and trailer==tail and
            a[spans[-1][1]:]==out[new_spans[-1][1]:],'Variant numeric PSP data changed')
    return out
