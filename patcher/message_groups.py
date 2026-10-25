"""Repartition complete local narration groups into existing PSP windows."""
import re
from formats import require


def paginate(payloads,originals):
    """Repartition complete donor text at existing line/page boundaries.

    Every donor byte except each C terminator is retained in order. Only new
    page/termination controls and repeated initial display style are added.
    """
    require(payloads and originals,'Empty narration group')
    require(all(x.endswith(b'\0') for x in payloads),'Invalid narration terminator')
    if len(payloads)==len(originals):return list(payloads)
    merged=b'\x03'.join(x[:-1] for x in payloads)
    boundaries=[0];p=0
    while p<len(merged):
        ch=merged[p];p+=1
        if ch==7:p+=1
        elif ch==0x1f:p+=2
        elif 0x81<=ch<=0x9f or 0xe0<=ch<=0xfc:p+=1
        elif ch in (1,2,3):boundaries.append(p)
    boundaries.append(len(merged))
    require(len(set(boundaries))>=len(originals)+1,'Not enough narration boundaries')
    weights=[max(1,len(x)-1) for x in originals];total=sum(weights);cuts=[0];cum=0
    for i,w in enumerate(weights[:-1]):
        cum+=w;target=len(merged)*cum/total
        candidates=[v for v in boundaries if v>cuts[-1] and sum(t>v for t in set(boundaries))>=len(originals)-i-1]
        require(candidates,'Cannot repartition narration')
        cuts.append(min(candidates,key=lambda v:abs(v-target)))
    cuts.append(len(merged));out=[]
    for i,(lo,hi) in enumerate(zip(cuts,cuts[1:])):
        text=merged[lo:hi]
        # Font-size and color state may be reset by the original PSP window.
        style=re.match(rb'(?:\x07.|#-?\d+[S])',originals[i],re.S)
        if i and style:text=style.group()+text
        if not text.endswith(b'\x02'):text+=b'\x02'
        out.append(text+b'\0')
    return out
