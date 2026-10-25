"""In-place native UI edits, assembled solely from a user's local PC donor.

No executable code, relocation, allocation or original string is stored here.
Each recipe entry is numeric offsets plus hashes. Text must fit its PSP slot.
"""
import hashlib
import re
from formats import require


PRINTF=re.compile(rb'%(?:[-+ #0]*\d*(?:\.\d+)?[hlL]?[diuoxXfFeEgGcspn]|%)')


def apply_ui(boot,pc_executable,recipe):
    require(hashlib.sha256(boot).hexdigest()==recipe['boot_sha256'],'PSP executable hash mismatch')
    require(hashlib.sha256(pc_executable).hexdigest()==recipe['pc_exe_sha256'],'PC executable hash mismatch')
    out=bytearray(boot);previous=0
    for field in sorted(recipe['fields'],key=lambda f:f['psp_start']):
        a,b=field['psp_start'],field['psp_end']
        require(previous<=a<b<=len(boot),'Overlapping native UI edits');previous=b
        original=boot[a:b]
        require(hashlib.sha256(original).hexdigest()==field['source_sha256'],'Native UI source field changed')
        payload=b''.join(pc_executable[p:p+n] for p,n in field['pc_parts'])
        require(b'\0' not in payload and len(payload)<len(original),'Native UI field exceeds original slot')
        require(PRINTF.findall(original)==PRINTF.findall(payload),'Native UI printf argument sequence changed')
        out[a:b]=payload.ljust(len(original),b'\0')
    require(len(out)==len(boot),'Native executable size changed')
    return bytes(out)
