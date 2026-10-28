"""In-place native UI edits, assembled solely from a user's local PC donor.

String recipes contain numeric offsets and hashes, with no extracted text.
Text must fit its PSP slot. The synthesis hint also receives six verified
instruction edits to reuse the existing English element labels.
"""
import hashlib
import re
import struct
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


def apply_shop_element_labels(boot):
    # Reuse the existing, relocated address and the translated eight-byte
    # elemental labels. The original synthesis hint copied seven three-byte
    # Japanese labels onto its stack; those slots cannot hold English names.
    edits=[
        (0x102cb0,0x24483474,0x24484108), # t0 -> existing element labels
        (0x102cf0,0x91090014,0x01004821), # retain the relocated base in t1
        (0x102d14,0xa3a90014,0x00000000), # old packed-label stack byte unused
        (0x102d30,0x00033040,0x000330c0), # element index * 8
        (0x102d34,0x00c33021,0x00000000), # remove the old * 3 addition
        (0x102d3c,0x03a63021,0x01263021), # sprintf argument = base + offset
    ]
    out=bytearray(boot)
    for address,before,after in edits:
        offset=address+0xc0
        require(offset+4<=len(out) and struct.unpack_from('<I',out,offset)[0]==before,
                'Unexpected PSP synthesis-label instruction')
        struct.pack_into('<I',out,offset,after)
    return bytes(out)
