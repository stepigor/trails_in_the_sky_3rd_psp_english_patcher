"""Finalize XMB/save artwork locally; keep the full game build reproducible."""
import hashlib
import json
import os
from pathlib import Path
from archives import append_iso_files,pc_file
from formats import Iso9660,require,sha256_file
from graphics import png_logo


def finish(output,pc_root,recipe_root):
    output=Path(output);iso=Iso9660(output);recipe=json.loads((recipe_root/'xmb-recipe.json').read_text())
    exe=(pc_root/'ed6_win3.exe').read_bytes();require(hashlib.sha256(exe).hexdigest()==recipe['pc_exe_sha256'],'XMB donor mismatch')
    donors={};replacements={}
    for e in recipe['images']:
        old=iso.get(e['path']);require(hashlib.sha256(old).hexdigest()==e['psp_sha256'],'XMB source mismatch')
        key=(e['pc_archive'],e['pc_member'])
        if key not in donors:donors[key]=pc_file(pc_root,*key)
        donor=donors[key];require(hashlib.sha256(donor).hexdigest()==e['pc_sha256'],'XMB logo donor mismatch')
        replacements[e['path']]=png_logo(old,donor,e,exe)
    for e in recipe['plain']:
        require(hashlib.sha256(iso.get(e['path'])).hexdigest()==e['psp_sha256'],'Save detail source mismatch')
        replacements[e['path']]=bytes([239,187,191])+b''.join(exe[p:p+n] for p,n in e['parts'])
    temp=output.with_suffix('.xmb-stage.iso');require(not temp.exists(),'Temporary XMB output already exists')
    append_iso_files(output,temp,replacements)
    parent_sha256=sha256_file(output);after=Iso9660(temp)
    for p in replacements:require(after.get(p)==replacements[p],'XMB readback differs')
    os.replace(temp,output)
    return dict(output_sha256=sha256_file(output),output_size=output.stat().st_size,xmb_files=len(replacements),xmb_parent_sha256=parent_sha256)
