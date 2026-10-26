"""Build the English PSP image from verified local source files."""
import re
import bisect
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import struct

from formats import Iso9660,FormatError,require,cclm_members,u16,sha256_file,falcom3
from scena import Script
from archives import pc_file,repack_cclm as repack_uncompressed,append_iso_files,encode_falcom3
from banks import split_script
from message_groups import paginate
from native_ui import apply_ui
from battle_text import transplant as transplant_monster,transplant_variant
from battle_quotes import transplant as transplant_battle_quotes
from battle_packs import repack_records,pkc_members,repack_pkc,description,translate_copy
from movies import MOVIES
from graphics import title_model,convert_texture
from text_layout import reflow
from tables import LAYOUTS,transplant_rows,transplant_string_array,transplant_chain,transplant_fish,transplant_memo,transplant_quests


def family(name):
    return re.sub(r'_\d+$', '', Path(name).stem)


BASE_HASH='6e839745322286a4587767a260cb86cbd2bf8d77baaec272c73780c600b939e8'


def repack_cclm(archive,replacements,additions=None):
    return repack_uncompressed(archive,replacements,additions,compress=True)


def sfo_title(source,title):
    require(source[:4]==b'\0PSF','Invalid SFO metadata')
    keys,values,count=struct.unpack_from('<III',source,8);out=bytearray(source);found=False
    for i in range(count):
        p=20+16*i;key,fmt,size,capacity,offset=struct.unpack_from('<HHIII',source,p)
        end=source.index(0,keys+key);name=source[keys+key:end].decode('ascii')
        if name=='TITLE':
            data=title.encode('utf8')+b'\0';require(len(data)<=capacity,'SFO title exceeds slot')
            out[values+offset:values+offset+capacity]=data.ljust(capacity,b'\0');struct.pack_into('<I',out,p+4,len(data));found=True
    require(found,'SFO title missing');return bytes(out)


def plan_bank(script,edits,parent_id,bank_id,bank_name,self_slot,roster):
    # A branch-connected component must stay within one file.
    n=len(script.funcs);component=list(range(n))
    def root(i):
        while component[i]!=i:i=component[i]
        return i
    for p,t in script.labels:
        i=bisect.bisect_right(script.funcs,p)-1;j=bisect.bisect_right(script.funcs,t)-1
        component[root(i)]=root(j)
    groups=defaultdict(set)
    for i in range(n):groups[root(i)].add(i)
    def translated_size(indices):
        total=0
        for i in indices:
            a=script.funcs[i];b=script.funcs[i+1] if i+1<n else script.header['function_table']
            total+=b-a+sum(len(v)-(y-x) for x,y,v in edits if a<=x<y<=b)
        return total
    choices=sorted(groups.values(),key=translated_size,reverse=True);moved=set();last=None
    for group in choices:
        moved.update(group)
        try:return split_script(script,edits,moved,parent_id,bank_id,bank_name,self_slot,roster)
        except FormatError as e:
            last=e
            if 'Split bank still exceeds' not in str(e):raise
    raise FormatError('Unable to plan bank: '+str(last))


def build(iso_path,pc_root,output,recipe_root,movies_dir=None):
    require(sha256_file(iso_path)==BASE_HASH,'PSP ISO version/hash mismatch')
    inputs=json.loads((recipe_root/'pc-inputs.json').read_text())
    for name,sha in inputs.items():require(sha256_file(pc_root/name)==sha,'PC input version/hash mismatch: '+name)
    print('Verified local inputs; rebuilding scenario text',flush=True)
    iso=Iso9660(iso_path);archives={};sources={};occurrences=defaultdict(set)
    for path in iso.entries:
        if not path.endswith('.mc1'):continue
        raw=iso.get(path);archives[path]=raw
        for m in cclm_members(raw):
            if not m.name.endswith('.bin'):continue
            data=m.read(raw)
            require(m.name not in sources or sources[m.name]==data,'Different PSP copies share a script name')
            sources[m.name]=data;occurrences[m.name].add(path)
    recipe=json.loads((recipe_root/'scripts.json').read_text())
    adaptations=json.loads((recipe_root/'script-adaptations-recipe.json').read_text())
    pc_exe=(pc_root/'ed6_win3.exe').read_bytes()
    require(hashlib.sha256(pc_exe).hexdigest()==adaptations['pc_exe_sha256'],'PC executable hash mismatch')
    adapt_by_file=defaultdict(list)
    for field in adaptations['fields']:adapt_by_file[field['file']].append(field)
    donors={};scripts={};edits_by_name={}
    unresolved=[];field_count=0;wrapped_fields=0;added_pages=0
    def donor(name):
        if name not in donors:donors[name]=pc_file(pc_root,'ED6_DT21',Path(name).stem+'._sn')
        return donors[name]
    for entry in recipe['scripts']:
        name=entry['file'];raw=sources[name]
        require(hashlib.sha256(raw).hexdigest()==entry['sha256'],'PSP script hash mismatch')
        script=Script(raw);scripts[name]=script;edits={}
        for ref in entry['references']:
            text=donor(ref['pc_file'])[ref['pc_start']:ref['pc_end']]
            edits[ref['psp_start']]=(ref['psp_start'],ref['psp_end'],text)
        for group in entry.get('message_groups',[]):
            payloads=[donor(group['pc_file'])[a:b] for a,b in group['pc_spans']]
            originals=[raw[a:b] for a,b in group['psp_spans']]
            for (a,b),text in zip(group['psp_spans'],paginate(payloads,originals)):
                edits[a]=(a,b,text)
        for field in adapt_by_file[name]:
            a,b=field['psp_start'],field['psp_end']
            require(hashlib.sha256(raw[a:b]).hexdigest()==field['source_sha256'],'Adaptation source mismatch')
            value=b''.join(bytes([part['control']]) if 'control' in part else pc_exe[part['pc'][0]:part['pc'][0]+part['pc'][1]] for part in field['parts'])
            edits[a]=(a,b,value)
        unresolved.extend(dict(file=name,**r) for r in entry['unmapped'] if r['start'] not in edits)
        for row in script.instructions:
            if row['opcode'] not in (0x54,0x5b,0x5c):continue
            for span in row['texts']:
                if span.kind!='text' or span.start not in edits:continue
                a,b,value=edits[span.start];value,layout=reflow(value,row['opcode'] in (0x5b,0x5c))
                edits[a]=(a,b,value);wrapped_fields+=int(layout['changed']);added_pages+=layout['added_pages']
        edits_by_name[name]=list(edits.values());field_count+=len(edits)
    # Use unused names already present in PSP's scenario registry. The bank
    # roster uses global indices 0..7, including each file's own index.
    start_path=next(p for p in iso.entries if p.endswith('/start.dat'))
    start=iso.get(start_path);map_data=next(m.read(start) for m in cclm_members(start) if m.name=='map.txt')
    registry=map_data.decode('ascii').splitlines();ids={n:0x210000|i for i,n in enumerate(registry)}
    corpus=b''.join(sources.values())
    spare=[n for n in registry if n.startswith('a00') and n+'.bin' not in sources and struct.pack('<I',ids[n]) not in corpus]
    rebuilt={};banks={};bank_reports=[];roster_updates={}
    for name,script in scripts.items():
        try:rebuilt[name]=script.rebuild(edits_by_name[name])
        except (FormatError,struct.error) as e:
            if 'overflow' not in str(e).lower() and 'ushort format' not in str(e):raise
            root_name=family(name)+'.bin';root_script=scripts.get(root_name,script)
            roster=list(struct.unpack_from('<8I',root_script.data,0x20));root_id=ids[Path(root_name).stem]
            if roster[0]==0xffffffff:roster[0]=root_id
            parent_id=ids[Path(name).stem]
            self_slot=roster.index(parent_id) if parent_id in roster else 0
            bank_name=spare.pop(0);bank_id=ids[bank_name]
            main,bank,report=plan_bank(script,edits_by_name[name],parent_id,bank_id,bank_name,self_slot,roster)
            rebuilt[name]=main;banks[bank_name+'.bin']=bank
            report.update(file=name,bank=bank_name+'.bin',parent_id=parent_id,bank_id=bank_id)
            bank_reports.append(report)
            for source_name in scripts:
                if family(source_name)==family(name):
                    roster_updates.setdefault(source_name,{})[report['include_slot']]=bank_id
    for name,updates in roster_updates.items():
        d=bytearray(rebuilt[name]);ii=list(struct.unpack_from('<8I',d,0x20))
        if ii[0]==0xffffffff:ii[0]=ids[family(name)]
        for slot,value in updates.items():
            require(ii[slot] in (0xffffffff,value),'Global bank roster conflict')
            ii[slot]=value
        struct.pack_into('<8I',d,0x20,*ii);rebuilt[name]=bytes(d)
    replacements={}
    print('Packing scenario archives and five extension banks',flush=True)
    for path,archive in archives.items():
        members={m.name for m in cclm_members(archive)}
        changed={n:d for n,d in rebuilt.items() if n in members and d!=sources[n]}
        additions={r['bank']:banks[r['bank']] for r in bank_reports if any(family(n)==family(r['file']) for n in members if n in sources)}
        if changed or additions:replacements[path]=repack_cclm(archive,changed,additions)
    table_reports=[]
    print('Rebuilding text tables and monster descriptions',flush=True)
    for path in iso.entries:
        name=Path(path).name.lower()
        if '/text/' not in path.lower():continue
        if name not in LAYOUTS and name not in ['t_town._dt','t_fish._dt','t_chain._dt','t_title._dt'] and not (name.startswith('t_book') and name!='t_book00._dt'):continue
        try:
            psp=iso.get(path);pc=pc_file(pc_root,'ED6_DT22',name)
            if name=='t_memo._dt':data,info=transplant_memo(psp,pc,pc_file(pc_root,'ED6_DT22','t_ittxt._dt'))
            elif name=='t_quest._dt':data,info=transplant_quests(psp,pc)
            elif name in LAYOUTS:data,info=transplant_rows(psp,pc,name)
            elif name=='t_town._dt':data,info=transplant_string_array(psp,pc)
            elif name=='t_fish._dt':data,info=transplant_fish(psp,pc)
            elif name=='t_chain._dt':data,info=transplant_chain(psp,pc)
            else:data,info=pc,{'mode':'pure_text_copy'}
            replacements[path]=data;table_reports.append(dict(file=name,status='rebuilt',**{k:v for k,v in info.items() if k!='mapping'}))
        except (FormatError,ValueError) as e:table_reports.append(dict(file=name,status='unresolved',error=str(e)))
    plain=json.loads((recipe_root/'plain-text-recipe.json').read_text())
    require(hashlib.sha256(pc_exe).hexdigest()==plain['pc_exe_sha256'],'Plain-text PC donor hash mismatch')
    for entry in plain['files']:
        require(hashlib.sha256(iso.get(entry['path'])).hexdigest()==entry['source_sha256'],'Plain-text PSP donor hash mismatch')
        replacements[entry['path']]=b''.join(bytes([p['control']]) if 'control' in p else pc_exe[p['pc'][0]:p['pc'][0]+p['pc'][1]] for p in entry['parts'])
    monster=json.loads((recipe_root/'battle-text-recipe.json').read_text())
    require(sha256_file(pc_root/'ED6_DT30.dir')==monster['pc_directory_sha256'],'PC monster directory hash mismatch')
    battle_donors={}
    pack_recipe=json.loads((recipe_root/'battle-packs-recipe.json').read_text())
    require(hashlib.sha256(pc_exe).hexdigest()==pack_recipe['pc_exe_sha256'],'Battle panel donor mismatch')
    description_overrides={e['fid']:b''.join(pc_exe[p:p+n] for p,n in e['parts']) for e in pack_recipe['description_overrides']}
    monster_updates={}
    def battle_donor(name):
        if name not in battle_donors:battle_donors[name]=pc_file(pc_root,'ED6_DT30',name)
        return battle_donors[name]
    for entry in monster['entries']+monster['variant_entries']:
        path='PSP_GAME/USRDIR/data_3rd/battle/dat/'+entry['psp_file'];old=iso.get(path)
        require(hashlib.sha256(old).hexdigest()==entry['psp_sha256'],'PSP monster hash mismatch')
        if 'fields' in entry:data=transplant_variant(old,battle_donor,entry)
        else:
            donor_data=battle_donor(entry['pc_member'])
            require(hashlib.sha256(donor_data).hexdigest()==entry['pc_sha256'],'PC monster hash mismatch')
            data=transplant_monster(old,donor_data,entry)
        fid=int(entry['psp_file'][2:8],16)
        data=description(data,entry['count_offset'],description_overrides.get(fid))
        replacements[path]=data;monster_updates[fid]=(old,data,entry['count_offset'])
    for path,sha in pack_recipe['source_hashes'].items():
        require(hashlib.sha256(iso.get(path)).hexdigest()==sha,'Monster pack source mismatch')
    runtime_path='PSP_GAME/USRDIR/data_3rd/battle2/dtpack.da2'
    speech=json.loads((recipe_root/'battle-quotes-recipe.json').read_text())
    runtime_updates={fid:(old,new) for fid,(old,new,_) in monster_updates.items()}
    print('Transferring battle speech and random phrase lists',flush=True)
    for entry in speech['entries']:
        path='PSP_GAME/USRDIR/data_3rd/battle/dat/'+entry['psp_file'];old=iso.get(path)
        new=transplant_battle_quotes(old,battle_donor(entry['pc_member']),entry)
        fid=int(entry['psp_file'][2:8],16)
        require(fid not in runtime_updates,'Battle speech and monster records overlap')
        replacements[path]=new;runtime_updates[fid]=(old,new)
    def runtime_member(fid,data):
        if fid not in runtime_updates:return data
        old,new=runtime_updates[fid];require(data==old,'Runtime battle record differs from standalone source');return new
    packed,runtime_report=repack_records(falcom3(iso.get(runtime_path)),1,runtime_member)
    replacements[runtime_path]=encode_falcom3(packed,compress=True)
    bestiary_path='PSP_GAME/USRDIR/data_3rd/monsnote/monsnote.dt2'
    variants={e['fid']:e for e in pack_recipe['bestiary_variants']}
    def bestiary_member(fid,data):
        if fid not in monster_updates:return data
        old,new,offset=monster_updates[fid];variant=variants.get(fid)
        if variant:require(hashlib.sha256(data).hexdigest()==variant['source_sha256'],'Bestiary variant source mismatch')
        else:require(data==old,'Unexpected bestiary variant')
        return translate_copy(data,old,new,offset,variant['approved_text_differences'] if variant else ())
    replacements[bestiary_path],bestiary_report=repack_records(iso.get(bestiary_path),2,bestiary_member)
    graphics=json.loads((recipe_root/'graphics-recipe.json').read_text())
    print('Converting English image atlases and notebook pages',flush=True)
    for entry in graphics['models']:
        old=iso.get(entry['path']);donor_image=pc_file(pc_root,entry['pc_archive'],entry['pc_member'])
        require(hashlib.sha256(old).hexdigest()==entry['psp_sha256'] and hashlib.sha256(donor_image).hexdigest()==entry['pc_sha256'],'Logo model/donor hash mismatch')
        replacements[entry['path']]=title_model(old,donor_image,entry)
    require(hashlib.sha256(pc_exe).hexdigest()==graphics['pc_exe_sha256'],'Graphic text donor mismatch')
    require(graphics.get('preserve_status_portraits') and not any(Path(e['path']).name.startswith('c_stch') for e in graphics['textures']), 'Status portraits must remain original')
    raster_donors={}
    for entry in graphics.get('textures',[]):
        old=iso.get(entry['path']);key=(entry['pc_archive'],entry['pc_member'])
        if key not in raster_donors:raster_donors[key]=pc_file(pc_root,*key) if key[0] else b''
        donor_image=raster_donors[key]
        require(hashlib.sha256(old).hexdigest()==entry['psp_sha256'] and hashlib.sha256(donor_image).hexdigest()==entry['pc_sha256'],'Graphic input hash mismatch')
        replacements[entry['path']]=convert_texture(old,donor_image,entry,pc_exe)
    packed_graphics=defaultdict(dict)
    for entry in graphics.get('packed_textures',[]):
        archive=iso.get(entry['path']);require(hashlib.sha256(archive).hexdigest()==entry['container_sha256'],'System texture pack mismatch')
        old=next(raw for name,_,raw in pkc_members(archive) if name==entry['member'])
        donor_image=pc_file(pc_root,entry['pc_archive'],entry['pc_member'])
        require(hashlib.sha256(old).hexdigest()==entry['psp_sha256'] and hashlib.sha256(donor_image).hexdigest()==entry['pc_sha256'],'Battle menu donor mismatch')
        packed_graphics[entry['path']][entry['member']]=convert_texture(old,donor_image,entry,pc_exe)
    for path,changes in packed_graphics.items():replacements[path]=repack_pkc(iso.get(path),changes)
    # The engine also loads cached copies of tables from start.dat and other
    # containers. Replace each copy only after matching its original bytes.
    resource_updates={Path(p).name.lower():(iso.get(p),d) for p,d in replacements.items() if '/text/' in p or '/battle/dat/' in p or '/monsnote/' in p or p.endswith(('.it3','.itp','.pkc','.da2'))}
    cached_copies=[];cache_conflicts=[]
    print('Updating cached copies of localized resources',flush=True)
    with Path(iso_path).open('rb') as f:
        for path,entry in iso.entries.items():
            if entry.directory or entry.size<16 or '/data_3rd/' not in path:continue
            f.seek(entry.lba*2048);head=f.read(16)
            if head[:4]*4!=head or int.from_bytes(head[:4],'little')==0:continue
            archive=replacements.get(path,iso.get(path))
            try:members=cclm_members(archive)
            except (FormatError,UnicodeError):continue
            changes={}
            for m in members:
                if m.name.lower() not in resource_updates:continue
                old,new=resource_updates[m.name.lower()]
                if m.read(archive)!=old:
                    cache_conflicts.append(dict(container=path,member=m.name));continue
                changes[m.name]=new
            if changes:
                replacements[path]=repack_cclm(archive,changes)
                cached_copies.extend(dict(container=path,member=n) for n in changes)
    require(not cache_conflicts,'A cached resource differs from its standalone version')
    movie_reports=[]
    if movies_dir:
        for name,pc_name in MOVIES.items():
            path='PSP_GAME/USRDIR/data_3rd/movie/'+name+'.pmf';target=movies_dir/(name+'.pmf')
            info=json.loads(target.with_suffix('.build.json').read_text())
            require(info.get('converter_version')==2 and sha256_file(pc_root/pc_name)==info['pc_source_sha256'] and hashlib.sha256(iso.get(path)).hexdigest()==info['psp_original_sha256'] and sha256_file(target)==info['output_sha256'],'Movie input/output version/hash mismatch')
            replacements[path]=target.read_bytes();movie_reports.append(dict(file=name,frames=info['frames'],sha256=info['output_sha256']))
    ui_recipe=json.loads((recipe_root/'native-ui-recipe.json').read_text())
    boot=iso.get('PSP_GAME/SYSDIR/BOOT.BIN')
    native=apply_ui(boot,(pc_root/'ed6_win3.exe').read_bytes(),ui_recipe)
    from journal_layout import apply_door_layout,apply_chapter_separator
    native=apply_chapter_separator(apply_door_layout(native))
    replacements['PSP_GAME/SYSDIR/BOOT.BIN']=native
    replacements['PSP_GAME/SYSDIR/EBOOT.BIN']=native
    replacements['PSP_GAME/PARAM.SFO']=sfo_title(iso.get('PSP_GAME/PARAM.SFO'),'Trails in the Sky the 3rd')
    for name,text in [('title.txt','Trails in the Sky the 3rd'),('dtitle.txt','Clear Data')]:
        path='PSP_GAME/USRDIR/savefile/'+name
        if path in iso.entries:replacements[path]=text.encode('ascii')+b'\r\n'
    require(not unresolved and all(t['status']=='rebuilt' for t in table_reports),'Localization coverage incomplete')
    print('Writing and reading back the new ISO',flush=True)
    append_iso_files(iso_path,output,replacements)
    result=Iso9660(output)
    portraits=[p for p in iso.entries if Path(p).name.startswith('c_stch') and p.endswith('.itp')]
    require(all(result.get(p)==iso.get(p) for p in portraits),'Original status portrait changed')
    return dict(status='full_coverage_candidate_pending_acceptance',script_fields=field_count,unresolved_script_fields=unresolved,
                banks=bank_reports,tables=table_reports,changed_containers=len(replacements),
                output_sha256=sha256_file(output),output_size=Path(output).stat().st_size,
                native_ui_fields=len(ui_recipe['fields']),executable_format='decrypted_PRX',
                monster_files=len(monster['entries'])+len(monster['variant_entries']),cached_resource_copies=cached_copies,
                runtime_monster_pack=runtime_report,bestiary_monster_pack=bestiary_report,
                dialogue_layout=dict(wrapped_fields=wrapped_fields,added_page_breaks=added_pages),
                movie_files=movie_reports,title_logo_converted=True,graphic_textures=len(graphics['textures']),
                packed_graphic_textures=sum(map(len,packed_graphics.values())),original_status_portraits=len(portraits),
                full_playthrough_verified=False,hardware_tested=False,
                pending_acceptance=['all-scene layout and semantic review','full playthrough','new build on real PSP','movie audio synchronization and PSP decoder']+([] if movies_dir else ['movie captions omitted']))
