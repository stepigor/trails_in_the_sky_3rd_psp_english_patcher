"""Convert local PC videos into the original PSP PSMF layout."""
import hashlib
import json
from pathlib import Path
import subprocess
from formats import require,sha256_file
from psmf import indexed_layout,mux
MOVIES={'ed6_3_op':'ED6_3_OP.avi','ed6_logo':'ED6_3_LOGO.avi',
        **{f'ed6_dt{i}':f'ED6_DT{i}.dat' for i in range(48,52)}}


def convert(original,source,ffmpeg,work,target):
    require(original[:8]==b'PSMF0014','Unexpected PSMF version')
    offset=int.from_bytes(original[8:12],'big');require(offset==2048,'Unexpected PSMF data offset')
    require(int.from_bytes(original[0x80:0x82],'big')==1 and original[0x82]==0xe0,'Only single-stream AVC PSMF supported')
    start=int.from_bytes(original[0x54:0x5a],'big');end=int.from_bytes(original[0x5a:0x60],'big')
    require(start==90000 and (end-start)%3003==0,'Unexpected movie clock/frame rate')
    frames=(end-start)//3003
    original_aus,_,_,_=indexed_layout(original)
    force='expr:'+'+'.join('eq(n,%d)'%i for i,(_,idr) in enumerate(original_aus) if idr)
    raw=work/(target.stem+'.h264');log=work/(target.stem+'.ffmpeg.log')
    command=[str(ffmpeg),'-nostdin','-y','-v','warning','-i',str(source),'-an',
             '-vf','fps=30000/1001,scale=480:240:flags=lanczos,pad=480:272:0:16,tpad=stop_mode=clone:stop_duration=1',
             '-frames:v',str(frames),'-c:v','libx264','-threads','1','-profile:v','main','-level:v','2.1',
             '-pix_fmt','yuv420p','-b:v','800k','-maxrate','2000k','-bufsize','2000k',
             '-forced-idr','1','-force_key_frames',force,
             '-x264-params','bframes=0:cabac=1:aud=1:keyint=59:min-keyint=1:scenecut=0:ref=1:repeat-headers=1:nal-hrd=vbr',
             '-f','h264',str(raw)]
    with log.open('wb') as f:result=subprocess.run(command,stdout=f,stderr=f)
    require(result.returncode==0,'Video conversion failed; inspect '+str(log))
    payload,stats=mux(original,raw.read_bytes())
    target.write_bytes(payload)
    report=dict(status='converted_pending_PSP_decoder_test',pc_source_sha256=sha256_file(source),
                psp_original_sha256=hashlib.sha256(original).hexdigest(),output_sha256=sha256_file(target),
                frame_clock=3003,start_clock=start,end_clock=end,converter_version=2,
                video_profile='Main 2.1; CABAC; 480x272; 30000/1001; no B frames; one reference; native AU indexes',
                **stats)
    target.with_suffix('.build.json').write_text(json.dumps(report,indent=2)+'\n')
    return report
