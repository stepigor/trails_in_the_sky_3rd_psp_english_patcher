#!/usr/bin/env python3
"""Build an English PSP image from the user's Japanese PSP and English PC copies."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys

sys.dont_write_bytecode = True
RUNTIME = Path(__file__).resolve().parent / 'patcher'
sys.path.insert(0, str(RUNTIME))

from formats import FormatError, Iso9660, require, sha256_file
from builder import BASE_HASH, build
from finish_xmb import finish
from movies import MOVIES, convert


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--iso', type=Path, required=True, help='Original Japanese ULJM05353 v1.01 ISO')
    parser.add_argument('--pc-dir', type=Path, required=True, help='Supported English GOG installation directory')
    parser.add_argument('--output', type=Path, default=Path('output/Trails in the Sky the 3rd ENG.iso'), help='New output ISO (default: output/Trails in the Sky the 3rd ENG.iso)')
    parser.add_argument('--work-dir', type=Path, default=Path('work'), help='Local conversion cache (default: work)')
    parser.add_argument('--ffmpeg', default='ffmpeg', help='FFmpeg executable or path (default: ffmpeg on PATH)')
    args = parser.parse_args()

    try:
        try:
            import PIL
        except ImportError:
            raise FormatError('Pillow is required: python -m pip install -r requirements.txt')
        executable = shutil.which(args.ffmpeg)
        if executable is None and Path(args.ffmpeg).is_file():
            executable = str(Path(args.ffmpeg).resolve())
        require(executable is not None, 'FFmpeg was not found; install it or use --ffmpeg /path/to/ffmpeg')
        require(not args.output.exists(), 'Output already exists; choose a new --output path')
        require(not args.output.resolve().is_relative_to(args.pc_dir.resolve()), 'Keep the output ISO outside the PC installation')

        recipes = RUNTIME / 'recipes'
        require(sha256_file(args.iso) == BASE_HASH, 'Unsupported PSP ISO: expected Japanese ULJM05353 v1.01 with the SHA-256 in README.MD')
        for name, expected in json.loads((recipes / 'pc-inputs.json').read_text()).items():
            path = args.pc_dir / name
            require(path.is_file(), 'Required PC file is missing: ' + str(path))
            require(sha256_file(path) == expected, 'Unsupported PC file version: ' + name + '; see the supported GOG build in README.MD')

        args.work_dir.mkdir(parents=True, exist_ok=True)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        iso = Iso9660(args.iso)
        for name, source in MOVIES.items():
            target = args.work_dir / (name + '.pmf')
            metadata = target.with_suffix('.build.json')
            original = iso.get('PSP_GAME/USRDIR/data_3rd/movie/' + name + '.pmf')
            if target.exists() and metadata.exists():
                cached = json.loads(metadata.read_text())
                if (cached.get('converter_version') == 2
                        and cached['pc_source_sha256'] == sha256_file(args.pc_dir / source)
                        and cached['psp_original_sha256'] == hashlib.sha256(original).hexdigest()
                        and cached['output_sha256'] == sha256_file(target)):
                    print('Verified cached movie: ' + name, flush=True)
                    continue
            print('Converting movie: ' + name, flush=True)
            convert(original, args.pc_dir / source, Path(executable), args.work_dir, target)

        build(args.iso, args.pc_dir, args.output, recipes, args.work_dir)
        print('Finalizing XMB and save artwork', flush=True)
        result = finish(args.output, args.pc_dir, recipes)
        print('Created: ' + str(args.output.resolve()))
        print('SHA-256: ' + result['output_sha256'])
    except (FormatError, OSError, ValueError) as error:
        parser.exit(1, 'Error: ' + str(error) + '\n')


if __name__ == '__main__':
    main()
