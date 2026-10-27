<h1 align="center">Trails in the Sky The 3rd: PSP English Patcher</h1>

<p align="center">
    <strong>Bring the English PC localization to the Japanese PSP game using your own copies</strong>
</p>

Ports English dialogue, menus and battle commands, quests and Door entries, item/arts/enemy descriptions, books, minigame text, notebook pages, interface artwork and cinematics from the PC version to PSP.

## 📦 Requirements

- A Japanese PSP ISO of **Eiyuu Densetsu: Sora no Kiseki the 3rd**, **ULJM05353, disc version 1.01**;
- An installed, updated English Windows copy from [GOG](https://www.gog.com/en/game/the_legend_of_heroes_trails_in_the_sky_the_3rd): **build 50438031059769469**, with `ed6_win3.exe` version **1.0.0.2**, built on **2017-08-19**;
- **Python 3.9+**, **Pillow**, **FFmpeg with libx264**, and an installed **Arial or DejaVu Sans** font for generated labels;
- About **5 GB of free space**, in addition to the source games.

## 🛠️ Usage

1. Clone this repository and open a terminal in its root directory;
2. Create a Python environment and install the dependency:

   ```sh
   python3 -m venv .venv
   source .venv/bin/activate
   python -m pip install -r requirements.txt
   ```

   On Windows, use `py -3 -m venv .venv`, then `.venv\Scripts\Activate.ps1` in PowerShell;

3. Make sure FFmpeg is available on `PATH`, then run:

   ```sh
   python patch.py --iso "/path/to/ULJM05353.iso" --pc-dir "/path/to/English PC installation"
   ```

   If needed, add `--ffmpeg "/path/to/ffmpeg"`. Use `--output "/path/to/new.iso"` to choose another destination;

4. Copy `output/Trails in the Sky the 3rd ENG.iso` to the `ISO` directory on your PSP memory stick.

## 📖 About

English text is reflowed for the PSP screen. Interface artwork, notebook pages, title/XMB/save artwork and movies are converted from the PC installation into PSP-compatible formats.

PSP gameplay data and audio are retained (UNDUB).

This repository contains code and numeric conversion recipes: offsets, mappings, coordinates and hashes. It contains no game archives, game executables, translated scripts, images, fonts or movies. Both source games must be supplied separately (by you with your own licensed copies).

## ⚙️ Compatibility

Testing in progress on **PSP-3000, CFW 6.61 ARK-4**.

## 📄 Third-party components and references

- [psp-media-toolkit](https://github.com/TotalKommando/psp-media-toolkit) — adapted Annex-B and timestamp helpers in `patcher/psmf.py`, MIT; the original notice is included in [third-party/pspmedia-LICENSE](third-party/pspmedia-LICENSE);
- [uyjulian's Falcom PSP ISO extractor](https://gist.github.com/uyjulian/b596c978da0c1031047e124eaf5d4f84) — ISO, CCLM and FALCOM3 format/compression reference;
- [Calmare](https://github.com/Aureole-Suite/Calmare) and [Cradle](https://github.com/Aureole-Suite/Cradle) — scenario bytecode and image format references;
- [PPSSPP](https://github.com/hrydgard/ppsspp) — PSP movie/container behavior reference;
- [FFmpeg](https://ffmpeg.org/) with [libx264](https://www.videolan.org/developers/x264.html) and [Pillow](https://github.com/python-pillow/Pillow) — local video and image conversion.

The patcher's original code is provided under the [MIT License](LICENSE). Game assets and the English localization remain the property of their respective owners. This is an unofficial project, unaffiliated with Nihon Falcom or XSEED Games.
