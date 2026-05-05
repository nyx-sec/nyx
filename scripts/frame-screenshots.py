#!/usr/bin/env python3
"""Frame Nyx screenshots with the brand mint-led four-corner gradient.

Reads a list of PNG paths from argv (or all PNGs under
assets/screenshots/ if no args) and overwrites each with a framed
version: inner screenshot with rounded corners, centered on a
four-corner mint-led gradient (TL #72f3d7, TR #ff6aa2,
BL #f8c56b, BR #4cc9ff).

Two framing modes:
  - default          inner is resampled to 1600x992, outer is 1800x1113.
                     Used for serve-* PNGs whose source is 1440x900.
  - --natural        inner is kept at its native size, outer grows to
                     match (inner + 100/60/100/61 padding). Used for
                     CLI captures whose height varies per command.

Usage:
    python3 scripts/frame-screenshots.py path/to/foo.png ...
    python3 scripts/frame-screenshots.py --natural path/to/cli.png ...
    python3 scripts/frame-screenshots.py            # frames the default set

Framing is not idempotent — re-framing an already-framed image will
re-pad it, so callers are expected to keep raw captures separately or
re-capture before re-framing.
"""
from __future__ import annotations

import sys
from pathlib import Path

from PIL import Image, ImageDraw

# Frame geometry (matches existing docs/serve-*.png files).
OUTER_W, OUTER_H = 1800, 1113
PAD_L, PAD_T = 100, 60
INNER_W, INNER_H = 1600, 992
PAD_R = OUTER_W - INNER_W - PAD_L  # 100
PAD_B = OUTER_H - INNER_H - PAD_T  # 61
CORNER_RADIUS = 12

# Four-corner bilinear gradient. The primary brand accent anchors the
# frame, with distinct warm/cool corners for richer screenshot depth.
GRAD_TL = (114, 243, 215)  # #72f3d7
GRAD_TR = (255, 106, 162)  # #ff6aa2
GRAD_BL = (248, 197, 107)  # #f8c56b
GRAD_BR = ( 76, 201, 255)  # #4cc9ff


def make_gradient(w: int, h: int) -> Image.Image:
    """Bilinear gradient between the four GRAD_* corners.

    Implemented row-by-row with PIL's linear-interpolation paste so a
    1800x1113 canvas builds in a few hundred ms (vs ~10s for a pure-
    Python pixel loop).
    """
    # Top edge: TL → TR
    top_row = Image.new("RGB", (w, 1))
    top_pixels = top_row.load()
    for x in range(w):
        t = x / (w - 1) if w > 1 else 0.0
        top_pixels[x, 0] = (
            int(GRAD_TL[0] + (GRAD_TR[0] - GRAD_TL[0]) * t),
            int(GRAD_TL[1] + (GRAD_TR[1] - GRAD_TL[1]) * t),
            int(GRAD_TL[2] + (GRAD_TR[2] - GRAD_TL[2]) * t),
        )
    # Bottom edge: BL → BR
    bot_row = Image.new("RGB", (w, 1))
    bot_pixels = bot_row.load()
    for x in range(w):
        t = x / (w - 1) if w > 1 else 0.0
        bot_pixels[x, 0] = (
            int(GRAD_BL[0] + (GRAD_BR[0] - GRAD_BL[0]) * t),
            int(GRAD_BL[1] + (GRAD_BR[1] - GRAD_BL[1]) * t),
            int(GRAD_BL[2] + (GRAD_BR[2] - GRAD_BL[2]) * t),
        )
    # Vertically blend top row → bottom row across each column.
    out = Image.new("RGB", (w, h))
    for y in range(h):
        t = y / (h - 1) if h > 1 else 0.0
        # Per-row blend of the two edge images.
        row = Image.blend(top_row, bot_row, t)
        out.paste(row, (0, y))
    return out


def round_corners(img: Image.Image, radius: int) -> Image.Image:
    """Apply rounded corners to img by masking alpha."""
    mask = Image.new("L", img.size, 0)
    ImageDraw.Draw(mask).rounded_rectangle(
        (0, 0, img.size[0], img.size[1]), radius=radius, fill=255
    )
    out = img.convert("RGBA")
    out.putalpha(mask)
    return out


def compose_frame(inner_rgb: Image.Image, gradient_bg: Image.Image) -> Image.Image:
    """Resize an RGB frame to the inner target and paste it onto the
    pre-rendered gradient with rounded corners. Returns an RGB image
    of OUTER_W x OUTER_H."""
    inner = inner_rgb
    if inner.size != (INNER_W, INNER_H):
        inner = inner.resize((INNER_W, INNER_H), Image.LANCZOS)
    inner_rounded = round_corners(inner, CORNER_RADIUS)
    canvas = gradient_bg.copy()
    canvas.paste(inner_rounded, (PAD_L, PAD_T), inner_rounded)
    return canvas.convert("RGB")


def compose_frame_natural(inner_rgb: Image.Image) -> Image.Image:
    """Frame an inner image at its native size with the same per-edge
    padding as the fixed-size frame (100/60/100/61). Used for CLI
    captures whose height varies per command — short ones stay short,
    long ones stay long, and nothing gets resampled."""
    inner_w, inner_h = inner_rgb.size
    outer_w = inner_w + PAD_L + PAD_R
    outer_h = inner_h + PAD_T + PAD_B
    bg = make_gradient(outer_w, outer_h).convert("RGBA")
    inner_rounded = round_corners(inner_rgb, CORNER_RADIUS)
    bg.paste(inner_rounded, (PAD_L, PAD_T), inner_rounded)
    return bg.convert("RGB")


def frame_one(src: Path, natural: bool = False) -> None:
    inner = Image.open(src).convert("RGB")
    if natural:
        out = compose_frame_natural(inner)
    else:
        bg = make_gradient(OUTER_W, OUTER_H).convert("RGBA")
        out = compose_frame(inner, bg)
    out.save(src, "PNG", optimize=True)
    print(f"framed: {src}", file=sys.stderr)


def frame_gif(src: Path) -> None:
    """Frame an animated GIF in place: every frame gets the same
    mint-cyan gradient frame, then the result is re-encoded as a single-
    palette GIF.  Calls ffmpeg for the final encode (Pillow's GIF
    output is noticeably worse for large animations).
    """
    import subprocess
    import tempfile
    from PIL import ImageSequence

    src_img = Image.open(src)
    bg = make_gradient(OUTER_W, OUTER_H).convert("RGBA")

    durations: list[int] = []
    with tempfile.TemporaryDirectory(prefix="nyx-gif-frames-") as tmp:
        tmp_path = Path(tmp)
        for i, frame in enumerate(ImageSequence.Iterator(src_img)):
            rgb = frame.convert("RGB")
            composed = compose_frame(rgb, bg)
            composed.save(tmp_path / f"{i:05d}.png", "PNG")
            durations.append(int(frame.info.get("duration", 67)))
        if not durations:
            print(f"no frames in {src}", file=sys.stderr)
            return

        avg_ms = sum(durations) / len(durations)
        fps = max(1, round(1000.0 / avg_ms))
        palette = tmp_path / "palette.png"

        # palette pass
        subprocess.run(
            [
                "ffmpeg", "-y",
                "-framerate", str(fps),
                "-i", str(tmp_path / "%05d.png"),
                "-vf", "palettegen=stats_mode=diff",
                str(palette),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # encode
        subprocess.run(
            [
                "ffmpeg", "-y",
                "-framerate", str(fps),
                "-i", str(tmp_path / "%05d.png"),
                "-i", str(palette),
                "-lavfi", "paletteuse=dither=bayer:bayer_scale=5:diff_mode=rectangle",
                "-loop", "0",
                str(src),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    print(f"framed gif: {src}", file=sys.stderr)


def main(argv: list[str]) -> int:
    natural = False
    if argv and argv[0] == "--natural":
        natural = True
        argv = argv[1:]
    if not argv:
        # No args: walk the default location.
        root = Path(__file__).resolve().parent.parent / "assets" / "screenshots"
        paths = sorted(p for p in root.rglob("*.png"))
    else:
        paths = [Path(p) for p in argv]
    if not paths:
        print("no PNGs to frame", file=sys.stderr)
        return 1
    for p in paths:
        if not p.is_file():
            print(f"skip (not a file): {p}", file=sys.stderr)
            continue
        if p.suffix.lower() == ".gif":
            frame_gif(p)
        else:
            frame_one(p, natural=natural)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
