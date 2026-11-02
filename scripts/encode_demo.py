"""Turn recorded frames and narration into docs/demo/demo.mp4 (with sound) and demo.gif (silent).

    python scripts/encode_demo.py <frames-folder> <output-folder> <path-to-ffmpeg>
"""
import json, os, subprocess, sys

FRAMES, OUT, FFMPEG = sys.argv[1:4]
frames = json.load(open(os.path.join(FRAMES, "frames.json")))
listing = os.path.join(FRAMES, "list.txt")
with open(listing, "w") as f:
    for (path, start), (_, end) in zip(frames, frames[1:]):
        f.write(f"file '{path}'\nduration {end - start:.3f}\n")
    f.write(f"file '{frames[-1][0]}'\nduration 2.0\nfile '{frames[-1][0]}'\n")
base = [FFMPEG, "-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i", listing]
narration = json.load(open(os.path.join(FRAMES, "narration.json")))
inputs, filters = [], []
for i, line in enumerate(narration):
    inputs += ["-i", line["audio"]]
    delay = round((line["start"] - frames[0][1]) * 1000)
    filters.append(f"[{i + 1}:a]aresample=44100,adelay={delay}:all=1[a{i}]")
mix = "".join(f"[a{i}]" for i in range(len(narration)))
# normalize=0 keeps every line at full volume: lines never overlap, so nothing needs ducking.
audio = ";".join(filters) + f";{mix}amix=inputs={len(narration)}:normalize=0,alimiter=limit=0.95[voice]"
subprocess.run(base + inputs + ["-filter_complex", audio, "-map", "0:v", "-map", "[voice]",
                                "-vf", "scale=trunc(iw/2)*2:trunc(ih/2)*2,fps=15,format=yuv420p", "-color_range", "tv",
                                "-c:v", "libx264", "-crf", "24", "-c:a", "aac", "-b:a", "128k", "-movflags", "+faststart",
                                os.path.join(OUT, "demo.mp4")], check=True)
for fps, width in ((6, 900), (5, 800), (4, 720)):
    gif = os.path.join(OUT, "demo.gif")
    subprocess.run(base + ["-vf", f"fps={fps},scale={width}:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=128:stats_mode=diff[p];[b][p]paletteuse=dither=bayer:bayer_scale=4:diff_mode=rectangle", gif], check=True)
    size = os.path.getsize(gif) / 1e6
    print(f"gif {fps}fps {width}px: {size:.1f} MB")
    if size < 10:  # GitHub shows larger GIFs poorly, and they slow the page
        break
print(f"mp4: {os.path.getsize(os.path.join(OUT, 'demo.mp4')) / 1e6:.1f} MB")
