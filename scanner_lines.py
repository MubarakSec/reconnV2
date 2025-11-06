from pathlib import Path
lines = Path("recon_cli/scanners/integrations.py").read_text(encoding="utf-8").splitlines()
for i, line in enumerate(lines, 1):
    if "WPSCAN_API_TOKEN" in line:
        print(f"{i}: {line}")
    if 'cmd: List[str] = [\"wpscan\"' in line:
        print(f"{i}: {line}")
    if 'cmd: List[str] = [\"nuclei\"' in line:
        print(f"{i}: {line}")
