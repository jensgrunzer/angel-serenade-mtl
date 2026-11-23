# angel-serenade-mtl
MTL of *Angelic Serenade* using Gemini 4 Hydrogen. If you have access to a better model or know Japanese, feel free to improve this translation.

### Installation
Just download the zip from the most recent release, extract its contents into your game folder and overwrite if prompted.

## Translation
`wps_tool.py` supports combinable `tar`-style flags (e.g., `-xg`, `-sqb`, `-isb`). Flags always execute in logical pipeline order regardless of the order you type them.

### Flag Reference
- `-T` / `--test` — Verify 145/145 `.Wps` lossless roundtrip and `Script.pak` CRC-16
- `-x` / `--extract` — Extract `.Wps` scripts → `tl_json/*.json` (skips existing unless `--force`)
- `-g` / `--gather` — Gather `tl_json/*.json` → `ALL_SCRIPTS.json` (+ `ALL_SCRIPTS_MAP.json`)
- `-i` / `--import-token` — Merge token-optimized output (`ALL_SCRIPTS_OUT.json` or part files) into `ALL_SCRIPTS.json`
- `-s` / `--split` — Split `ALL_SCRIPTS.json` → `tl_json/*.json`
- `-t` / `--split-token` — Split token-optimized output (`[g, "en"]`, `{"g":..,"en":..}`, `{"0":".."}`, JSONL, or truncated JSON) directly → `tl_json/*.json`
- `-q` / `--qc` — Run QC checks without packing (writes `qc_report.txt`; checks files in-memory if passed standalone)
- `-b` / `--build` — Compile modified `.Wps` files and pack `Script.pak` (auto-backs up `Script.pak.orig`)

### Workflow
1. Obtain [r2395](https://vndb.org/r2395) from a trusted source of your choice.
2. Edit the game path inside wps_tool.py accordingly.
3. Open `Script.pak` in **GARbro** and extract all `.Wps` files into `<game_dir>\Script\`.
4. Place `wps_tool.py` in `<game_dir>`, then extract and gather everything into `ALL_SCRIPTS.json`:
   ```powershell
   py wps_tool.py -xg
   ```
5. Translate `ALL_SCRIPTS.json` (manually or with an LLM), QC it without packing, then split and build `Script.pak`:
   ```powershell
   py wps_tool.py -q ALL_SCRIPTS.json
   py wps_tool.py -sb
   ```
6. Lastly you'll have to patch the name input field (otherwise the OK button will be greyed out):
      ```powershell
   py patch_name_entry.py
   ```

### Token-Optimized LLM Output (Optional)
To reduce output tokens, keep `ALL_SCRIPTS.json` as input and ask the LLM to return only `[g, "en"]` pairs:

```text
Translate every "jp" entry in the attached ALL_SCRIPTS.json into natural English.
Return only a JSON array of [g, "en"] pairs (one per line, do NOT repeat "jp" or "f"), e.g.:
[0, "Chirp... chirp-chirp! Birds are singing above the trees. Deep in a dew-drenched forest."]
```

Save the response as `ALL_SCRIPTS_OUT.json` (or multiple part files if split across turns), QC it, and either import it into `ALL_SCRIPTS.json` + build (`-isb`) or split directly + build (`-tb`):

```powershell
py wps_tool.py -q ALL_SCRIPTS_OUT.json
py wps_tool.py -isb ALL_SCRIPTS_OUT.json
```
