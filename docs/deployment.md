# Running in practice

Installation is covered in [windows_setup.md](windows_setup.md). This page is about using the detector
day to day, keeping its data current, and automating it.

## Day-to-day scanning

Place screenshots or ad images in a folder (sub-folders are included) and run:

```powershell
python -m src.cli batch .\inbox -o .\reports --summary .\reports\summary.csv --workers 4
```

- One report per image under `reports\`, plus `summary.csv` (one row per file; opens in Excel).
- `--workers 4` analyses four files at once; each file has a 300 s limit (`--timeout`).
- Add `--redact` when the reports will be shared: phone numbers, OTPs, e-mail / UPI ids and Wi-Fi passwords
  are masked, scores and verdicts are unchanged.

No server process is required. Reports are static files.

## Using it in scripts or CI

`--fail-on` turns the verdict into an exit code:

```powershell
python -m src.cli batch .\inbox --fail-on suspicious --summary results.csv
if ($LASTEXITCODE -eq 1) { Write-Host "Suspicious or worse found - see results.csv" }
if ($LASTEXITCODE -eq 2) { Write-Host "Some files could not be analysed" }
```

`--fail-on suspicious` also counts **Inconclusive** files, because they were not fully checked.
`--json` prints only JSON on stdout, so the output can be piped into other tools.

## Keeping data current

| Data | Refresh | Command |
| ---- | ------- | ------- |
| OpenPhish blocklist feed | daily to weekly | `python -m src.model.download_data` |
| Tranco top domains, Public Suffix List | monthly | same command |
| ML model | after refreshing PhiUSIIL or changing the training code | `python -m src.model.train` |

After each refresh, `python -m src.model.evaluate_realworld` reports detection and false-alarm rates and a
threshold sweep (`data/model/realworld_metrics.json`). Training rewrites `url_model.meta.json`, the checksum
record the detector verifies before loading the model.

## Tuning

- Rule weights: `data/config/scoring.json` (`url_rules`, `text_rules`, `qr_rules`); bands decide the verdict.
- Brands and their official domains: `data/config/brands.json`.
- Scam wording: `data/config/keywords.json`.
- Trusted domains for your organisation: `data/config/allowlist.txt`.
- Hosting platforms and user-content hosts: `data/config/hosting_platforms.json`.

Re-run `python -m src.cli evaluate data/test_images` and `python -m pytest -q` after a change.

## Linux and macOS

Install Tesseract (`sudo apt-get install tesseract-ocr` or `brew install tesseract`) and optionally ZBar
(`sudo apt-get install libzbar0`) for pyzbar. The OCR tests use the Arial font and are skipped where it is
missing; the Red Team images then use DejaVu Sans.

## Continuous integration

`.github/workflows/ci.yml` lints (ruff), type-checks (mypy) and tests the project on Windows (with Tesseract)
and Ubuntu (without Tesseract, which exercises the Inconclusive paths) on every push.

## Limitations

- OCR quality depends on image resolution and fonts.
- Brand list is finite; novel brands need `data/config/brands.json` updates.
- Shorteners are opaque without network expansion — scored as Suspicious+.
- Pages on free hosting platforms are scored more strictly; a legitimate site hosted there can be flagged.
- PDF and e-mail (.eml / HTML) files are not read; screenshot them or extract their images first.
- Not a replacement for browser Safe Browsing / enterprise email gateways.
