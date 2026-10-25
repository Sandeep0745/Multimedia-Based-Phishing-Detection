# Multimedia-Based Phishing Detection

Offline Python toolkit that finds phishing signals hidden in **images**, **QR codes**, **screenshots**, and **ad creatives**. It extracts text (Tesseract OCR) and QR payloads (OpenCV), then scores URLs and wording for lookalikes, urgency language, and other phishing cues.

**This project only analyzes files you provide on your machine.** It does not fetch URLs, send messages, or contact targets.

## Features

- Image ingest: JPG, PNG, BMP, WebP, TIFF, GIF; animated GIF / WebP and multi-page TIFF are read frame by frame
  (up to 8 distinct frames, analysed together as one message)
- OpenCV preprocessing: bilateral denoise, CLAHE, thresholding, deskew (both directions), perspective warp,
  rotation recovery (30°, 90°, 180°)
- Tesseract OCR with multi-variant selection (most URLs + highest confidence), one Tesseract run per variant,
  a 60 s limit per run and a low-confidence warning
- QR decode via OpenCV (`QRCodeDetector`, plus the ArUco-based detector for codes the classic one misses),
  optional `pyzbar`; damaged codes reported
- OCR-tolerant URL extraction: defanged links (`hxxps://evil[.]com`), line splits, domains without `http://`
for every real TLD (`.in`, `.co.in`, `.online`, `.site`, `.ai`, `bit.ly`, Unicode), Public Suffix List parsing,
links with brackets (`..._(disambiguation)`)
- URL heuristics: typosquatting, brand and short-name impersonation (HDFC, SBI…), Unicode / punycode look-alikes,
odd TLDs, shorteners, IP hosts, `@` tricks, open redirects (`?url=`, also double-encoded), Google Sites / Forms
abuse, cloud-storage pages (S3, Azure Blob), free hosting and dynamic-DNS hosts; hostnames longer than DNS allows
are flagged without slowing the scan
- QR payload rules: Wi-Fi / contact cards treated as harmless, UPI "scan to receive money" scams, `javascript:` payloads
- ML hostname classifier trained on 219k real URLs (PhiUSIIL dataset; raise-only, heuristics always apply);
  the model file is checked against its recorded SHA-256 before loading, and load or version problems are reported
- Blocklist of reported phishing URLs (your own reports + OpenPhish feed); allowlist for domains your organisation trusts
- Trusted top-domain list (Tranco) and free-hosting platform detection
- Text lexicon: urgency, threats, credential harvest, KYC / OTP, payment and reward cues; ignores negated
("never share your OTP"), quoted and awareness-poster wording — but a "call this number" or "send money to
this UPI id" request keeps its full weight even when scammers add "stay safe"
- Unified threat score → **Safe** / **Suspicious** / **High-Risk Phishing**; unreadable files are
**Error**, and images that could not be fully read (QR not decodable, OCR unavailable) are **Inconclusive** (never silently Safe)
- Text and JSON reports with per-rule reasons; CSV / JSONL batch summary; `--redact` masks phone numbers, OTPs,
  e-mail / UPI ids and Wi-Fi passwords
- Batch scanning in worker processes with a per-file time limit, so one hostile file cannot stall or crash a batch
- Exit codes for scripts and CI (`--fail-on suspicious|high-risk`)



## Architecture

```
Image → Frames → Preprocess → OCR + QR → URL extract → URL/Text analysis → Scorer → Report
```

See [docs/architecture.md](docs/architecture.md) for the full diagram and module map, and
[CHANGELOG.md](CHANGELOG.md) for what changed in each version.

## Requirements

- Python **3.10+** (tested on 3.13; the exact lock file needs 3.11+)
- [Tesseract OCR](https://github.com/tesseract-ocr/tesseract) binary (for text-in-image fixtures)



### Install Python packages

```powershell
cd "path\to\Financial Project"
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-lock.txt
```

`requirements-lock.txt` pins the exact versions used for the results below. `requirements.txt` lists compatible
ranges instead, and `requirements-dev.txt` adds the developer tools (pytest-cov, ruff, mypy).

A `.venv` folder only works on the computer that created it. If you copied the project from another PC
and `.venv\Scripts\python.exe` reports "did not find executable", delete the `.venv` folder and run the commands above again.



### Install Tesseract on Windows

```powershell
winget install UB-Mannheim.TesseractOCR
```

If `tesseract` is not on `PATH`, set:

```powershell
$env:TESSERACT_CMD = "C:\Program Files\Tesseract-OCR\tesseract.exe"
```

The app also probes that default path automatically.

### Real-world data and ML model

```powershell
# 1. Download PhiUSIIL (UCI), Tranco top sites, and the OpenPhish feed
python -m src.model.download_data

# 2. Train the hostname model (about a minute) -> data/model/url_model.joblib + url_model.meta.json + metrics.json
python -m src.model.train

# 3. Measure on live phishing + unseen legitimate sites -> data/model/realworld_metrics.json
python -m src.model.evaluate_realworld
```

The CLI still works without the model (heuristics only). Re-run step 1 regularly:
the OpenPhish feed changes daily.

`url_model.meta.json` records the model's SHA-256 checksum and the scikit-learn version that saved it. A model
file that no longer matches its checksum is not loaded, and a model saved by another scikit-learn version is
used with a warning; both appear under "Errors / warnings" in the report. A `.joblib` file can run code when it
is loaded, so only use models you trained yourself.

**Current results** (version 1.1, measured 2026-10-25):


| Test                                                                                        | Result                                                           |
| ------------------------------------------------------------------------------------------- | ---------------------------------------------------------------- |
| PhiUSIIL held-out hosts (50,342)                                                            | ROC AUC 0.943; at p≥0.9 precision 99.6%, recall 65.6%            |
| Live OpenPhish phishing, blocklist off (300 URLs fetched 2026-10-09)                        | **72.0% detected** (64.3% with version 1.0)*                     |
| Unseen legitimate sites, Tranco ranks 30,001–31,000 (1,000)                                 | 6.9% false alarms (7.0% with version 1.0)                        |
| Popular sites, Tranco top 30,000 (29,964 trusted domains)                                   | 17 flagged, none High-Risk; 15 of them are URL shorteners (version 1.0: 156 flagged, 120 High-Risk) |
| Red Team images (`data/test_images`, 33)                                                    | 33 / 33 as expected (25 phishing caught, 8 genuine left Safe)    |
| Red Team QR codes (`data/test_qr`, 21) and samples (`data/samples`, 6)                      | 21 / 21 and 6 / 6 as expected                                    |
| Automated tests (`python -m pytest`)                                                        | 253 passed                                                       |

\* The hosting-platform list (`data/config/hosting_platforms.json`) was extended after inspecting this
snapshot, so 72.0% is optimistic, as the brand-list figures were before it. Fetch a fresh feed
(step 1) and run step 3 for an unbiased figure. Version 1.0 counted the OpenPhish rate on the same
snapshot, so the 64.3% → 72.0% comparison is like for like.

The model reads only the **hostname**. PhiUSIIL's legitimate URLs are all bare
`https://www.<domain>` homepages, so a model trained on full URLs would learn
"has a path = phishing". Path cues are handled by the heuristic rules.

### Blocklist

Add confirmed phishing URLs (e.g. from phishtank.org) to `data/config/blocklist.txt`,
one per line. A match is scored High-Risk. Never open these URLs in a browser.

### Allowlist

Add domains your organisation trusts to `data/config/allowlist.txt`, one hostname or registrable domain per
line (for example your intranet or university domain). Links there are treated like official brand
domains: the look-alike, keyword and ML rules are skipped, but an exact blocklist match still counts.

## Quick start

```powershell
# Generate local labeled sample images
python data/samples/generate_samples.py

# Analyze one image
python -m src.cli analyze data\samples\phishing_security_alert.png

# JSON report
python -m src.cli analyze data\samples\phishing_qr_lookalike.png --json -o report.json

# Batch a folder (and its sub-folders); one report per image plus a spreadsheet summary
python -m src.cli batch data\samples -o reports --summary reports\summary.csv

# Faster batch: 4 worker processes; mask personal data in every report
python -m src.cli batch data\test_images -o reports --workers 4 --redact

# Acceptance check against labels.json (prints a confusion matrix)
python -m src.cli evaluate data\samples
```

`batch` and `evaluate` run each file in a worker process with a 300 s limit (`--timeout`, `0` = no limit).
A file that takes longer, or that crashes the image libraries, is reported as **Error** and the batch carries on.



### Exit codes

| Code | Meaning |
| ---- | ------- |
| 0 | Finished; with `--fail-on`, no file reached that level |
| 1 | `--fail-on suspicious` / `high-risk`: a file was classified at that level or higher (`suspicious` also counts Inconclusive); `evaluate`: a label did not match |
| 2 | A file could not be analysed, or bad input (missing folder, no images); takes precedence over 1 |

```powershell
python -m src.cli batch .\inbox --fail-on suspicious --summary results.csv
if ($LASTEXITCODE -ne 0) { Write-Host "Review the flagged files" }
```



### Expected sample labels


| File                          | Expected                |
| ----------------------------- | ----------------------- |
| `benign_microsoft_notice.png` | Safe                    |
| `phishing_security_alert.png` | High-Risk Phishing      |
| `phishing_gift_card_ad.png`   | High-Risk Phishing      |
| `phishing_qr_lookalike.png`   | High-Risk Phishing      |
| `suspicious_shortener_qr.png` | Suspicious or High-Risk |
| `blank_no_content.png`        | Safe (`no_indicators`)  |




## Red Team vs Blue Team exercise

**Red Team (attacker)** generates phishing samples with known answers (`labels.json`):

```powershell
python make_test_qr.py        # 21 QR codes  -> data/test_qr/     (typosquat, @ trick, IP, shortener, punycode,
                              #   no http://, free hosting, open redirect, Google Sites, SMS/javascript payloads, safe Wi-Fi/vCard/UPI)
python make_test_images.py    # 33 images    -> data/test_images/ (SMS, WhatsApp, e-mail, fake login pages, ads,
                              #   QR posters, social posts, evasion: rotated / low-res / photo / dark mode / defanged)
```

Both scripts write next to themselves, whichever folder you run them from.
Add your own attacks to the `tests` dictionary in `make_test_qr.py` or to `build()` in `make_test_images.py`,
e.g. a new reported URL from PhishTank (copy it as text, never open it).

**Blue Team (defender)** scans, explains and scores:

```powershell
python -m src.cli batch data/test_images          # verdict + reasons for every image
python -m src.cli evaluate data/test_images       # PASS/FAIL against the Red Team's labels.json
python -m src.cli evaluate data/test_qr
```

Anything that gets through is answered by adding the URL to `data/config/blocklist.txt`, the brand to
`data/config/brands.json` or the scam wording to `data/config/keywords.json`, then re-scanning.
Rule weights are in `data/config/scoring.json` (`url_rules`, `text_rules`, `qr_rules`).

Current result: **33 / 33** images and **21 / 21** QR codes classified as expected (25 + 15 attacks caught,
8 + 6 genuine samples left Safe). Detection used for this includes sender e-mail domains, a brand named in the
text whose links go elsewhere, job / investment / loan / crypto / "new number" scam wording, UPI money
requests, callback numbers and login-form screens.

## Tests

```powershell
python data/samples/generate_samples.py
python -m pytest -q
```

OCR-dependent tests skip automatically when Tesseract (or the Arial font they use) is not installed; without
Tesseract, images with a harmless QR code are expected to be Inconclusive rather than Safe. QR and URL/text unit
tests do not need Tesseract.

Developer checks (after `pip install -r requirements-dev.txt`):

```powershell
python -m pytest --cov=src     # tests with a coverage report
ruff check .                   # lint
mypy                           # type check (settings in pyproject.toml)
```

`.github/workflows/ci.yml` runs the same checks on Windows (with Tesseract) and Linux (without) when the
project is pushed to GitHub.

## Project layout

```
src/
  cli.py
  core/           # config, models, pipeline, batch (worker processes, time limits)
  extraction/     # preprocess, ocr, qr, urls
  analysis/       # url_analysis, text_analysis
  classification/ # threat scorer
  model/          # optional URL classifier, data download, real-world evaluation
  reporting/      # text / JSON / CSV reports, redaction
data/
  config/         # brands, TLDs, keywords, scoring weights, blocklist, allowlist, hosting platforms
  model/          # trained model (+ checksum record) and metrics
  datasets/       # downloaded training / evaluation data
  samples/        # fixture generator
  test_images/, test_qr/   # Red Team sets with labels.json
tests/
docs/
requirements.txt, requirements-lock.txt, requirements-dev.txt
pyproject.toml    # pytest, coverage, ruff and mypy settings
README.md, CHANGELOG.md
```



## Safety notes

- Analysis is **lexical / structural only** — destinations are never fetched (avoids SSRF and accidental contact with phishing hosts).
- Sample images contain **fake lookalike hosts and warning text** for local verification only. Do not distribute them as real lures.
- Reports contain the text read from each image, which for real screenshots can include OTPs, phone numbers or
  private messages. Use `--redact` when reports are shared, and store them like the original screenshots.
- Only load ML model files you trained yourself (see "Real-world data and ML model").
- Do not use this repository to craft or deliver phishing against people.

## Troubleshooting

| Symptom | Fix |
| ------- | --- |
| `did not find executable at 'C:\Users\...\python.exe'` | The `.venv` was created on another computer. Delete `.venv` and recreate it (see "Install Python packages"). |
| `Tesseract OCR binary not found` and results are Inconclusive | Install Tesseract or set `TESSERACT_CMD`. Without OCR the text in an image is not checked, so harmless-looking images are never reported as Safe. |
| `pyzbar` cannot load `libzbar-64.dll` | Optional. On Windows it needs the Microsoft Visual C++ 2013 Redistributable (x64). OpenCV (classic and ArUco detectors) decodes QR codes without it. |
| "ML model was saved by another scikit-learn version" | Run `python -m src.model.train`, or install `requirements-lock.txt`. |
| A file is reported as "Timed out after 300 s" | Raise `--timeout`, or check the file: legitimate screenshots normally finish in a few seconds. |



## License

Educational / portfolio use. No warranty.
