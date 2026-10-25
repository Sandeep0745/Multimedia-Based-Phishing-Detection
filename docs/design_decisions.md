# Design decisions

## Offline-only URL analysis

Fetching submitted URLs would create an SSRF surface and could contact live phishing infrastructure from the analyst machine. Structure, brands, and lexicon are enough for a local lab detector.

## Public Suffix List kept offline, no `tldextract`

`tldextract` often pulls a public-suffix list at runtime. The project ships the Public Suffix List
(`data/config/public_suffix_list.dat`, refreshed by `python -m src.model.download_data`) and parses its ICANN
section itself, so the tool stays air-gappable. Without the file a small built-in suffix table is used.

## OpenCV QR primary, pyzbar optional

`cv2.QRCodeDetector` has no extra native DLL on Windows. Some clean codes defeat it (for example a
`javascript:` payload in the Red Team set), so when it finds nothing the ArUco-based detector, also part of
OpenCV, tries the same images. `pyzbar` needs ZBar binaries (and on Windows the Visual C++ 2013 runtime) and is
only a best-effort extra, so results do not depend on whether it loads.

## Multi-variant OCR selection, one Tesseract run per variant

Screenshots and ads vary in contrast. Running OCR on color, upscaled grayscale, thresholded, deskewed and
warped images, then preferring the variant with the **most recovered URLs** (tie-break: confidence), improves
URL recovery. Each variant runs Tesseract once: the text is rebuilt from `image_to_data` with Tesseract's own
line and paragraph layout, which matched `image_to_string` on all 157 variant images of the test sets while
halving OCR time. Each run is limited to 60 seconds.

## Raise-only ML

The hostname model is trained on real URLs (PhiUSIIL) but can still be wrong, especially on unusual legitimate
names. Heuristics remain authoritative; the model may only add score, never suppress a lookalike or shortener hit.

## Model file integrity

A `.joblib` model is a pickle and can run code when loaded. Training records the file's SHA-256 and library
versions in `url_model.meta.json`; a file that does not match is not loaded. This guards against a swapped or
corrupted model, not against someone who can rewrite both files, so only self-trained models should be used.
Load failures and scikit-learn version mismatches are reported in the results instead of being skipped silently.

## Worst-signal elevation

Phishing creatives often mix benign filler with one malicious QR or link. Averaging would hide the threat, so
the final score is the strongest component (the configured blend can only matter if its weights sum to more than 1).

## Never silently Safe

An image is only Safe when everything in it was read: unreadable files are Error, and a QR code that cannot be
decoded or text that cannot be read (no Tesseract) makes the result Inconclusive unless other evidence already
shows a risk.

## Brand matching at token boundaries

Short brand names hide inside ordinary words ("purchase" contains "chase"), and big brands own many hostnames
("amazonaws.com", "yahoo.co.jp"). Brand names of five letters or fewer only count at the start of a hostname
token, and popular (Tranco top-list) domains are not checked for brand look-alikes. On the 29,964 trusted
popular domains, flagged sites fell from 156 (120 High-Risk) to 17 (none High-Risk, 15 of them URL shorteners).
The few live phishing URLs that had been caught only through such accidental matches (pages on S3 buckets and
Bluehost sites) are now caught by the user-content and hosting-platform rules instead.

## Worker processes for batches

A per-file time limit cannot interrupt pure-Python work or a native library from inside the same process.
Each file is therefore analysed in a worker process that the parent can stop; a crash in OpenCV or a stuck
OCR run then costs one file, not the batch. Workers use the `spawn` start method, so behaviour is the same on
Windows, macOS and Linux.

## No new runtime dependencies

Version 1.1 added features (animated images, redaction, CSV export, parallel batches) using only packages the
project already required, so an existing environment keeps working after the update.
