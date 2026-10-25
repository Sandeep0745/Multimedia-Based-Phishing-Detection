# Windows setup (step by step)

## 1. Python environment

```powershell
cd "path\to\Financial Project"
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements-lock.txt
```

`requirements-lock.txt` installs the exact versions the published results were produced with (Python 3.11–3.13).
On another Python version use `pip install -r requirements.txt` (compatible ranges).

If the project was copied from another computer, its `.venv` points at that computer's Python and fails with
"did not find executable". Delete the `.venv` folder and repeat this step.

If PowerShell refuses to run `Activate.ps1`, use the Command Prompt (`.venv\Scripts\activate`) or call
`.venv\Scripts\python.exe` directly, as the demonstration script does.

## 2. Tesseract OCR

```powershell
winget install UB-Mannheim.TesseractOCR
```

Verify:

```powershell
& "C:\Program Files\Tesseract-OCR\tesseract.exe" --version
```

Optional, when Tesseract is installed elsewhere:

```powershell
$env:TESSERACT_CMD = "D:\Tools\Tesseract-OCR\tesseract.exe"
```

## 3. Optional: pyzbar QR decoder

OpenCV decodes QR codes on its own. `pyzbar` is an extra decoder; on Windows its DLL needs the
Microsoft Visual C++ 2013 Redistributable (x64). Without it pyzbar is skipped automatically.

## 4. Generate fixtures and check the model

```powershell
python data/samples/generate_samples.py
python -c "from src.core.config import resolve_tesseract_cmd, model_path; print(resolve_tesseract_cmd(), model_path().is_file())"
```

The trained model (`data/model/url_model.joblib`) is optional; train it with `python -m src.model.train`
after `python -m src.model.download_data`.

## 5. Smoke test

```powershell
python -m src.cli evaluate data/samples
python -m src.cli evaluate data/test_qr
python -m pytest -q
```

Expected: 6 / 6 and 21 / 21 passed, and all tests passed.
