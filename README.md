# UnboxFW

**UnboxFW** is a red-team tool for professional IoT firmware analysis. It provides automated unpacking, static analysis, and reporting capabilities to support embedded system security assessments.

---

##  Features

###  Firmware Unpacking
- Extracts embedded filesystems from firmware images (`.bin`, `.img`) using [binwalk](https://github.com/ReFirmLabs/binwalk).
- Supports common filesystem types:
  - `squashfs`, `jffs2`, `cramfs`, `ext2/3/4`, and more.
- Handles nested archives (e.g., `.tar.gz`, `.zip`) within firmware packages.
- Generates extraction metadata for traceability and deeper analysis.

###  Static Analysis
- Scans extracted filesystems for:
  - Credentials, private keys, API tokens, and other secrets.
  - Suspicious binaries, high-entropy blobs, and misconfigurations.
- Integrates with [YARA](https://github.com/VirusTotal/yara) for:
  - Malware detection
  - Custom signature matching
- Outputs structured findings and summary statistics.

###  Reporting
-- Outputs are CLI-driven and saved in structured JSON format.

---

##  Usage

```
python cli.py --input firmware.bin --extract-only
python cli.py --input firmware.bin --analyze
python cli.py --input firmware.bin --output ./out
python cli.py --input firmware.bin --extract-only --verbose
```

---

##  Requirements

- Python **3.7+**
- [binwalk](https://github.com/ReFirmLabs/binwalk)
- `yara-python`
- `pycryptodome`
- `python-magic`
- See `requirements.txt` for full list
- Some firmware formats (especially `squashfs`, `jffs2`, `cramfs`) may require additional tools to extract properly.

---

## Security Warning
 UnboxFW is intended for **educational and authorized security assessment purposes only**. Use it **only on firmware you own or have explicit permission to analyze**. This tool extracts and analyzes firmware that may contain: - Malicious binaries, scripts, or embedded malware - High-risk files (e.g. hardcoded credentials, private keys, backdoors) - Payloads that may trigger antivirus or endpoint protection tools Always analyze firmware in a **sandboxed or isolated environment** (e.g., virtual machine or container). Do **not** execute or interact with extracted files unless you understand the risks. The developers of UnboxFW are **not responsible for any misuse, damage, or legal consequences** resulting from this tool. Use responsibly. Stay within the law.

--- 

##  License

This project is licensed under the **MIT License**. See the `LICENSE` file for details.
