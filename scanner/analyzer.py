import os
import re
import json
import hashlib
import time
from collections import defaultdict
# Add YARA import
try:
    import yara
except ImportError:
    yara = None

# Helper: Calculate Shannon entropy for a string
def shannon_entropy(data):
    if not data:
        return 0.0
    import math
    entropy = 0
    length = len(data)
    for x in set(data):
        p_x = float(data.count(x)) / length
        entropy -= p_x * math.log2(p_x)
    return entropy

# Patterns for credentials, keys, suspicious files, etc.
CREDENTIAL_PATTERNS = [
    re.compile(rb'(password|passwd|pwd|secret|token)[\s:=\"]+([\w\d!@#$%^&*()_+\-=\[\]{};:\'\",.<>/?]+)', re.IGNORECASE),
    re.compile(rb'(user(name)?|login)[\s:=\"]+([\w\d!@#$%^&*()_+\-=\[\]{};:\'\",.<>/?]+)', re.IGNORECASE),
]
KEY_PATTERNS = [
    re.compile(rb'-----BEGIN (RSA|DSA|EC|OPENSSH|PRIVATE|CERTIFICATE)[ -]+KEY-----'),
    re.compile(rb'AKIA[0-9A-Z]{16}'),  # AWS Access Key
    re.compile(rb'sk_live_[0-9a-zA-Z]{24,}'),  # Stripe
    re.compile(rb'AIza[0-9A-Za-z\-_]{35}'),  # Google API
]
SUSPICIOUS_EXTENSIONS = [
    '.sh', '.py', '.pl', '.php', '.cgi', '.js', '.exe', '.bin', '.so', '.dll', '.bat', '.cmd', '.scr', '.ps1', '.vbs', '.jar', '.class', '.apk', '.elf'
]
SUSPICIOUS_FILENAMES = [
    'shadow', 'passwd', 'id_rsa', 'id_dsa', 'authorized_keys', 'known_hosts', 'config', 'wp-config.php', 'settings.py', 'secrets', 'credentials', 'key', 'token', 'private', 'ssl', 'cert', 'pem', 'crt', 'ovpn', 'vpn', 'db', 'database', 'sqlite', 'my.cnf', 'php.ini', 'web.xml', 'docker-compose.yml', 'dockerfile', 'init', 'startup', 'boot', 'rc.local', 'systemd', 'service', 'firewall', 'iptables', 'sudoers', 'cron', 'crontab', 'log', 'debug', 'error', 'dump', 'core', 'backup', 'bak', 'old', 'tmp', 'test', 'sample', 'example'
]
# Patterns for JWT, API keys, etc.
STATIC_PATTERNS = [
    re.compile(rb'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}'),  # JWT
    re.compile(rb'AIza[0-9A-Za-z\-_]{35}'),  # Google API
    re.compile(rb'xox[baprs]-([0-9a-zA-Z]{10,48})'),  # Slack
]

# Helper: File type detection (text/binary)
def is_text_file(filepath, blocksize=512):
    try:
        with open(filepath, 'rb') as f:
            chunk = f.read(blocksize)
            if b'\0' in chunk:
                return False
            # Heuristic: mostly printable
            text_chars = bytearray({7,8,9,10,12,13,27} | set(range(0x20, 0x100)))
            return all(c in text_chars for c in chunk)
    except Exception:
        return False

def run_analysis(extracted_path, output_dir, verbose=False):
    """
    Recursively scan all files in extracted_path, apply static analysis rules, save results as analysis_results.json in output_dir, and return results as dict.
    """
    results = {
        'findings': [],
        'stats': defaultdict(int),
        'metadata': {
            'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'tool_version': 'UnboxFW-Analyzer-1.0',
            'extracted_path': extracted_path,
        }
    }
    # --- YARA rule loading ---
    yara_ruleset = None
    yara_errors = []
    if yara is not None:
        yara_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'yara_rules')
        rule_files = []
        if os.path.isdir(yara_dir):
            for fname in os.listdir(yara_dir):
                if fname.endswith('.yar') or fname.endswith('.yara'):
                    rule_files.append(os.path.join(yara_dir, fname))
        if rule_files:
            try:
                # Build a dict for yara.compile
                sources = {os.path.basename(f): f for f in rule_files}
                yara_ruleset = yara.compile(filepaths=sources)
            except Exception as e:
                yara_errors.append(f"YARA compile error: {e}")
                if verbose:
                    print(f"[!] YARA compile error: {e}")
        else:
            if verbose:
                print("[!] No YARA rules found in yara_rules/ directory.")
    else:
        if verbose:
            print("[!] YARA Python module not installed. Skipping YARA scan.")
    for root, dirs, files in os.walk(extracted_path):
        for fname in files:
            fpath = os.path.join(root, fname)
            relpath = os.path.relpath(fpath, extracted_path)
            finding = {'file': relpath, 'matches': [], 'suspicious': False, 'entropy': None, 'size': None}
            try:
                size = os.path.getsize(fpath)
                finding['size'] = size
                # Check suspicious extension/filename
                ext = os.path.splitext(fname)[1].lower()
                if ext in SUSPICIOUS_EXTENSIONS or any(x in fname.lower() for x in SUSPICIOUS_FILENAMES):
                    finding['suspicious'] = True
                    results['stats']['suspicious_files'] += 1
                # Read file (sample if large)
                if size > 2 * 1024 * 1024:  # >2MB, sample first 128KB
                    with open(fpath, 'rb') as f:
                        data = f.read(128 * 1024)
                else:
                    with open(fpath, 'rb') as f:
                        data = f.read()
                # Entropy analysis
                entropy = shannon_entropy(data.decode('latin1', errors='ignore'))
                finding['entropy'] = entropy
                if entropy > 4.5:
                    results['stats']['high_entropy_files'] += 1
                # Credential patterns
                for pat in CREDENTIAL_PATTERNS:
                    for m in pat.finditer(data):
                        results['stats']['credentials'] += 1
                        finding['matches'].append({'type': 'credential', 'match': m.group(0).decode('latin1', errors='ignore')})
                # Key patterns
                for pat in KEY_PATTERNS:
                    for m in pat.finditer(data):
                        results['stats']['keys'] += 1
                        finding['matches'].append({'type': 'key', 'match': m.group(0).decode('latin1', errors='ignore')})
                # Static patterns
                for pat in STATIC_PATTERNS:
                    for m in pat.finditer(data):
                        results['stats']['static_pattern'] += 1
                        finding['matches'].append({'type': 'static_pattern', 'match': m.group(0).decode('latin1', errors='ignore')})
                # --- YARA scan ---
                if yara_ruleset is not None:
                    try:
                        matches = yara_ruleset.match(data=data)
                        for m in matches:
                            finding['matches'].append({
                                'type': 'yara',
                                'rule': m.rule,
                                'tags': list(m.tags),
                                'meta': dict(m.meta)
                            })
                        if matches:
                            results['stats']['yara_matches'] += len(matches)
                    except Exception as e:
                        if verbose:
                            print(f"[!] YARA scan error in {relpath}: {e}")
                        results['stats']['yara_errors'] += 1
                # If any matches or suspicious, add finding
                if finding['matches'] or finding['suspicious'] or (entropy and entropy > 4.5):
                    results['findings'].append(finding)
                results['stats']['files_scanned'] += 1
            except Exception as e:
                if verbose:
                    print(f"[!] Error analyzing {fpath}: {e}")
                results['stats']['errors'] += 1
    # Save results
    os.makedirs(output_dir, exist_ok=True)
    outpath = os.path.join(output_dir, 'analysis_results.json')
    with open(outpath, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)
    if verbose:
        print(f"[*] Analysis complete. Results saved to {outpath}")
    return results

