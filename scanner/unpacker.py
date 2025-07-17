import os
import subprocess
import shutil
import json
from pathlib import Path


def run_extract(input_firmware_path, output_dir, verbose=False):
    """
    Extracts embedded filesystems from a firmware image using binwalk.
    Args:
        input_firmware_path (str): Path to the firmware image.
        output_dir (str): Directory to extract filesystems and metadata.
        verbose (bool): If True, print detailed output.
    Returns:
        dict: Extraction metadata (offsets, types, sizes, paths).
    """
    def vprint(*args, **kwargs):
        if verbose:
            print(*args, **kwargs)

    # 1. Validate input file
    if not os.path.isfile(input_firmware_path):
        raise FileNotFoundError(f"Input firmware file not found: {input_firmware_path}")
    if not os.access(input_firmware_path, os.R_OK):
        raise PermissionError(f"Input firmware file is not readable: {input_firmware_path}")

    # 2. Create output directory if missing
    os.makedirs(output_dir, exist_ok=True)
    vprint(f"Output directory: {output_dir}")

    # 3. Check binwalk dependency
    if shutil.which("binwalk") is None:
        raise RuntimeError("binwalk is not installed or not in PATH.")

    # 4. Run binwalk -e
    vprint(f"Running binwalk extraction on {input_firmware_path}...")
    binwalk_cmd = [
        "binwalk", "-e", input_firmware_path, "--directory", output_dir
    ]
    try:
        result = subprocess.run(
            binwalk_cmd,
            capture_output=not verbose,
            text=True,
            check=True
        )
        if verbose and result.stdout:
            print(result.stdout)
        if verbose and result.stderr:
            print(result.stderr)
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Binwalk extraction failed: {e.stderr or e}")

    # 5. Parse binwalk results
    # Binwalk creates a _<firmware> directory in output_dir
    firmware_name = os.path.basename(input_firmware_path)
    extract_root = os.path.join(output_dir, f"_{firmware_name}.extracted")
    if not os.path.isdir(extract_root):
        # Try without .extracted suffix (older binwalk)
        extract_root = os.path.join(output_dir, f"_{firmware_name}")
    if not os.path.isdir(extract_root):
        raise RuntimeError(f"Binwalk did not produce an extraction directory: {extract_root}")

    vprint(f"Extraction root: {extract_root}")

    # 6. Identify filesystem roots and collect metadata
    fs_types = ["squashfs", "jffs2", "cramfs", "ext2", "ext3", "ext4"]
    metadata = {"filesystems": [], "archives": [], "errors": []}
    for root, dirs, files in os.walk(extract_root):
        for fname in files:
            fpath = os.path.join(root, fname)
            # Identify by extension or magic bytes
            ext = os.path.splitext(fname)[1].lower()
            if any(fs in fname.lower() for fs in fs_types):
                # Try to get offset from filename (binwalk format: <offset>-<type>.bin)
                offset = None
                try:
                    offset = int(fname.split("-", 1)[0])
                except Exception:
                    pass
                size = os.path.getsize(fpath)
                metadata["filesystems"].append({
                    "path": fpath,
                    "type": next((fs for fs in fs_types if fs in fname.lower()), "unknown"),
                    "offset": offset,
                    "size": size
                })
            elif ext in [".tar", ".gz", ".tgz", ".zip"]:
                metadata["archives"].append({
                    "path": fpath,
                    "type": ext.lstrip("."),
                    "size": os.path.getsize(fpath)
                })

    # 7. Handle nested archives (extract .tar.gz, .zip, etc.)
    def is_within_directory(base_dir, target_path):
        base_dir = os.path.realpath(base_dir)
        target_path = os.path.realpath(target_path)
        return os.path.commonpath([base_dir]) == os.path.commonpath([base_dir, target_path])

    def extract_nested_archives(archive_path, out_dir, depth=1, MAX_DEPTH=2):
        if depth > MAX_DEPTH:
            msg = f"Extraction depth exceeded for {archive_path}: max depth {MAX_DEPTH}"
            vprint(msg)
            metadata["errors"].append(msg)
            raise Exception(msg)
        MAX_FILES = 5000
        MAX_SIZE = 500 * 1024 * 1024  # 500MB
        if archive_path.endswith(('.tar.gz', '.tgz', '.tar')):
            import tarfile
            try:
                with tarfile.open(archive_path, 'r:*') as tar:
                    members = tar.getmembers()
                    if len(members) > MAX_FILES:
                        msg = f"Archive bomb detected: exceeds safe extraction limits (file count > {MAX_FILES}) in {archive_path}"
                        vprint(msg)
                        metadata["errors"].append(msg)
                        raise Exception(msg)
                    total_size = sum(m.size for m in members)
                    if total_size > MAX_SIZE:
                        msg = f"Archive bomb detected: exceeds safe extraction limits (total size > 500MB) in {archive_path}"
                        vprint(msg)
                        metadata["errors"].append(msg)
                        raise Exception(msg)
                    for member in members:
                        member_path = os.path.join(out_dir, member.name)
                        if not is_within_directory(out_dir, member_path):
                            msg = f"Blocked path traversal attempt in tar archive: {member.name} -> {member_path}"
                            vprint(msg)
                            metadata["errors"].append(msg)
                            raise Exception(msg)
                    tar.extractall(path=out_dir)
                    vprint(f"Extracted nested archive: {archive_path}")
            except Exception as e:
                metadata["errors"].append(f"Failed to extract {archive_path}: {e}")
        elif archive_path.endswith('.zip'):
            import zipfile
            try:
                with zipfile.ZipFile(archive_path, 'r') as zipf:
                    names = zipf.namelist()
                    if len(names) > MAX_FILES:
                        msg = f"Archive bomb detected: exceeds safe extraction limits (file count > {MAX_FILES}) in {archive_path}"
                        vprint(msg)
                        metadata["errors"].append(msg)
                        raise Exception(msg)
                    total_size = sum(zinfo.file_size for zinfo in zipf.infolist())
                    if total_size > MAX_SIZE:
                        msg = f"Archive bomb detected: exceeds safe extraction limits (total size > 500MB) in {archive_path}"
                        vprint(msg)
                        metadata["errors"].append(msg)
                        raise Exception(msg)
                    for member in names:
                        member_path = os.path.join(out_dir, member)
                        if not is_within_directory(out_dir, member_path):
                            msg = f"Blocked path traversal attempt in zip archive: {member} -> {member_path}"
                            vprint(msg)
                            metadata["errors"].append(msg)
                            raise Exception(msg)
                    zipf.extractall(path=out_dir)
                    vprint(f"Extracted nested archive: {archive_path}")
            except Exception as e:
                metadata["errors"].append(f"Failed to extract {archive_path}: {e}")

    for archive in metadata["archives"]:
        extract_nested_archives(archive["path"], os.path.dirname(archive["path"]))

    # 8. Write metadata file
    metadata_path = os.path.join(output_dir, "extraction_metadata.json")
    with open(metadata_path, "w") as f:
        json.dump(metadata, f, indent=2)
    vprint(f"Metadata written to {metadata_path}")

    return metadata
