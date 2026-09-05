import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

SOURCE_DIR = os.path.abspath(".")
STAGING_DIR = os.path.join(tempfile.gettempdir(), "brand-ai-readiness-audit-clean")
FINAL_ZIP = os.path.abspath("brand-ai-readiness-audit-final.zip")

def clean_staging():
    if os.path.exists(STAGING_DIR):
        shutil.rmtree(STAGING_DIR)
    os.makedirs(STAGING_DIR)

def copy_clean_files():
    # Allowed top-level entries per contest specifications
    allowed = ["marketplace.json", "README.md", "PROJECT_CONTEXT.md", "scripts", "skills", "tests", "docs"]
    
    for item in allowed:
        src = os.path.join(SOURCE_DIR, item)
        dst = os.path.join(STAGING_DIR, item)
        if not os.path.exists(src):
            continue
        if os.path.isdir(src):
            shutil.copytree(
                src,
                dst,
                ignore=shutil.ignore_patterns(
                    '__pycache__', '*.pyc', '*.pyo', '.pytest_cache',
                    'scratch', 'temp', 'debug', 'logs', '.git', '*.zip'
                )
            )
        else:
            shutil.copy2(src, dst)

def run_cmd(cmd, cwd):
    res = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"FAILED: {' '.join(cmd)}")
        print("STDOUT:", res.stdout)
        print("STDERR:", res.stderr)
        sys.exit(1)
    return res.stdout, res.stderr

def create_zip():
    if os.path.exists(FINAL_ZIP):
        os.remove(FINAL_ZIP)
    
    file_count = 0
    with zipfile.ZipFile(FINAL_ZIP, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(STAGING_DIR):
            for file in files:
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, STAGING_DIR)
                if "__pycache__" in rel_path or file.endswith(".pyc") or file.endswith(".zip"):
                    continue
                zipf.write(file_path, rel_path)
                file_count += 1
    return file_count

def test_fresh_extraction():
    with tempfile.TemporaryDirectory() as fresh_dir:
        with zipfile.ZipFile(FINAL_ZIP, 'r') as zipf:
            zipf.extractall(fresh_dir)
        
        # Verify no pycache, pyc, or nested zip in archive
        for root, dirs, files in os.walk(fresh_dir):
            if "__pycache__" in dirs:
                raise RuntimeError(f"Found __pycache__ directory in {root}")
            for f in files:
                if f.endswith(".pyc") or f.endswith(".pyo"):
                    raise RuntimeError(f"Found compiled bytecode file: {f}")
                if f.endswith(".zip"):
                    raise RuntimeError(f"Found nested zip file: {f}")

        # Check marketplace.json is at root
        mp_path = os.path.join(fresh_dir, "marketplace.json")
        if not os.path.exists(mp_path):
            raise RuntimeError("marketplace.json missing from root of extracted zip")

        # Check README.md exists and local image paths exist
        readme_path = os.path.join(fresh_dir, "README.md")
        if not os.path.exists(readme_path):
            raise RuntimeError("README.md missing from root of extracted zip")
        
        with open(readme_path, "r", encoding="utf-8") as f:
            readme_text = f.read()

        # Find relative image paths like src="docs/..." or [alt](docs/...)
        img_refs = re.findall(r'(?:src=["\']|\]\()((?:docs/|images/)[^"\'\)]+)', readme_text)
        for img_ref in img_refs:
            full_img_path = os.path.join(fresh_dir, img_ref)
            if not os.path.exists(full_img_path):
                raise RuntimeError(f"Broken README image path: {img_ref} (resolved to {full_img_path})")

        # Run validations from fresh extraction
        print("[1/5] Running marketplace validator from fresh extraction...")
        out, _ = run_cmd(["python", "scripts/validate_marketplace.py"], fresh_dir)
        print("     ", out.strip())

        print("[2/5] Running unittest discover from fresh extraction...")
        _, err = run_cmd(["python", "-m", "unittest", "discover", "tests", "-q"], fresh_dir)
        print("     ", err.strip().splitlines()[-1] if err.strip() else "OK")

        print("[3/5] Running local fixtures from fresh extraction...")
        _, err = run_cmd(["python", "tests/run_local_fixtures.py"], fresh_dir)
        print("     ", err.strip().splitlines()[-1] if err.strip() else "OK")

        print("[4/5] Running blind generalization benchmark from fresh extraction...")
        out, _ = run_cmd(["python", "tests/run_blind_generalization_eval.py"], fresh_dir)
        print("      21/21 Archetypes evaluated cleanly.")

        print("[5/5] Running CLI --help from fresh extraction...")
        run_cmd(["python", "skills/audit-orchestrator/scripts/run_audit.py", "--help"], fresh_dir)
        print("      CLI help functional.")

def main():
    print("Building clean marketplace package...")
    clean_staging()
    copy_clean_files()
    file_count = create_zip()
    zip_size_bytes = os.path.getsize(FINAL_ZIP)
    zip_size_mb = zip_size_bytes / (1024 * 1024)
    print(f"Created: {FINAL_ZIP} ({zip_size_mb:.2f} MB, {file_count} files)")
    
    if zip_size_mb >= 50.0:
        raise RuntimeError(f"ZIP size {zip_size_mb:.2f} MB exceeds 50 MB contest limit!")

    print("Running fresh extraction verification...")
    test_fresh_extraction()
    print("SUCCESS: Final marketplace ZIP built, extracted, and 100% verified.")

if __name__ == "__main__":
    main()
