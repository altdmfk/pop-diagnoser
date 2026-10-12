import os
import re
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

MOJIBAKE_QUESTION_RE = re.compile(r"[가-힣]\?+[가-힣]|\?\?[가-힣]|[가-힣]\?\?")

def check_files(custom_files=None):
    default_files = [
        "index.html", "README.md", "docs/case-study.md", "css/style.css", "test.html",
        "js/core/profiles/paper.js", "js/core/encoding.js", "js/core/ecdsa.js",
        "js/core/inspect.js", "js/core/curlParser.js", "js/core/canonical.js",
        "js/core/hypotheses.js", "js/core/jsonError.js", "js/core/diagnose.js",
        "js/ui/samples.js", "js/ui/jsonError.js", "js/ui/tabs.js", "js/ui/slots.js",
        "js/ui/render.js", "js/ui/inspector.js", "js/ui/importer.js",
        "js/app.js", "test.js", "test/test.js", "test/test-runner.js",
        "test/fixtures/fixtures.js", "tools/generate_fixtures.py",
        "tools/differential_check.py", "tools/differential_fixtures.json",
        "tools/golden_pass.js", "tools/check_encoding.py", ".github/workflows/test.yml"
    ]
    files_to_check = custom_files if custom_files else default_files
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    has_failure = False

    print("File | Strict UTF-8 | BOM | U+FFFD")
    print("-" * 40)

    for file in files_to_check:
        path = file if os.path.isabs(file) else os.path.join(base_dir, file)
        if not os.path.exists(path):
            print(f"{file} | Not found | - | -")
            has_failure = True
            continue

        with open(path, "rb") as f:
            content = f.read()

        has_bom = content.startswith(b'\xef\xbb\xbf')
        if has_bom:
            content = content[3:]

        strict_ok = True
        decoded_text = ""
        try:
            decoded_text = content.decode("utf-8")
        except UnicodeDecodeError:
            strict_ok = False
            decoded_text = content.decode("utf-8", errors="replace")

        has_fffd = '\ufffd' in decoded_text
        if not strict_ok or has_bom or has_fffd:
            has_failure = True

        suspicious_lines = []
        lines = decoded_text.splitlines()
        for i, line in enumerate(lines):
            if MOJIBAKE_QUESTION_RE.search(line):
                suspicious_lines.append((i + 1, line.strip()))
                has_failure = True

        print(f"{file} | {strict_ok} | {has_bom} | {has_fffd}")
        for idx, l in suspicious_lines:
            print(f"  Line {idx}: {l}")

    if has_failure:
        sys.exit(1)

if __name__ == "__main__":
    check_files(sys.argv[1:] if len(sys.argv) > 1 else None)

