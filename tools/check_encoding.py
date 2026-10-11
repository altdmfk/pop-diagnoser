import os
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

def check_files():
    files_to_check = [
        "index.html", "README.md", "css/style.css", "test.html",
        "js/core/profiles/paper.js", "js/core/encoding.js", "js/core/ecdsa.js",
        "js/core/inspect.js", "js/core/curlParser.js", "js/core/canonical.js", "js/core/hypotheses.js", "js/core/diagnose.js",
        "js/ui/jsonError.js", "js/ui/tabs.js", "js/ui/slots.js", "js/ui/render.js", "js/ui/inspector.js", "js/ui/importer.js",
        "js/app.js", "test.js", "test/test.js", "test/test-runner.js",
        "test/fixtures/fixtures.js", "tools/generate_fixtures.py",
        "tools/differential_check.py", "tools/golden_pass.js"
    ]
    
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    print("File | Strict UTF-8 | BOM | U+FFFD")
    print("-" * 40)
    
    for file in files_to_check:
        path = os.path.join(base_dir, file)
        if not os.path.exists(path):
            print(f"{file} | Not found | - | -")
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
        
        suspicious_lines = []
        lines = decoded_text.splitlines()
        for i, line in enumerate(lines):
            # Suspicious if it has ? surrounded by spaces or Korean letters, 
            # or multiple ? in a row where Korean usually is.
            if '?' in line and any(ord(c) > 127 or c == '?' for c in line.replace(' ', '')):
                if '?' in line and not line.strip().startswith('//') and not 'http' in line and not '===' in line:
                    suspicious_lines.append((i+1, line.strip()))
                    
        print(f"{file} | {strict_ok} | {has_bom} | {has_fffd}")
        for idx, l in suspicious_lines:
            print(f"  Line {idx}: {l}")

if __name__ == "__main__":
    check_files()
