import re
import sys
import os

RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"


def scan_file(filename):
    issues = []
    suspicious_imports = ["pickle", "subprocess", "os"]

    try:
        with open(filename, 'r', encoding='utf-8') as file:
            lines = file.readlines()

        for line_no, line in enumerate(lines, start=1):

            if re.search(r'password\s*=\s*["\'].*["\']', line):
                issues.append((RED, f"[HIGH] Hardcoded password in {filename} at line {line_no}"))

            if "eval(" in line:
                issues.append((RED, f"[CRITICAL] eval() detected in {filename} at line {line_no}"))

            if "exec(" in line:
                issues.append((RED, f"[CRITICAL] exec() detected in {filename} at line {line_no}"))

            if "md5(" in line:
                issues.append((YELLOW, f"[MEDIUM] Weak MD5 hashing in {filename} at line {line_no}"))

            for imp in suspicious_imports:
                if f"import {imp}" in line:
                    issues.append((BLUE, f"[INFO] Suspicious import '{imp}' in {filename} at line {line_no}"))

    except:
        pass

    return issues


def scan_directory(directory):
    all_issues = []

    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".py") and file != "securehound.py":
                filepath = os.path.join(root, file)
                all_issues.extend(scan_file(filepath))

    return all_issues

def main():
    if len(sys.argv) != 2:
        print("Usage: python securehound.py <file_or_directory>")
        return

    target = sys.argv[1]

    print(f"\nScanning {target}...\n")

    if os.path.isfile(target):
        issues = scan_file(target)
    elif os.path.isdir(target):
        issues = scan_directory(target)
    else:
        print("Invalid file or directory.")
        return

    if issues:
        with open("report.txt", "w", encoding="utf-8") as report:
            for color, issue in issues:
                print(color + issue + RESET)
                report.write(issue + "\n")

            report.write(f"\nTotal Issues Found: {len(issues)}")

        print(f"\nTotal Issues Found: {len(issues)}")
        print("Report saved as report.txt")

    else:
        print("No security issues found.")

if __name__ == "__main__":
    main()