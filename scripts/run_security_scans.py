#!/usr/bin/env python3
"""
Runs Semgrep, Gitleaks, and Checkov on changed files.
Normalizes all output into consistent JSON files for the reviewer.

Findings are classified as 'new' (on lines introduced by the PR)
or 'existing' (on lines that already existed before the PR).
"""

import subprocess
import json
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Dict, List, Set, Tuple


# ---------------------------------------------------------------------------
# Diff parsing — extract which lines are NEW (added) per file
# ---------------------------------------------------------------------------

def parse_diff_added_lines(diff_text: str) -> Dict[str, Set[int]]:
    """
    Parse a unified diff and return a dict mapping each file path to the set
    of line numbers (in the new/PR version) that were added or modified.

    Only '+' lines in the diff hunks count as 'new'. Context lines and
    removed lines are not included.
    """
    added_lines: Dict[str, Set[int]] = {}
    current_file = None
    new_line_num = 0

    for line in diff_text.splitlines():
        # Detect file header: +++ b/path/to/file.py
        if line.startswith('+++ '):
            match = re.match(r'^\+\+\+ b/(.+)$', line)
            if match:
                current_file = match.group(1)
                if current_file not in added_lines:
                    added_lines[current_file] = set()
            else:
                current_file = None
            continue

        # Detect hunk header: @@ -old_start,old_count +new_start,new_count @@
        if line.startswith('@@') and current_file:
            hunk_match = re.match(r'^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@', line)
            if hunk_match:
                new_line_num = int(hunk_match.group(1))
            continue

        if current_file is None:
            continue

        # Inside a hunk
        if line.startswith('+') and not line.startswith('+++'):
            # This is an added line
            added_lines[current_file].add(new_line_num)
            new_line_num += 1
        elif line.startswith('-') and not line.startswith('---'):
            # Removed line — doesn't increment new line counter
            pass
        else:
            # Context line (unchanged) — increments new line counter
            new_line_num += 1

    return added_lines


def classify_finding(finding: dict, added_lines: Dict[str, Set[int]], proximity: int = 5) -> str:
    """
    Classify a finding as 'new' or 'existing'.

    A finding is 'new' if its line number falls on or within `proximity`
    lines of an added line in the same file. This small window accounts
    for tools that report the issue a few lines above/below the actual
    change (e.g. a function signature when the body changed).
    """
    filepath = finding.get('file', '')
    line = finding.get('line', 0)

    # Normalize path: strip leading ./ or /
    normalized = filepath.lstrip('.').lstrip('/')

    file_added = added_lines.get(normalized, set())
    if not file_added:
        # File had no added lines in the diff — finding is pre-existing
        return 'existing'

    # Check if the finding line is near any added line
    for added_line in file_added:
        if abs(line - added_line) <= proximity:
            return 'new'

    return 'existing'


def split_findings(findings: List[dict], added_lines: Dict[str, Set[int]]) -> Tuple[List[dict], List[dict]]:
    """Split a list of findings into (new, existing) based on diff lines."""
    new_findings = []
    existing_findings = []
    for f in findings:
        scope = classify_finding(f, added_lines)
        f['scope'] = scope
        if scope == 'new':
            new_findings.append(f)
        else:
            existing_findings.append(f)
    return new_findings, existing_findings


# ---------------------------------------------------------------------------
# Tool runners (unchanged logic, just return raw findings)
# ---------------------------------------------------------------------------

def read_changed_files():
    """Read the list of changed files from git diff output."""
    try:
        with open('changed-files.txt') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("⚠️ changed-files.txt not found")
        return []


def run_command(cmd, timeout=120):
    """Run a shell command and return (returncode, stdout, stderr)."""
    print(f"  $ {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        print(f"  ⚠️ Command timed out after {timeout}s")
        return -1, "", "timeout"
    except FileNotFoundError:
        print(f"  ⚠️ Command not found: {cmd[0] if isinstance(cmd, list) else cmd}")
        return -1, "", "not found"


def run_semgrep(changed_files):
    """Run Semgrep on changed files and return normalized results."""
    print("\n🔒 Running Semgrep...")

    code_files = [f for f in changed_files if os.path.isfile(f)]
    if not code_files:
        print("  No files to scan")
        return []

    rules = os.environ.get('SEMGREP_RULES', 'p/security-audit,p/owasp-top-ten')
    cmd = ['semgrep', 'scan', '--json']
    for rule in rules.split(','):
        rule = rule.strip()
        if rule:
            cmd.extend([f'--config={rule}'])
    cmd += code_files

    rc, stdout, stderr = run_command(cmd, timeout=180)

    results = []
    try:
        data = json.loads(stdout)
        for r in data.get('results', []):
            results.append({
                'tool': 'Semgrep',
                'file': r.get('path', 'unknown'),
                'line': r.get('start', {}).get('line', 0),
                'severity': r.get('extra', {}).get('severity', 'WARNING'),
                'message': r.get('extra', {}).get('message', ''),
                'rule': r.get('check_id', ''),
            })
        print(f"  ✅ {len(results)} findings")
    except (json.JSONDecodeError, KeyError) as e:
        print(f"  ⚠️ Failed to parse Semgrep output: {e}")

    return results


def run_gitleaks(changed_files):
    """Run Gitleaks on changed files only by copying them to a temp dir."""
    print("\n🔐 Running Gitleaks...")

    if not changed_files:
        print("  No files to scan")
        return []

    # Copy changed files to a temp directory to scope the scan
    tmpdir = tempfile.mkdtemp(prefix="gitleaks-")
    copied = 0
    try:
        for filepath in changed_files:
            if os.path.isfile(filepath):
                dest = os.path.join(tmpdir, filepath)
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                shutil.copy2(filepath, dest)
                copied += 1

        if copied == 0:
            print("  No files copied for scanning")
            return []

        print(f"  Scanning {copied} changed files...")

        report_path = os.path.join(tmpdir, "report.json")

        cmd = [
            'gitleaks', 'detect',
            '--source', tmpdir,
            '--no-git',
            '--report-format', 'json',
            '--report-path', report_path,
        ]

        # Use config if available
        config_path = '.github/scripts/gitleaks.toml'
        if os.path.isfile(config_path):
            cmd.extend(['--config', os.path.abspath(config_path)])

        rc, stdout, stderr = run_command(cmd)

        results = []
        if os.path.isfile(report_path):
            try:
                with open(report_path) as f:
                    findings = json.load(f)

                if isinstance(findings, list):
                    for finding in findings:
                        # Fix file paths: remove tmpdir prefix to get original path
                        file_path = finding.get('File', 'unknown')
                        # Strip the temp dir prefix
                        if tmpdir in file_path:
                            file_path = file_path.replace(tmpdir + '/', '')

                        results.append({
                            'tool': 'Gitleaks',
                            'file': file_path,
                            'line': finding.get('StartLine', 0),
                            'severity': 'CRITICAL',
                            'message': f"Potential secret: {finding.get('Description', 'Secret found')}",
                            'rule': finding.get('RuleID', ''),
                            'secret': finding.get('Secret', '')[:20] + '...',
                        })
            except (json.JSONDecodeError, KeyError) as e:
                print(f"  ⚠️ Failed to parse Gitleaks output: {e}")

        print(f"  ✅ {len(results)} findings")
        return results

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def run_checkov(changed_files):
    """Run Checkov on infrastructure files and return normalized results."""
    print("\n🏗️ Running Checkov...")

    # Filter for infrastructure files
    infra_extensions = {'.yaml', '.yml', '.json', '.tf'}
    infra_files = []
    for f in changed_files:
        if not os.path.isfile(f):
            continue
        name_lower = os.path.basename(f).lower()
        ext = Path(f).suffix.lower()
        if ext in infra_extensions or 'dockerfile' in name_lower:
            infra_files.append(f)

    if not infra_files:
        print("  No infrastructure files to scan")
        return []

    print(f"  Scanning {len(infra_files)} infra files: {infra_files}")

    # Build command: checkov -f file1 -f file2 ...
    cmd = ['checkov']
    for f in infra_files:
        cmd.extend(['-f', f])
    cmd.extend([
        '--framework', 'dockerfile', '--framework', 'secrets',
        '--framework', 'kubernetes', '--framework', 'terraform',
        '--quiet', '--compact', '--output', 'json',
    ])

    rc, stdout, stderr = run_command(cmd, timeout=120)

    results = []

    # Parse stdout — checkov writes JSON to stdout when using --output json
    raw = stdout.strip()
    if not raw:
        print("  ⚠️ Checkov produced no output")
        if stderr.strip():
            print(f"  stderr: {stderr[:500]}")
        return []

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"  ⚠️ Failed to parse Checkov JSON: {e}")
        print(f"  First 500 chars: {raw[:500]}")
        return []

    # Normalize: data can be a dict (single framework) or list (multiple)
    items = data if isinstance(data, list) else [data]

    for item in items:
        if not isinstance(item, dict):
            continue

        check_type = item.get('check_type', 'unknown')
        results_section = item.get('results', {})

        if isinstance(results_section, dict):
            failed = results_section.get('failed_checks', [])
        elif isinstance(results_section, list):
            failed = []
            for sub in results_section:
                if isinstance(sub, dict):
                    failed.extend(sub.get('failed_checks', []))
        else:
            continue

        for chk in failed:
            if not isinstance(chk, dict):
                continue

            line_range = chk.get('file_line_range', [0])
            line = line_range[0] if isinstance(line_range, list) and line_range else 0

            results.append({
                'tool': 'Checkov',
                'file': chk.get('file_path', 'unknown'),
                'line': line,
                'severity': chk.get('severity') or 'HIGH',
                'message': chk.get('check_name', ''),
                'rule': chk.get('check_id', ''),
                'guideline': chk.get('guideline', ''),
                'check_type': check_type,
            })

    print(f"  ✅ {len(results)} findings from {len(items)} framework(s)")
    return results


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=" * 60)
    print("Security Scan Runner")
    print("=" * 60)

    changed_files = read_changed_files()
    print(f"\n📋 {len(changed_files)} changed files")
    for f in changed_files:
        print(f"  - {f}")

    # --- Parse diff to know which lines are new ---
    diff_text = ""
    try:
        with open('pr-diff.txt', 'r') as f:
            diff_text = f.read()
    except FileNotFoundError:
        print("⚠️ pr-diff.txt not found — all findings will be classified as 'new'")

    added_lines = parse_diff_added_lines(diff_text)
    total_added = sum(len(v) for v in added_lines.values())
    print(f"\n📊 Diff analysis: {len(added_lines)} files with {total_added} added/modified lines")

    # --- Run all scanners ---
    semgrep_results = run_semgrep(changed_files)
    gitleaks_results = run_gitleaks(changed_files)
    checkov_results = run_checkov(changed_files)

    # --- Classify each finding as new or existing ---
    semgrep_new, semgrep_existing = split_findings(semgrep_results, added_lines)
    gitleaks_new, gitleaks_existing = split_findings(gitleaks_results, added_lines)
    checkov_new, checkov_existing = split_findings(checkov_results, added_lines)

    # --- Save normalized + classified results ---
    all_results = {
        'semgrep_new': semgrep_new,
        'semgrep_existing': semgrep_existing,
        'gitleaks_new': gitleaks_new,
        'gitleaks_existing': gitleaks_existing,
        'checkov_new': checkov_new,
        'checkov_existing': checkov_existing,
    }

    with open('scan-results.json', 'w') as f:
        json.dump(all_results, f, indent=2)

    # --- Summary ---
    new_total = len(semgrep_new) + len(gitleaks_new) + len(checkov_new)
    existing_total = len(semgrep_existing) + len(gitleaks_existing) + len(checkov_existing)

    print(f"\n{'=' * 60}")
    print(f"Scan Complete: {new_total + existing_total} total findings")
    print(f"  NEW (introduced by this PR):")
    print(f"    Semgrep:  {len(semgrep_new)}")
    print(f"    Gitleaks: {len(gitleaks_new)}")
    print(f"    Checkov:  {len(checkov_new)}")
    print(f"    Total:    {new_total}")
    print(f"  EXISTING (pre-existing in changed files):")
    print(f"    Semgrep:  {len(semgrep_existing)}")
    print(f"    Gitleaks: {len(gitleaks_existing)}")
    print(f"    Checkov:  {len(checkov_existing)}")
    print(f"    Total:    {existing_total}")
    print("=" * 60)


if __name__ == "__main__":
    main()