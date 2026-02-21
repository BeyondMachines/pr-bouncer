#!/usr/bin/env python3
"""
Runs Semgrep, Gitleaks, and Checkov on changed files.
Normalizes all output into consistent JSON files for the reviewer.
"""

import subprocess
import json
import os
import shutil
import tempfile
from pathlib import Path


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

    cmd = [
        'semgrep', 'scan',
        '--config=p/security-audit', '--config=p/owasp-top-ten',
        '--json',
    ] + code_files

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
        # Check stderr
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

        # Handle case where results is a dict or a list
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


def main():
    print("=" * 60)
    print("Security Scan Runner")
    print("=" * 60)

    changed_files = read_changed_files()
    print(f"\n📋 {len(changed_files)} changed files")
    for f in changed_files:
        print(f"  - {f}")

    # Run all scanners
    semgrep_results = run_semgrep(changed_files)
    gitleaks_results = run_gitleaks(changed_files)
    checkov_results = run_checkov(changed_files)

    # Save normalized results for the reviewer
    all_results = {
        'semgrep': semgrep_results,
        'gitleaks': gitleaks_results,
        'checkov': checkov_results,
    }

    with open('scan-results.json', 'w') as f:
        json.dump(all_results, f, indent=2)

    # Summary
    total = sum(len(v) for v in all_results.values())
    print(f"\n{'=' * 50}")
    print(f"Scan Complete: {total} total findings")
    print(f"  Semgrep:  {len(semgrep_results)}")
    print(f"  Gitleaks: {len(gitleaks_results)}")
    print(f"  Checkov:  {len(checkov_results)}")
    print("=" * 50)


if __name__ == "__main__":
    main()