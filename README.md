# 🚪 pr-bouncer

Automated PR security review powered by Gemini AI, Semgrep, Gitleaks, and Checkov.

Three static analysis tools scan your code. Gemini evaluates the findings, checks for false positives, and posts a structured security review as a PR comment. A configurable security gate blocks risky merges.

---

## How It Works

```
PR Opened → Semgrep + Gitleaks + Checkov → Gemini AI Review → PR Comment + Security Gate
```

1. **Semgrep** — code-level vulnerabilities (injection, auth issues, OWASP Top 10)
2. **Gitleaks** — hardcoded secrets and credentials
3. **Checkov** — infrastructure misconfigurations (Dockerfiles, Terraform, Kubernetes)
4. **Gemini AI** — evaluates each finding against the actual code, flags false positives, computes a composite risk score
5. **Security Gate** — blocks the PR if the risk score exceeds your threshold or any critical issues are confirmed

---

## Quick Start

### 1. Ensure org secrets are configured

The following secrets should already be set at the org level. If you don't have access or they're missing, contact your platform/security team.

| Secret | Required | Description |
|---|---|---|
| `GEMINI_API_KEY` | ✅ Yes | Google Gemini API key |
| `AWS_ACCESS_KEY_ID` | Only if using S3 upload | AWS access key |
| `AWS_SECRET_ACCESS_KEY` | Only if using S3 upload | AWS secret key |
| `AWS_REGION` | Only if using S3 upload | AWS region (e.g. `us-east-1`) |

> **Note:** `GITHUB_TOKEN` is provided automatically by GitHub Actions — you don't need to configure it.

Your repo must be granted access to these org secrets. Go to **GitHub → Your Org → Settings → Secrets and variables → Actions** and check that your repo is in the "Selected repositories" list for each secret.

### 2. Add the workflow to your repo

Create a single file in your repo:

**`.github/workflows/security-review.yml`**

```yaml
name: PR Security Review

on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  security-review:
    uses: BeyondMachines/pr-bouncer/.github/workflows/security-review.yml@v1
    secrets:
      GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}
```

That's it. The next PR opened in your repo will trigger the review.

### 3. (Optional) Make it a required check

To block merges when the security gate fails, go to **Repo → Settings → Branches → Branch protection rules** for your default branch and add `security-analysis` as a required status check.

---

## Configuration Reference

### Inputs

Set these per-repo in the `with:` block of your caller workflow.

| Input | Type | Default | Description |
|---|---|---|---|
| `risk_threshold` | number | `7` | Risk score (1–10) at which the security gate fails. Lower = stricter. |
| `semgrep_rules` | string | `p/security-audit,p/owasp-top-ten` | Comma-separated Semgrep rule sets. Add language-specific packs as needed. |
| `upload_to_s3` | boolean | `false` | Upload review results to S3. Requires AWS secrets. |

### Full example with all options

```yaml
name: PR Security Review

on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  security-review:
    uses: BeyondMachines/pr-bouncer/.github/workflows/security-review.yml@v1
    with:
      risk_threshold: 5
      semgrep_rules: "p/security-audit,p/owasp-top-ten,p/python"
      upload_to_s3: true
    secrets:
      GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}
      AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
      AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
      AWS_REGION: ${{ secrets.AWS_REGION }}
```

---

## What Gets Posted

pr-bouncer posts a single comment on each PR with:

- **Risk Score** (1–10) with color indicator (🟢 🟡 🔴)
- **Critical Issues** — confirmed vulnerabilities with file, line, description, and fix
- **Disputed Findings** — where the AI disagrees with a static tool finding, with reasoning
- **Breaking Changes** — database migrations, removed endpoints, changed API signatures
- **Recommendations** — top 3 actionable security improvements
- **Raw Tool Findings** — collapsible section with all Semgrep, Gitleaks, and Checkov results

---

## Security Gate

The gate blocks the PR if:

- Risk score ≥ `risk_threshold` (default 7), **OR**
- Any critical issues are confirmed

The risk score is a **composite** of the static tool findings and the AI evaluation:

- If both tools and AI agree something is risky → high score
- If tools flag something but AI identifies it as a false positive → dampened score
- If AI finds something tools missed → AI score is used

---

## Per-Repo Customization Examples

**Strict security for a production API:**
```yaml
with:
  risk_threshold: 3
  semgrep_rules: "p/security-audit,p/owasp-top-ten,p/python,p/django"
  upload_to_s3: true
```

**Relaxed for an internal tool:**
```yaml
with:
  risk_threshold: 8
```

**Frontend repo with JS-specific rules:**
```yaml
with:
  semgrep_rules: "p/security-audit,p/owasp-top-ten,p/javascript,p/react"
```

---

## Security Considerations

pr-bouncer sends PR diffs and file contents to the Gemini API for analysis. This means **untrusted code from PR authors is included in the AI prompt**. We apply multiple layers of defense against prompt injection — input sanitization, prompt hardening, structural separation of instructions from data, and output validation that catches suspicious AI responses.

However, **no defense against prompt injection is foolproof**. A sufficiently crafted PR could theoretically manipulate the AI review. The static tool results (Semgrep, Gitleaks, Checkov) are not affected by this — they run independently and their raw findings are always included in the PR comment. The composite scoring system is designed so that static tool findings cannot be fully overridden by the AI alone.

**pr-bouncer is a complement to human code review, not a replacement.** Critical PRs should always have a human reviewer, especially in security-sensitive codebases.

---

## Troubleshooting

**"No review result found, failing as precaution"**
The Gemini API call failed. Check the workflow logs for the "Run Gemini PR Review" step. Common causes: invalid API key, rate limiting, or the prompt exceeded the context window.

**Gate fails but the review looks clean**
The composite score may be elevated by static tool findings even if the AI downgraded them. Lower `risk_threshold` or check the raw findings section for what triggered the tools.

**Review comment not appearing**
Ensure `GITHUB_TOKEN` has `pull-requests: write` permission. This is set in the reusable workflow's `permissions` block, but org-level policies can override it.

**S3 upload fails silently**
The upload step only runs when `upload_to_s3: true` AND `review-result.json` exists. Check that AWS secrets are set at the org level and granted to your repo.

**Secrets not available**
If the workflow fails with missing secrets, your repo may not be in the "Selected repositories" list for the org secrets. Contact your platform team or check org settings.