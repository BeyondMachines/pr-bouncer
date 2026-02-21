# pr-bouncer

Automated PR security review powered by Gemini AI, Semgrep, Gitleaks, and Checkov.

Three static analysis tools scan your code. Gemini evaluates the findings, checks for false positives, and posts a structured security review as a PR comment. A configurable security gate blocks risky merges.

---

## Why pr-bouncer?

Most AI-powered PR review tools fall into one of two camps: commercial platforms with per-seat pricing (Aikido, Snyk, Semgrep Pro), or lightweight open-source actions that send diffs to an LLM and post the response — essentially AI wrappers with no static analysis grounding and a general code quality focus rather than a security focus.

pr-bouncer sits in the gap. It combines **three established static analysis tools** (Semgrep, Gitleaks, Checkov) with **AI-powered evaluation** that cross-validates each finding against the actual code. The static tools catch what pattern matching is good at — known vulnerability signatures, leaked secrets, infrastructure misconfigurations. The AI layer then evaluates whether each finding is real or a false positive, checks for logic bugs the tools miss, and produces a structured review with a composite risk score.

**Why Gemini?** Security reviews need context. A meaningful review requires the diff, full file contents of changed files, AST structure, security configurations, base class sources, and cross-references to where changed functions are called. This easily reaches 50,000–100,000+ tokens for non-trivial PRs. Gemini's large context window (1M+ tokens) handles this without truncation or chunking, which means the AI sees the complete picture rather than reviewing code fragments in isolation.

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

### 1. Configure secrets

pr-bouncer needs API keys passed as GitHub secrets. You can set these at **either** level depending on your setup:

- **Organization level** (recommended for multiple repos) — Go to **GitHub → Your Org → Settings → Secrets and variables → Actions**. Set visibility to "Selected repositories" and grant access to repos that use pr-bouncer. All granted repos share the same secrets.
- **Repository level** (for single repos or per-repo keys) — Go to **Repo → Settings → Secrets and variables → Actions**. These override org-level secrets of the same name.

| Secret | Required | Description |
|---|---|---|
| `GEMINI_API_KEY` | Yes | Google Gemini API key |
| `AWS_ACCESS_KEY_ID` | Only if using S3 upload | AWS access key |
| `AWS_SECRET_ACCESS_KEY` | Only if using S3 upload | AWS secret key |
| `AWS_REGION` | Only if using S3 upload | AWS region (e.g. `us-east-1`) |

> **Note:** `GITHUB_TOKEN` is provided automatically by GitHub Actions — you don't need to configure it.

### 2. Add the workflow to your repo

Create a single file in your repo:

**`.github/workflows/security-review.yml`**

#### Minimal setup (all defaults)

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

#### Public repos — block fork PRs

If your repo is public, anyone can open a PR from a fork and trigger the workflow, consuming API credits. Add the `if:` condition to restrict reviews to PRs from branches within your repo only:

```yaml
name: PR Security Review

on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  security-review:
    if: github.event.pull_request.head.repo.full_name == github.repository
    uses: BeyondMachines/pr-bouncer/.github/workflows/security-review.yml@v1
    secrets:
      GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}
```

Private repos don't need this — only people with repo access can open PRs.

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
    # Optional: uncomment the next line for public repos to block fork PRs
    # if: github.event.pull_request.head.repo.full_name == github.repository
    uses: BeyondMachines/pr-bouncer/.github/workflows/security-review.yml@v1
    with:
      risk_threshold: 5           # Block PRs at risk score >= 5 (default: 7)
      semgrep_rules: "p/security-audit,p/owasp-top-ten,p/python"  # Extra rules
      upload_to_s3: true          # Store results in S3 (default: false)
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

## S3 Review Storage

When `upload_to_s3: true`, pr-bouncer stores review data in S3 for long-term analysis. The purpose is to build an organizational dataset that a separate reporting tool can use to identify trends over time: which vulnerability types appear most often, which repos have recurring issues, whether the AI is consistently agreeing or disagreeing with static tools (signaling false positive/negative patterns), and where targeted developer training would have the most impact.

### What gets saved

The upload behavior depends on the **composite risk score**:

**Risk score ≥ 5 — Full review saved:**
- Complete AI review including all critical issues, finding evaluations, recommendations, and breaking changes
- PR metadata (repo, PR number, author, branch, SHA, timestamp)
- Token usage statistics

These are the reviews most likely to contain real findings worth analyzing.

**Risk score < 5 — Summary only:**
- Risk score, one-line summary, counts of critical issues and recommendations
- PR metadata and token usage

Low-risk reviews are saved in condensed form to reduce storage costs while still tracking that a review occurred and what the score was.

**Token usage — always logged:**
- Every review (regardless of risk score) appends a row to a monthly CSV with timestamp, repo, PR number, risk score, and token counts
- Used for monitoring API costs across repos

### S3 bucket structure

```
bm-pr-reviews/
├── reviews/
│   └── YYYY/
│       └── MM/
│           └── DD/
│               ├── org__repo__PR-42__a1b2c3d4.json            # risk ≥ 5: full review
│               └── org__repo__PR-43__e5f6g7h8__summary.json   # risk < 5: summary only
└── tokens/
    └── YYYY/
        └── MM.csv    # monthly token usage (one row per review)
```

The `tokens/` CSVs have columns: `timestamp, repo, pr, risk_score, prompt_tokens, completion_tokens, cached_tokens, total_tokens`.

---

## Per-Repo Customization Examples

**Strict security for a production API:**
```yaml
    uses: BeyondMachines/pr-bouncer/.github/workflows/security-review.yml@v1
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
The upload step only runs when `upload_to_s3: true` AND `review-result.json` exists. Check that AWS secrets are set at the org level or repo level and granted to your repo.

**Secrets not available**
If the workflow fails with missing secrets, your repo may not be in the "Selected repositories" list for the org secrets, or the repo-level secrets haven't been configured. Check org settings or add secrets directly to the repo.