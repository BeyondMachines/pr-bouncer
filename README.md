# pr-bouncer by BeyondMachines

Automated PR security review powered by Semgrep, Gitleaks, and Checkov and reviewed by Gemini AI

Three static analysis tools scan your code. Gemini evaluates the findings, checks for false positives, and posts a structured security review as a PR comment. A configurable security gate blocks risky merges.

---

## Why pr-bouncer?

Most development teams don't have the resources to do dedicated security reviews on every pull request. Unless you're in a heavily regulated industry, security review is either skipped entirely or becomes a bottleneck where one overloaded person gates every merge. The reality is that most code ships without any security eyes on it.

![pr-bouncer](images/bouncer.jpg)

A little automation goes a long way. But AI-only review is unreliable: LLMs hallucinate vulnerabilities and miss real ones. Static analysis tools are consistent and deterministic but noisy with false positives. pr-bouncer combines both: **static tools provide a grounded, reproducible baseline**, and the **AI evaluates whether each finding is real**, adds context the tools can't see, and catches logic bugs that pattern matching misses.

Most existing tools fall into one of two camps: commercial platforms with per-seat pricing (Aikido, Snyk, Semgrep Pro), or lightweight open-source actions that send diffs to an LLM and post the response — essentially AI wrappers with no static analysis grounding and a general code quality focus rather than a security focus. pr-bouncer sits in the gap — free, self-hosted, security-focused, and grounded in real tool output.

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
| `GEMINI_API_KEY` | ✅ Yes | Google Gemini API key |
| `AWS_ACCESS_KEY_ID` | Only if using S3 upload | AWS access key |
| `AWS_SECRET_ACCESS_KEY` | Only if using S3 upload | AWS secret key |
| `AWS_REGION` | Only if using S3 upload | AWS region (e.g. `us-east-1`) |

> **Note:** `GITHUB_TOKEN` is provided automatically by GitHub Actions — you don't need to configure it.

### 2. Add the security review workflow

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

### 3. (Optional) Add slash commands

pr-bouncer posts action commands at the bottom of every review comment. To enable them, add a second workflow file:

**`.github/workflows/pr-bouncer-commands.yml`**

```yaml
name: PR Bouncer Commands

on:
  issue_comment:
    types: [created]

jobs:
  commands:
    if: >
      github.event.issue.pull_request &&
      contains(fromJSON('["OWNER","MEMBER","COLLABORATOR"]'), github.event.comment.author_association)
    uses: BeyondMachines/pr-bouncer/.github/workflows/pr-commands.yml@v1
    with:
      upload_to_s3: true    # save decisions to S3 (default: false)
    secrets:
      AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
      AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
      AWS_REGION: ${{ secrets.AWS_REGION }}
```

The `if:` condition ensures only PR comments from repo owners, org members, or collaborators trigger the workflow. This prevents unauthorized users from executing slash commands or accessing AWS secrets.

This enables two commands that developers can use directly in PR comments:

| Command | What it does |
|---|---|
| `/accept-risk` | Overrides the security gate, marks the PR as risk-accepted, adds a label |
| `/false-positive` | Flags the review as inaccurate, adds a label for tracking |

Developers add their reasoning after the command, e.g.: `/accept-risk This is a test environment, no real credentials exposed`

The command, author, and reasoning are recorded in the PR comment thread. If `upload_to_s3` is enabled, decisions are also saved to S3 for organizational tracking.

### 4. (Optional) Make it a required check

To block merges when the security gate fails, go to **Repo → Settings → Branches → Branch protection rules** for your default branch and add `security-analysis` as a required status check.

When combined with slash commands, developers can unblock a failed gate by commenting `/accept-risk` with their reasoning — the command overrides the status check while maintaining a full audit trail.

---

## Configuration Reference

### Inputs — Security Review

Set these per-repo in the `with:` block of your security review workflow.

| Input | Type | Default | Description |
|---|---|---|---|
| `risk_threshold` | number | `7` | Risk score (1–10) at which the security gate fails. Lower = stricter. |
| `semgrep_rules` | string | `p/security-audit,p/owasp-top-ten` | Comma-separated Semgrep rule sets. Add language-specific packs as needed. |
| `upload_to_s3` | boolean | `false` | Upload review results to S3. Requires AWS secrets. |

### Inputs — Slash Commands

Set these in the `with:` block of your commands workflow.

| Input | Type | Default | Description |
|---|---|---|---|
| `upload_to_s3` | boolean | `false` | Save accept-risk and false-positive decisions to S3. |

### Full example with all options

```yaml
# .github/workflows/security-review.yml
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
      risk_threshold: 5
      semgrep_rules: "p/security-audit,p/owasp-top-ten,p/python"
      upload_to_s3: true
    secrets:
      GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}
      AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
      AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
      AWS_REGION: ${{ secrets.AWS_REGION }}
```

```yaml
# .github/workflows/pr-bouncer-commands.yml
name: PR Bouncer Commands

on:
  issue_comment:
    types: [created]

jobs:
  commands:
    if: >
      github.event.issue.pull_request &&
      contains(fromJSON('["OWNER","MEMBER","COLLABORATOR"]'), github.event.comment.author_association)
    uses: BeyondMachines/pr-bouncer/.github/workflows/pr-commands.yml@v1
    with:
      upload_to_s3: true
    secrets:
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
- **Actions** — slash commands for developers to accept risk or flag false positives

---

## Security Gate

The gate blocks the PR if:

- Risk score ≥ `risk_threshold` (default 7), **OR**
- Any critical issues are confirmed

The risk score is a **composite** of the static tool findings and the AI evaluation:

- If both tools and AI agree something is risky → high score
- If tools flag something but AI identifies it as a false positive → dampened score
- If AI finds something tools missed → AI score is used

If slash commands are enabled, a developer can override a failed gate by commenting `/accept-risk` with their reasoning. This sets the status check to passing while recording who accepted the risk and why.

---

## S3 Review Storage

When `upload_to_s3: true`, pr-bouncer stores review data in S3 for long-term analysis. The purpose is to build an organizational dataset that a separate reporting tool can use to identify trends over time: which vulnerability types appear most often, which repos have recurring issues, whether the AI is consistently agreeing or disagreeing with static tools (signaling false positive/negative patterns), and where targeted developer training would have the most impact.

### What gets saved

**Reviews** — saved by the security review workflow:

| Condition | What's saved |
|---|---|
| Risk score ≥ 5 | Full review: all critical issues, finding evaluations, recommendations, breaking changes, PR metadata, token usage |
| Risk score < 5 | Summary only: risk score, one-line summary, issue/recommendation counts, PR metadata, token usage |

**Token usage** — always logged regardless of risk score. Every review appends a row to a monthly CSV for monitoring API costs across repos.

**Decisions** — saved by the commands workflow when a developer uses `/accept-risk` or `/false-positive`. Each decision records the command, author, reasoning, timestamp, repo, and PR number. A monthly CSV is also maintained for quick querying.

### S3 bucket structure

```
bm-pr-reviews/
├── reviews/
│   └── YYYY/
│       └── MM/
│           └── DD/
│               ├── org__repo__PR-42__a1b2c3d4.json            # risk ≥ 5: full review
│               └── org__repo__PR-43__e5f6g7h8__summary.json   # risk < 5: summary only
├── decisions/
│   └── YYYY/
│       └── MM/
│           └── DD/
│               ├── org__repo__PR-42__accept-risk__username.json
│               └── org__repo__PR-43__false-positive__username.json
│       └── MM.csv    # monthly decisions log
└── tokens/
    └── YYYY/
        └── MM.csv    # monthly token usage (one row per review)
```

The `tokens/` CSVs have columns: `timestamp, repo, pr, risk_score, prompt_tokens, completion_tokens, cached_tokens, total_tokens`.

The `decisions/` CSVs have columns: `timestamp, repo, pr, decision, author, reasoning`.

Reviews and decisions share the same repo/PR naming convention, so a reporting tool can join them to see how often findings are accepted vs fixed vs disputed.

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

**Slash commands not working**
Make sure you've added the second workflow file (`.github/workflows/pr-bouncer-commands.yml`) to the repo. The commands workflow triggers on `issue_comment`, which is a separate event from `pull_request` — it needs its own workflow file.

**`/accept-risk` doesn't unblock the PR**
The command sets a status check called `security-analysis` to passing. If your branch protection uses a different check name, the override won't match. Verify the required check name in your branch protection rules.

**S3 upload fails silently**
The upload step only runs when `upload_to_s3: true` AND `review-result.json` exists. Check that AWS secrets are set at the org level or repo level and granted to your repo.

**Secrets not available**
If the workflow fails with missing secrets, your repo may not be in the "Selected repositories" list for the org secrets, or the repo-level secrets haven't been configured. Check org settings or add secrets directly to the repo.