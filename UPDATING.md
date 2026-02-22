# Maintaining pr-bouncer

Internal guide for developers maintaining this action.

---

## Repo Structure

```
pr-bouncer/
├── README.md                          # User-facing docs
├── UPDATING.md                        # This file
├── action.yml                         # Action metadata (pointer to reusable workflow)
├── requirements.txt                   # Python dependencies
├── scripts/
│   ├── run_security_scans.py          # Static tool runner (Semgrep, Gitleaks, Checkov)
│   └── gemini_pr_reviewer.py          # Gemini AI reviewer + composite scoring
└── .github/
    └── workflows/
        ├── security-review.yml        # Reusable workflow: scan + review + gate + S3
        └── pr-commands.yml            # Reusable workflow: slash commands + S3 decisions
```

---

## Workflows Overview

**security-review.yml** — triggered by consuming repos on `pull_request`. Runs static tools, calls Gemini, posts review comment, enforces security gate, optionally uploads to S3.

**pr-commands.yml** — triggered by consuming repos on `issue_comment`. Listens for `/accept-risk` and `/false-positive` commands. Overrides status checks, adds labels, optionally saves decisions to S3.

Each consuming repo needs its own thin caller workflow for each of these. See README for examples.

---

## Releasing

### Non-breaking changes (patch/minor)

Push to `main`, then move the `v1` tag:

```bash
git add .
git commit -m "v1.x.x — description"
git push origin main

git tag -fa v1 -m "v1.x.x — description"
git push origin v1 --force
```

All repos pinned to `@v1` pick up the change on their next PR. No action needed from consuming repos.

### Breaking changes (major)

Create a new major tag:

```bash
git add .
git commit -m "v2.0.0 — breaking change description"
git push origin main

git tag -a v2 -m "v2.0.0 — breaking change description"
git push origin v2
```

Then notify consuming repo owners to update their caller workflows from `@v1` to `@v2`.

### What counts as breaking

- Removing or renaming an input/secret
- Changing default behavior (e.g. default `risk_threshold`)
- Changing the output format of `review-result.json` in ways that break the gate
- Changing the S3 key structure (reviews or decisions)
- Changing slash command names (`/accept-risk`, `/false-positive`)

### What is non-breaking

- Improving the Gemini prompt
- Adding new optional inputs with defaults
- Fixing bugs in the Python scripts
- Updating tool versions (Semgrep, Gitleaks, Checkov)
- Adding new fields to the review JSON
- Adding new slash commands (as long as existing ones still work)

---

## Org-Level Secrets Setup

Set these once at **GitHub → your-org → Settings → Secrets and variables → Actions → Secrets tab**:

| Secret | Required |
|---|---|
| `GEMINI_API_KEY` | Yes |
| `AWS_ACCESS_KEY_ID` | If S3 enabled |
| `AWS_SECRET_ACCESS_KEY` | If S3 enabled |
| `AWS_REGION` | If S3 enabled |

For each secret, set visibility to **"Selected repositories"** and add repos as they onboard.

---

## Onboarding a New Repo

1. Grant the repo access to org secrets (see above)
2. Have the repo owner create `.github/workflows/security-review.yml` per the README
3. (Optional) Have the repo owner create `.github/workflows/pr-bouncer-commands.yml` for slash commands
4. (Optional) Set up branch protection to require the `security-analysis` check

---

## S3 Storage Structure

```
bm-pr-reviews/
├── reviews/                           # From security-review.yml
│   └── YYYY/
│       └── MM/
│           └── DD/
│               ├── org__repo__PR-42__a1b2c3d4.json            # risk >= 5: full review
│               └── org__repo__PR-43__e5f6g7h8__summary.json   # risk < 5: summary only
├── decisions/                         # From pr-commands.yml
│   └── YYYY/
│       └── MM/
│           └── DD/
│               ├── org__repo__PR-42__accept-risk__username.json
│               └── org__repo__PR-43__false-positive__username.json
│       └── MM.csv                     # monthly decisions log
└── tokens/                            # From security-review.yml
    └── YYYY/
        └── MM.csv                     # monthly token usage tracking
```

Reviews and decisions use the same `org__repo__PR-N` naming convention so they can be joined by a reporting tool.

---

## Dependency Updates

Update `requirements.txt` and test locally before tagging. Key dependencies:

- `google-genai` — Gemini SDK
- `PyGithub` — PR comment posting
- `tree-sitter` / `tree-sitter-languages` — AST analysis (pinned versions, test carefully)
- `semgrep`, `checkov` — static tools
- `gitleaks` — binary, version pinned in the workflow YAML wget step
- `boto3` — S3 uploads (used in both workflows)

---

## Testing Changes Locally

### Security review (main workflow)

```bash
# Set env vars
export GEMINI_API_KEY="your-key"
export PR_NUMBER=0          # 0 = local mode, skips GitHub posting
export REPO_NAME="test"
export BASE_REF="main"
export HEAD_REF="feature-branch"

# Generate inputs
git diff -U15 main...HEAD > pr-diff.txt
git diff --name-only main...HEAD > changed-files.txt

# Run
python scripts/run_security_scans.py
python scripts/gemini_pr_reviewer.py
```

The reviewer prints the full comment to stdout in local mode instead of posting to GitHub.

### Slash commands (pr-commands workflow)

The commands workflow is harder to test locally since it depends on GitHub's `issue_comment` event. Test it by:

1. Deploying to a test repo
2. Opening a PR that triggers a security review
3. Commenting `/accept-risk test reasoning` or `/false-positive test reasoning`
4. Verifying the response comment, label, and status check override
5. If S3 is enabled, checking the `decisions/` path in the bucket