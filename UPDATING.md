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
│   ├── run_security_scans.py          # Static tool runner (Semgrep, Gitleaks, Checkov) + diff classification
│   ├── gemini_pr_reviewer.py          # Gemini AI reviewer + composite scoring (new/existing separation)
│   └── process_command.py             # Slash command handler (/accept-risk, /false-positive)
└── .github/
    └── workflows/
        ├── security-review.yml        # Reusable workflow: scan + review + gate + S3
        ├── pr-commands.yml            # Reusable workflow: slash commands + S3 decisions
        └── self-test.yml              # Runs pr-bouncer on its own PRs
```

---

## Version History

### v2 — New vs Existing Finding Separation

**Problem:** In v1, static tools scanned entire changed files and all findings were treated equally. Pre-existing issues (e.g. `DEBUG = True` on line 1) could block a PR that only added a comment on line 200.

**Solution:** v2 parses the PR diff to classify each finding as NEW (introduced by the PR) or EXISTING (pre-existing). The security gate only blocks on NEW findings.

**What changed:**

| Component | v1 | v2 |
|---|---|---|
| `scan-results.json` | 3 keys: `semgrep`, `gitleaks`, `checkov` | 6 keys: `semgrep_new`, `semgrep_existing`, etc. |
| Gemini schema | No `scope` field | `scope: "NEW"/"EXISTING"` on evaluations and critical issues |
| Gemini schema | Single `risk_score` | `risk_score` (new only) + `existing_risk_score` (informational) |
| Security gate | Gates on all findings | Gates only on NEW findings |
| PR comment | Single list of findings | Separated: NEW (prominent) + EXISTING (collapsible) |
| Commit status description | `risk score: 7/10` | `new: 7/10, existing: 3/10` |
| S3 tokens CSV | 8 columns | 9 columns (added `existing_risk_score`) |
| S3 review JSON | No scope on findings | `scope` field on evaluations and critical issues |

**Breaking changes (why this is v2, not v1.x):**
- `scan-results.json` key names changed — any tool reading this file needs updating
- S3 `tokens/` CSV has a new column — downstream parsers need updating
- S3 review JSON has new fields — downstream reporting tools need updating

**Backward compatibility:** The `gemini_pr_reviewer.py` detects the old 3-key format and auto-converts (treating everything as NEW). So if the old scan runner somehow ran with the new reviewer, it wouldn't crash.

### v1 — Initial Release

Static tools + Gemini review + security gate. All findings treated equally regardless of whether they were introduced by the PR.

---

## Workflows Overview

**security-review.yml** — triggered by consuming repos on `pull_request`. Runs static tools, classifies findings by diff lines, calls Gemini with separated findings, posts review comment, enforces security gate (NEW findings only), optionally uploads to S3.

**pr-commands.yml** — triggered by consuming repos on `issue_comment`. Listens for `/accept-risk` and `/false-positive` commands. Overrides status checks, adds labels, optionally saves decisions to S3.

Each consuming repo needs its own thin caller workflow for each of these. See README for examples.

---

## Releasing

### Testing changes before release

Never push untested changes directly to a version tag. Use a test tag on a feature branch:

```bash
# 1. Create and push your feature branch
git checkout -b feat/my-change
# ... make changes ...
git add .
git commit -m "description of change"
git push --set-upstream origin feat/my-change

# 2. Create a test tag on the branch
git tag v2-test        # or v1-test if patching v1
git push origin v2-test
```

Then in a test repo, point the caller workflow at the test tag:

```yaml
jobs:
  security-review:
    uses: BeyondMachines/pr-bouncer/.github/workflows/security-review.yml@v2-test
    secrets:
      GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}
```

Open a PR in the test repo to trigger the workflow. Verify the results, iterate on the branch and re-tag as needed:

```bash
# If you need to update the test tag after more commits:
git tag -fa v2-test -m "updated test"
git push origin v2-test --force
```

Once validated, clean up:

```bash
git tag -d v2-test
git push origin :refs/tags/v2-test
```

### Non-breaking changes (patch/minor)

Push to `main`, then move the current major tag:

```bash
git checkout main
git merge feat/my-change
git push origin main

git tag -fa v2 -m "v2.x.x — description"
git push origin v2 --force
```

All repos pinned to `@v2` pick up the change on their next PR. No action needed from consuming repos.

### Breaking changes (new major version)

Create a new major tag:

```bash
git checkout main
git merge feat/my-change
git push origin main

git tag -a v3 -m "v3.0.0 — breaking change description"
git push origin v3
```

Then notify consuming repo owners to update their caller workflows from `@v2` to `@v3`.

### What counts as breaking

- Removing or renaming an input/secret
- Changing default behavior (e.g. default `risk_threshold`)
- Changing the output format of `review-result.json` in ways that break the gate
- Changing the `scan-results.json` key structure
- Changing the S3 key structure or CSV columns
- Changing slash command names (`/accept-risk`, `/false-positive`)

### What is non-breaking

- Improving the Gemini prompt
- Adding new optional inputs with defaults
- Fixing bugs in the Python scripts
- Updating tool versions (Semgrep, Gitleaks, Checkov)
- Adding new fields to the review JSON (as long as existing fields remain)
- Adding new slash commands (as long as existing ones still work)
- Adjusting the proximity window for diff classification

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
2. Have the repo owner create `.github/workflows/security-review.yml` per the README (pointing at `@v2`)
3. (Optional) Have the repo owner create `.github/workflows/pr-bouncer-commands.yml` for slash commands
4. (Optional) Set up branch protection to require the `pr-bouncer-analysis` check

---

## Diff Classification Details

The finding classification logic lives in `run_security_scans.py`:

1. **`parse_diff_added_lines(diff_text)`** — parses the unified diff to extract which line numbers (in the new/PR version) were added or modified in each file.

2. **`classify_finding(finding, added_lines, proximity=5)`** — checks if a finding's line number falls within `proximity` lines of any added line in the same file. If yes → `new`, otherwise → `existing`.

3. **`split_findings(findings, added_lines)`** — splits a list of tool findings into `(new, existing)` tuples.

The **proximity window** (default: 5 lines) exists because static tools sometimes report issues a few lines away from the actual change — for example, Semgrep might flag a function signature when the vulnerable code is in the body a few lines below. The window ensures these don't get misclassified as existing.

Path normalization handles tools that report paths with leading `./` or `/` prefixes (common with Checkov).

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

### v2 S3 format changes

**`tokens/` CSV columns (v2):**
`timestamp, repo, pr, risk_score, existing_risk_score, prompt_tokens, completion_tokens, cached_tokens, total_tokens`

**Review JSON additions (v2):**
- Top-level `existing_risk_score` field
- `scope: "NEW"/"EXISTING"` on each `finding_evaluations` entry
- `scope: "NEW"/"EXISTING"` on each `critical_issues` entry

**Summary JSON additions (v2):**
- `existing_risk_score` in `review_summary`
- `existing_critical_count` in `review_summary`

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

The scan runner will print the new/existing split in the summary. The reviewer prints the full comment to stdout in local mode instead of posting to GitHub.

### Verifying diff classification locally

To test the new/existing classification without running the full pipeline:

```python
from scripts.run_security_scans import parse_diff_added_lines, classify_finding

with open('pr-diff.txt') as f:
    diff = f.read()

added = parse_diff_added_lines(diff)
for filepath, lines in added.items():
    print(f"{filepath}: {sorted(lines)}")

# Test a specific finding
finding = {'file': 'app/views.py', 'line': 42}
print(classify_finding(finding, added))  # 'new' or 'existing'
```

### Slash commands (pr-commands workflow)

The commands workflow is harder to test locally since it depends on GitHub's `issue_comment` event. Test it by:

1. Deploying to a test repo using a test tag (see "Testing changes before release" above)
2. Opening a PR that triggers a security review
3. Commenting `/accept-risk test reasoning` or `/false-positive test reasoning`
4. Verifying the response comment, label, and status check override
5. If S3 is enabled, checking the `decisions/` path in the bucket