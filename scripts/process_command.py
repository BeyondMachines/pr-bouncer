#!/usr/bin/env python3
"""
Processes /accept-risk and /false-positive slash commands from PR comments.
Posts a response comment, updates the pr-bouncer-analysis commit status,
and optionally saves the decision to S3.

Required environment variables:
    GITHUB_TOKEN
    COMMENT_BODY
    COMMENT_AUTHOR
    PR_NUMBER
    REPO
    GITHUB_OUTPUT

Optional environment variables (S3 upload):
    UPLOAD_TO_S3        — set to "true" to enable
    AWS_ACCESS_KEY_ID
    AWS_SECRET_ACCESS_KEY
    AWS_DEFAULT_REGION
"""

import json
import os
import subprocess
import sys
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def sanitize_csv(value: str) -> str:
    """Prevent CSV formula injection and strip newlines."""
    s = str(value).strip().replace('\n', ' ').replace('\r', ' ')
    return ("'" + s) if s and s[0] in ('=', '+', '-', '@', '|', '%') else s


def gh(*args: str) -> subprocess.CompletedProcess:
    """Run a gh CLI command, inheriting the environment (includes GITHUB_TOKEN)."""
    return subprocess.run(['gh', *args], check=True, text=True, capture_output=True)


def gh_out(key: str, value: str) -> None:
    """Write a key=value pair to GITHUB_OUTPUT."""
    # Newlines in values break the output file format
    safe_value = value.replace('\n', ' ').replace('\r', ' ')
    with open(os.environ['GITHUB_OUTPUT'], 'a') as f:
        f.write(f'{key}={safe_value}\n')


# ---------------------------------------------------------------------------
# Command parsing
# ---------------------------------------------------------------------------

def parse_command(body: str) -> tuple[str | None, str]:
    """
    Returns (command, reasoning) where command is 'accept-risk',
    'false-positive', or None if no recognised command is found.
    """
    if '/accept-risk' in body:
        return 'accept-risk', body.replace('/accept-risk', '').strip()
    if '/false-positive' in body:
        return 'false-positive', body.replace('/false-positive', '').strip()
    return None, ''


# ---------------------------------------------------------------------------
# GitHub actions
# ---------------------------------------------------------------------------

def post_comment(pr: str, repo: str, command: str, author: str, reasoning: str) -> None:
    if command == 'accept-risk':
        body = (
            f'✅ **Risk accepted** by @{author}.\n\n'
            f'**Reason:** {reasoning or "No reason provided."}\n\n'
            'The security gate has been overridden for this PR.'
        )
    else:
        body = (
            f'📝 **False positive flagged** by @{author}.\n\n'
            f'**Reason:** {reasoning or "No reason provided."}\n\n'
            'The security gate has been overridden for this PR.'
        )
    # body is passed as a positional argument — never shell-interpolated
    gh('pr', 'comment', pr, '--repo', repo, '--body', body)


def update_commit_status(pr: str, repo: str, command: str, author: str) -> None:
    result = gh('pr', 'view', pr, '--repo', repo, '--json', 'headRefOid', '-q', '.headRefOid')
    sha = result.stdout.strip()
    description = f"{command.replace('-', ' ').title()} by {author}"
    gh('api', f'repos/{repo}/statuses/{sha}',
       '-f', 'state=success',
       '-f', 'context=pr-bouncer-analysis',
       '-f', f'description={description}')


# ---------------------------------------------------------------------------
# S3 upload
# ---------------------------------------------------------------------------

def save_to_s3(repo: str, pr: str, command: str, author: str, reasoning: str) -> None:
    try:
        import boto3
    except ImportError:
        print('⚠️  boto3 not installed — skipping S3 upload')
        return

    now = datetime.now(timezone.utc)
    repo_key = repo.replace('/', '__')
    bucket = 'bm-pr-reviews'

    decision = {
        'type': command,
        'repo': repo,
        'pr_number': int(pr),
        'author': author,
        'reasoning': reasoning,
        'timestamp': now.isoformat(),
    }

    s3 = boto3.client('s3')

    # Individual decision JSON
    key = f'decisions/{now.year}/{now.month:02d}/{now.day:02d}/{repo_key}__PR-{pr}__{command}__{author}.json'
    s3.put_object(
        Bucket=bucket, Key=key,
        Body=json.dumps(decision, indent=2),
        ContentType='application/json',
    )
    print(f'Decision saved: {key}')

    # Monthly decisions CSV
    csv_key = f'decisions/{now.year}/{now.month:02d}.csv'
    row = ','.join([
        now.isoformat(),
        sanitize_csv(repo),
        sanitize_csv(pr),
        sanitize_csv(command),
        sanitize_csv(author),
        sanitize_csv(reasoning),
    ]) + '\n'

    try:
        existing = s3.get_object(Bucket=bucket, Key=csv_key)['Body'].read().decode()
        if not existing.endswith('\n'):
            existing += '\n'
    except s3.exceptions.NoSuchKey:
        existing = 'timestamp,repo,pr,decision,author,reasoning\n'

    s3.put_object(Bucket=bucket, Key=csv_key, Body=existing + row, ContentType='text/csv')
    print(f'Decision logged to {csv_key}')


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    body = os.environ['COMMENT_BODY']
    author = os.environ['COMMENT_AUTHOR']
    pr = os.environ['PR_NUMBER']
    repo = os.environ['REPO']

    command, reasoning = parse_command(body)
    if command is None:
        print('No recognised command found — nothing to do.')
        return 0

    print(f'Command: /{command}')
    print(f'Author:  {author}')
    print(f'PR:      #{pr}')

    post_comment(pr, repo, command, author, reasoning)
    print('✅ Comment posted')

    update_commit_status(pr, repo, command, author)
    print('✅ Commit status updated')

    gh_out('command', command)
    gh_out('author', author)
    gh_out('pr_number', pr)
    gh_out('reasoning', reasoning)

    if os.environ.get('UPLOAD_TO_S3', '').lower() == 'true':
        print('Uploading decision to S3...')
        save_to_s3(repo, pr, command, author, reasoning)

    return 0


if __name__ == '__main__':
    sys.exit(main())