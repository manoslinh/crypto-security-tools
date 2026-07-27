---
name: jira-triage
description: "Read, triage, and act on Jira/Atlassian tickets. Use when the user provides a Jira ticket URL or asks to check/create/update tickets on a BEST, KAN, or other Atlassian board."
---

# Jira Ticket Triage and Management

## Overview

Read a Jira ticket, understand its context, find related tickets, and optionally create or update tickets. Works across multiple Atlassian instances (Bragi BEST board, Zvelto KAN board, etc.).

**Core principle:** Read first, act second. Never create or modify tickets without confirming the draft with the user (unless explicitly told to "just do it").

## When to Use

- User provides a Jira/Atlassian ticket URL (e.g., `https://bragi.atlassian.net/browse/BEST-XXXX`)
- User asks to "check the board", "raise a ticket", "what's on the backlog"
- User describes an issue and wants it filed as a ticket
- User asks to verify if a fix is in a branch/master

## Prerequisites

- Atlassian MCP tools must be available and authenticated. If not, prompt user to run `/mcp` and authenticate.
- For API-based access (curl), environment must have JIRA_BASE_URL, JIRA_EMAIL, JIRA_API_TOKEN set (typically in `.env.jira`).

## The Process

### Step 1: Fetch the Ticket

**Via MCP (preferred):**
Use `mcp__claude_ai_Atlassian_Rovo__getJiraIssue` with the ticket key.

**Via API fallback:**
```bash
curl -s -u "$JIRA_EMAIL:$JIRA_API_TOKEN" \
  -H "Content-Type: application/json" \
  "$JIRA_BASE_URL/rest/api/3/issue/<TICKET_KEY>"
```

Extract and present:
- Summary, status, assignee, priority
- Description and acceptance criteria
- Linked issues, parent ticket, sprint
- Most recent comments (especially from team members)

### Step 2: Understand the Code Context

1. Identify which project/directory the ticket relates to
2. Check git for branches mentioning the ticket key: `git branch --list "*<TICKET_KEY>*"`
3. Check if any recent commits reference it: `git log --oneline --all --grep="<TICKET_KEY>"`
4. Read relevant source files if the ticket references specific code

### Step 3: Find Related Tickets

Search for related work:

- **Same epic/parent:** Look up the parent ticket and its children
- **Same component:** Search by component label
- **Keywords:** Extract 2-3 key terms from the summary, search JQL
- **Board context:** If a board URL was provided, scan open/in-progress tickets

Present related tickets with their status so the user can see the landscape.

### Step 4: Recommend Action

Based on what was found, recommend one of:

- **Read and report:** Just understanding the ticket (default)
- **Create a new ticket:** Draft the ticket fields (summary, description, type, assignee, parent, labels) and confirm before posting
- **Update an existing ticket:** Draft the changes and confirm before applying
- **Link tickets:** Suggest parent/child/related links

### Step 5: Execute (if directed)

When the user confirms or says "just do it":

**Create ticket:**
```bash
curl -s -u "$JIRA_EMAIL:$JIRA_API_TOKEN" \
  -H "Content-Type: application/json" \
  -X POST "$JIRA_BASE_URL/rest/api/3/issue" \
  -d '{
    "fields": {
      "project": {"key": "<PROJECT_KEY>"},
      "issuetype": {"name": "Bug"},
      "summary": "<summary>",
      "description": {"type": "doc", "version": 1, "content": [...]},
      "assignee": {"id": "<ACCOUNT_ID>"},
      "priority": {"name": "Medium"}
    }
  }'
```

**Set parent/link:**
```bash
curl -s -u "$JIRA_EMAIL:$JIRA_API_TOKEN" \
  -H "Content-Type: application/json" \
  -X PUT "$JIRA_BASE_URL/rest/api/3/issue/<KEY>" \
  -d '{"fields": {"parent": {"key": "<PARENT_KEY>"}}}'
```

## Output Format

Return a concise summary:

- Ticket key and one-line summary
- Status and key details
- Related tickets (if any)
- Recommended next steps
- Draft of any ticket to be created/updated (if applicable)

## Anti-Patterns

- Do not create tickets without user confirmation (unless explicitly told to)
- Do not use em dashes in ticket descriptions (use commas, periods, or colons)
- Do not skip reading the ticket before acting on it
- Do not post API tokens or credentials in output
