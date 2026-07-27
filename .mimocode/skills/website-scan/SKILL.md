---
name: website-scan
description: "Scan a website project to understand what is built, what is planned, and current status. Use when starting work on an unfamiliar website project or when asked to 'look around', 'check the project', or 'what's missing'."
---

# Website Project Scan

## Overview

Systematically audit a website project to produce a clear picture of: what is built, what is missing, what the next steps are, and current deployment status. Produces a structured status note (optionally synced to Obsidian).

**Core principle:** Parallel exploration first, synthesis second. Never guess what is missing; read the code.

## When to Use

- User asks to "scan the project", "look around", "what's built", "what's missing"
- Starting a new session on an unfamiliar website codebase
- User provides a Jira/Kanban board URL alongside a project directory
- Resuming work after context loss ("I got disconnected, where were we?")

## The Process

### Step 1: Parallel Reconnaissance

Launch these reads in parallel (subagents if available):

1. **Docs:** README.md, docs/CONTEXT.md, docs/PLAN.md, any .md files in project root
2. **Git state:** `git status`, `git log --oneline -10`, current branch, uncommitted changes
3. **Source structure:** `ls -la` at root, then scan src/ or app/ directory tree
4. **Config:** package.json (dependencies, scripts), vercel.json or netlify.toml, CI config (.github/workflows/)
5. **Jira/Kanban (if URL provided):** Read the ticket or board, understand what is tracked

### Step 2: Categorize Findings

Group everything into:

- **Built and working:** Features that exist in code and appear complete
- **Built but incomplete:** Code exists but has TODOs, missing tests, or placeholder content
- **Planned but not started:** Referenced in docs/plan/tickets but no corresponding code
- **Infrastructure:** Deployment config, CI, environment variables, staging setup
- **Blockers:** Anything preventing progress (missing env vars, auth issues, etc.)

### Step 3: Cross-Reference with Issue Tracker (if available)

If the user provided a Jira/Atlassian board URL:

1. Read open tickets on the board
2. Map tickets to code areas
3. Identify: which tickets are done, which are in progress, which are blocked
4. Flag any discrepancies between board state and code state

### Step 4: Produce Status Summary

Write a concise status note. Structure:

```
## Project: <name>

### What is built
- ...

### What is incomplete
- ...

### What is planned (not started)
- ...

### Infrastructure / Deployment
- ...

### Blockers / Risks
- ...

### Recommended next steps
1. ...
```

### Step 5: Sync to Obsidian (if vault path known)

If the user has an Obsidian vault (typically at `~/Library/Mobile Documents/iCloud~md~obsidian/Documents/MyiVault/`):

1. Check if a note already exists for this project
2. If yes, update it in place
3. If no, create a new note following the existing folder/naming convention
4. Do NOT create duplicate notes or break the existing folder structure

## Output Format

Return the status summary directly to the user. If the user asked for an Obsidian sync, confirm which file was updated.

## Anti-Patterns

- Do not start implementing without user approval (use compose:brainstorm for that)
- Do not modify code during the scan (read-only until directed otherwise)
- Do not create new documentation files unless the user asks
