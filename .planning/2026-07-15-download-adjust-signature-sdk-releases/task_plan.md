# Task Plan: Download All Adjust Signature SDK Releases

## Goal
Download every asset from every GitHub release of adjust/adjust_signature_sdk into `adjust_signature_sdk`, then verify local names, counts, and byte sizes against the official release API.

## Current Phase
Phase 5

## Phases

### Phase 1: Requirements & Discovery
- [x] Confirm destination directory and requested scope
- [x] Fetch every release and asset from the official GitHub API
- [x] Document exact version and asset counts
- **Status:** complete

### Phase 2: Build Download Manifest
- [x] Produce a complete manifest
- [x] Check for duplicate filenames and historical asset-family changes
- **Status:** complete

### Phase 3: Download
- [x] Download all manifest assets with retries and resume support
- [x] Preserve official asset filenames under per-release subdirectories
- **Status:** complete

### Phase 4: Verification
- [x] Compare local file set against remote manifest
- [x] Compare every local byte size against GitHub metadata
- [x] Confirm no missing or mismatched assets require retry
- **Status:** complete

### Phase 5: Delivery
- [x] Record final version/file/byte totals
- [x] Report destination and verification result
- **Status:** complete

## Decisions Made
| Decision | Rationale |
|----------|-----------|
| Use GitHub Releases API as source of truth | It exposes all releases, exact asset names, URLs, and byte sizes without assuming four assets for every historical release. |
| Store assets under `adjust_signature_sdk/<release-tag>/` | Seven asset names are shared by beta and final releases; per-tag directories preserve all 91 release assets without overwrite or ambiguity. |
| Use resumable downloads and byte-size verification | The complete set may be large and must survive transient network failures. |

## Errors Encountered
| Error | Resolution |
|-------|------------|
| First planning-file patch had one mismatched context line | Re-read the generated files and applied a targeted patch using their exact content. |
| `agent-reach check-update` executable was unavailable in PATH | This optional update check does not affect GitHub access or download verification; GitHub data was fetched through the skill's documented `gh` route. |
