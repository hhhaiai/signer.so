# Findings & Decisions

## Requirements
- Source: `https://github.com/adjust/adjust_signature_sdk/releases`
- Destination: `/Users/sanbo/Desktop/signer.so/adjust_signature_sdk`
- Scope: all released versions and all SDK assets attached to those releases.
- Example current asset families include Android AAR, iOS static archive ZIP, iOS/tvOS dynamic XCFramework ZIP, and iOS/tvOS static XCFramework ZIP.
- Completion requires checking the complete local set and exact file sizes against GitHub release metadata.

## Research Findings
- GitHub CLI is authenticated and the official Releases API is accessible.
- As of 2026-07-15, the official API reports 29 published releases, 91 assets, and 95,732,412 total bytes.
- Asset counts: four newest releases have 4 assets; the other 25 releases have 3 assets each.
- Older releases legitimately lack the newer iOS/tvOS static XCFramework asset; still older releases use an iOS-only dynamic XCFramework filename.
- Seven filenames occur in both a beta tag and its later final tag (`v3.47.0-beta`/`v3.47.0` and `v3.67.0-beta`/`v3.67.0`). Flat storage would overwrite those release entries.
- The v3.67.0 beta/final duplicate names have identical SHA-256 digests according to GitHub. The v3.47.0 beta assets predate GitHub digest metadata, so both copies will be retained and locally hashed.
- Fresh final API verification confirmed 29 releases, 91 assets, and 95,732,412 bytes.
- All 19 assets for which GitHub exposes SHA-256 metadata matched locally.
- All 91 AAR/ZIP assets passed `unzip -tqq` archive-integrity checks.
- Local SHA-256 comparison confirmed all three v3.47.0 beta/final same-name pairs are byte-identical.

## Technical Decisions
| Decision | Rationale |
|----------|-----------|
| Treat actual release assets as authoritative | Historical releases may not all use the same four-file naming/layout convention. |
| Create one subdirectory per release tag | This retains every asset entry, including beta/final duplicates, while keeping all downloads inside the requested directory. |

## Issues Encountered
| Issue | Resolution |
|-------|------------|
| `agent-reach check-update` was not installed as a shell executable | Continued with the documented authenticated GitHub CLI backend; only the optional skill-version check was unavailable. |

## Resources
- https://github.com/adjust/adjust_signature_sdk/releases
- GitHub API endpoint: `repos/adjust/adjust_signature_sdk/releases`
