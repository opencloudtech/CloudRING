# Developer Certificate of Origin

CloudRING accepts signed-off commits from contributors who are authorized to submit the work under the Apache License 2.0 (`Apache-2.0`).

Use a `Signed-off-by:` line only when the contribution is your original work, or you have the right to submit it, and the contribution can be distributed as part of CloudRING under Apache-2.0.

The protected `dco` check validates the author and every declared co-author
against matching trailers in pull-request, merge-queue, and protected-branch
push ranges. The same trailer records CLA assent as described in `CLA.md`.

Approved automation identities (`dependabot[bot]`, `github-actions[bot]`) are
exempt from the sign-off requirement: a bot cannot certify origin, so the
maintainer who configured the automation and approves the merge carries that
responsibility. The exemption matches the exact canonical commit identity and
is defined in `.github/scripts/validate-contribution-range.sh`; extending it
is a governance change, not an editing convenience.

Maintainers may ask for provenance or authorization details when a contribution touches public contracts, licensing, trademarks, generated code, security, deployment automation, or material that could have come from a private environment.
