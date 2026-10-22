# TrustVault - AI Usage Log

This file records AI assistance used during the development
of TrustVault. Entries summarize actual assistance and
describe how the resulting changes were checked.

## Entry 1 - 21 October 2026

**Task:** Fix indentation errors in Django views.

**Prompt summary:** Asked for help correcting indentation in
the dashboard, upload, download, sharing, and revocation views.

**AI assistance:** Reviewed the provided code and suggested
corrected code.

**Verification:** Ran `python manage.py check` and
`python manage.py test documents`; both passed.

**Related commit:** Add the real Git commit URL here.

## Entry 2 - 21 October 2026

**Task:** Add document-title search.

**Prompt summary:** Asked how to implement document search
in the dashboard.

**AI assistance:** Suggested using a GET query parameter
and Django's case-insensitive title filter.

**Verification:** Tested the search in the local dashboard.

**Related commit:** Add the real Git commit URL here.

## Entry 3 - 21 October 2026

**Task:** Understand Django server output.

**Prompt summary:** Asked what the HTTP request messages
printed in the terminal meant.

**AI assistance:** Explained HTTP status codes and redirects.

**Verification:** Checked dashboard and search requests
in the browser.

**Related commit:** Add a relevant commit URL if available.

## Entry 4 - 21 October 2026

**Task:** Review hiring-challenge requirements.

**Prompt summary:** Asked for an estimate of project completion
against the challenge requirements.

**AI assistance:** Identified functionality, security,
documentation, testing, and deployment items to review.

**Verification:** Compared the suggested tasks with the
known project status.

**Related commit:** Add a relevant commit URL if available.

## Entry 5 - 21 October 2026

**Task:** Prepare a threat model.

**Prompt summary:** Asked for help creating `THREATS.md`.

**AI assistance:** Helped draft a threat model covering
unauthorized downloads, sharing, revoked access, malicious
uploads, audit logs, and secret management.

**Verification:** Review the threat model against the
actual implementation before submission.

**Related commit:** https://github.com/danaboinavarshini-2005/TrustVault/commit/57f09eebcfe5b901ae65b6de8413ba6f5f1234fc