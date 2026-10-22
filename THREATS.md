# TrustVault — Threat Model

## 1. Project Overview

TrustVault is a Django-based document-sharing application.
Users can upload documents, download their own documents,
share documents with other users, and revoke access.

The application records selected activities in an audit log.

## 2. Assets to Protect

- Uploaded documents and their contents
- User accounts and authentication credentials
- Document ownership and access permissions
- Audit logs
- Application configuration and secret keys

## 3. Threats and Mitigations

### Threat 1: Unauthorized Document Access

**Risk:** A user attempts to download another user's document
without permission.

**Mitigation:** The download view checks document ownership
and explicitly granted read or edit access.

**Verification:** Automated tests check unauthorized downloads.

### Threat 2: Unauthorized Sharing

**Risk:** A user attempts to share a document they do not own.

**Mitigation:** The sharing view checks that the logged-in user
owns the document.

**Verification:** Automated tests check unauthorized sharing.

### Threat 3: Access After Revocation

**Risk:** A user attempts to download a document after their
permission has been revoked.

**Mitigation:** Permissions are checked for each download request.

**Verification:** An automated test checks that revoked access
blocks subsequent downloads.

### Threat 4: Malicious File Uploads

**Risk:** An attacker uploads an unexpected or oversized file.

**Current Mitigation:** The application restricts file extensions
and limits uploads to 5 MB.

**Remaining Work:** Validate actual file contents and investigate
malware scanning before production deployment.

### Threat 5: Unauthorized Permission Changes

**Risk:** A user attempts to share or revoke access to a document
without being its owner.

**Mitigation:** Sharing and revocation views restrict these
operations to the document owner and require POST requests.

**Verification:** Automated tests check unauthorized sharing
and revocation attempts.

### Threat 6: Audit Log Tampering

**Risk:** Someone with sufficient database access alters or deletes
audit records.

**Current Mitigation:** The application records selected upload,
download, sharing, and revocation events.

**Remaining Work:** Verify complete event coverage and investigate
external append-only logging or separately protected audit storage.

### Threat 7: Exposure of Application Secrets

**Risk:** Secret keys or credentials are accidentally exposed.

**Mitigation:** Keep secrets in environment variables and exclude
the local .env file from Git.

**Verification:** Check the repository and its history before
publishing it publicly.

## 4. Automated Security Tests

The project currently has seven automated tests covering:

- Owner document downloads
- Unauthorized download attempts
- Authorized shared-document downloads
- Access revocation
- Unauthorized sharing
- Unauthorized revocation
- Audit logging for document uploads

The seven tests passed in the latest recorded test run.

## 5. Known Limitations

- Production deployment and HTTPS have not been verified.
- File-content validation needs further work.
- Audit-log tamper resistance needs additional safeguards.
- Administrator activity-view functionality needs verification.
- Role separation and all permission combinations need further testing.

## 6. Security Priorities

1. Verify authentication and authorization on every document route.
2. Validate uploaded file contents and use safe storage.
3. Expand automated security tests.
4. Improve audit-log coverage and tamper resistance.
5. Configure HTTPS and secure production settings.
6. Check the Git repository for exposed secrets.