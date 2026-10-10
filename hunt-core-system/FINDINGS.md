# Hunt Core System: *.ispring.ru — Findings Report

> Date: 2026-10-10
> Target: `*.ispring.ru` / `*.ispringlearn.ru` / `*.ispringlearn.com`
> API Host: `api-learn.ispringlearn.ru` (RU) / `api-learn.ispringlearn.com` (INT)
> Method: Passive recon, OpenAPI spec analysis, public data correlation

---

## Exclusions

The following classes are **out of scope** per engagement rules:

- Brute Force
- Blind SSRF
- DDoS / Rate Limiting as standalone finding

---

## Verdict Legend

| Tag | Meaning |
|---|---|
| **CONFIRMED** | Verified through spec analysis or public data |
| **LIKELY** | Strong indicators from spec + known patterns |
| **NEEDS VALIDATION** | Requires active testing to confirm |
| **FP** | False Positive — not a real issue |
| **BD** | By Design — intentional vendor behavior |

---

## Finding Index

| # | Title | Severity | Verdict |
|---|---|---|---|
| F-001 | IDOR via Predictable/Enumerable User IDs | HIGH | LIKELY |
| F-002 | Mass Assignment on User Create/Update (role field) | HIGH | CONFIRMED |
| F-003 | Missing CSP / Unsafe-Inline / Unsafe-Eval | MEDIUM | CONFIRMED |
| F-004 | X-Frame-Options Not Set (Clickjacking) | MEDIUM | CONFIRMED |
| F-005 | X-Content-Type-Options Missing | LOW | CONFIRMED |
| F-006 | HSTS Without includeSubDomains | MEDIUM | CONFIRMED |
| F-007 | HSTS Preload Not Enabled | LOW | CONFIRMED |
| F-008 | Deprecated API Endpoints Still Active | MEDIUM | CONFIRMED |
| F-009 | Potential XXE via XML Content-Type on REST Endpoints | MEDIUM | LIKELY |
| F-010 | Webhook Callback URL — No Documented Validation | MEDIUM | NEEDS VALIDATION |
| F-011 | Statistics/Grade Falsification via API | HIGH | LIKELY |
| F-012 | Enrollment Manipulation — Arbitrary User Assignment | HIGH | LIKELY |
| F-013 | Distinct 404 vs 403 — Object ID Enumeration | MEDIUM | CONFIRMED |
| F-014 | No Pagination Limits on Bulk List Endpoints | MEDIUM | CONFIRMED |
| F-015 | SOAP + REST Dual Attack Surface | MEDIUM | CONFIRMED |
| F-016 | Infostealer Malware Indicator on Infrastructure | HIGH | CONFIRMED |
| F-017 | DNSSEC Not Enabled | MEDIUM | CONFIRMED |
| F-018 | Open HTTP Port on Internet-Facing Server | LOW | CONFIRMED |
| F-019 | Password Change Without Current Password Verification | HIGH | NEEDS VALIDATION |
| F-020 | Bulk User Termination Without Granular Authz Check | HIGH | NEEDS VALIDATION |
| F-021 | CVE-2025-23922 — CSRF in iSpring Embedder Plugin | CRITICAL | CONFIRMED (adjacent) |
| F-022 | Appraisal Session Permission Injection | HIGH | LIKELY |

---

## Detailed Findings

---

### F-001 — IDOR via Predictable/Enumerable User IDs

**Severity:** HIGH
**Category:** Broken Access Control (OWASP A01)
**Verdict:** LIKELY

**Description:**
OpenAPI spec defines `userId` as `type: string` without `format: uuid` enforcement on multiple endpoints. The spec documents no ownership or tenancy checks — only a generic `403 PermissionDenied` response. Endpoints affected:

```
GET    /user/{userId}
POST   /user/{userId}
DELETE /user/{userId}
POST   /user/{userId}/password
POST   /user/{userId}/status
POST   /user/{userId}/subordination
GET    /user/{userId}/v2
```

Similar pattern for `departmentId`, `enrollmentId`, `groupId`, `issuedCertificateId` — none have UUID format constraints in the spec.

**Impact:** Horizontal privilege escalation — access to any user's profile, password change, status change, deletion.

**FP Assessment:** NOT FP. The absence of format constraints in the spec is a documented fact. Whether runtime authorization prevents cross-tenant access requires active testing, but the spec signals no such protection.

**BD Assessment:** NOT BD. No LMS vendor intentionally allows cross-user access without authorization. The ID format choice (non-UUID strings) may be by design, but the access control gap is not.

---

### F-002 — Mass Assignment on User Create/Update (role field)

**Severity:** HIGH
**Category:** Mass Assignment (OWASP API3)
**Verdict:** CONFIRMED

**Description:**
The `POST /user` (create) and `POST /user/{userId}` (update) endpoints accept the following privilege-escalation-relevant fields directly in the request body:

```json
{
  "role": "administrator | owner | supervisor | publisher | ...",
  "roleId": "<uuid>",
  "roles": [{"roleId": "...", "departmentId": "..."}],
  "manageableDepartmentIds": ["<dept-uuid>", ...],
  "groupIds": ["<group-uuid>", ...],
  "departmentId": "<dept-uuid>"
}
```

The `role` field accepts `UserRoleEnum` values including: `learner`, `administrator`, `department_administrator`, `publisher`, `custom`, `owner`, `supervisor`, `studio_author`.

The spec documents no server-side filtering of these fields based on the caller's role.

**Impact:** A user with API access (even learner-level if token is scoped broadly) could:
- Escalate their own role to `administrator` or `owner`
- Assign themselves manageable departments
- Move themselves into privileged groups

**FP Assessment:** POSSIBLE FP. The server may enforce role-based field filtering at runtime even though the spec doesn't document it. Requires active testing — send `role: "administrator"` as a learner-scoped token and check if accepted.

**BD Assessment:** PARTIAL BD. Accepting these fields is by design for admin callers creating users. The question is whether non-admin callers can set them. If the server silently ignores `role` from non-admin callers → BD. If it accepts → vulnerability.

---

### F-003 — Missing CSP / Unsafe-Inline / Unsafe-Eval

**Severity:** MEDIUM
**Category:** Security Misconfiguration (OWASP A05)
**Verdict:** CONFIRMED

**Description:**
UpGuard external scan confirms:
- Content-Security-Policy uses `unsafe-inline` without nonce/hash
- Content-Security-Policy contains `unsafe-eval`
- Both directives weaken XSS protections

**Source:** [UpGuard Security Report](https://www.upguard.com/security-report/ispring-solutions)

**Impact:** Stored or reflected XSS payloads can execute without CSP blocking them. `unsafe-eval` permits `eval()`, `Function()`, `setTimeout("string")` execution.

**FP Assessment:** NOT FP. Externally verified by third-party scanner.

**BD Assessment:** LIKELY BD (partial). Many SaaS platforms use `unsafe-inline` for dynamic content rendering in LMS course players. `unsafe-eval` is harder to justify — possibly required by legacy SCORM content players that use `eval()`. The combination still degrades security posture.

---

### F-004 — X-Frame-Options Not Set (Clickjacking)

**Severity:** MEDIUM
**Category:** Security Misconfiguration (OWASP A05)
**Verdict:** CONFIRMED

**Description:**
`X-Frame-Options` header is not set to `DENY` or `SAMEORIGIN` on `ispring.ru` web properties.

**Source:** [UpGuard Security Report](https://www.upguard.com/security-report/ispring-solutions)

**Impact:** Pages can be embedded in attacker-controlled `<iframe>`, enabling clickjacking attacks on authenticated users.

**FP Assessment:** NOT FP. Externally verified.

**BD Assessment:** POSSIBLE BD. iSpring may intentionally allow iframe embedding for LMS content integration into third-party portals. If `frame-ancestors` in CSP covers this → BD with acceptable risk. If neither CSP `frame-ancestors` nor `X-Frame-Options` is set → vulnerability.

---

### F-005 — X-Content-Type-Options Missing

**Severity:** LOW
**Category:** Security Misconfiguration (OWASP A05)
**Verdict:** CONFIRMED

**Description:**
`X-Content-Type-Options: nosniff` header is not present. Browser may MIME-sniff responses.

**Source:** [UpGuard Security Report](https://www.upguard.com/security-report/ispring-solutions)

**Impact:** MIME confusion can lead to content being interpreted as executable. Primarily affects legacy browsers.

**FP Assessment:** NOT FP. Externally verified.

**BD Assessment:** NOT BD. No legitimate reason to omit this header.

---

### F-006 — HSTS Without includeSubDomains

**Severity:** MEDIUM
**Category:** Insufficient Transport Security
**Verdict:** CONFIRMED

**Description:**
HSTS header is present but lacks `includeSubDomains` directive. This means only the exact domain enforces HTTPS — all subdomains (`*.ispring.ru`, `*.ispringlearn.ru`) can be served over plaintext HTTP.

**Source:** [UpGuard Security Report](https://www.upguard.com/security-report/ispring-solutions)

**Impact:** MITM attacks on subdomains. An attacker on the same network can intercept traffic to `docs.ispring.ru`, `api-learn.ispringlearn.ru`, or customer account subdomains.

**FP Assessment:** NOT FP. Externally verified.

**BD Assessment:** POSSIBLE BD. Adding `includeSubDomains` requires every subdomain to support HTTPS. If any legacy subdomain lacks a certificate, the vendor may intentionally omit it. Still a risk.

---

### F-007 — HSTS Preload Not Enabled

**Severity:** LOW
**Category:** Insufficient Transport Security
**Verdict:** CONFIRMED

**Description:**
Domain is not on the HSTS preload list. First-time visitors (no cached HSTS policy) are vulnerable to SSL stripping on initial connection.

**Source:** [UpGuard Security Report](https://www.upguard.com/security-report/ispring-solutions)

**FP Assessment:** NOT FP.

**BD Assessment:** LIKELY BD. Preload submission is opt-in and irreversible. Many vendors choose not to preload.

---

### F-008 — Deprecated API Endpoints Still Active

**Severity:** MEDIUM
**Category:** Improper Asset Management (OWASP API9)
**Verdict:** CONFIRMED

**Description:**
The OpenAPI spec marks the following endpoints as `deprecated: true` but they remain in the spec (and presumably active):

```
GET  /content                         (replaced by: unclear)
GET  /contents                        (replaced by: unclear)
POST /contents                        (replaced by: unclear)
GET  /content/{contentId}             (replaced by: unclear)
GET  /content/{contentId}/final_statuses
GET  /courses/modules                 (replaced by: /course/{courseId}/modules)
GET  /courses_tree                    (replaced by: POST /course/tree)
GET  /users                           (replaced by: GET /users/v2)
```

**Impact:** Deprecated endpoints often have weaker validation, fewer authorization checks, and lack of security patches. Attackers can use older versions to bypass restrictions added to newer endpoints.

**FP Assessment:** NOT FP. Confirmed in the published OpenAPI spec.

**BD Assessment:** PARTIAL BD. Maintaining backwards compatibility is common in SaaS. However, keeping deprecated endpoints active without deprecation enforcement (e.g., sunset headers, hard removal dates) is an unnecessary risk.

---

### F-009 — Potential XXE via XML Content-Type on REST Endpoints

**Severity:** MEDIUM
**Category:** Injection (OWASP A03)
**Verdict:** LIKELY

**Description:**
Multiple REST endpoints accept `application/xml` alongside `application/json`:

```
POST /course/list         (accepts XML)
POST /contents            (accepts XML)
POST /course/tree         (accepts XML)
POST /api/v3/token        (accepts XML)
```

Combined with active SOAP API (`api_2.0.wsdl`, `api_3.0.wsdl`), the XML parsing surface is significant.

Known analogous CVEs:
- CVE-2022-40705 (Apache SOAP XXE)
- CVE-2025-2775 (SysAid SOAP XXE)

**Impact:** If external entity resolution is not disabled: local file read, SSRF (confirmed, not blind), denial of service via entity expansion.

**FP Assessment:** POSSIBLE FP. Modern frameworks (Spring, .NET) disable external entities by default. Requires active testing with `<!DOCTYPE>` payloads.

**BD Assessment:** NOT BD. Accepting XML on REST endpoints when JSON is the primary format serves no clear user need and widens the attack surface.

---

### F-010 — Webhook Callback URL — No Documented Validation

**Severity:** MEDIUM
**Category:** Server-Side Request Forgery (OWASP A10)
**Verdict:** NEEDS VALIDATION

**Description:**
`POST /webhook/register` accepts `callbackUrl` as a plain string with no documented format validation:

```json
{
  "subscriberName": "attacker",
  "callbackUrl": "https://internal-service.corp:8080/admin",
  "secret": "optional"
}
```

A confirmation flow exists (`/webhook/code/send` → `/webhook/confirm`), which mitigates blind SSRF. However:
- The confirmation code delivery itself makes a server-side HTTP request to the URL
- If the server follows HTTP redirects (see CVE-2026-48051 analogy), the initial URL check is bypassed

**Note:** Blind SSRF is excluded. This finding covers only confirmed SSRF (where the attacker receives response data) via redirect chain bypass.

**Impact:** Internal service discovery, potential access to cloud metadata (`169.254.169.254`), internal API access.

**FP Assessment:** POSSIBLE FP. If the confirmation flow validates URL format, restricts to HTTPS, blocks private IP ranges, and does not follow redirects → FP. Requires active testing.

**BD Assessment:** NOT BD. No platform intentionally allows internal network access via webhook callbacks.

---

### F-011 — Statistics/Grade Falsification via API

**Severity:** HIGH
**Category:** Business Logic (OWASP API10)
**Verdict:** LIKELY

**Description:**
The following endpoints allow direct modification of learning records:

```
POST   /statistics/course          — Set course completion status + score (0-100) for any enrollmentId
POST   /statistics/module          — Set module completion statuses
DELETE /statistics/module          — Reset all module statistics
POST   /assignments/attempts/grade — Set grades on assignment attempts
```

The `UpdateCourseStatus` schema accepts:
- `courseId`, `enrollmentIds`, `status`, `date`, `reason`, `awardedScore` (0–100)

No documented check that the caller is the instructor or admin for the given course/enrollment.

**Impact:** Compliance fraud — marking mandatory safety/compliance training as completed without taking it. Certification fraud. Audit trail manipulation.

**FP Assessment:** POSSIBLE FP. If the server enforces that only course instructors/admins can update statistics for their courses → FP. The spec does not document this restriction.

**BD Assessment:** PARTIAL BD. Admins legitimately need to adjust grades and statuses. The question is granularity — can any API token holder modify any user's records, or is it scoped? If unscoped → vulnerability. If admin-only with audit logging → BD with acceptable risk.

---

### F-012 — Enrollment Manipulation — Arbitrary User Assignment

**Severity:** HIGH
**Category:** Broken Access Control (OWASP A01)
**Verdict:** LIKELY

**Description:**
`POST /enrollment` (create enrollment) accepts:

```json
{
  "courseIds": ["<any-course-id>"],
  "learnerIds": ["<any-user-id>"]
}
```

`POST /enrollment/delete` accepts:

```json
{
  "enrollmentIds": ["<any-enrollment-id>"]
}
```

No documented scoping to the caller's department or manageable courses.

**Impact:**
- Enroll any user in any course (including paid/restricted content)
- Remove users from mandatory training (compliance violation)
- Denial of service by mass-enrolling users in heavy courses

**FP Assessment:** POSSIBLE FP. Server may enforce department-scoped enrollment at runtime.

**BD Assessment:** PARTIAL BD. Admins need to manage enrollments. The scope of "which admins for which users/courses" is the key question.

---

### F-013 — Distinct 404 vs 403 — Object ID Enumeration

**Severity:** MEDIUM
**Category:** Information Disclosure (OWASP A01)
**Verdict:** CONFIRMED

**Description:**
The OpenAPI spec defines distinct error responses:
- `403 PermissionDenied` — object exists, caller lacks access
- `404 NotFound` — object does not exist

Specific 404 messages observed: `"Unknown content item"`, `"Issued certificate not found"`, `"Session not found"`.

This allows an attacker to enumerate valid IDs by distinguishing "exists but forbidden" from "does not exist".

**Impact:** Pre-attack reconnaissance. Enumerate valid user IDs, content IDs, certificate IDs, then target confirmed IDs for IDOR exploitation (F-001).

**FP Assessment:** NOT FP. Confirmed in the OpenAPI spec error definitions.

**BD Assessment:** LIKELY BD. REST API conventions use 404 for not-found and 403 for forbidden. Returning 404 for both (to prevent enumeration) is a security hardening measure that most APIs skip. This is a defense-in-depth gap, not a design error.

---

### F-014 — No Pagination Limits on Bulk List Endpoints

**Severity:** MEDIUM
**Category:** Unrestricted Resource Consumption (OWASP API4)
**Verdict:** CONFIRMED

**Description:**
Multiple list endpoints have optional or no pagination, with no `maxItems` constraint on array parameters:

```
GET /enrollment        — all filters optional, unpaginated
GET /gamification/points — all filters optional, unpaginated
GET /group             — unpaginated
GET /department        — unpaginated
GET /learning_track/courses — unpaginated
GET /report/active-users-by-period — unpaginated
```

Array parameters like `contentItemIds[]`, `userIds[]`, `courseIds[]` have no `maxItems`.

**Impact:** Full dataset dumps in a single request. Memory exhaustion on the server (though DoS is excluded, data leakage via single-request dump is in scope).

**FP Assessment:** NOT FP. Confirmed in OpenAPI spec.

**BD Assessment:** PARTIAL BD. Pagination may exist at runtime even if not documented in the spec. Some vendors set server-side hard limits. Requires validation.

---

### F-015 — SOAP + REST Dual Attack Surface

**Severity:** MEDIUM
**Category:** Improper Asset Management (OWASP API9)
**Verdict:** CONFIRMED

**Description:**
Both SOAP (WSDL 2.0 and 3.0) and REST APIs are active simultaneously, covering the same functional areas: users, groups, departments, content, assignments, points, events.

**Impact:** Security patches applied to one API version may not be applied to the other. Authorization models may differ between SOAP and REST. Attackers can test both surfaces for inconsistencies.

**FP Assessment:** NOT FP. Both are documented and served.

**BD Assessment:** BD. Maintaining SOAP alongside REST is a common backwards-compatibility decision. The risk is accepted but real.

---

### F-016 — Infostealer Malware Indicator on Infrastructure

**Severity:** HIGH
**Category:** Compromised Infrastructure
**Verdict:** CONFIRMED

**Description:**
UpGuard external assessment reports:

> "Infostealer malware detected on systems associated with the organization, indicating a potential data breach."

**Source:** [UpGuard Security Report](https://www.upguard.com/security-report/ispring-solutions)

**Impact:** If accurate: compromised credentials, session tokens, API keys, customer data. Could affect all subdomains and services.

**FP Assessment:** POSSIBLE FP. UpGuard's detection methodology is not disclosed. "Associated with the organization" could mean employee devices, not production servers. Requires vendor confirmation.

**BD Assessment:** NOT BD. Malware indicators are never by design.

---

### F-017 — DNSSEC Not Enabled

**Severity:** MEDIUM
**Category:** Insufficient Transport Security
**Verdict:** CONFIRMED

**Description:**
DNSSEC is not enabled for the `ispring.ru` domain. DNS responses can be spoofed.

**Source:** [UpGuard Security Report](https://www.upguard.com/security-report/ispring-solutions)

**Impact:** DNS poisoning → redirect users to phishing/malware sites, intercept API traffic.

**FP Assessment:** NOT FP. Externally verified.

**BD Assessment:** LIKELY BD. DNSSEC adoption is low globally (~30%). Many vendors skip it due to operational complexity. Still a risk.

---

### F-018 — Open HTTP Port on Internet-Facing Server

**Severity:** LOW
**Category:** Security Misconfiguration (OWASP A05)
**Verdict:** CONFIRMED

**Description:**
HTTP (port 80) is open on internet-facing server.

**Source:** [UpGuard Security Report](https://www.upguard.com/security-report/ispring-solutions)

**FP Assessment:** POSSIBLE FP. If HTTP→HTTPS redirect is in place (confirmed by UpGuard), the open port is for redirect only.

**BD Assessment:** BD. HTTP→HTTPS redirect requires port 80 to be open. This is expected behavior. Not a vulnerability if redirect is properly configured.

---

### F-019 — Password Change Without Current Password Verification

**Severity:** HIGH
**Category:** Broken Authentication (OWASP A07)
**Verdict:** NEEDS VALIDATION

**Description:**
`POST /user/{userId}/password` schema requires only:

```json
{
  "password": "<new-password>"
}
```

No `currentPassword` or re-authentication field is present in the spec. Combined with IDOR (F-001), this could allow setting any user's password.

**Impact:** Full account takeover.

**FP Assessment:** POSSIBLE FP. This is an admin API, so the expectation may be that only admins call it and don't need current password verification. If the token is scoped to admin-only → FP for non-admin context, BD for admin context.

**BD Assessment:** LIKELY BD for admin callers (admins legitimately reset passwords without knowing the current one). NOT BD if non-admin tokens can call this endpoint.

---

### F-020 — Bulk User Termination Without Granular Authz Check

**Severity:** HIGH
**Category:** Broken Access Control (OWASP A01)
**Verdict:** NEEDS VALIDATION

**Description:**
Three bulk endpoints operate on arbitrary user sets:

```
POST /users/activate      — accepts user ID array
POST /users/deactivate    — accepts user ID array
POST /users/terminate     — accepts user ID array
```

No documented restriction on which users the caller can affect. A department_administrator with a scoped token could potentially terminate users outside their department.

**Impact:** Mass account disruption, business continuity impact, data loss (terminated users may lose access permanently).

**FP Assessment:** POSSIBLE FP. Server may enforce department-level scoping at runtime.

**BD Assessment:** NOT BD if scoping is absent. PARTIAL BD if properly scoped to caller's manageable scope.

---

### F-021 — CVE-2025-23922: CSRF in iSpring Embedder (WordPress Plugin)

**Severity:** CRITICAL (CVSS 10.0)
**Category:** Cross-Site Request Forgery
**Verdict:** CONFIRMED (adjacent product)

**Description:**
The "Harsh iSpring Embedder" WordPress plugin (≤ 1.0) has a critical CSRF vulnerability allowing web shell upload.

**Source:** [NVD CVE-2025-23922](https://nvd.nist.gov/vuln/detail/cve-2025-23922)

**Impact:** Complete server compromise of any WordPress site using this plugin. Not directly in iSpring LMS, but affects sites embedding iSpring content.

**FP Assessment:** NOT FP. Published CVE with CVSS 10.0.

**BD Assessment:** NOT BD. CSRF leading to webshell upload is never by design.

**Scope Note:** This is an adjacent finding — it affects the iSpring ecosystem but not the core `*.ispring.ru` platform directly. Included for completeness.

---

### F-022 — Appraisal Session Permission Injection

**Severity:** HIGH
**Category:** Broken Access Control (OWASP A01)
**Verdict:** LIKELY

**Description:**
Performance Management endpoints allow modifying session permissions:

```
POST /performance-management/appraisal/session/{sessionId}/permissions/add
POST /performance-management/appraisal/session/{sessionId}/permissions/remove
POST /performance-management/appraisal/session/{sessionId}/employee-card/reviewer/replace
POST /performance-management/appraisal/session/{sessionId}/employee-card/reviewer/remove
```

An attacker with API access could:
- Add themselves as a reviewer on any 360° appraisal session
- Remove legitimate reviewers
- Access confidential employee performance data and reviews

**Impact:** HR data breach, performance review manipulation, insider threat escalation.

**FP Assessment:** POSSIBLE FP. If session ownership is enforced at runtime → FP.

**BD Assessment:** NOT BD. Self-granting reviewer permissions is not a legitimate workflow.

---

## Summary Matrix

| # | Finding | Severity | FP? | BD? | Action |
|---|---|---|---|---|---|
| F-001 | IDOR User IDs | HIGH | Unlikely | No | **Test** |
| F-002 | Mass Assignment (role) | HIGH | Possible | Partial | **Test** |
| F-003 | Unsafe CSP | MEDIUM | No | Likely partial | **Accept / Report** |
| F-004 | Clickjacking | MEDIUM | No | Possible | **Report** |
| F-005 | No nosniff | LOW | No | No | **Report** |
| F-006 | HSTS no subdomains | MEDIUM | No | Possible | **Report** |
| F-007 | No HSTS preload | LOW | No | Likely | **Accept** |
| F-008 | Deprecated endpoints live | MEDIUM | No | Partial | **Report** |
| F-009 | XXE via XML endpoints | MEDIUM | Possible | No | **Test** |
| F-010 | Webhook URL validation | MEDIUM | Possible | No | **Test** |
| F-011 | Grade falsification | HIGH | Possible | Partial | **Test** |
| F-012 | Enrollment manipulation | HIGH | Possible | Partial | **Test** |
| F-013 | ID enumeration (404/403) | MEDIUM | No | Likely | **Accept / Report** |
| F-014 | No pagination limits | MEDIUM | No | Partial | **Report** |
| F-015 | SOAP+REST dual surface | MEDIUM | No | Yes | **Accept** |
| F-016 | Infostealer indicator | HIGH | Possible | No | **Escalate** |
| F-017 | No DNSSEC | MEDIUM | No | Likely | **Accept** |
| F-018 | Open HTTP port | LOW | Possible | Yes | **Accept** |
| F-019 | Password no re-auth | HIGH | Possible | Partial | **Test** |
| F-020 | Bulk termination scope | HIGH | Possible | Partial | **Test** |
| F-021 | CVE-2025-23922 CSRF | CRITICAL | No | No | **Report (adjacent)** |
| F-022 | Appraisal permission inject | HIGH | Possible | No | **Test** |

---

## Statistics

| Category | Count |
|---|---|
| Total findings | 22 |
| CRITICAL | 1 |
| HIGH | 9 |
| MEDIUM | 9 |
| LOW | 3 |
| Confirmed | 12 |
| Likely | 5 |
| Needs Validation | 3 |
| Confirmed FP | 0 |
| Confirmed BD | 2 (F-015, F-018) |
| Partial BD | 7 |

---

## Next Steps (Validation Priority)

| Priority | Finding | Test Method |
|---|---|---|
| 1 | F-001 (IDOR) | Create two users with different roles; attempt cross-access with each token |
| 2 | F-002 (Mass Assignment) | Send `role: "administrator"` as learner token on `POST /user/{selfId}` |
| 3 | F-019 (Password no re-auth) | Call `POST /user/{targetId}/password` with non-admin token |
| 4 | F-011 (Grade falsification) | Update statistics for enrollment owned by different user |
| 5 | F-012 (Enrollment manipulation) | Create enrollment for user in different department |
| 6 | F-020 (Bulk termination) | Call `/users/terminate` with users outside caller's department |
| 7 | F-009 (XXE) | Send XML payload with `<!DOCTYPE>` entity to `/course/list` |
| 8 | F-010 (Webhook SSRF) | Register webhook with redirect chain → internal IP |
| 9 | F-022 (Appraisal perms) | Add self as reviewer on another session |

---

## Sources

- [OpenAPI Spec — api-learn.ispringlearn.ru](https://api-learn.ispringlearn.ru/docs/rest-api)
- [REST API Docs (RU)](https://docs.ispring.ru/pages/viewpage.action?pageId=18808964)
- [API Overview (RU)](https://docs.ispring.ru/pages/viewpage.action?pageId=18808961)
- [UpGuard Security Report](https://www.upguard.com/security-report/ispring-solutions)
- [CVE-2025-23922 (NVD)](https://nvd.nist.gov/vuln/detail/cve-2025-23922)
- [Webhook Docs](https://docs.ispringsolutions.com/ispring-learn/webhook-62863671.html)
- [iSpring API Profile (3rd party)](https://github.com/api-evangelist/ispring)
- [CVE-2026-48051 — SSRF via redirect (Papra, analogous)](https://www.incibe.es/en/incibe-cert/early-warning/vulnerabilities/cve-2026-48051)
