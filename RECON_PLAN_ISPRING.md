# Recon: *.ispring.ru — Plan & API Criticality Assessment

> Date: 2026-10-10
> Scope: `*.ispring.ru` (iSpring Learn LMS platform)
> Subscription required: Business plan

---

## 1. Discovered Infrastructure

| Subdomain / Host | Purpose | Notes |
|---|---|---|
| `www.ispring.ru` | Marketing site, product pages | Static content, blog |
| `docs.ispring.ru` | Documentation (Confluence) | API docs, guides |
| `api-learn.ispringlearn.ru` | **REST API host (RU)** | Primary API surface |
| `api-learn.ispringlearn.com` | REST API host (International) | Same API, different region |
| `api-learn.ispringlearn.eu` | REST API host (EU) | GDPR-compliant hosting |
| `*.ispringlearn.com` | Customer LMS instances | `<account>.ispringlearn.com` |
| `webinar.ispringlearn.com` | Webinar service | Tokbox/OpenTok integration |

---

## 2. Authentication

| Endpoint | Method | Description | Criticality |
|---|---|---|---|
| `/api/v3/token` | POST | Generate access token from `client_id` + `client_secret` | **CRITICAL** |

- Token передаётся в заголовке `Authorization: Bearer <token>`
- Ключи API создаёт только Account Owner / Account Administrator
- OpenAPI spec: `https://api-learn.ispringlearn.ru/docs/rest-api`
- SOAP WSDL: `api_2.0.wsdl`, `api_3.0.wsdl` (legacy)

---

## 3. Full API Endpoint Map & Criticality

### Legend

| Level | Meaning |
|---|---|
| **CRITICAL** | Authentication, PII exposure, account takeover, data destruction |
| **HIGH** | Mass data access, privilege escalation, business logic abuse |
| **MEDIUM** | Limited data modification, non-sensitive data reads |
| **LOW** | Read-only, public-like data, informational |

---

### 3.1 User Management — CRITICAL

| # | Method | Path | Description | Criticality |
|---|---|---|---|---|
| 1 | GET | `/user` | List all users | **CRITICAL** |
| 2 | POST | `/user` | Create new user | **CRITICAL** |
| 3 | GET | `/user/{userId}` | Get user profile (PII) | **CRITICAL** |
| 4 | POST | `/user/{userId}` | Update user profile | **CRITICAL** |
| 5 | DELETE | `/user/{userId}` | Delete user | **CRITICAL** |
| 6 | POST | `/user/{userId}/password` | Change user password | **CRITICAL** |
| 7 | POST | `/user/{userId}/status` | Activate/deactivate user | **CRITICAL** |
| 8 | POST | `/users/activate` | Bulk activate users | **CRITICAL** |
| 9 | POST | `/users/deactivate` | Bulk deactivate users | **CRITICAL** |
| 10 | POST | `/users/terminate` | Bulk terminate users | **CRITICAL** |
| 11 | POST | `/users/find_existing` | Find users by criteria | **HIGH** |
| 12 | GET | `/user/{userId}/v2` | Get user profile v2 | **CRITICAL** |
| 13 | GET | `/user/v2` | List users v2 | **CRITICAL** |
| 14 | GET | `/users` | List users (deprecated) | **CRITICAL** |
| 15 | GET | `/users/v2` | List users v2 | **CRITICAL** |
| 16 | POST | `/users/v2` | List users v2 (filtered) | **CRITICAL** |
| 17 | GET | `/user/profile/fields` | User profile field schema | **MEDIUM** |
| 18 | POST | `/user/{userId}/subordination` | Change reporting chain | **HIGH** |
| 19 | POST | `/user/{userId}/scheduled_deactivation` | Schedule deactivation | **HIGH** |
| 20 | DELETE | `/user/{userId}/scheduled_deactivation` | Cancel scheduled deactivation | **HIGH** |
| 21 | POST | `/user/{userId}/scheduled_termination` | Schedule termination | **HIGH** |
| 22 | DELETE | `/user/{userId}/scheduled_termination` | Cancel scheduled termination | **HIGH** |
| 23 | POST | `/user/{userId}/groups/remove` | Remove user from groups | **HIGH** |
| 24 | GET | `/role` | List roles | **MEDIUM** |
| 25 | POST | `/user/list` | Paginated user list | **CRITICAL** |
| 26 | POST | `/users/work-leave-status` | Update work-leave statuses | **HIGH** |
| 27 | POST | `/users/work-leave-status/delete` | Remove work-leave statuses | **HIGH** |

**Risks:** Full PII enumeration, mass account takeover via password reset, privilege escalation through role/subordination manipulation, denial of service via bulk termination.

---

### 3.2 Department Management — HIGH

| # | Method | Path | Description | Criticality |
|---|---|---|---|---|
| 28 | GET | `/department` | List departments | **MEDIUM** |
| 29 | POST | `/department` | Create department | **HIGH** |
| 30 | GET | `/department/{departmentId}` | Get department info | **MEDIUM** |
| 31 | POST | `/department/{departmentId}` | Update department | **HIGH** |
| 32 | DELETE | `/department/{departmentId}` | Delete department | **HIGH** |
| 33 | GET | `/departments` | List departments (alt) | **MEDIUM** |
| 34 | POST | `/department/{departmentId}/subordination` | Change department hierarchy | **HIGH** |
| 35 | POST | `/department/{departmentId}/user/move` | Move users between departments | **HIGH** |
| 36 | POST | `/department/{parentId}/department/move` | Move sub-departments | **HIGH** |

**Risks:** Org structure manipulation, unauthorized user reassignment, data access boundary bypass.

---

### 3.3 Group Management — HIGH

| # | Method | Path | Description | Criticality |
|---|---|---|---|---|
| 37 | GET | `/group` | List groups | **MEDIUM** |
| 38 | POST | `/group` | Create group | **HIGH** |
| 39 | POST | `/group/smart` | Create smart group (auto-rules) | **HIGH** |
| 40 | POST | `/group/smart/{groupId}` | Update smart group rules | **HIGH** |
| 41 | GET | `/group/smart/{groupId}/rules` | Get smart group rules | **MEDIUM** |
| 42 | GET | `/group/{groupId}` | Get group details | **MEDIUM** |
| 43 | POST | `/group/{groupId}` | Update group | **HIGH** |
| 44 | DELETE | `/group/{groupId}` | Delete group | **HIGH** |
| 45 | POST | `/group/{groupId}/members` | Update group members | **HIGH** |
| 46 | GET | `/groups` | List groups (alt) | **MEDIUM** |

**Risks:** Unauthorized group membership modification → access to restricted content, smart group rule injection.

---

### 3.4 Content & Courses — HIGH

| # | Method | Path | Description | Criticality |
|---|---|---|---|---|
| 47 | GET | `/content` | List content (deprecated) | **HIGH** |
| 48 | GET | `/contents` | List content (deprecated) | **HIGH** |
| 49 | POST | `/contents` | List content (POST, deprecated) | **HIGH** |
| 50 | POST | `/course/list` | List courses | **HIGH** |
| 51 | GET | `/content/{contentId}` | Get content item (deprecated) | **HIGH** |
| 52 | GET | `/content/{contentId}/final_statuses` | Content completion statuses | **MEDIUM** |
| 53 | GET | `/courses/modules` | List course modules (deprecated) | **MEDIUM** |
| 54 | GET | `/course_fields` | Course field definitions | **LOW** |
| 55 | POST | `/content/create/{contentType}` | Create content item | **HIGH** |
| 56 | GET | `/course/{courseId}/modules` | List modules by course | **MEDIUM** |
| 57 | GET | `/courses_tree` | Full course tree (deprecated) | **HIGH** |
| 58 | POST | `/course/tree` | Full course tree v2 | **HIGH** |

**Risks:** IP theft (course content extraction), unauthorized content injection, content structure enumeration.

---

### 3.5 Enrollments — HIGH

| # | Method | Path | Description | Criticality |
|---|---|---|---|---|
| 59 | GET | `/enrollment` | List enrollments | **HIGH** |
| 60 | POST | `/enrollment` | Create enrollments | **HIGH** |
| 61 | GET | `/enrollments` | List enrollments (alt) | **HIGH** |
| 62 | POST | `/enrollments` | List enrollments (POST) | **HIGH** |
| 63 | GET | `/enrollment/{enrollmentId}` | Get enrollment details | **MEDIUM** |
| 64 | POST | `/enrollment/{enrollmentId}` | Update enrollment | **HIGH** |
| 65 | POST | `/enrollment/{enrollmentId}/reenroll` | Re-enroll learner | **HIGH** |
| 66 | POST | `/enrollment/delete` | Delete enrollments | **HIGH** |

**Risks:** Unauthorized course assignment, enrollment manipulation to bypass mandatory training, compliance violations.

---

### 3.6 Assignments & Grading — HIGH

| # | Method | Path | Description | Criticality |
|---|---|---|---|---|
| 67 | GET | `/assignments` | List assignments | **MEDIUM** |
| 68 | GET | `/assignment/{id}/attempts/ungraded` | Ungraded attempts | **MEDIUM** |
| 69 | POST | `/assignments/attempts/grade` | Grade attempts | **HIGH** |

**Risks:** Grade manipulation, fraudulent completion of mandatory training.

---

### 3.7 Statistics & Results — HIGH

| # | Method | Path | Description | Criticality |
|---|---|---|---|---|
| 70 | POST | `/statistics/course` | Update course completion status | **HIGH** |
| 71 | POST | `/statistics/module` | Update module statuses | **HIGH** |
| 72 | DELETE | `/statistics/module` | Reset module statistics | **HIGH** |
| 73 | GET | `/learners/results` | Learner course results | **HIGH** |
| 74 | GET | `/learners/modules/results` | Learner module results | **HIGH** |

**Risks:** Falsification of training records, compliance fraud, evidence tampering.

---

### 3.8 Reports — MEDIUM

| # | Method | Path | Description | Criticality |
|---|---|---|---|---|
| 75 | GET | `/report/active-users-by-period` | Active users report | **MEDIUM** |
| 76 | GET | `/report/answer-breakdown` | Quiz answer breakdown | **MEDIUM** |

**Risks:** User activity profiling, quiz answer leakage.

---

### 3.9 Webhooks — CRITICAL

| # | Method | Path | Description | Criticality |
|---|---|---|---|---|
| 77 | POST | `/webhook/register` | Register subscriber | **CRITICAL** |
| 78 | POST | `/webhook/code/send` | Send confirmation code | **HIGH** |
| 79 | POST | `/webhook/confirm` | Confirm callback URL | **CRITICAL** |
| 80 | POST | `/webhook/disable` | Disable subscriber | **HIGH** |
| 81 | POST | `/webhook/enable` | Enable subscriber | **HIGH** |
| 82 | POST | `/webhook/settings/change` | Change subscriber settings | **CRITICAL** |
| 83 | POST | `/webhook/remove` | Remove subscriber | **HIGH** |
| 84 | POST | `/webhook/subscribe` | Add event subscription | **HIGH** |
| 85 | POST | `/webhook/unsubscribe` | Remove event subscription | **HIGH** |
| 86 | GET | `/webhook/subscription/list` | List subscriptions | **MEDIUM** |
| 87 | GET | `/webhook/subscriber/info` | Get subscriber info | **MEDIUM** |

**Risks:** Data exfiltration via rogue webhook, event interception (user registrations, completions, grades), SSRF through callback URL, webhook takeover.

Signature: `X-Hub-Signature` (SHA-256).

---

### 3.10 Certificates — MEDIUM

| # | Method | Path | Description | Criticality |
|---|---|---|---|---|
| 88 | GET | `/certificate/{issuedCertificateId}` | Get issued certificate | **MEDIUM** |

**Risks:** Certificate forgery verification, PII in certificate metadata.

---

### 3.11 Gamification / Points — MEDIUM

| # | Method | Path | Description | Criticality |
|---|---|---|---|---|
| 89 | GET | `/gamification/points` | List users with points | **MEDIUM** |
| 90 | POST | `/gamification/points/award` | Award points | **MEDIUM** |
| 91 | POST | `/gamification/points/withdraw` | Withdraw points | **MEDIUM** |

---

### 3.12 Learning Tracks — LOW

| # | Method | Path | Description | Criticality |
|---|---|---|---|---|
| 92 | GET | `/learning_track/courses` | List courses in tracks | **LOW** |

---

### 3.13 Quizzes — MEDIUM

| # | Method | Path | Description | Criticality |
|---|---|---|---|---|
| 93 | GET | `/quizzes` | List quizzes | **MEDIUM** |

---

### 3.14 Job Training (OJT) — MEDIUM

| # | Method | Path | Description | Criticality |
|---|---|---|---|---|
| 94 | POST | `/job-training/checklist/sessions/list` | Checklist sessions | **MEDIUM** |
| 95 | POST | `/job-training/sessions/result/list` | Session results | **MEDIUM** |
| 96 | POST | `/job-training/completed-session/criterion-group/result/list` | Criterion group results | **MEDIUM** |
| 97 | POST | `/job-training/completed-session/criterion/result/list` | Criterion results | **MEDIUM** |

---

### 3.15 Performance Management: Competencies — HIGH

| # | Method | Path | Description | Criticality |
|---|---|---|---|---|
| 98 | GET | `/performance-management/competencies/scale/list` | List scales | **LOW** |
| 99 | POST | `/performance-management/competencies/scale/create` | Create scale | **MEDIUM** |
| 100 | POST | `/performance-management/competencies/scale/{id}/change` | Change scale | **MEDIUM** |
| 101 | POST | `/performance-management/competencies/group/create` | Create group | **MEDIUM** |
| 102 | POST | `/performance-management/competencies/group/{id}/rename` | Rename group | **LOW** |
| 103 | POST | `/performance-management/competencies/group/batch-move` | Move groups | **MEDIUM** |
| 104 | POST | `/performance-management/competencies/competency/batch-move` | Move competencies | **MEDIUM** |
| 105 | GET | `/performance-management/competencies/group/list` | List groups | **LOW** |
| 106 | POST | `/performance-management/competencies/competency/list` | List competencies | **LOW** |
| 107 | POST | `/performance-management/competencies/competency/create` | Create competency | **MEDIUM** |
| 108 | POST | `/performance-management/competencies/competency/{id}/change` | Change competency | **MEDIUM** |
| 109 | POST | `.../competency/{id}/indicator/create` | Create indicator | **MEDIUM** |
| 110 | POST | `.../competency/{id}/indicator/{iid}/change` | Change indicator | **MEDIUM** |
| 111 | POST | `/performance-management/competencies/profile/list` | List profiles | **LOW** |

---

### 3.16 Performance Management: Appraisal (360°) — HIGH

| # | Method | Path | Description | Criticality |
|---|---|---|---|---|
| 112 | POST | `.../appraisal/session/list` | List sessions | **MEDIUM** |
| 113 | POST | `.../appraisal/session/create` | Create session | **HIGH** |
| 114 | GET | `.../appraisal/session/{id}/info` | Full session info | **HIGH** |
| 115 | POST | `.../appraisal/session/{id}/update` | Update session | **HIGH** |
| 116 | POST | `.../appraisal/session/{id}/start` | Start session | **HIGH** |
| 117 | POST | `.../appraisal/session/{id}/restart` | Restart session | **HIGH** |
| 118 | POST | `.../appraisal/session/{id}/complete` | Complete session | **HIGH** |
| 119 | POST | `.../appraisal/session/{id}/notification/change` | Change notifications | **MEDIUM** |
| 120 | GET | `.../appraisal/session/{id}/employee-card/list` | Employee cards | **HIGH** |
| 121 | POST | `.../appraisal/session/{id}/employee-card/add` | Add employee cards | **HIGH** |
| 122 | POST | `.../appraisal/session/{id}/employee-card/remove` | Remove employee cards | **HIGH** |
| 123 | POST | `.../appraisal/session/{id}/employee-card/reviewer/replace` | Replace reviewers | **HIGH** |
| 124 | POST | `.../appraisal/session/{id}/employee-card/reviewer/remove` | Remove reviewers | **HIGH** |
| 125 | GET | `.../appraisal/session/{id}/review/list` | List reviews | **HIGH** |
| 126 | GET | `.../appraisal/session/{id}/results` | Session results | **HIGH** |
| 127 | GET | `.../appraisal/session/{id}/content/competencies` | Session competencies | **MEDIUM** |
| 128 | POST | `.../appraisal/session/{id}/user/attributes/list` | User attributes | **MEDIUM** |
| 129 | POST | `.../appraisal/session/{id}/question/add` | Add question | **MEDIUM** |
| 130 | POST | `.../appraisal/session/{id}/question/{qid}/update` | Update question | **MEDIUM** |
| 131 | POST | `.../appraisal/session/{id}/question/change-order` | Reorder questions | **LOW** |
| 132 | POST | `.../appraisal/session/{id}/question/{qid}/remove` | Remove question | **MEDIUM** |
| 133 | POST | `.../appraisal/session/{id}/permissions/add` | Add permissions | **HIGH** |
| 134 | POST | `.../appraisal/session/{id}/permissions/remove` | Remove permissions | **HIGH** |

**Risks:** HR data tampering, 360-review manipulation, employee evaluation fraud.

---

### 3.17 Training — MEDIUM

| # | Method | Path | Description | Criticality |
|---|---|---|---|---|
| 135 | GET | `/training/{trainingId}` | Get training info | **MEDIUM** |
| 136 | GET | `/training/session/{sessionId}` | Get training session | **MEDIUM** |

---

### 3.18 Tasks (Async) — LOW

| # | Method | Path | Description | Criticality |
|---|---|---|---|---|
| 137 | GET | `/task/{taskId}/status` | Async task status | **LOW** |

---

## 4. SOAP API (Legacy)

Available via `api_2.0.wsdl` / `api_3.0.wsdl`. Covers:

| Category | Operations | Criticality |
|---|---|---|
| User Management | CRUD, password, activation | **CRITICAL** |
| Group Management | CRUD, members | **HIGH** |
| Department Management | CRUD, hierarchy | **HIGH** |
| Content Management | CRUD, upload | **HIGH** |
| Assignment Management | CRUD | **HIGH** |
| Points Management | Award, withdraw | **MEDIUM** |
| Event Management | List, subscribe | **MEDIUM** |

**Note:** SOAP API is legacy; test for lack of deprecation enforcement (both APIs active simultaneously = double attack surface).

---

## 5. Work Plan (Priority Order)

### Phase 1 — CRITICAL (Week 1)

| # | Task | Target | Goal |
|---|---|---|---|
| 1.1 | Auth token lifecycle | `POST /api/v3/token` | Token expiration, revocation, scope limits, brute-force resistance |
| 1.2 | IDOR on user endpoints | `/user/{userId}`, `/user/{userId}/password` | Horizontal privilege escalation between users |
| 1.3 | Bulk user operations | `/users/terminate`, `/users/deactivate`, `/users/activate` | Mass account manipulation without proper authz |
| 1.4 | Webhook SSRF | `/webhook/register`, `/webhook/confirm` | SSRF via callback URL, internal network scanning |
| 1.5 | Webhook data exfil | `/webhook/subscribe` | Register rogue subscriber to exfiltrate events |
| 1.6 | Password change IDOR | `/user/{userId}/password` | Change arbitrary user's password |

### Phase 2 — HIGH (Week 2)

| # | Task | Target | Goal |
|---|---|---|---|
| 2.1 | Enrollment manipulation | `/enrollment`, `/enrollment/delete` | Bypass mandatory training, assign courses to arbitrary users |
| 2.2 | Statistics falsification | `/statistics/course`, `/statistics/module` | Forge completion records |
| 2.3 | Grade tampering | `/assignments/attempts/grade` | Set arbitrary grades |
| 2.4 | Department/Group escalation | `/department/*/user/move`, `/group/*/members` | Move self into privileged department/group |
| 2.5 | Content extraction | `/content/{id}`, `/course/tree` | Mass course content download |
| 2.6 | Appraisal manipulation | `.../appraisal/session/*/results` | Tamper with 360° review results |
| 2.7 | Permission escalation | `.../appraisal/session/*/permissions/add` | Grant self review permissions |

### Phase 3 — MEDIUM (Week 3)

| # | Task | Target | Goal |
|---|---|---|---|
| 3.1 | Report data leakage | `/report/*`, `/learners/results` | Unauthorized access to learner data |
| 3.2 | Certificate forgery | `/certificate/{id}` | Predictable IDs, certificate data exposure |
| 3.3 | Gamification abuse | `/gamification/points/award` | Self-award points |
| 3.4 | Competency manipulation | `/performance-management/competencies/*` | Alter competency scales/profiles |
| 3.5 | OJT result tampering | `/job-training/sessions/result/list` | Access/modify field training results |
| 3.6 | Deprecated endpoint abuse | `/content`, `/contents`, `/users`, `/courses_tree` | Old endpoints with weaker validation |

### Phase 4 — LOW (Week 4)

| # | Task | Target | Goal |
|---|---|---|---|
| 4.1 | Rate limiting | All endpoints | Absence of rate limits on sensitive operations |
| 4.2 | SOAP vs REST parity | WSDL endpoints | Inconsistent access controls between API versions |
| 4.3 | API versioning bypass | v1/v2 endpoints | Access old versions to bypass new restrictions |
| 4.4 | Error-based info leak | All endpoints | Stack traces, internal IPs, debug info in errors |
| 4.5 | Mass assignment | POST/PUT endpoints | Hidden fields accepted (role, isAdmin, etc.) |

---

## 6. Summary Statistics

| Criticality | Endpoint Count | % of Total |
|---|---|---|
| **CRITICAL** | 22 | 16% |
| **HIGH** | 58 | 42% |
| **MEDIUM** | 42 | 31% |
| **LOW** | 15 | 11% |
| **Total** | **137** | 100% |

---

## 7. Sources

- [REST API Docs (RU)](https://docs.ispring.ru/pages/viewpage.action?pageId=18808964)
- [API Overview (RU)](https://docs.ispring.ru/pages/viewpage.action?pageId=18808961)
- [OpenAPI Spec](https://api-learn.ispringlearn.ru/docs/rest-api)
- [REST API (EN)](https://docs.ispringsolutions.com/learn/rest-api-2623678.html)
- [Webhooks](https://docs.ispringsolutions.com/ispring-learn/webhook-62863671.html)
- [API Keys](https://ispringhelpdocs.com/ispring-learn/api-keys-86770535.html)
- [Access Token](https://ispringhelpdocs.com/ispring-learn/access-token-86770677.html)
- [iSpring API Profile (3rd party)](https://github.com/api-evangelist/ispring)
- [Integration Guide](https://www.ispringsolutions.com/articles/integration-of-ispring-learn-with-your-system)
