# Auth Sub-Skills Index

> **Parent Skill**: S-038 (auth_simulator) | **Phase**: 3
> **Directory**: `skills/auth/`

## Overview

The auth_simulator skill (S-038) is decomposed into 9 fine-grained sub-skills. Each sub-skill handles one specific aspect of credential acquisition and validation. They can be invoked individually or orchestrated as a pipeline.

## Sub-Skill Registry

| ID | File | Title | Purpose |
|----|------|-------|---------|
| S-038a | `auth_type_detector.md` | Auth Type Auto-Detection | Scan source code signatures to classify the authentication mechanism |
| S-038b | `auto_registration_executor.md` | Auto-Registration & Login | Register a test account, login, extract cookie/token |
| S-038c | `admin_user_injector.md` | Direct Database Admin Insertion | Insert admin user into DB when registration cannot yield admin |
| S-038d | `jwt_signer.md` | JWT Signing Reverse-Engineer | Extract JWT_SECRET, self-sign tokens at multiple privilege levels |
| S-038e | `oauth2_token_fetcher.md` | OAuth2 Token Acquisition | Obtain tokens via Password / Client Credentials / PAT grants |
| S-038f | `api_key_discoverer.md` | API Key Extraction | Discover API keys from database and config files |
| S-038g | `multi_tenant_provisioner.md` | Multi-Tenant Credential Isolation | Create per-tenant accounts for cross-tenant testing |
| S-038h | `role_extractor.md` | Multi-Role Credential Acquisition | Extract role definitions, batch-create per-role accounts |
| S-038i | `credential_validator.md` | Credential Validation | Validate all acquired credentials against live endpoints |

## Execution Flow

```
┌─────────────────┐
│  S-038a          │  ① Detect auth type(s)
│  Auth Type       │
│  Detector        │
└────────┬────────┘
         │ auth_type_report.json
         ▼
┌─────────────────────────────────────────────────────┐
│  Select strategies based on detected type            │
│                                                      │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌─────────┐ │
│  │ S-038b   │ │ S-038c   │ │ S-038d   │ │ S-038e  │ │  ② Acquire
│  │ Auto-Reg │ │ Admin DB │ │ JWT Sign │ │ OAuth2  │ │  credentials
│  └──────────┘ └──────────┘ └──────────┘ └─────────┘ │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐             │
│  │ S-038f   │ │ S-038g   │ │ S-038h   │             │
│  │ API Key  │ │ Tenant   │ │ Roles    │             │
│  └──────────┘ └──────────┘ └──────────┘             │
└────────────────────┬────────────────────────────────┘
                     │ credentials.json
                     ▼
              ┌──────────────┐
              │  S-038i       │  ③ Validate all credentials
              │  Credential   │
              │  Validator    │
              └──────────────┘
                     │
                     ▼
              credentials.json (validated)
```

## Input / Output Summary

| Stage | Sub-Skills | Input | Output |
|-------|-----------|-------|--------|
| Detection | S-038a | Source code | `auth_type_report.json` |
| Acquisition | S-038b–S-038h | Route map, DB, env, source | `credentials.json` (sections populated per strategy) |
| Validation | S-038i | `credentials.json` + live endpoints | `credential_validation.json` + updated `credentials.json` |

## Strategy Selection Matrix

| Detected Auth Type | Primary Sub-Skill | Fallback Sub-Skill |
|--------------------|-------------------|---------------------|
| Laravel Session | S-038b → S-038c | S-038h |
| JWT | S-038d | S-038b + S-038d |
| OAuth2 (Passport) | S-038e | S-038b + S-038e |
| Laravel Sanctum | S-038e | S-038b |
| HTTP Basic | S-038b | S-038c |
| API Key | S-038f | — |
| Multi-Tenant | S-038g | S-038b + S-038g |
| WordPress | S-038b | S-038c |
| HMAC Signature | S-038f | — |
| Unknown | S-038b → S-038c | S-038f |
