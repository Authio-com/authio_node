# Changelog

All notable changes to `@useauthio/node` are documented here. This
project adheres to [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0] — 2026-10-10

### Added
- **Changing a user's email.** The email is the sign-in identifier, and
  until now the SDK had no way to change it.
  - `users.requestEmailChange(userId, { email })` emails a confirmation
    link to the new address; the change applies when it is clicked, and
    the old address is told. Requires `sk_`.
  - `users.requestOwnEmailChange(accessToken, { email, code })` does the
    same from the signed-in user's access token. `code` is their TOTP or
    recovery code, required when they have one.
  - `users.update(userId, { email, emailVerified, revokeSessions,
    notifyPreviousEmail, name, externalId })` sets fields directly. With
    `email`, the address changes immediately; use it when your app has
    already verified the address.

  Links and codes sent to the old address stop working, and a
  `user.email.changed` webhook fires. Users whose email comes from SCIM
  or SSO are refused with `email_managed_by_idp` (409).
- Types `UpdateUserInput`, `UpdatedUser`, `EmailChangeStarted`.

### Security
- Dev dependency override `source-map-js >=1.2.2` (high-severity
  advisory). Not shipped in the package.

## [0.5.0] — 2026-09-18

### Security
- **Tenant binding defaults to `AUTHIO_PROJECT_ID`.** `projectId` was
  optional, and no documentation ever showed passing it to a
  verification call — it appeared only as a client-side
  `X-Authio-Project` routing header — so in practice the check was off
  almost everywhere. Every tenant's tokens are signed with the same key
  under the same issuer and audience, so `project_id` is the only claim
  separating your users from someone else's Authio project, and sign-up
  is self-serve. Configuring the SDK the documented way now binds
  verification too.
- **A token carrying no `project_id` claim is now refused** when a
  project is configured. This was warn-and-accept so sessions minted
  before auth-core emitted the claim would not be signed out mid-flight;
  with a 30-day maximum refresh window those expired long ago, and
  meanwhile an absent claim skipped the one check that attributes a
  token to your tenant.

### Fixed
- **`apiKey` now falls back to `AUTHIO_SECRET_KEY`.** The constructor
  error has always read "Pass it directly or set AUTHIO_SECRET_KEY" and
  every docs example reads that variable, but nothing looked at it —
  passing it in code was the only thing that worked. `AuthioOptions.apiKey`
  is now optional and the resolved key is exposed as `client.apiKey`.

## [0.2.0] — 2026-06-12

### Changed
- **Renamed npm package `@authio/node` → `@useauthio/node`.** The
  original `@authio` scope could not be claimed on npm, so every Authio
  SDK now publishes under the organization scope `@useauthio`. Install
  with `npm install @useauthio/node` and update imports accordingly.
  The old `@authio/node` name is retired; releases below this entry were
  published (or prepared) under the old name and are kept for history.

