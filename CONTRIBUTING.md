# Contributing

Keep this relay Microsoft 365-only. Provider abstractions, local delivery,
Internet-facing relay support, DKIM signing, and unrelated MTA features are out
of scope.

Before submitting a change:

1. Do not use production mailboxes, applications, tenants, credentials, or logs.
2. Add comments for security-sensitive behavior and record useful failed
   approaches without including private environment details.
3. Add a regression test for changed behavior, including its failure path.
4. Run the offline suite documented in `docs/TESTING.md`.
5. Run `git diff --check` and verify no secrets or real identifiers are present.

Pull requests must not claim Microsoft delivery, alias support, certificate
rotation, or a platform artifact is verified unless the contributor personally
observed the corresponding release-gate test. Exchange permission changes are
eventually consistent; wait two hours after a change before treating a live
result as conclusive.
