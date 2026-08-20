# Security policy

Do not open a public issue containing tenant identifiers, mailbox addresses,
access tokens, private keys, SMTP passwords, webhook URLs/tokens, message bodies,
or unredacted logs.

Report a suspected vulnerability through GitHub private vulnerability reporting:

<https://github.com/sg1888/postfix-m365-relay/security/advisories/new>

Include the affected image digest/version, deployment posture, reproducible
steps using non-production data, and the smallest redacted log excerpt that
shows the problem. Never test a report against infrastructure or tenants you do
not own or have explicit permission to assess.

The project supports the latest published release. Operators should pin a tested
image digest, monitor the verifier, and regularly recreate the container from a
current image so CA roots and distro security packages are refreshed.
