# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately, using GitHub's **"Report a vulnerability"** button on the repository's Security tab. Do not open a public issue. Include the version (commit), configuration details that matter, and steps to reproduce. You should get an acknowledgement within a few working days.

## Design summary

Keyport's threat model, controls and known limitations are documented in the README:
- [§4 Security model](README.md#4-security-model): threats and mitigations, cryptography, TLS/CA, authentication, authorization, hardening
- [§14 Known limitations](README.md#14-known-limitations-and-roadmap)

## Hardening checklist for operators

1. **Master key**: keep it outside the data volume and back it up separately. Anyone holding both the volume and the key can decrypt everything. Rotate with `--rotate-kek` if it may have leaked.
2. **Names before first start**: set `Edge:HostNames` / `Edge:IpAddresses` (and `Ca:PermittedDnsSuffixes` if more names will follow). The generated CA is limited to them.
3. **First admin**: read the one-time password with `podman exec keyport dotnet Keyport.Server.dll --bootstrap-password` and sign in promptly. Then create named admin accounts and retire the shared `admin`.
4. **Network**: expose :8443 to admin networks only, and each environment port only to that environment's networks. :8080 serves just `/ca.crt` and `/health`.
5. **Verify the CA fingerprint** out of band before installing `root.crt` on clients.
6. **Limit outbound reach**: set `ConnectionTest:AllowedTargets` to your database subnets, and `Proxy:AllowedUpstreams` if you use the reverse proxy. Leave `Proxy:AllowAdminPort` off.
7. **Sessions**: defaults are a 30-minute idle timeout, an 8-hour absolute limit and a 15-minute step-up for protected environments (`Keyport:Auth`). Tighten if your policy requires.
8. **Monitoring**: export the audit trail to your SIEM regularly. Watch for `auth.*` failures, `api.authenticate` denials, `secret.reveal` in protected environments, and the audit-chain health check.
9. **Updates**: rebuild the image regularly to pick up .NET and base-image security patches.
