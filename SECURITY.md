# Security policy

NetShield 2.0.0rc1 is a public source candidate for a controlled local SOC. Observe-only is default; automatic response is unsupported. Replay cannot authorize host response. Controlled manual Linux runtime acceptance is documented; the new installer lifecycle still needs owned-VM acceptance. No production support or enterprise certification is claimed. See [threat model](docs/THREAT-MODEL.md), [response boundaries](docs/RESPONSE.md) and [Linux acceptance](docs/LINUX-ACCEPTANCE.md).

Report potential vulnerabilities privately to the repository owner using a GitHub private vulnerability report **once enabled by the owner**, or a private contact channel the owner explicitly publishes. No email/contact address has been invented. Do not publish real captures, credentials, targets, exploit traffic or sensitive victim details in public issues. Include affected version, boundary, bounded reproduction, expected/observed result and sanitized evidence.

Do not run unrestricted traffic or firewall tests on shared machines. Tests use authored offline fixtures and explicit backend doubles. Privileged Linux namespace tests are opt-in on a dedicated owned VM; hosted PR CI does not run them. Management should remain loopback or behind an explicitly configured TLS proxy; never make the app's code tree writable by the unprivileged user when a root helper imports it.
