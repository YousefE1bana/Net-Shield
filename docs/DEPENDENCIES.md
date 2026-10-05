# Dependency license inventory

Recorded from installed distribution metadata for the exact pins on 2026-10-05. NetShield's Apache-2.0 license applies to project source; dependencies retain their own license terms. Runtime wheels are installed by pip rather than vendored into this repository. Their distribution license files remain authoritative, especially for bundled components (for example Pillow and PDFium).

| Distribution | Pin | Use | Declared license / metadata |
|---|---|---|---|
| Flask | 3.1.3 | Runtime | BSD-3-Clause |
| Werkzeug | 3.1.8 | Runtime | BSD-3-Clause |
| scapy | 2.7.0 | Runtime | GPL-2.0-only |
| reportlab | 5.0.1 | Runtime | BSD license (see license.txt for details), Copyright (c) 2000-2025, ReportLab Inc. |
| waitress | 3.0.2 | Runtime | ZPL 2.1 |
| blinker | 1.9.0 | Runtime | License :: OSI Approved :: MIT License |
| charset-normalizer | 3.5.2 | Runtime | MIT |
| click | 8.5.0 | Runtime | BSD-3-Clause |
| colorama | 0.4.6 | Runtime | License :: OSI Approved :: BSD License |
| itsdangerous | 2.2.0 | Runtime | License :: OSI Approved :: BSD License |
| jinja2 | 3.1.6 | Runtime | License :: OSI Approved :: BSD License |
| markupsafe | 3.0.4 | Runtime | BSD-3-Clause |
| pillow | 12.3.0 | Runtime | MIT-CMU |
| pytest | 9.1.1 | Development | MIT |
| ruff | 0.16.10 | Development | MIT |
| pypdf | 6.19.0 | Development | BSD-3-Clause |
| pypdfium2 | 5.9.0 | Development | BSD-3-Clause, Apache-2.0, dependency licenses |
| iniconfig | 2.3.0 | Development | MIT |
| packaging | 26.3 | Development | Apache-2.0 OR BSD-2-Clause |
| pluggy | 1.6.0 | Development | MIT |
| pygments | 2.21.0 | Development | BSD-2-Clause |

The build backend is setuptools 82.0.1 (MIT metadata). Browser QA optionally uses separately installed Playwright; no browser binary or Playwright distribution is bundled. Linux deployment uses separately installed systemd, Nginx, OpenSSL, iproute2 and nftables under their upstream licenses. NetShield does not relicense these tools. GitHub Actions are referenced by immutable commit IDs and are not vendored source.

Preserve upstream license/notices when redistributing packaged dependencies or an appliance image. This inventory records metadata, not a legal certification or proof of contributor assignments. Maintainer source-license choice is documented in [LICENSE-DECISION](LICENSE-DECISION.md).
