# Browser verification

`v2-browser.cjs` verifies the real authenticated app across10screens ×5viewports (1920×1080,1440×900,1024×900,390×844,320×740), alert/incident drill-down, authenticated PDF representation, script errors and overflow. It does not intercept APIs or fabricate metrics. Credentials are read only from ignored .workbench/qa-credentials.json, generated locally before QA (never committed). Use the local unprivileged config/server and authored replay runs before testing.

Set PLAYWRIGHT_MODULE to an installed Playwright Node module path if necessary; PLAYWRIGHT_CHROMIUM_PATH optionally selects an installed Chromium executable; NETSHIELD_UI_URL defaults to http://127.0.0.1:18483. Node is development-only. Install Playwright in a separate development tools environment, never expose its credentials/artifacts in a release.

The operator's IDM can intercept browser binary-download events. Tests verify authenticated HTTP200/application-pdf/%PDF bytes independently. Actual IDM-downloaded files were separately inspected. v2-workflow.cjs covers real analyst/dry-run workflow interactions. Earlier console-browser.cjs/serve_console.py and console-data.test.mjs are historical UI-foundation tests and are not V2 backend acceptance evidence.

`v2-states.cjs` delays actual status responses to inspect loading and stale-data states. It changes only transport timing, never API contents or sensor measurements. Run it against the same private QA server after the matrix and workflow scripts.
