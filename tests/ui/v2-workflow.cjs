// Actual analyst workflow against a private local database; no fake telemetry.
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || "playwright");
const fs = require("node:fs");
const assert = require("node:assert/strict");
const path = require("node:path");
const base = process.env.NETSHIELD_UI_URL || "http://127.0.0.1:18483";
const output = path.resolve("docs/assets/v2-final");
const credentials = JSON.parse(
  fs.readFileSync(".workbench/qa-credentials.json", "utf8"),
);
(async () => {
  const browser = await chromium.launch({
    headless: true,
    executablePath: process.env.PLAYWRIGHT_CHROMIUM_PATH,
  });
  try {
    const context = await browser.newContext({
        viewport: { width: 1440, height: 900 },
      }),
      page = await context.newPage();
    const errors = [];
    page.on("pageerror", (e) => errors.push(e.message));
    await page.goto(base + "/auth/login");
    await page.getByLabel("Username").fill(credentials.username);
    await page.getByLabel("Password").fill(credentials.password);
    await page.getByRole("button", { name: "Sign in" }).click();
    await page.waitForURL(base + "/");
    const navigate = async (screen) => {
      await page.goto(base + "/#" + screen + "?origin=replay&range=all");
      await page.reload();
      await page.waitForSelector('#page-content[aria-busy="false"]');
    };
    const screenshot = async (name) => {
      const modal =
        /^(scenario-detail|lab-result|response-dry-run|incident-timeline|detection-detail|alert-evidence|navigation)-/.test(
          name,
        );
      if (modal) await page.waitForSelector("dialog[open]");
      await page.screenshot({
        path: path.join(output, name + ".png"),
        fullPage: !modal,
      });
    };
    await navigate("lab");
    await page
      .getByRole("button", { name: "View scenario", exact: true })
      .first()
      .click();
    await screenshot("scenario-detail-1440");
    await page
      .getByRole("button", { name: "Run scenario", exact: true })
      .click();
    await page.getByRole("button", { name: "Confirm", exact: true }).click();
    await page.locator("#detail-dialog").waitFor({ state: "hidden" });
    const run = new URLSearchParams((await page.url()).split("?")[1]).get(
      "run",
    );
    assert(run);
    let actual;
    for (let attempt = 0; attempt < 300; attempt++) {
      actual = await (
        await page.request.get(base + "/api/v2/lab-runs/" + run)
      ).json();
      if (["PASS", "FAIL", "INCOMPLETE", "COMPLETE"].includes(actual.status))
        break;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    assert.equal(actual.status, "PASS");
    const runURL = async (screen) => {
      await page.goto(base + `/#${screen}?origin=replay&run=${run}&range=all`);
      await page.reload();
      await page.waitForSelector('#page-content[aria-busy="false"]');
    };
    await runURL("lab");
    await page
      .getByRole("button", { name: "Vertical port scan", exact: true })
      .first()
      .click();
    await screenshot("lab-result-1440");
    await page.keyboard.press("Escape");
    await runURL("traffic");
    await page
      .getByText("Endpoint / protocol filters", { exact: true })
      .click();
    await page.getByLabel("Destination port", { exact: true }).fill("8001");
    await page.getByRole("button", { name: "Search", exact: true }).click();
    await page.waitForFunction(
      () =>
        document.querySelector(".result-count")?.textContent ===
        "1 matching records",
    );
    await screenshot("traffic-filter-1440");
    await runURL("alerts");
    const openAlert = async () => {
      await page
        .getByRole("button", {
          name: "Vertical port scan indicator",
          exact: true,
        })
        .click();
      await page.waitForSelector("#detail-dialog[open]");
    };
    await openAlert();
    await page
      .getByRole("button", { name: "ACKNOWLEDGED", exact: true })
      .click();
    await page.getByText("Status ACKNOWLEDGED", { exact: true }).waitFor();
    const malicious = '<img src=x onerror="window.__telemetryXss=1">';
    await page.getByLabel("Note", { exact: true }).fill(malicious);
    await page
      .getByRole("button", { name: "Add investigation note", exact: true })
      .click();
    await page.locator("#detail-dialog").waitFor({ state: "hidden" });
    await openAlert();
    assert.equal(await page.evaluate(() => window.__telemetryXss), undefined);
    assert.equal(await page.locator("#detail-content img").count(), 0);
    await page.getByText(malicious, { exact: true }).waitFor();
    const responseForm = page.locator("form").filter({
      has: page.getByRole("heading", {
        name: "Review response request",
        exact: true,
      }),
    });
    await responseForm
      .getByLabel("Reason")
      .fill("Authorized offline browser validation; never enforce");
    await responseForm.getByLabel("Temporary TTL (60–3600 seconds)").fill("60");
    await responseForm
      .getByRole("button", { name: "Review response request", exact: true })
      .click();
    await page.getByRole("button", { name: "Confirm", exact: true }).click();
    await page.locator("#detail-dialog").waitFor({ state: "hidden" });
    await runURL("response");
    await page.locator("#page-content .row-button").first().click();
    await page.getByText("not_enforced", { exact: true }).waitFor();
    await screenshot("response-dry-run-1440");
    await page
      .getByRole("button", { name: "Remove / rollback", exact: true })
      .click();
    await page.getByRole("button", { name: "Confirm", exact: true }).click();
    await page.keyboard.press("Escape");
    await runURL("incidents");
    await page.locator("#page-content .row-button").first().click();
    await page.getByText("Evidence timeline · UTC", { exact: true }).waitFor();
    await screenshot("incident-timeline-1440");
    const href = await page
        .getByRole("link", { name: "Download PDF" })
        .getAttribute("href"),
      pdf = await page.request.get(base + href);
    assert.equal(pdf.status(), 200);
    assert.equal((await pdf.body()).subarray(0, 5).toString(), "%PDF-");
    await page.keyboard.press("Escape");
    await navigate("detections");
    await page
      .getByRole("button", { name: /NS-RECON-VERTICAL \// })
      .first()
      .click();
    await screenshot("detection-detail-1440");
    await page.keyboard.press("Escape");
    await page.setViewportSize({ width: 320, height: 740 });
    await runURL("alerts");
    await openAlert();
    await screenshot("alert-evidence-320");
    assert.equal(
      await page.evaluate(() => document.documentElement.scrollWidth),
      320,
    );
    await page.keyboard.press("Escape");
    await page.getByRole("button", { name: "Open navigation" }).click();
    await screenshot("navigation-320");
    await page.keyboard.press("Escape");
    await page.setViewportSize({ width: 390, height: 844 });
    await navigate("alerts");
    await page
      .getByRole("searchbox", { name: "Search alerts", exact: true })
      .fill("no-such-retained-evidence");
    await page.getByRole("button", { name: "Search", exact: true }).click();
    await page
      .getByText("No alerts observed in this time range.", { exact: true })
      .waitFor();
    await screenshot("no-results-390");
    await context.setOffline(true);
    await page.getByRole("button", { name: "Refresh data" }).click();
    await page.getByText("Data unavailable", { exact: true }).waitFor();
    await screenshot("disconnected-390");
    await context.setOffline(false);
    await page.getByRole("button", { name: "Refresh data" }).click();
    await page.waitForSelector('#page-content[aria-busy="false"]');
    assert.deepEqual(errors, []);
    fs.writeFileSync(
      path.join(output, "workflow-qa.json"),
      JSON.stringify(
        {
          result: "PASS",
          run_id: run,
          scope:
            "Actual authored replay, manual dry run, inert malicious note in private QA DB, simulated transport failure only",
          checks: [
            "scenario confirmation and parser/rules",
            "real PASS result",
            "destination port filter",
            "acknowledge and analyst note",
            "inert telemetry",
            "dry-run response and removal",
            "incident timeline",
            "authenticated PDF",
            "detection detail",
            "320px drawer and keyboard escape",
            "390px no-results and disconnected states",
          ],
          browserErrors: errors,
        },
        null,
        2,
      ),
    );
    console.log(
      "PASS: real analyst workflow, filtering, evidence, dry-run response, PDF, inert telemetry, mobile and disconnected states",
    );
  } finally {
    await browser.close();
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
