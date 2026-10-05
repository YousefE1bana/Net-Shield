// Transport timing only: retain real API responses and never fabricate telemetry.
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || "playwright");
const fs = require("node:fs");
const path = require("node:path");
const assert = require("node:assert/strict");
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
      viewport: { width: 390, height: 844 },
    });
    const page = await context.newPage();
    const errors = [];
    page.on("pageerror", (e) => errors.push(e.message));
    await page.goto(base + "/auth/login");
    await page.getByLabel("Username").fill(credentials.username);
    await page.getByLabel("Password").fill(credentials.password);
    await page.getByRole("button", { name: "Sign in" }).click();
    await page.waitForURL(base + "/");
    await page.waitForSelector('#page-content[aria-busy="false"]');

    const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
    await page.route("**/api/v2/status", async (route) => {
      await pause(1500);
      await route.continue();
    });
    await page.reload();
    await page.waitForSelector('#page-content[aria-busy="true"]');
    await page.screenshot({
      path: path.join(output, "loading-390.png"),
      fullPage: true,
    });
    await page.waitForSelector('#page-content[aria-busy="false"]');
    await page.unrouteAll({ behavior: "wait" });

    // Delay less than the fifteen-second API timeout; use actual response bytes.
    await page.route("**/api/v2/status", async (route) => {
      await pause(12000);
      await route.continue();
    });
    await page.getByRole("button", { name: "Refresh data" }).click();
    await page.waitForFunction(
      () => document.getElementById("freshness").textContent.includes("Stale"),
      null,
      { timeout: 15000 },
    );
    assert.equal(await page.locator("#sensor-chip .success").count(), 0);
    await page.screenshot({
      path: path.join(output, "stale-390.png"),
      fullPage: true,
    });
    await page.unrouteAll({ behavior: "wait" });
    await page.waitForFunction(
      () => !document.getElementById("freshness").textContent.includes("Stale"),
    );
    assert.deepEqual(errors, []);
    fs.writeFileSync(
      path.join(output, "states-qa.json"),
      JSON.stringify(
        {
          result: "PASS",
          scope: "Real API records; delayed transport only",
          checks: [
            "initial loading",
            "aged/API-failure values never show a healthy sensor badge",
            "390px transport states",
          ],
          browserErrors: errors,
        },
        null,
        2,
      ) + "\n",
    );
    console.log("PASS: real loading and delayed-transport freshness states");
  } finally {
    await browser.close();
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
