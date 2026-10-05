// Browser evidence uses actual persisted replay outputs, no intercepted metrics.
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || "playwright");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const base = process.env.NETSHIELD_UI_URL || "http://127.0.0.1:18483";
const credentials = JSON.parse(
  fs.readFileSync(".workbench/qa-credentials.json", "utf8"),
);
const output = path.resolve("docs/assets/v2-final");
fs.mkdirSync(output, { recursive: true });
const sizes = [
  [1920, 1080],
  [1440, 900],
  [1024, 900],
  [390, 844],
  [320, 740],
];
const screens = [
  "overview",
  "traffic",
  "alerts",
  "incidents",
  "assets",
  "detections",
  "response",
  "lab",
  "health",
  "settings",
];
(async () => {
  const browser = await chromium.launch({
    headless: true,
    executablePath: process.env.PLAYWRIGHT_CHROMIUM_PATH,
  });
  try {
    const page = await browser.newPage();
    const errors = [];
    page.on("pageerror", (error) => errors.push(error.message));
    await page.goto(base + "/auth/login");
    await page.getByLabel("Username").fill(credentials.username);
    await page.getByLabel("Password").fill(credentials.password);
    await page.getByRole("button", { name: "Sign in" }).click();
    await page.waitForURL(base + "/");
    const runs = await page.evaluate(
      async () => await (await fetch("/api/v2/lab-runs?limit=100")).json(),
    );
    const run = runs.items.find((r) => r.scenario === "port-scan");
    assert(run && run.status === "PASS");
    const qa = [];
    for (const [width, height] of sizes) {
      await page.setViewportSize({ width, height });
      for (const screen of screens) {
        await page.goto(
          base + `/#${screen}?origin=replay&run=${run.id}&range=all`,
        );
        await page.reload();
        await page.waitForSelector('#page-content[aria-busy="false"]');
        assert.equal(
          await page.locator("#page-title").textContent(),
          {
            overview: "Network overview",
            traffic: "Traffic explorer",
            alerts: "Alerts",
            incidents: "Incidents",
            assets: "Observed assets",
            detections: "Detection inventory",
            response: "Response center",
            lab: "Attack Lab",
            health: "System health",
            settings: "Settings",
          }[screen],
        );
        const dimensions = await page.evaluate(() => ({
          viewport: innerWidth,
          document: document.documentElement.scrollWidth,
          errors: [...document.querySelectorAll("main *")]
            .filter((e) => {
              const r = e.getBoundingClientRect();
              return (
                r.width > 0 &&
                (r.right > innerWidth + 1 || r.left < -1) &&
                !e.closest(".table-scroll,.journey")
              );
            })
            .map((e) => e.className),
        }));
        assert.equal(
          dimensions.document,
          width,
          `${screen} @${width} page overflow`,
        );
        assert.deepEqual(
          dimensions.errors,
          [],
          `${screen} @${width} clipped non-table elements`,
        );
        await page.screenshot({
          path: path.join(output, `${screen}-${width}.png`),
          fullPage: true,
        });
        qa.push({ screen, width, height, documentWidth: dimensions.document });
      }
    }
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto(base + `/#alerts?origin=replay&run=${run.id}&range=all`);
    await page.reload();
    await page.waitForSelector('#page-content[aria-busy="false"]');
    await page
      .getByRole("button", {
        name: "Vertical port scan indicator",
        exact: true,
      })
      .click();
    await page.waitForSelector("#detail-dialog[open]");
    assert(
      await page.getByText("Exact detection reason", { exact: true }).count(),
    );
    await page.screenshot({
      path: path.join(output, "alert-evidence-1440.png"),
      fullPage: false,
    });
    await page.locator("#detail-dialog [data-close-dialog]").click();
    await page.goto(base + `/#incidents?origin=replay&run=${run.id}&range=all`);
    await page.reload();
    await page.waitForSelector('#page-content[aria-busy="false"]');
    await page.locator("#page-content .row-button").first().click();
    await page.waitForSelector("#detail-dialog[open]");
    await page.screenshot({
      path: path.join(output, "incident-evidence-1440.png"),
      fullPage: false,
    });
    const href = await page
      .getByRole("link", { name: "Download PDF" })
      .getAttribute("href");
    // Download managers can intercept browser navigation. Verify the authenticated
    // HTTP representation without assuming ownership of the browser download event.
    const response = await page.request.get(base + href);
    assert.equal(response.status(), 200);
    assert.match(response.headers()["content-type"], /application\/pdf/);
    const pdf = await response.body();
    assert.equal(pdf.subarray(0, 5).toString(), "%PDF-");
    fs.writeFileSync(path.join(output, "browser-verified-incident.pdf"), pdf);
    assert.deepEqual(errors, [], "Browser script errors");
    fs.writeFileSync(
      path.join(output, "browser-qa.json"),
      JSON.stringify(
        {
          base,
          scope: "Actual persisted authored replay; no live enforcement",
          checks: qa,
          browserErrors: errors,
        },
        null,
        2,
      ),
    );
    console.log(
      `PASS: ${qa.length} screen/viewport checks, real alert detail, incident detail and authenticated PDF response`,
    );
  } finally {
    await browser.close();
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
