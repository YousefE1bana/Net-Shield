// Authenticated V2 controller. The approved native shell and tokens are retained.

import {
  el,
  append,
  icon,
  badge,
  button,
  link,
  number,
  datetime,
  stamp,
  panel,
  empty,
  notice,
  definitions,
  table,
  metric,
  field,
} from "./ui.mjs";

const $ = (id) => document.getElementById(id);

const context = JSON.parse($("console-context").textContent);

const titles = {
  overview: [
    "Network overview",
    "Observe activity. Investigate evidence. Know your coverage.",
  ],
  traffic: [
    "Traffic explorer",
    "Bidirectional conversations from normalized packet metadata.",
  ],
  alerts: [
    "Alerts",
    "Indicators and evidence, with an explicit investigation lifecycle.",
  ],
  incidents: [
    "Incidents",
    "Explainable grouping by observed endpoints and time.",
  ],
  assets: [
    "Observed assets",
    "Addresses and service observations; identity is not verified.",
  ],
  detections: [
    "Detection inventory",
    "Versioned rules, exact evidence requirements and practical limits.",
  ],
  response: [
    "Response center",
    "Manual decisions. Finite expiry. Kernel evidence before success.",
  ],
  lab: [
    "Attack Lab",
    "Controlled validation through the same parser and detection pipeline.",
  ],
  health: [
    "System health",
    "Capture coverage, loss uncertainty and persistent-state health.",
  ],
  settings: [
    "Settings",
    "Local authority, operator session and data retention.",
  ],
};

const resources = {
  traffic: "flows",
  alerts: "alerts",
  incidents: "incidents",
  assets: "assets",
  detections: "rules",
  response: "actions",
};

const state = {
  screen: "overview",
  origin: "capture",
  run: "",
  range: "3600",
  q: "",
  offset: 0,
  filters: {},
  busy: false,
  error: "",
  updated: 0,
  status: null,
  runs: [],
  data: null,
  scenarios: [],
  anchor: null,
};

const scenarioPageSize = () =>
  matchMedia("(max-width: 600px)").matches ? 3 : 6;
let timer,
  detailToken = 0,
  liveRunDetail = null;
state.scenarioLimit = scenarioPageSize();
state.scenarioCategory = "";

const tone = (value) =>
  ({
    HIGH: "high",
    CRITICAL: "critical",
    MEDIUM: "medium",
    LOW: "low",
    PASS: "success",
    FAIL: "danger",
    APPLIED: "success",
    REMOVED: "info",
    OPEN: "warning",
    UNKNOWN: "warning",
    INCOMPLETE: "warning",
    ACKNOWLEDGED: "info",
    RESOLVED: "success",
  })[value] || "neutral";

async function api(path, method = "GET", value = null) {
  const controller = new AbortController(),
    timeout = setTimeout(() => controller.abort(), 15000);

  try {
    const response = await fetch("/api/v2/" + path, {
      method,
      credentials: "same-origin",
      signal: controller.signal,
      headers:
        method === "GET"
          ? {}
          : {
              "Content-Type": "application/json",
              "X-CSRF-Token": context.csrf,
            },
      body: value == null ? undefined : JSON.stringify(value),
    });

    if (response.status === 401) {
      location.assign("/auth/login");
      throw new Error("Session expired");
    }

    const data = await response.json();
    if (!response.ok)
      throw new Error(data.error || `API error ${response.status}`);
    return data;
  } finally {
    clearTimeout(timeout);
  }
}

function route(screen, values = {}) {
  return (
    "#" +
    screen +
    "?" +
    new URLSearchParams({
      origin: state.origin,
      range: state.range,
      ...(state.run ? { run: state.run } : {}),
      ...values,
    })
  );
}

function filters(extra = {}) {
  const result = {
    origin: state.origin,
    ...(state.run ? { run: state.run } : {}),
    ...state.filters,
    ...extra,
  };
  if (state.q) result.q = state.q;

  if (state.range !== "all") {
    const end = ["replay", "isolated_lab"].includes(state.origin)
      ? state.anchor
      : Date.now() / 1000;
    if (end != null) {
      result.start = end - Number(state.range);
      result.end = end;
    }
  }

  return new URLSearchParams(result).toString();
}

function action(text, fn, className = "button") {
  return button(
    text,
    async () => {
      try {
        await fn();
      } catch (error) {
        showError(error.message);
      }
    },
    className,
  );
}

function showError(message) {
  const node = notice("Action could not be completed", message);
  node.setAttribute("role", "alert");
  (
    document.querySelector("dialog[open] #detail-content") || $("page-content")
  ).prepend(node);
  $("status-announcement").textContent = message;
}

function rowLink(text, resource, item) {
  return action(text, () => openDetail(resource, item.id), "row-button");
}

function addr(address, endpoint = "source") {
  return link(
    address || "—",
    route("traffic", { [endpoint]: address || "" }),
    "cell-link",
  );
}

function lists(data = state.data) {
  return data?.items || [];
}

function collectionRows(resource, items) {
  const schemas = {
    flows: {
      headers: [
        "Last seen",
        "Source / port",
        "Destination / port",
        "Protocol",
        "Packets",
        "Bytes",
        "Duration",
        "Findings",
      ],
      rows: () =>
        items.map((f) => [
          stamp(f.last_seen),
          rowLink(f.source_ip + ":" + f.source_port, "flows", f),
          link(
            f.target_ip + ":" + f.target_port,
            route("traffic", { destination: f.target_ip }),
            "cell-link",
          ),
          f.protocol,
          number(f.packets),
          number(f.bytes),
          number(f.duration) + "s",
          f.alert_ids.length,
        ]),
    },

    alerts: {
      headers: [
        "Time",
        "Severity",
        "Rule",
        "Source",
        "Destination",
        "Observed / threshold",
        "Occurrences",
        "Status",
      ],
      rows: () =>
        items.map((a) => [
          stamp(a.last_seen),
          badge(a.severity, tone(a.severity)),
          rowLink(a.name, "alerts", a),
          addr(a.source_ip),
          addr(a.target_ip, "destination"),
          `${a.evidence?.observed ?? "—"} / ${a.evidence?.threshold ?? "—"}`,
          a.occurrences,
          badge(a.status, tone(a.status)),
        ]),
    },

    incidents: {
      headers: [
        "Last seen",
        "Severity",
        "Investigation",
        "Source",
        "Destination",
        "Linked alerts",
        "Status",
      ],
      rows: () =>
        items.map((i) => [
          stamp(i.last_seen),
          badge(i.severity, tone(i.severity)),
          rowLink(i.id.slice(0, 12), "incidents", i),
          addr(i.source_ip),
          addr(i.target_ip, "destination"),
          i.alert_ids.length,
          badge(i.status, tone(i.status)),
        ]),
    },

    assets: {
      headers: [
        "Last seen",
        "Address",
        "Analyst label",
        "Observed ports",
        "MAC observations",
        "Binding conflict",
        "Origin",
      ],
      rows: () =>
        items.map((a) => [
          stamp(a.last_seen),
          rowLink(a.source_ip, "assets", a),
          a.label || "Unlabelled",
          a.observed_target_ports.join(", ") || "—",
          a.mac_observations.length,
          a.binding_conflict ? "Observed" : "Not observed",
          a.origin,
        ]),
    },

    rules: {
      headers: [
        "Rule / version",
        "Category",
        "Enabled",
        "Mode",
        "Window",
        "Threshold",
        "Alerts¹",
        "Last triggered¹",
        "Manual response",
      ],
      rows: () =>
        items.map((r) => [
          rowLink(r.rule_id + " / " + r.version, "rules", r),
          r.category,
          r.enabled ? "Enabled" : "Disabled",
          r.mode,
          r.window + "s",
          r.threshold + " " + r.unit,
          r.alert_count,
          stamp(r.last_triggered),
          r.response_eligible ? "Eligible after review" : "Not eligible",
        ]),
    },

    actions: {
      headers: [
        "Created",
        "Target",
        "Requested by",
        "State",
        "Backend",
        "Expiry",
        "Verification",
        "Authority",
      ],
      rows: () =>
        items.map((a) => [
          stamp(a.created_at),
          rowLink(a.target_ip, "actions", a),
          a.requested_by,
          badge(a.status, tone(a.status)),
          a.backend,
          stamp(a.expires_at),
          a.verification,
          a.dry_run ? "Dry run" : a.origin,
        ]),
    },

    "lab-runs": {
      headers: [
        "Started",
        "Scenario",
        "Result",
        "Processed",
        "Observed rules",
        "Elapsed",
        "Evidence",
      ],
      rows: () =>
        items.map((r) => [
          stamp(r.started_at),
          rowLink(r.name || r.scenario, "lab-runs", r),
          badge(r.status, tone(r.status)),
          `${r.processed} / ${r.budget ?? "import"}`,
          r.observed_rules?.length ?? "—",
          number(r.elapsed_seconds) + "s",
          link(
            "Investigate",
            route("alerts", { origin: r.origin, run: r.id }),
            "cell-link",
          ),
        ]),
    },
  };
  const result = schemas[resource];

  return table(
    result.headers,
    result.rows(),
    resource === "alerts"
      ? "No alerts observed in this time range."
      : "No matching observations.",
    "Change filters or run offline validation. Capture health is separate.",
  );
}

function filterBar(resource) {
  const wrap = el("div", "table-toolbar"),
    form = el("form", "filters"),
    search = el("input");
  search.type = "search";
  search.placeholder = "Search this resource…";
  search.value = state.q;
  search.setAttribute("aria-label", "Search " + resource);
  search.maxLength = 128;
  form.append(search);

  if (resource === "alerts" || resource === "incidents")
    for (const [key, values, label] of [
      ["severity", ["", "CRITICAL", "HIGH", "MEDIUM", "LOW"], "All severities"],
      ["status", ["", "OPEN", "ACKNOWLEDGED", "RESOLVED"], "All statuses"],
    ]) {
      const select = el("select");
      select.setAttribute("aria-label", key);
      values.forEach((v) => select.append(new Option(v || label, v)));
      select.value = state.filters[key] || "";
      select.addEventListener("change", () => {
        state.filters[key] = select.value;
        state.offset = 0;
        poll();
      });
      form.append(select);
    }

  if (["flows", "alerts", "incidents", "assets"].includes(resource)) {
    const details = append(
      el("details", "advanced-filters"),
      el("summary", "", "Endpoint / protocol filters"),
    );

    for (const [name, label] of [
      ["source", "Source IP"],
      ["destination", "Destination IP"],
      ["protocol", "Protocol"],
      ["source_port", "Source port"],
      ["target_port", "Destination port"],
      ["rule", "Rule ID"],
    ]) {
      const input = field(
        label,
        name,
        name.endsWith("_port") ? "number" : "text",
        state.filters[name] || "",
      );
      input.querySelector("input").required = false;
      details.append(input);
    }

    form.append(details);
  }

  const submit = el("button", "button", "Search");
  submit.type = "submit";
  form.append(submit);
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    state.q = search.value.trim();
    for (const [k, v] of new FormData(form)) state.filters[k] = v;
    state.offset = 0;
    updateURL();
    poll();
  });
  form.append(
    action(
      "Clear",
      () => {
        state.q = "";
        state.filters = {};
        state.offset = 0;
        return poll();
      },
      "button text",
    ),
  );

  return append(
    wrap,
    form,
    el("span", "result-count", number(state.data?.total) + " matching records"),
  );
}

function pagination() {
  const prev = button("Previous", () => {
      state.offset = Math.max(0, state.offset - 50);
      poll();
    }),
    next = button("Next", () => {
      state.offset += 50;
      poll();
    });
  prev.disabled = !state.offset;
  next.disabled = state.offset + 50 >= (state.data?.total || 0);
  return append(
    el("div", "pagination"),
    el(
      "span",
      "",
      `${state.data?.total ? state.offset + 1 : 0}–${Math.min(state.offset + 50, state.data?.total || 0)} of ${state.data?.total || 0}`,
    ),
    append(el("div"), prev, next),
  );
}

function chart(summary) {
  const wrap = el("div"),
    toolbar = append(
      el("div", "chart-toolbar"),
      el("span", "chart-key", "Packets / second"),
      el("span", "muted", "Observed one-second buckets · " + state.origin),
    ),
    area = el("div", "activity-chart"),
    points = summary.points || [];

  if (points.length === 1) {
    area.classList.add("single-bucket");
    area.append(
      append(
        el("div", "single-bucket-summary"),
        el("span", "muted", datetime(points[0].event_time)),
        el("strong", "", number(points[0].packets) + " packets / second"),
        el(
          "span",
          "",
          number(points[0].bytes) +
            " bytes / second · " +
            points[0].alerts +
            " alert occurrences",
        ),
        el("p", "muted", "One observed bucket. No temporal trend inferred."),
      ),
    );
  } else if (!points.length)
    area.append(
      append(
        el("div", "chart-empty"),
        el(
          "strong",
          "",
          state.origin === "capture"
            ? "No observed traffic buckets"
            : "No packet observations in this scope",
        ),
        el(
          "p",
          "",
          state.origin === "capture"
            ? "Check capture health or switch to recorded replay."
            : "Trusted service events may have no packet time series.",
        ),
      ),
    );
  else {
    const max = Math.max(1, ...points.map((p) => p.packets)),
      first = points[0].event_time,
      last = points.at(-1).event_time,
      grid = el("div", "chart-grid");
    [max, max * 0.75, max * 0.5, max * 0.25, 0].forEach((n) =>
      grid.append(append(el("div"), el("span", "", number(n)))),
    );
    area.append(grid);

    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("viewBox", "0 0 1000 220");
    svg.setAttribute("preserveAspectRatio", "none");
    svg.setAttribute("role", "img");
    svg.setAttribute(
      "aria-label",
      `${state.origin} packet activity, ${points.length} observed buckets, peak ${max} packets per second`,
    );

    const coords = points.map((p) => [
      35 + ((p.event_time - first) / Math.max(1, last - first)) * 960,
      185 - (p.packets / max) * 165,
    ]);

    const segments = [];
    points.forEach((point, index) => {
      if (!index || point.event_time - points[index - 1].event_time > 1)
        segments.push([]);
      segments.at(-1).push(coords[index]);
    });
    segments
      .filter((segment) => segment.length > 1)
      .forEach((segment) => {
        const line = document.createElementNS(svg.namespaceURI, "polyline");
        line.setAttribute("points", segment.map((p) => p.join(",")).join(" "));
        line.setAttribute("fill", "none");
        line.setAttribute("stroke", "var(--accent)");
        line.setAttribute("stroke-width", "2");
        line.setAttribute("vector-effect", "non-scaling-stroke");
        svg.append(line);
      });

    points.forEach((p, i) => {
      const dot = document.createElementNS(svg.namespaceURI, "circle");
      dot.setAttribute("cx", coords[i][0]);
      dot.setAttribute("cy", coords[i][1]);
      dot.setAttribute("r", p.alerts ? 4 : 2);
      dot.setAttribute("fill", p.alerts ? "var(--warning)" : "var(--accent)");
      const title = document.createElementNS(svg.namespaceURI, "title");
      title.textContent = `${datetime(p.event_time)} · ${p.packets} packets · ${p.bytes} bytes · ${p.alerts} alert occurrences`;
      dot.append(title);
      svg.append(dot);
    });

    area.append(
      svg,
      append(
        el("div", "chart-axis"),
        el("span", "", datetime(first)),
        el("span", "", datetime(last)),
      ),
    );
  }

  const packets = (summary.protocols || []).reduce((n, p) => n + p.packets, 0),
    bytes = (summary.protocols || []).reduce((n, p) => n + p.bytes, 0);

  return panel(
    "Network activity",
    append(
      wrap,
      toolbar,
      area,
      append(
        el("div", "panel-footnote"),
        el("span", "", `${number(packets)} packets / ${number(bytes)} bytes`),
        el("span", "", summary.chart_semantics),
      ),
    ),
    link("Explore traffic", route("traffic")),
    "activity-panel",
  );
}

function overview() {
  const summary = state.data.summary,
    counts = summary.alert_counts,
    active = counts
      .filter((c) => c.status !== "RESOLVED")
      .reduce((n, c) => n + c.count, 0),
    high = counts
      .filter(
        (c) =>
          c.status !== "RESOLVED" && ["HIGH", "CRITICAL"].includes(c.severity),
      )
      .reduce((n, c) => n + c.count, 0);

  const strip = append(
    el("div", "status-strip"),
    metric(
      "Live sensor",
      state.status.live_capture,
      "Separate from replay evidence",
    ),
    metric(
      "Data scope",
      state.origin,
      state.run ? state.run.slice(0, 12) : "All matching observations",
    ),
    metric(
      "Capture interface",
      state.status.interface || "Not configured",
      "Operator-selected interface",
    ),
    metric("Active alerts", number(active), "Open + acknowledged"),
    metric("Critical / high", number(high), "Unresolved in this scope"),
    metric(
      "Response",
      "Manual only",
      state.status.response_enabled
        ? "Locally enabled"
        : "Live enforcement disabled",
    ),
  );

  const grid = append(
    el("div", "overview-grid"),
    panel(
      "Recent alerts",
      table(
        ["Time", "Severity", "Detection"],
        state.data.alerts.items
          .slice(0, 6)
          .map((a) => [
            stamp(a.last_seen),
            badge(a.severity, tone(a.severity)),
            rowLink(a.name, "alerts", a),
          ]),
        "No alerts observed in this time range.",
      ),
      link("View all", route("alerts")),
    ),
    panel(
      "Top conversations",
      table(
        ["Endpoints", "Bytes"],
        summary.top_flows
          .slice(0, 5)
          .map((f) => [
            rowLink(
              f.source_ip + " → " + f.target_ip + ":" + f.target_port,
              "flows",
              f,
            ),
            number(f.bytes),
          ]),
      ),
      link("Investigate", route("traffic")),
    ),
    panel(
      "Protocol distribution",
      table(
        ["Protocol", "Packets", "Bytes"],
        summary.protocols.map((p) => [
          p.protocol,
          number(p.packets),
          number(p.bytes),
        ]),
      ),
      link("Rules", route("detections")),
    ),
  );

  return append(
    el("div"),
    strip,
    chart(summary),
    grid,
    append(
      el("div", "coverage-row"),
      append(
        el("div", "coverage-item"),
        el("strong", "coverage-title", "Capture coverage"),
        el(
          "p",
          "",
          state.status.live_capture === "running"
            ? "Capture heartbeat observed; kernel drop count unknown."
            : "Capture is " +
                state.status.live_capture +
                ". Zero alerts do not establish security.",
        ),
        link("Inspect health", route("health")),
      ),
      append(
        el("div", "coverage-item"),
        el("strong", "coverage-title", "Provenance boundary"),
        el(
          "p",
          "",
          state.origin === "replay"
            ? "Recorded fixtures / local PCAP. No live response authority."
            : "Trusted local ingress assigns observation provenance.",
        ),
        link("Validate a scenario", route("lab")),
      ),
      append(
        el("div", "coverage-item"),
        el("strong", "coverage-title", "Response verification"),
        el(
          "p",
          "",
          "Finite TTL and owned nftables source sets. Success requires helper evidence.",
        ),
        link("Open response center", route("response")),
      ),
    ),
  );
}

function lab() {
  const journey = append(
    el("div", "journey"),
    ["Generate", "Observe", "Detect", "Investigate", "Respond", "Verify"].map(
      (s, i) =>
        append(
          el("div", "journey-step"),
          el("span", "number", i + 1),
          el("strong", "", s),
        ),
    ),
  );

  const selected = state.scenarios.filter(
    (s) => !state.scenarioCategory || s.category === state.scenarioCategory,
  );
  const chooser = el("select");
  chooser.setAttribute("aria-label", "Scenario category");
  chooser.append(new Option("All categories", ""));
  [...new Set(state.scenarios.map((s) => s.category))].forEach((c) =>
    chooser.append(new Option(c, c)),
  );
  chooser.value = state.scenarioCategory;
  chooser.addEventListener("change", () => {
    state.scenarioCategory = chooser.value;
    state.scenarioLimit = scenarioPageSize();
    render();
  });
  const browse = append(
    el("div", "table-toolbar"),
    chooser,
    el(
      "span",
      "muted",
      Math.min(state.scenarioLimit, selected.length) +
        " of " +
        selected.length +
        " scenarios",
    ),
  );
  const library = append(
    el("div", "scenario-library"),
    selected.slice(0, state.scenarioLimit).map((s) =>
      append(
        el("article", "scenario"),
        append(
          el("div", "scenario-top"),
          icon("lab"),
          badge("Offline replay", "info"),
        ),
        el("h2", "", s.name),
        el("p", "", s.description),
        definitions([
          ["Category", s.category],
          ["Expected rule", s.expected_rules.join(", ") || "No findings"],
          ["Traffic budget", s.budget + " observations"],
          ["Mode / safety", "Replay · no network access"],
        ]),
        append(
          el("div", "scenario-footer"),
          el("span", "muted", "Authored controlled fixture"),
          action("View scenario", () => scenarioDetail(s)),
        ),
      ),
    ),
  );

  return append(
    el("div"),
    notice(
      "Authorized validation",
      "The built-in library is offline and transmits no traffic. Live namespace validation is a separate Linux CLI gate.",
    ),
    journey,
    panel(
      "Validation history",
      collectionRows(
        "lab-runs",
        [
          ...state.data.items.filter((r) => r.id === state.run),
          ...state.data.items.filter((r) => r.id !== state.run),
        ].slice(0, 6),
      ),
    ),
    panel(
      "Scenario library",
      append(
        el("div"),
        browse,
        library,
        selected.length > state.scenarioLimit
          ? action("Show more scenarios", () => {
              state.scenarioLimit += scenarioPageSize();
              render();
            })
          : null,
      ),
    ),
  );
}

function health() {
  const s = state.status;
  return append(
    el("div"),
    notice(
      "Coverage is an operational claim",
      "Quiet traffic, stopped capture and a failed sensor are distinct conditions. Kernel loss remains unknown.",
    ),
    panel(
      "Local system",
      definitions([
        ["Capture state", s.live_capture],
        ["Configured interface", s.interface],
        ["Database", s.database],
        ["Database size", number(s.database_bytes) + " bytes"],
        ["Disk free", number(s.disk_free_bytes) + " bytes"],
        ["Kernel drops", "Unknown"],
        ["Automatic response", "Disabled"],
        ["Live response", s.response_enabled ? "Locally enabled" : "Disabled"],
        ["Platform", s.platform],
      ]),
    ),
    panel(
      "Sensors",
      s.sensors.length
        ? table(
            [
              "Sensor",
              "Interface",
              "State",
              "Heartbeat age",
              "Queue",
              "Overflow",
              "Parser errors",
              "Writer errors",
            ],
            s.sensors.map((s) => [
              s.id,
              s.interface,
              s.capture_state,
              number(s.heartbeat_age_seconds) + "s",
              s.queue_size + " / " + s.queue_capacity,
              s.queue_overflow,
              s.parser_failures,
              s.writer_failures,
            ]),
          )
        : empty(
            "No capture sensor heartbeat",
            "Configure an approved interface and start the separate capture service. The web process has no capture privileges.",
          ),
    ),
    panel(
      "Coverage limits",
      append(
        el("div", "guardrail-list"),
        s.coverage.map((c) => el("p", "", c)),
      ),
    ),
  );
}

function settings() {
  const s = state.data,
    wrap = el("div");
  append(
    wrap,
    panel(
      "Operator session",
      definitions([
        ["Operator", s.username],
        ["Role", s.role],
        ["Session", "Server-side, expiring; HttpOnly Strict cookie"],
        ["Authentication", "Local account; no default credentials"],
      ]),
      action("Sign out", async () => {
        const r = await fetch("/auth/logout", {
          method: "POST",
          headers: { "X-CSRF-Token": context.csrf },
        });
        if (r.ok) location.assign("/auth/login");
        else throw new Error("Logout failed");
      }),
    ),
    panel(
      "Authority and network scope",
      definitions([
        ["Capture interface", s.interface || "Not configured"],
        ["Internal networks", s.internal_networks.join(", ")],
        ["Response scope", s.response_networks.join(", ") || "None"],
        ["Protected networks", s.protected_networks.join(", ")],
        ["Automatic response", "Disabled; manual review required"],
        ["Privileges", "Capture and helper are separate processes"],
      ]),
    ),
  );

  const form = el("form", "analyst-form");
  append(
    form,
    field(
      "Raw observation retention (days)",
      "event_retention_days",
      "number",
      s.saved?.event_retention_days ?? s.event_retention_days,
    ),
    field(
      "Evidence retention (days)",
      "evidence_retention_days",
      "number",
      s.saved?.evidence_retention_days ?? s.evidence_retention_days,
    ),
  );
  const save = el("button", "button", "Save retention");
  save.type = "submit";
  save.disabled = s.role !== "admin";
  form.append(
    save,
    el(
      "p",
      "muted",
      "Applied by the local retention job. Privileged policy is not editable here.",
    ),
  );
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      await api(
        "settings",
        "POST",
        Object.fromEntries(
          [...new FormData(form)].map(([k, v]) => [k, Number(v)]),
        ),
      );
      await poll();
    } catch (error) {
      showError(error.message);
    }
  });

  append(
    wrap,
    panel(
      "Scoped detection exceptions",
      table(
        ["Rule", "Scope", "Expiry", "State", "Action"],
        s.exceptions.map((x) => [
          x.rule_id,
          x.origin + " / " + (x.source_ip || x.target_ip),
          stamp(x.expires_at),
          x.status || "ACTIVE",
          context.role === "viewer" || x.status === "REVOKED"
            ? "—"
            : action("Revoke", () =>
                confirmAction("Revoke detection exception?", x.reason, () =>
                  api("exceptions/" + x.id + "/revoke", "POST", {}),
                ),
              ),
        ]),
        "No retained detection exceptions.",
        "Exceptions suppress only their configured rule and scope.",
      ),
    ),
    panel(
      "Response protected targets",
      table(
        ["Network", "Reason", "Owner", "Action"],
        s.protections.map((x) => [
          x.network,
          x.reason,
          x.actor,
          context.role === "admin"
            ? action("Review removal", () => {
                const root = detail(x.network, "Response protection");
                root.append(
                  notice(
                    "Independent policy",
                    "Removing this application protection never changes root helper protections.",
                  ),
                );
                formAction(
                  root,
                  "Remove application protection",
                  [field("Reason", "reason", "textarea")],
                  (value) =>
                    api("protections/" + x.id + "/remove", "POST", value),
                );
                $("detail-dialog").showModal();
              })
            : "Read only",
        ]),
        "No additional protected targets configured.",
        "Built-in and independent helper protections still apply.",
      ),
    ),
  );

  if (context.role === "admin")
    formAction(
      wrap,
      "Protect response network",
      [
        field("Network (CIDR)", "network"),
        field("Reason", "reason", "textarea"),
      ],
      (value) => api("protections", "POST", value),
    );

  append(
    wrap,
    panel("Retention policy", form),
    panel(
      "Exports and integrations",
      definitions([
        [
          "Incident exports",
          "Local JSON and PDF; downloadable from an incident",
        ],
        ["Webhooks / Syslog", "Not enabled in this release"],
        [
          "Capture / firewall policy",
          "Local configuration, outside browser authority",
        ],
      ]),
    ),
  );
  return wrap;
}

function chrome() {
  $("data-mode").value = state.origin;
  $("time-range").value = state.range;
  const age = state.updated
    ? Math.round((Date.now() - state.updated) / 1000)
    : null;
  const fresh = !state.error && age !== null && age <= 10 && navigator.onLine;
  const captureState = fresh
    ? state.status?.live_capture || "unknown"
    : age === null && !state.error
      ? "Connecting"
      : "Unknown / stale";

  $("freshness").textContent = state.error
    ? "API failure · " + state.error
    : `${age > 10 ? "Stale · received" : "Received"} ${age ?? "—"}s ago · ${state.origin} · live capture ${captureState}`;
  $("connection-bar").classList.toggle(
    "degraded",
    Boolean(state.error) || age > 10 || !navigator.onLine,
  );

  $("sensor-chip").replaceChildren(
    el(
      "span",
      "dot " + (fresh && captureState === "running" ? "success" : "neutral"),
    ),
    el("span", "", captureState),
  );

  document.querySelectorAll("[data-screen]").forEach((a) => {
    a.classList.toggle("active", a.dataset.screen === state.screen);
    if (a.dataset.screen === state.screen)
      a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  });
}

function render() {
  const [title, description] = titles[state.screen];
  document.title = title + " · NetShield";
  $("page-title").textContent = title;
  $("page-description").textContent = description;
  $("page-eyebrow").textContent = "Operations / " + state.screen;
  $("page-actions").replaceChildren();

  if (!["health", "settings", "detections"].includes(state.screen)) {
    const select = el("select", "run-select");
    select.setAttribute("aria-label", "Observation run");
    select.append(new Option("All runs in scope", ""));
    state.runs
      .filter((r) => r.origin === state.origin)
      .forEach((r) =>
        select.append(
          new Option(
            (r.name || r.scenario) +
              " · " +
              r.status +
              " · " +
              r.id.slice(0, 6),
            r.id,
          ),
        ),
      );
    select.value = state.run;
    select.addEventListener("change", () => {
      state.run = select.value;
      state.offset = 0;
      updateURL();
      poll();
    });
    $("page-actions").append(select);
  }

  let content;
  if (state.error)
    content = notice(
      "Data unavailable",
      state.error + " Previously received values are not presented as fresh.",
    );
  else if (state.screen === "overview") content = overview();
  else if (state.screen === "lab") content = lab();
  else if (state.screen === "health") content = health();
  else if (state.screen === "settings") content = settings();
  else {
    const resource = resources[state.screen];
    content = append(
      el("div"),
      filterBar(resource),
      panel(titles[state.screen][0], collectionRows(resource, lists())),
      pagination(),
    );
    if (state.screen === "detections")
      content.prepend(
        notice(
          "Versioned detection inventory",
          "¹ Alert counts and last trigger include all retained origins for the exact rule version. Archived versions remain attached to historical evidence.",
        ),
      );
    if (state.screen === "response")
      content.prepend(
        notice(
          "Manual response only",
          "Replay actions are dry-run decisions. Enforcement is not inferred from an alert or request.",
        ),
      );
  }

  $("page-content").replaceChildren(content);
  $("page-content").setAttribute("aria-busy", "false");
  chrome();
}

async function poll(force = true) {
  if (state.busy) {
    state.pending = true;
    return;
  }
  state.busy = true;
  clearTimeout(timer);
  $("refresh").disabled = true;

  try {
    state.status = await api("status");
    const runs = await api("lab-runs?limit=100");
    state.runs = runs.items;

    if (["replay", "isolated_lab"].includes(state.origin)) {
      const latest = await api(
        "events?" +
          new URLSearchParams({
            origin: state.origin,
            ...(state.run ? { run: state.run } : {}),
            limit: 1,
          }),
      );
      state.anchor = latest.items[0]?.event_time ?? null;
    }

    if (state.screen === "overview") {
      const summary = await api("overview?" + filters()),
        alerts = await api("alerts?" + filters({ limit: 6 }));
      state.data = { summary, alerts };
      $("nav-alert-count").textContent = summary.alert_counts.reduce(
        (n, c) => n + c.count,
        0,
      );
    } else if (state.screen === "lab") {
      state.scenarios = (await api("scenarios")).items;
      state.data = { items: runs.items, total: runs.total };
    } else if (state.screen === "settings")
      state.data = {
        ...(await api("settings")),
        exceptions: (await api("exceptions?limit=250")).items,
        protections: (await api("protections?limit=250")).items,
      };
    else if (state.screen === "health") state.data = state.status;
    else
      state.data = await api(
        resources[state.screen] +
          "?" +
          (state.screen === "detections"
            ? "limit=100&status=CURRENT"
            : filters({ limit: 50, offset: state.offset })),
      );

    state.error = "";
    state.updated = Date.now();
    if (liveRunDetail && $("detail-dialog").open) {
      const run = runs.items.find((r) => r.id === liveRunDetail);
      if (run) await openDetail("lab-runs", run.id);
    }
  } catch (error) {
    state.error =
      error.name === "AbortError" ? "Request timed out" : error.message;
  } finally {
    state.busy = false;
    $("refresh").disabled = false;
    if (state.pending) {
      state.pending = false;
      poll(force);
      return;
    }
    if (
      !document.querySelector("dialog[open]") &&
      (force || !document.activeElement.closest(".filters, .analyst-form"))
    )
      render();
    else chrome();
    if (!document.hidden) timer = setTimeout(() => poll(false), 5000);
  }
}

function updateURL() {
  history.replaceState(
    null,
    "",
    route(state.screen, {
      ...(state.q ? { q: state.q } : {}),
      ...state.filters,
    }),
  );
}

function readRoute() {
  const [screen, query = ""] = location.hash.slice(1).split("?");
  state.screen = titles[screen] ? screen : "overview";
  const params = new URLSearchParams(query);
  if (
    ["capture", "service_event", "replay", "isolated_lab"].includes(
      params.get("origin"),
    )
  )
    state.origin = params.get("origin");
  if (params.has("run")) state.run = params.get("run");
  if (params.has("range"))
    state.range = ["900", "3600", "86400", "all"].includes(params.get("range"))
      ? params.get("range")
      : "3600";
  state.q = params.get("q") || "";
  state.filters = {};
  for (const k of [
    "source",
    "destination",
    "protocol",
    "source_port",
    "target_port",
    "rule",
    "severity",
    "status",
  ])
    if (params.get(k)) state.filters[k] = params.get(k);
  state.offset = 0;
  poll();
}

function detail(title, category = "Investigation") {
  $("detail-category").textContent = category;
  const root = append(el("div"), el("h2", "detail-title", title));
  root.firstChild.id = "detail-title";
  $("detail-content").replaceChildren(root);
  return root;
}

function formAction(root, title, fields, onSubmit) {
  const form = append(el("form", "analyst-form"), el("h3", "", title), fields),
    submit = el("button", "button primary", title);
  submit.type = "submit";
  form.append(submit);
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    submit.disabled = true;
    try {
      await onSubmit(Object.fromEntries(new FormData(form)));
      $("detail-dialog").close();
      await poll();
    } catch (error) {
      form.prepend(notice("Action rejected", error.message));
    } finally {
      submit.disabled = false;
    }
  });
  root.append(form);
}

async function openDetail(resource, id) {
  liveRunDetail = null;
  const token = ++detailToken,
    item = await api(resource + "/" + encodeURIComponent(id));
  if (token !== detailToken) return;
  const root = detail(
    item.name ||
      item.label ||
      item.rule_id ||
      item.source_ip ||
      "Investigation " + item.id.slice(0, 12),
    resource,
  );

  root.append(
    append(
      el("div", "detail-badges"),
      badge(item.origin || "Rule catalogue", "info"),
      item.severity
        ? badge("Severity " + item.severity, tone(item.severity))
        : null,
      item.status ? badge("Status " + item.status, tone(item.status)) : null,
      item.confidence ? badge("Confidence " + item.confidence) : null,
    ),
  );
  const metadata =
    resource === "rules"
      ? [
          ["Rule", item.rule_id],
          ["Version", item.version],
          ["Mode", item.mode],
        ]
      : resource === "lab-runs"
        ? [
            ["Run", item.id],
            ["Scenario", item.scenario],
            ["Started", datetime(item.started_at)],
            ["Finished", datetime(item.finished_at)],
          ]
        : resource === "actions"
          ? [
              ["Identifier", item.id],
              ["Target", item.target_ip],
              ["Created", datetime(item.created_at)],
              [
                "Source alert",
                item.alert_id
                  ? rowLink(item.alert_id.slice(0, 12), "alerts", {
                      id: item.alert_id,
                    })
                  : "Not linked",
              ],
            ]
          : [
              ["Identifier", item.id],
              ["Source", item.source_ip],
              ["Destination", item.target_ip],
              ["First observed", datetime(item.first_seen)],
              ["Last observed", datetime(item.last_seen)],
              ["Run", item.run_id || "Live / not run-scoped"],
            ];
  root.append(definitions(metadata));

  if (resource === "alerts") {
    root.append(
      panel(
        "Exact detection reason",
        append(
          el("div", "detail-section"),
          el("p", "", item.description),
          definitions([
            ["Rule / version", item.rule_id + " / " + item.rule_version],
            ["Observed", item.evidence.observed],
            ["Threshold", item.evidence.threshold + " " + item.evidence.unit],
            ["Window", item.evidence.window_seconds + " seconds"],
            ["Occurrences", item.occurrences],
          ]),
        ),
      ),
      panel(
        "Observed evidence",
        el("pre", "evidence-pre", JSON.stringify(item.evidence, null, 2)),
      ),
    );

    const occurrences = await api(
      "occurrences?" + new URLSearchParams({ alert_id: item.id, limit: 100 }),
    );
    root.append(
      panel(
        "Occurrence timeline",
        table(
          ["Time", "Observed", "Flow"],
          occurrences.items.map((o) => [
            stamp(o.event_time),
            o.evidence.observed,
            o.flow_id
              ? rowLink(o.flow_id.slice(0, 12), "flows", { id: o.flow_id })
              : "Service evidence",
          ]),
        ),
      ),
    );

    if (item.incident_id)
      root.append(
        action("Open incident", () =>
          openDetail("incidents", item.incident_id),
        ),
      );
    root.append(
      link(
        "Related conversations",
        route("traffic", {
          source: item.source_ip,
          destination: item.target_ip,
        }),
        "button",
      ),
    );

    if (item.response_eligible && context.role !== "viewer")
      formAction(
        root,
        "Review response request",
        [
          field("Reason", "reason", "textarea"),
          field("Temporary TTL (60–3600 seconds)", "ttl", "number", 300),
        ],
        async (value) => {
          const dry = !(
            state.status.response_enabled &&
            ["capture", "service_event"].includes(item.origin) &&
            !item.run_id
          );
          await confirmAction(
            dry
              ? "Record a dry-run response decision?"
              : "Apply a temporary live block?",
            `Target ${item.source_ip}. TTL ${value.ttl}s. ${dry ? "No firewall call." : "The independent helper must authorize and verify the target."}`,
            () =>
              api("actions", "POST", {
                alert_id: item.id,
                reason: value.reason,
                ttl: Number(value.ttl),
                dry_run: dry,
              }),
          );
        },
      );

    if (context.role !== "viewer")
      formAction(
        root,
        "Add scoped detection exception",
        [
          field("Reason", "reason", "textarea"),
          field("Expiry (60–86400 seconds)", "duration", "number", 600),
        ],
        (value) =>
          api("exceptions", "POST", {
            rule_id: item.rule_id,
            origin: item.origin,
            source_ip: item.source_ip,
            duration: Number(value.duration),
            reason: value.reason,
          }),
      );
  }

  if (resource === "incidents") {
    const evidence = await api(
      "incidents/" + encodeURIComponent(id) + "/evidence",
    );
    if (token !== detailToken) return;
    root.append(
      panel(
        "Evidence timeline · UTC",
        table(
          ["Time", "Rule", "Observed", "Flow"],
          evidence.occurrences.map((o) => [
            stamp(o.event_time),
            rowLink(
              evidence.alerts.find((a) => a.id === o.alert_id)?.rule_id ||
                o.alert_id,
              "alerts",
              { id: o.alert_id },
            ),
            o.evidence.observed,
            o.flow_id
              ? rowLink(o.flow_id.slice(0, 12), "flows", { id: o.flow_id })
              : "Service evidence",
          ]),
        ),
      ),
    );
    if (evidence.truncation.length)
      root.append(notice("Bounded evidence", evidence.truncation.join(" ")));
    root.append(
      panel(
        "Correlation rationale",
        el("p", "detail-section", item.grouping_reason),
      ),
      panel(
        "Linked alerts",
        table(
          ["Alert", "Action"],
          item.alert_ids.map((a) => [
            rowLink(a.slice(0, 12), "alerts", { id: a }),
            context.role === "viewer"
              ? "Read only"
              : action("Detach", () => detachForm(root, item.id, a)),
          ]),
        ),
      ),
    );
    root.append(
      append(
        el("div", "detail-actions"),
        link(
          "Download PDF",
          "/api/v2/incidents/" + item.id + "/export?format=pdf",
          "button primary",
        ),
        link(
          "Download JSON",
          "/api/v2/incidents/" + item.id + "/export?format=json",
          "button",
        ),
      ),
    );
  }

  if (resource === "flows")
    root.append(
      panel(
        "Conversation evidence",
        definitions([
          ["Protocol", item.protocol],
          ["Observed packets", item.packets],
          ["Observed bytes", item.bytes],
          [
            "Forward / reverse packets",
            item.forward_packets + " / " + item.reverse_packets,
          ],
          [
            "Forward / reverse bytes",
            item.forward_bytes + " / " + item.reverse_bytes,
          ],
          ["Duration", item.duration + "s"],
          ["Direction basis", item.direction_basis],
        ]),
      ),
      panel(
        "Linked alerts",
        table(
          ["Alert"],
          item.alert_ids.map((a) => [
            rowLink(a.slice(0, 12), "alerts", { id: a }),
          ]),
        ),
      ),
    );

  if (resource === "assets") {
    root.append(
      panel(
        "Observed address evidence",
        definitions([
          ["Observed target ports", item.observed_target_ports.join(", ")],
          ["MAC observations", item.mac_observations.join(", ")],
          [
            "Binding conflict",
            item.binding_conflict ? "Observed" : "Not observed",
          ],
          ["Identity limit", item.identity_limit],
        ]),
      ),
      link(
        "Investigate conversations",
        route("traffic", { source: item.source_ip }),
        "button",
      ),
    );
    if (context.role !== "viewer")
      formAction(
        root,
        "Save analyst label",
        [field("Asset label", "label", "text", item.label)],
        (value) => api("assets/" + id, "PATCH", value),
      );
  }

  if (resource === "rules")
    root.append(
      panel(
        "Rule specification",
        definitions([
          ["Description", item.description],
          ["Category", item.category],
          [
            "Threshold / window",
            item.threshold + " " + item.unit + " / " + item.window + "s",
          ],
          ["Evidence requirement", item.evidence_requirement],
          ["Benign causes", item.benign_causes],
          ["Scope", item.scope],
          ["Version", item.version],
          ["ATT&CK rationale", item.mapping_rationale || "No mapping asserted"],
        ]),
      ),
      link(
        "Find matching alerts",
        route("alerts", { rule: item.rule_id }),
        "button",
      ),
    );

  if (resource === "rules" && context.role === "admin") {
    const enabled = el("select");
    enabled.name = "enabled";
    enabled.setAttribute("aria-label", "Rule enabled");
    enabled.append(
      new Option("Enabled", "true"),
      new Option("Disabled", "false"),
    );
    enabled.value = String(item.enabled);

    formAction(
      root,
      "Save rule configuration",
      [
        field("Threshold", "threshold", "number", item.threshold),
        field("Window (seconds)", "window", "number", item.window),
        enabled,
      ],
      async (value) => {
        const saved = await api("rule-config");
        saved.overrides[item.rule_id] = {
          threshold: Number(value.threshold),
          window: Number(value.window),
          enabled: value.enabled === "true",
        };
        return api("rule-config", "POST", { overrides: saved.overrides });
      },
    );

    root.append(
      notice(
        "Configuration adoption",
        "New replay runs use saved values. Restart capture and service consumers to adopt. Historical evidence retains the original rule version.",
      ),
    );
  }

  if (resource === "actions") {
    root.append(
      panel(
        "Response evidence",
        definitions([
          ["Reason", item.reason],
          ["Requested by", item.requested_by],
          ["Authority", item.dry_run ? "Dry run" : item.origin],
          ["Backend", item.backend],
          ["Verification", item.verification],
          ["Expiry", datetime(item.expires_at)],
          ["Helper scope", item.helper_scope || "Not verified"],
        ]),
      ),
      panel(
        "Action history",
        table(
          ["Time", "State", "Actor"],
          item.history.map((h) => [
            stamp(h.time),
            badge(h.status, tone(h.status)),
            h.actor,
          ]),
        ),
      ),
    );
    if (
      item.status !== "REMOVED" &&
      (item.dry_run || ["capture", "service_event"].includes(item.origin)) &&
      context.role !== "viewer"
    )
      root.append(
        action("Remove / rollback", () =>
          confirmAction(
            "Remove this response action?",
            item.dry_run
              ? "Retire the dry-run decision."
              : "Only the helper-owned target element will be removed and verified.",
            () => api("actions/" + id + "/remove", "POST", {}),
          ),
        ),
      );
  }

  if (resource === "lab-runs") {
    liveRunDetail = item.status === "RUNNING" ? item.id : null;
    root.append(
      panel(
        "Expected vs observed",
        definitions([
          ["Result", item.status],
          ["Stage", item.stage || "Not recorded"],
          ["Generated observations", item.generated_count ?? "Not recorded"],
          ["Processed", item.processed + " / " + (item.budget ?? "import")],
          [
            "Detected occurrences",
            item.detected_events ?? "See scoped alert evidence",
          ],
          [
            "Expected rules",
            item.expected_rules?.join(", ") || "No findings / external PCAP",
          ],
          ["Observed rules", item.observed_rules?.join(", ") || "None"],
          ["Elapsed", number(item.elapsed_seconds) + "s"],
          ["Response authority", item.response],
          ["Error", item.error || "None"],
        ]),
      ),
      panel(
        "Assertions",
        table(
          ["Assertion", "Result"],
          (item.assertions || []).map((a) => [
            a.rule,
            badge(a.passed ? "PASS" : "FAIL", a.passed ? "success" : "danger"),
          ]),
        ),
      ),
      link(
        "Open alert evidence",
        route("alerts", { origin: item.origin, run: item.id }),
        "button",
      ),
      link(
        "Open traffic evidence",
        route("traffic", { origin: item.origin, run: item.id }),
        "button",
      ),
    );
    if (item.status === "RUNNING" && context.role !== "viewer")
      root.append(
        action("Cancel run", () =>
          api("lab-runs/" + id + "/cancel", "POST", {}),
        ),
      );
  }

  if (["alerts", "incidents"].includes(resource) && context.role !== "viewer") {
    root.append(
      append(
        el("div", "detail-actions"),
        ["OPEN", "ACKNOWLEDGED", "RESOLVED"].map((status) =>
          action(status, async () => {
            await api(resource + "/" + id, "PATCH", { status });
            await openDetail(resource, id);
          }),
        ),
      ),
    );
    formAction(
      root,
      "Add investigation note",
      [field("Note", "note", "textarea")],
      (value) => api(resource + "/" + id, "PATCH", value),
    );
  }

  if (item.notes)
    root.append(
      panel(
        "Analyst notes",
        table(
          ["Time", "Actor", "Note"],
          item.notes.map((n) => [stamp(n.time), n.actor, n.text]),
        ),
      ),
    );
  if (item.attack)
    root.append(
      notice("ATT&CK mapping", item.attack + " — " + item.mapping_rationale),
    );
  if (token !== detailToken) return;
  if (!$("detail-dialog").open) $("detail-dialog").showModal();
}

function detachForm(root, incident, alert) {
  formAction(
    root,
    "Detach alert from incident",
    [field("Why is this activity unrelated?", "reason", "textarea")],
    (value) =>
      api("incidents/" + incident + "/detach", "POST", {
        alert_id: alert,
        reason: value.reason,
      }),
  );
  root.lastChild.scrollIntoView({ block: "nearest" });
}

function confirmAction(title, message, operation) {
  return new Promise((resolve, reject) => {
    const dialog = $("confirm-dialog"),
      root = append(el("div"), el("h2", "", title), el("p", "", message));
    root.firstChild.id = "confirm-title";
    $("confirm-content").replaceChildren(root);
    let done = false;
    root.append(
      action(
        "Confirm",
        async () => {
          try {
            const result = await operation();
            done = true;
            dialog.close();
            resolve(result);
          } catch (error) {
            reject(error);
            done = true;
            dialog.close();
            throw error;
          }
        },
        "button primary",
      ),
    );
    const closed = () => {
      dialog.removeEventListener("close", closed);
      if (!done) reject(new Error("Confirmation cancelled"));
    };
    dialog.addEventListener("close", closed);
    dialog.showModal();
  });
}

async function scenarioDetail(s) {
  const root = detail(s.name, "Scenario library");
  root.append(
    el("p", "detail-subtitle", s.description),
    definitions([
      ["Category", s.category],
      ["Expected rule", s.expected_rules.join(", ") || "No findings"],
      ["Budget", s.budget + " observations"],
      ["Target", "Authored fixture endpoints only"],
      ["Profile", "Fixed deterministic scenario"],
      ["Required mode", "Offline replay"],
      ["Safety", "No network access; no live firewall authority"],
      ["Duration", s.duration],
    ]),
  );
  const run = action(
    "Run scenario",
    () =>
      confirmAction(
        "Run " + s.name + "?",
        `${s.budget} offline observations enter the real parser and rules. Evidence is labelled replay. No packets are transmitted.`,
        async () => {
          const result = await api("lab-runs", "POST", { scenario: s.id });
          state.origin = "replay";
          state.run = result.id;
          state.screen = "lab";
          updateURL();
          $("detail-dialog").close();
          await poll();
          return result;
        },
      ),
    "button primary",
  );
  run.disabled = context.role === "viewer";
  root.append(run);
  if (!$("detail-dialog").open) $("detail-dialog").showModal();
}

$("mobile-navigation").replaceChildren(
  ...Array.from($("navigation").children, (child) => {
    const clone = child.cloneNode(true);
    clone.querySelectorAll("[id]").forEach((n) => n.removeAttribute("id"));
    return clone;
  }),
);

$("open-navigation").addEventListener("click", () =>
  $("navigation-dialog").showModal(),
);
$("mobile-navigation").addEventListener("click", (e) => {
  if (e.target.closest("a")) $("navigation-dialog").close();
});
document
  .querySelectorAll("[data-close-dialog]")
  .forEach((b) =>
    b.addEventListener("click", () => b.closest("dialog").close()),
  );
$("detail-dialog").addEventListener("close", () => {
  liveRunDetail = null;
  ++detailToken;
});

$("data-mode").addEventListener("change", () => {
  state.origin = $("data-mode").value;
  state.run = "";
  state.offset = 0;
  updateURL();
  poll();
});
$("time-range").addEventListener("change", () => {
  state.range = $("time-range").value;
  state.offset = 0;
  updateURL();
  poll();
});
$("global-search").addEventListener("submit", (e) => {
  e.preventDefault();
  state.q = $("search-input").value.trim();
  state.screen = "alerts";
  state.offset = 0;
  updateURL();
  poll();
});
$("refresh").addEventListener("click", poll);

document.addEventListener("keydown", (e) => {
  if (
    (e.ctrlKey || e.metaKey) &&
    e.key.toLowerCase() === "k" &&
    !document.querySelector("dialog[open]")
  ) {
    e.preventDefault();
    $("search-input").focus();
  }
});
window.addEventListener("hashchange", () => {
  document.querySelectorAll("dialog[open]").forEach((d) => d.close());
  readRoute();
});
window.addEventListener("offline", () => {
  state.error = "Browser is offline";
  chrome();
});
window.addEventListener("online", poll);
document.addEventListener("visibilitychange", () => {
  if (document.hidden) clearTimeout(timer);
  else poll();
});
setInterval(chrome, 1000);
readRoute();
