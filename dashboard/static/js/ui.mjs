// API strings are text nodes. No HTML injection or third-party runtime assets.
export function el(tag, className = "", text = "") {
  const node = document.createElement(tag);
  node.className = className;
  if (text !== "") node.textContent = String(text);
  return node;
}
export function append(node, ...children) {
  children
    .flat()
    .filter(Boolean)
    .forEach((child) => node.append(child));
  return node;
}
export function icon(name) {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  const use = document.createElementNS(svg.namespaceURI, "use");
  use.setAttribute("href", "/static/icons.svg#" + name);
  svg.setAttribute("aria-hidden", "true");
  svg.append(use);
  return svg;
}
export function badge(text, tone = "neutral") {
  return el("span", "badge " + tone, text);
}
export function button(text, action, className = "button") {
  const result = el("button", className, text);
  result.type = "button";
  result.dataset.focusKey = text;
  result.addEventListener("click", action);
  return result;
}
export function link(text, href, className = "button text") {
  const result = el("a", className, text);
  result.href = href;
  return result;
}
export function number(value) {
  return Number.isFinite(value)
    ? value.toLocaleString(undefined, { maximumFractionDigits: 1 })
    : "—";
}
export function datetime(value) {
  return value == null
    ? "Not observed"
    : new Date(value * 1000)
        .toISOString()
        .replace("T", " ")
        .replace(".000Z", " UTC");
}
export function stamp(value) {
  const node = el(
    "time",
    "",
    value == null
      ? "Not observed"
      : new Date(value * 1000).toISOString().slice(11, 19) + " UTC",
  );
  node.title = datetime(value);
  if (value != null) node.dateTime = new Date(value * 1000).toISOString();
  return node;
}
export function panel(title, body, action = null, className = "") {
  return append(
    el("section", "panel " + className),
    append(el("div", "panel-header"), el("h2", "", title), action),
    body,
  );
}
export function empty(title, message, action = null) {
  return append(
    el("div", "empty-state"),
    icon("file"),
    el("h3", "", title),
    el("p", "", message),
    action,
  );
}
export function notice(title, message) {
  return append(
    el("div", "notice"),
    icon("alerts"),
    append(el("div"), el("strong", "", title), el("p", "", message)),
  );
}
export function definitions(rows) {
  return append(
    el("dl", "definition-list"),
    rows.map(([label, value]) =>
      append(
        el("div"),
        el("dt", "", label),
        append(
          el("dd"),
          value instanceof Node
            ? value
            : el("span", "", value ?? "Not observed"),
        ),
      ),
    ),
  );
}
export function table(
  headers,
  rows,
  title = "No observations in this time range.",
  message = "Sensor health is reported separately.",
) {
  const result = el("table");
  result.append(
    append(
      el("thead"),
      append(
        el("tr"),
        headers.map((h) => el("th", "", h)),
      ),
    ),
  );
  const body = el("tbody");
  if (!rows.length) {
    const cell = el("td", "table-placeholder");
    cell.colSpan = headers.length;
    append(cell, el("strong", "", title), el("p", "", message));
    body.append(append(el("tr"), cell));
  }
  rows.forEach((row) =>
    body.append(
      append(
        el("tr"),
        row.map((cell) =>
          append(
            el("td"),
            cell instanceof Node ? cell : el("span", "", cell ?? "—"),
          ),
        ),
      ),
    ),
  );
  result.append(body);
  const scroll = append(el("div", "table-scroll"), result);
  scroll.tabIndex = 0;
  scroll.setAttribute("role", "region");
  scroll.setAttribute(
    "aria-label",
    headers.join(", ") + " table; scroll horizontally for more columns",
  );
  return scroll;
}
export function metric(label, value, note) {
  return append(
    el("div", "status-cell"),
    el("div", "status-label", label),
    el("div", "status-value", value),
    el("div", "status-note", note),
  );
}
let fieldSequence = 0;
export function field(label, name, type = "text", value = "") {
  const input = el(type === "textarea" ? "textarea" : "input");
  if (type !== "textarea") input.type = type;
  input.name = name;
  input.value = value;
  input.id = "field-" + name + "-" + ++fieldSequence;
  input.required = true;
  input.maxLength = type === "textarea" ? 2000 : 128;
  const title = el("label", "", label);
  title.htmlFor = input.id;
  return append(el("div", "form-field"), title, input);
}
