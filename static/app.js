const byId = (id) => document.getElementById(id);
const recordForm = byId("record-form");
const productForm = byId("product-form");
const recordDialog = byId("record-dialog");
const productDialog = byId("product-dialog");
const detailDialog = byId("detail-dialog");
let tracker = { products: [], vulnerabilities: [], inventory: [] };
let branding = { name: "Vulnerability Tracker", organization: "", has_logo: false, has_favicon: false, revision: 0 };
let editing = null;
let viewing = null;

function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}

async function request(path, method = "GET", data) {
  const response = await fetch(path, {
    method,
    headers: data ? { "Content-Type": "application/json" } : {},
    body: data ? JSON.stringify(data) : undefined,
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error);
  return result;
}

const productType = { hardware: "Hardware", software: "Software", unclassified: "Unclassified" };
const productLabel = (product) => product.name + " (" + (productType[product.kind] ?? "Unclassified") + ")";

const productNames = (record) => tracker.products
  .filter((product) => record.products.includes(product.id))
  .map((product) => productLabel(product)).join(", ");
const statusText = (record) => record.mitigated ? "Mitigated" : "Open";

const severityText = { low: "Low", medium: "Medium", high: "High", critical: "Critical", unrated: "Unrated" };
const severityOf = (record) => record.severity || "unrated";

function render() {
  const records = tracker.vulnerabilities;
  const mitigated = records.filter((record) => record.mitigated).length;
  byId("total").textContent = records.length;
  byId("open").textContent = records.length - mitigated;
  byId("mitigated").textContent = mitigated;
  const query = byId("search").value.trim().toLowerCase();
  const status = byId("status-filter").value;
  const severity = byId("severity-filter").value;
  const product = Number(byId("product-filter").value);
  const matches = records.filter((record) =>
    (!status || statusText(record).toLowerCase() === status) &&
    (!severity || severityOf(record) === severity) &&
    (!product || record.products.includes(product)) &&
    [record.title, record.cve, record.vendor, productNames(record)].some(
      (value) => value.toLowerCase().includes(query)
    )
  );
  byId("records").replaceChildren(...matches.map((record) => {
    const row = element("tr");
    const name = element("td");
    name.append(element("strong", record.title));
    const ids = [record.cve, record.vendor].filter(Boolean).join(" · ");
    if (ids) name.append(element("div", ids, "identifiers"));
    const rating = element("td");
    const severity = severityOf(record);
    rating.append(element("span", severityText[severity], "badge severity-" + severity));
    const state = element("td");
    state.append(element("span", statusText(record), record.mitigated ? "badge resolved" : "badge"));
    const action = element("td");
    const view = element("button", "View", "secondary");
    view.setAttribute("aria-label", "View " + record.title);
    view.addEventListener("click", () => showDetails(record));
    action.append(view);
    row.append(name, element("td", productNames(record)), element("td", record.disclosed), rating, state, action);
    return row;
  }));
  byId("table-wrap").hidden = !matches.length;
  const empty = byId("empty");
  empty.hidden = Boolean(matches.length);
  empty.replaceChildren(
    element("h3", records.length ? "No matching vulnerabilities" : "No vulnerabilities recorded"),
    element("p", records.length ? "Try a different search or filter." : "Add a vulnerability to start tracking affected products and mitigation.")
  );
}

function refreshProductFilter() {
  const filter = byId("product-filter");
  const previous = filter.value;
  filter.replaceChildren(new Option("All products", ""), ...tracker.products.map(
    (product) => new Option(productLabel(product), product.id)
  ));
  filter.value = previous;
}

async function refresh() {
  tracker = await request("/api/tracker");
  refreshProductFilter();
  render();
  renderInventory();
  renderReport();
}

function selectedProducts() {
  return [...recordForm.querySelectorAll('[name="product"]:checked')].map((input) => Number(input.value));
}

function renderProductOptions(selected) {
  const options = byId("product-options");
  options.replaceChildren(...tracker.products.map((product) => {
    const label = element("label", undefined, "checkbox");
    const input = element("input");
    input.type = "checkbox";
    input.name = "product";
    input.value = product.id;
    input.checked = selected.includes(product.id);
    label.append(input, productLabel(product));
    return label;
  }));
  if (!tracker.products.length) options.append(element("p", "Add a product to select it here."));
}

function syncMitigation() {
  const fields = recordForm.elements;
  byId("mitigation-fields").hidden = !fields.mitigated.checked;
  fields.mitigation_date.required = fields.mitigated.checked;
  fields.mitigation_details.required = fields.mitigated.checked;
}

function openRecord(record = null) {
  editing = record;
  recordForm.reset();
  recordForm.querySelector(".feedback").textContent = "";
  byId("record-title").textContent = record ? "Edit vulnerability" : "Add vulnerability";
  if (record) {
    for (const key of ["title", "cve", "vendor", "disclosed", "notes", "links", "mitigation_date", "mitigation_details"]) {
      recordForm.elements[key].value = record[key];
    }
    recordForm.elements.severity.value = record.severity || "";
    recordForm.elements.mitigated.checked = Boolean(record.mitigated);
  }
  renderProductOptions(record?.products ?? []);
  syncMitigation();
  recordDialog.showModal();
}

function showDetails(record) {
  viewing = record;
  const heading = element("h2", record.title);
  heading.id = "detail-title";
  const list = element("dl");
  function detail(label, value) {
    if (!value) return;
    const description = element("dd");
    description.append(value);
    list.append(element("dt", label), description);
  }
  detail("CVE", record.cve);
  detail("Vendor vulnerability ID", record.vendor);
  detail("Disclosure date", record.disclosed);
  detail("Affected products", productNames(record));
  detail("Severity", severityText[severityOf(record)]);
  detail("Status", statusText(record));
  detail("Mitigation date", record.mitigation_date);
  detail("How it was mitigated", record.mitigation_details);
  detail("Notes", record.notes);
  if (record.links) {
    const links = element("ul");
    for (const url of record.links.split("\n")) {
      const link = element("a", url);
      link.href = url;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      const item = element("li");
      item.append(link);
      links.append(item);
    }
    detail("Reference links", links);
  }
  byId("details").replaceChildren(heading, list);
  detailDialog.showModal();
}

function submit(form, action) {
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const feedback = form.querySelector(".feedback");
    const button = form.querySelector('[type="submit"]');
    feedback.textContent = "";
    button.disabled = true;
    try {
      await action();
    } catch (error) {
      feedback.textContent = error.message;
    } finally {
      button.disabled = false;
    }
  });
}

async function refreshAfterSave(message) {
  const feedback = byId("page-feedback");
  try {
    await refresh();
    feedback.textContent = message;
  } catch {
    feedback.textContent = message + " Reload the page to refresh the list.";
  }
}

submit(recordForm, async () => {
  const data = Object.fromEntries(new FormData(recordForm));
  const id = editing?.id;
  delete data.product;
  data.products = selectedProducts();
  data.mitigated = recordForm.elements.mitigated.checked;
  await request(id ? "/api/vulnerabilities/" + id : "/api/vulnerabilities", id ? "PUT" : "POST", data);
  recordDialog.close();
  await refreshAfterSave("Vulnerability saved.");
});

submit(productForm, async () => {
  const fields = productForm.elements;
  const name = fields.name.value.trim();
  const kind = fields.kind.value;
  const version = fields.version.value.trim();
  const quantity = fields.quantity.value === "" ? null : fields.quantity.valueAsNumber;
  const { id, inventory } = await request("/api/products", "POST", { name, kind, version, quantity });
  tracker.products.push({ id, name, kind });
  tracker.products.sort((a, b) => a.name.localeCompare(b.name));
  if (inventory) {
    tracker.inventory.push(inventory);
    const positions = new Map(tracker.products.map((product, index) => [product.id, index]));
    tracker.inventory.sort((a, b) => positions.get(a.product_id) - positions.get(b.product_id));
  }
  refreshProductFilter();
  renderInventory();
  if (recordDialog.open) renderProductOptions([...selectedProducts(), id]);
  productDialog.close();
  render();
  byId("page-feedback").textContent = "Product added.";
});

function openProduct() {
  productForm.reset();
  productForm.elements.quantity.required = false;
  productForm.querySelector(".feedback").textContent = "";
  productDialog.showModal();
}

byId("add-record").addEventListener("click", () => openRecord());
byId("add-product").addEventListener("click", openProduct);
byId("inline-product").addEventListener("click", openProduct);
productForm.elements.version.addEventListener("input", () => {
  productForm.elements.quantity.required = Boolean(productForm.elements.version.value.trim());
});
byId("edit-record").addEventListener("click", () => {
  detailDialog.close();
  openRecord(viewing);
});
recordForm.elements.mitigated.addEventListener("change", syncMitigation);
for (const id of ["search", "status-filter", "severity-filter", "product-filter"]) byId(id).addEventListener("input", render);
for (const button of document.querySelectorAll(".cancel")) {
  button.addEventListener("click", () => button.closest("dialog").close());
}
const inventoryForm = byId("inventory-form");
const classifyForm = byId("classify-form");
const reportForm = byId("report-form");
const brandingForm = byId("branding-form");

const views = [
  { id: "vulnerabilities", panel: "vulnerability-view", title: "Vulnerabilities", description: "Track disclosures, affected items, and mitigation." },
  { id: "inventory", panel: "inventory-view", title: "Product inventory", description: "Track installed hardware and software by running version." },
  { id: "report", panel: "report-view", title: "Reports", description: "Build a vulnerability report for printing or saving as PDF." },
  { id: "settings", panel: "settings-view", title: "Settings", description: "Customize the tracker and its printed reports." },
];
for (const view of views) {
  byId("show-" + view.id).addEventListener("click", () => {
    for (const entry of views) {
      byId(entry.panel).hidden = entry !== view;
      byId("show-" + entry.id).setAttribute("aria-pressed", String(entry === view));
    }
    byId("current-view").textContent = view.title;
    byId("view-title").textContent = view.title;
    byId("view-description").textContent = view.description;
    byId("add-record").hidden = view.id !== "vulnerabilities";
    byId("add-product").hidden = !["vulnerabilities", "inventory"].includes(view.id);
    byId("page-feedback").textContent = "";
  });
}

function renderInventory() {
  const fields = inventoryForm.elements;
  for (const select of [fields.product_id, classifyForm.elements.product_id]) {
    const previous = select.value;
    select.replaceChildren(new Option("Select hardware or software", ""), ...tracker.products.map(
      (product) => new Option(productLabel(product), product.id)
    ));
    select.value = previous;
  }
  const names = new Map(tracker.products.map((product) => [product.id, productLabel(product)]));
  const rows = tracker.inventory.map((entry) => {
    const row = element("tr");
    const action = element("td");
    const edit = element("button", "Edit quantity", "secondary");
    edit.type = "button";
    edit.addEventListener("click", () => {
      fields.product_id.value = entry.product_id;
      fields.version.value = entry.version;
      fields.quantity.value = entry.quantity;
      fields.quantity.focus();
    });
    action.append(edit);
    row.append(element("td", names.get(entry.product_id)), element("td", entry.version || "Unspecified"),
      element("td", String(entry.quantity)), action);
    return row;
  });
  byId("inventory-records").replaceChildren(...rows);
  byId("inventory-table").hidden = !rows.length;
  const empty = byId("inventory-empty");
  empty.hidden = Boolean(rows.length);
  empty.textContent = tracker.products.length ? "No inventory entries yet." : "Add a product to start tracking inventory.";
}

submit(inventoryForm, async () => {
  const fields = inventoryForm.elements;
  const quantity = fields.quantity.valueAsNumber;
  await request("/api/inventory", "PUT", {
    product_id: Number(fields.product_id.value), version: fields.version.value, quantity,
  });
  inventoryForm.reset();
  const feedback = inventoryForm.querySelector(".feedback");
  const message = quantity ? "Quantity saved." : "Inventory entry removed.";
  try {
    await refresh();
    feedback.textContent = message;
  } catch {
    feedback.textContent = message + " Reload the page to refresh the inventory.";
  }
});

classifyForm.elements.product_id.addEventListener("change", () => {
  const fields = classifyForm.elements;
  const product = tracker.products.find((item) => item.id === Number(fields.product_id.value));
  fields.kind.value = product?.kind === "unclassified" ? "" : (product?.kind ?? "");
});

submit(classifyForm, async () => {
  const fields = classifyForm.elements;
  const id = Number(fields.product_id.value);
  const kind = fields.kind.value;
  await request("/api/products/" + id, "PUT", { kind });
  tracker.products.find((item) => item.id === id).kind = kind;
  refreshProductFilter();
  render();
  renderInventory();
  renderReport();
  classifyForm.querySelector(".feedback").textContent = "Type saved.";
});

function reportTable(headers, rows) {
  const table = element("table");
  const head = table.createTHead().insertRow();
  for (const label of headers) {
    const cell = element("th", label);
    cell.scope = "col";
    head.append(cell);
  }
  const body = table.createTBody();
  for (const values of rows) {
    const row = body.insertRow();
    for (const value of values) row.append(element("td", String(value)));
  }
  return table;
}

function brandingImage(key) {
  return "/branding/" + key + "?v=" + branding.revision;
}

function applyBranding() {
  document.title = branding.name;
  byId("brand-name").textContent = branding.name;
  const organization = byId("brand-organization");
  organization.textContent = branding.organization;
  organization.hidden = !branding.organization;
  const logo = byId("brand-logo");
  if (branding.has_logo) logo.src = brandingImage("logo");
  else logo.removeAttribute("src");
  logo.hidden = !branding.has_logo;
  logo.previousElementSibling.hidden = Boolean(branding.has_logo);
  byId("brand-favicon").href = branding.has_favicon ? brandingImage("favicon") : "/favicon.png";
  brandingForm.reset();
  brandingForm.elements.name.value = branding.name;
  brandingForm.elements.organization.value = branding.organization;
  byId("remove-logo").hidden = !branding.has_logo;
  byId("remove-favicon").hidden = !branding.has_favicon;
  renderReport();
}

function readImage(file) {
  if (file.size > 256 * 1024) throw new Error("Choose an image up to 256 KB.");
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.addEventListener("load", () => resolve(reader.result.split(",")[1]));
    reader.addEventListener("error", () => reject(new Error("The image could not be read.")));
    reader.readAsDataURL(file);
  });
}

submit(brandingForm, async () => {
  const fields = brandingForm.elements;
  const data = { name: fields.name.value, organization: fields.organization.value };
  for (const key of ["logo", "favicon"]) {
    const file = fields[key].files[0];
    if (file) data[key] = await readImage(file);
    else if (fields["remove_" + key].checked) data[key] = null;
  }
  branding = await request("/api/branding", "PUT", data);
  applyBranding();
  brandingForm.querySelector(".feedback").textContent = "Branding saved.";
});

function reportHeader(period) {
  const header = element("header", undefined, "report-header");
  const identity = element("div", undefined, "report-identity");
  if (branding.has_logo) {
    const logo = element("img", undefined, "report-logo");
    logo.src = brandingImage("logo");
    logo.alt = "";
    identity.append(logo);
  } else {
    const mark = element("span", "V", "brand-mark");
    mark.setAttribute("aria-hidden", "true");
    identity.append(mark);
  }
  const brand = element("div");
  brand.append(element("strong", branding.name));
  if (branding.organization) brand.append(element("small", branding.organization));
  identity.append(brand);
  header.append(identity, element("h2", "Vulnerability report"),
    element("p", "Disclosure period · " + period, "report-period"));
  return header;
}

function renderReport() {
  const fields = reportForm.elements;
  const from = fields.from.value;
  const through = fields.through.value;
  fields.through.setCustomValidity(from && through && from > through ? "Use an end date on or after the start date." : "");
  const preview = byId("report-preview");
  preview.replaceChildren();
  const selected = ["total", "products", "active", "mitigated", "list"].some((key) => fields[key].checked);
  if (!fields.through.validity.valid || !selected) {
    preview.append(element("p", selected ? fields.through.validationMessage : "Select at least one report section."));
    return false;
  }
  const records = tracker.vulnerabilities.filter((record) =>
    (!from || record.disclosed >= from) && (!through || record.disclosed <= through)
  );
  const groups = tracker.products.map((product) => ({
    name: productLabel(product),
    records: records.filter((record) => record.products.includes(product.id)),
  })).filter((group) => group.records.length);
  const mitigated = records.filter((record) => record.mitigated).length;
  const period = from && through ? from + " through " + through
    : from ? "From " + from : through ? "Through " + through : "All dates";
  preview.append(reportHeader(period));
  const counts = [
    ["total", "Total vulnerabilities", records.length],
    ["active", "Active vulnerabilities", records.length - mitigated],
    ["mitigated", "Mitigated vulnerabilities", mitigated],
  ].filter(([key]) => fields[key].checked);
  if (counts.length) {
    const totals = element("dl", undefined, "report-totals");
    for (const [, label, count] of counts) {
      const metric = element("div");
      metric.append(element("dt", label), element("dd", String(count)));
      totals.append(metric);
    }
    preview.append(totals);
  }
  if (fields.products.checked) {
    const section = element("section", undefined, "report-section");
    section.append(element("h3", "Vulnerabilities by product or software"));
    if (groups.length) {
      section.append(element("p", "A vulnerability affecting several products counts once for each affected product.", "report-note"),
        reportTable(["Product or software", "Vulnerabilities"], groups.map((group) => [group.name, group.records.length])));
    } else {
      section.append(element("p", "No affected products in this period."));
    }
    preview.append(section);
  }
  if (fields.list.checked) {
    const section = element("section", undefined, "report-section");
    section.append(element("h3", "Vulnerability list"));
    const byTitle = (a, b) => a.title.localeCompare(b.title) || b.disclosed.localeCompare(a.disclosed) || a.id - b.id;
    const byDate = (a, b) => b.disclosed.localeCompare(a.disclosed) || byTitle(a, b);
    const sort = fields.sort.value;
    const tableFor = (entries, includeProduct) => {
      const headers = ["Vulnerability", "Disclosed", "Severity", "Status", "Mitigated on"];
      if (includeProduct) headers.splice(1, 0, "Affected products");
      const rows = entries.map((record) => {
        const identifiers = [record.title, record.cve, record.vendor].filter(Boolean).join(" · ");
        const values = [identifiers, record.disclosed, severityText[severityOf(record)], record.mitigated ? "Mitigated" : "Active", record.mitigation_date || "—"];
        if (includeProduct) values.splice(1, 0, productNames(record));
        return values;
      });
      const table = reportTable(headers, rows);
      table.className = "report-vulnerabilities";
      return table;
    };
    if (!records.length) {
      section.append(element("p", "No vulnerabilities match this disclosure period."));
    } else if (sort === "product") {
      for (const group of groups) {
        const block = element("section", undefined, "report-section");
        block.append(element("h3", group.name), tableFor(group.records.sort(byTitle), false));
        section.append(block);
      }
    } else {
      section.append(tableFor(records.sort(sort === "date" ? byDate : byTitle), true));
    }
    preview.append(section);
  }
  return true;
}

reportForm.addEventListener("input", () => {
  reportForm.querySelector(".feedback").textContent = "";
  renderReport();
});
reportForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!renderReport()) {
    reportForm.querySelector(".feedback").textContent = "Select at least one report section.";
    return;
  }
  const printReport = byId("print-report");
  printReport.replaceChildren(...[...byId("report-preview").childNodes].map((node) => node.cloneNode(true)));
  const logo = printReport.querySelector(".report-logo");
  if (logo) await logo.decode().catch(() => {});
  document.body.classList.add("printing-report");
  window.print();
});
window.addEventListener("afterprint", () => document.body.classList.remove("printing-report"));

refresh().catch(() => {
  byId("page-feedback").textContent = "Could not load the tracker. Reload the page to try again.";
});
request("/api/branding").then((saved) => {
  branding = saved;
  applyBranding();
}).catch(() => {
  brandingForm.querySelector(".feedback").textContent = "Could not load the saved branding. Reload the page to try again.";
});

function selectSettings(section) {
  for (const name of ["branding", "sign-in"]) {
    byId(name + "-settings").hidden = section !== name;
    byId("show-" + name + "-settings").setAttribute("aria-pressed", String(section === name));
  }
}

byId("show-branding-settings").addEventListener("click", () => selectSettings("branding"));
byId("show-sign-in-settings").addEventListener("click", () => selectSettings("sign-in"));
byId("copy-callback").addEventListener("click", async () => {
  const field = byId("setup-callback");
  try {
    await navigator.clipboard.writeText(field.value);
    byId("copy-callback-status").textContent = "Copied.";
  } catch {
    field.select();
    byId("copy-callback-status").textContent = "URL selected. Copy it to the clipboard.";
  }
});

byId("sign-out").addEventListener("click", async () => {
  try {
    await request("/auth/logout", "POST", {});
    window.location.assign("/");
  } catch {
    byId("sign-out-feedback").textContent = "Could not sign out. Try again.";
  }
});

request("/api/auth").then((settings) => {
  const user = settings.user;
  const testMode = settings.mode === "test";
  const required = settings.mode === "required";
  byId("setup-callback").value = settings.redirect_uri || (location.protocol === "https:"
    ? location.origin + "/auth/callback" : "https://tracker.example.com/auth/callback");
  byId("callback-hint").hidden = Boolean(settings.redirect_uri) || location.protocol === "https:";
  const role = user?.admin ? "administrator" : "member";
  const account = user ? " Signed in as " + user.name + " (" + role + ")." : "";
  byId("auth-status").textContent = settings.mode === "off" ? "OIDC sign-in is off."
    : settings.provider + (testMode ? " is in test mode. Sign-in is optional." : " sign-in is required.") + account;
  byId("test-sign-in").hidden = !testMode;
  if (testMode) byId("test-sign-in").href = new URL("/auth/login", settings.redirect_uri).href;
  byId("sidebar-session").hidden = !user;
  if (user) byId("session-name").textContent = user.name;
  if (required && user && !user.admin) {
    brandingForm.hidden = true;
    byId("branding-access").hidden = false;
  }
  if (testMode && new URLSearchParams(location.search).get("signin") === "test") {
    byId("show-settings").click();
    selectSettings("sign-in");
    history.replaceState(null, "", "/");
  }
}).catch(() => {
  byId("auth-status").textContent = "Could not load sign-in settings.";
});
