const byId = (id) => document.getElementById(id);
const recordForm = byId("record-form");
const productForm = byId("product-form");
const recordDialog = byId("record-dialog");
const productDialog = byId("product-dialog");
const detailDialog = byId("detail-dialog");
let tracker = { products: [], vulnerabilities: [] };
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

const productNames = (record) => tracker.products
  .filter((product) => record.products.includes(product.id))
  .map((product) => product.name).join(", ");
const statusText = (record) => record.mitigated ? "Mitigated" : "Open";

function render() {
  const records = tracker.vulnerabilities;
  const mitigated = records.filter((record) => record.mitigated).length;
  byId("total").textContent = records.length;
  byId("open").textContent = records.length - mitigated;
  byId("mitigated").textContent = mitigated;
  const query = byId("search").value.trim().toLowerCase();
  const status = byId("status-filter").value;
  const product = Number(byId("product-filter").value);
  const matches = records.filter((record) =>
    (!status || statusText(record).toLowerCase() === status) &&
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
    const state = element("td");
    state.append(element("span", statusText(record), record.mitigated ? "badge resolved" : "badge"));
    const action = element("td");
    const view = element("button", "View", "secondary");
    view.setAttribute("aria-label", "View " + record.title);
    view.addEventListener("click", () => showDetails(record));
    action.append(view);
    row.append(name, element("td", productNames(record)), element("td", record.disclosed), state, action);
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
    (product) => new Option(product.name, product.id)
  ));
  filter.value = previous;
}

async function refresh() {
  tracker = await request("/api/tracker");
  refreshProductFilter();
  render();
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
    label.append(input, product.name);
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
  const name = productForm.elements.name.value.trim();
  const { id } = await request("/api/products", "POST", { name });
  tracker.products.push({ id, name });
  tracker.products.sort((a, b) => a.name.localeCompare(b.name));
  refreshProductFilter();
  if (recordDialog.open) renderProductOptions([...selectedProducts(), id]);
  productDialog.close();
  render();
  byId("page-feedback").textContent = "Product added.";
});

function openProduct() {
  productForm.reset();
  productForm.querySelector(".feedback").textContent = "";
  productDialog.showModal();
}

byId("add-record").addEventListener("click", () => openRecord());
byId("add-product").addEventListener("click", openProduct);
byId("inline-product").addEventListener("click", openProduct);
byId("edit-record").addEventListener("click", () => {
  detailDialog.close();
  openRecord(viewing);
});
recordForm.elements.mitigated.addEventListener("change", syncMitigation);
for (const id of ["search", "status-filter", "product-filter"]) byId(id).addEventListener("input", render);
for (const button of document.querySelectorAll(".cancel")) {
  button.addEventListener("click", () => button.closest("dialog").close());
}
refresh().catch(() => {
  byId("page-feedback").textContent = "Could not load the tracker. Reload the page to try again.";
});
