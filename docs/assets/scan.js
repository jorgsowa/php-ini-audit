(function () {
  var PYODIDE = "https://cdn.jsdelivr.net/pyodide/v0.26.4/full/";
  var SEVERITIES = ["critical", "high", "medium", "low", "info"];
  var form = document.getElementById("scan-form");
  var input = document.getElementById("scan-input");
  var file = document.getElementById("scan-file");
  var kind = document.getElementById("scan-kind");
  var sapi = document.getElementById("scan-sapi");
  var version = document.getElementById("scan-version");
  var profile = document.getElementById("scan-profile");
  var button = document.getElementById("scan-button");
  var clear = document.getElementById("scan-clear");
  var status = document.getElementById("scan-status");
  var results = document.getElementById("results");
  var runtime = null;

  function loadScript(src) {
    return new Promise(function (resolve, reject) {
      var script = document.createElement("script");
      script.src = src;
      script.onload = resolve;
      script.onerror = function () { reject(new Error("could not load " + src)); };
      document.head.appendChild(script);
    });
  }

  function scanner() {
    if (!runtime) {
      runtime = loadScript(PYODIDE + "pyodide.js")
        .then(function () { return Promise.all([loadPyodide({ indexURL: PYODIDE }), fetch("assets/php_ini_audit.zip")]); })
        .then(function (loaded) {
          if (!loaded[1].ok) throw new Error("could not load the scanner bundle");
          return loaded[1].arrayBuffer().then(function (bundle) {
            var py = loaded[0];
            py.FS.writeFile("/php_ini_audit.zip", new Uint8Array(bundle));
            py.runPython(
              "import json, sys\nsys.path.insert(0, '/php_ini_audit.zip')\n" +
              "from php_ini_audit import paste, report\nfrom php_ini_audit.engine import Options"
            );
            return py;
          });
        });
      runtime.catch(function () { runtime = null; });
    }
    return runtime;
  }

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = text;
    return node;
  }

  function row(label, value) {
    var tr = el("tr");
    tr.appendChild(el("th", null, label));
    var td = el("td");
    td.appendChild(el("code", null, value));
    tr.appendChild(td);
    return tr;
  }

  function render(scan, detected) {
    var report = scan.report;
    var targets = report.targets;
    var first = targets[0];
    var files = [];
    targets.forEach(function (t) { t.files.forEach(function (f) { if (files.indexOf(f) === -1) files.push(f); }); });
    document.getElementById("target").replaceChildren(
      row("Input", scan.label + (detected ? " (detected)" : "")),
      row("PHP version", first.php_version ? first.php_version + (first.php_version_source ? " from " + first.php_version_source : "") : "unknown"),
      row("SAPI", first.sapi),
      row(targets.length > 1 ? "Configurations" : "Configuration", targets.map(function (t) { return t.name; }).join("\n")),
      row("Files", files.length ? files.join(", ") : "none")
    );
    document.getElementById("kind-hint").hidden = !(detected && scan.kind === "php.ini");

    var counts = report.summary.by_severity;
    var summary = document.getElementById("severity-summary");
    summary.replaceChildren();
    SEVERITIES.forEach(function (severity) {
      summary.appendChild(el("span", "sev sev-" + severity, counts[severity] + " " + severity));
    });

    var warnings = document.getElementById("warnings");
    warnings.replaceChildren.apply(warnings, report.warnings.map(function (w) { return el("li", null, w); }));

    var list = document.getElementById("findings");
    list.replaceChildren();
    if (!report.findings.length) list.appendChild(el("p", null, "No findings."));
    report.findings.forEach(function (finding) {
      var details = el("details", "rule");
      var summaryLine = el("summary");
      var id = el("a", "id", finding.rule_id);
      id.href = "rules.html#" + encodeURIComponent(finding.rule_id);
      summaryLine.appendChild(id);
      summaryLine.appendChild(el("span", "title", finding.title));
      summaryLine.appendChild(el("span", "sev sev-" + finding.severity, finding.severity));
      details.appendChild(summaryLine);

      var body = el("div", "body");
      var meta = el("div", "meta");
      meta.appendChild(el("span", null, "Confidence " + finding.confidence));
      if (finding.from_default) meta.appendChild(el("span", null, "PHP built-in default"));
      else if (finding.file) meta.appendChild(el("span", null, finding.file + (finding.line ? ":" + finding.line : "")));
      if (targets.length > 1) meta.appendChild(el("span", null, finding.target));
      if (finding.cwe) meta.appendChild(el("span", null, finding.cwe));
      body.appendChild(meta);
      body.appendChild(el("p", null, finding.message));
      if (finding.directive) {
        var value = el("p");
        value.appendChild(el("code", null, finding.directive + " = " + (finding.value === "" || finding.value === null ? "(empty)" : finding.value)));
        body.appendChild(value);
      }
      var fix = el("p", "fix");
      fix.appendChild(el("b", null, "Fix: "));
      fix.appendChild(document.createTextNode(finding.recommendation));
      body.appendChild(fix);
      details.appendChild(body);
      list.appendChild(details);
    });
    results.hidden = false;
  }

  function scan(text) {
    button.disabled = true;
    status.textContent = runtime ? "Scanning…" : "Loading the scanner (first scan only)…";
    return scanner()
      .then(function (py) {
        status.textContent = "Scanning…";
        py.globals.set("pasted", text);
        py.globals.set("kind", kind.value);
        py.globals.set("sapi", sapi.value);
        py.globals.set("version", version.value);
        py.globals.set("profile", profile.value);
        var json = py.runPython(
          "options = Options(profile=profile, sapi=sapi or None, php_version=paste.parse_version(version))\n" +
          "detected, result = paste.audit(pasted, kind or None, options)\n" +
          "json.dumps({'kind': detected, 'label': paste.KINDS[detected][0], " +
          "'report': json.loads(report.render_json(result, profile))})"
        );
        var result = JSON.parse(json);
        render(result, !kind.value);
        var count = result.report.findings.length;
        status.textContent = count + (count === 1 ? " finding" : " findings");
        document.getElementById("report").scrollIntoView({ behavior: "smooth" });
      })
      .catch(function (error) {
        var lines = String(error && error.message || error).trim().split("\n");
        status.textContent = lines[lines.length - 1].replace(/^\w+Error: /, "");
        results.hidden = true;
      })
      .then(function () { button.disabled = false; });
  }

  form.addEventListener("submit", function (event) {
    event.preventDefault();
    if (!input.value.trim()) {
      status.textContent = "Paste something to audit first.";
      return;
    }
    scan(input.value);
  });

  clear.addEventListener("click", function () {
    input.value = "";
    file.value = "";
    status.textContent = "";
    results.hidden = true;
    ["target", "severity-summary", "warnings", "findings"].forEach(function (id) {
      document.getElementById(id).replaceChildren();
    });
    input.focus();
  });

  file.addEventListener("change", function () {
    if (!file.files.length) return;
    var chosen = file.files[0];
    chosen.text().then(function (text) {
      input.value = text;
      // A file name settles what text alone cannot.
      if (chosen.name === ".user.ini") kind.value = "user.ini";
      else if (chosen.name === ".htaccess") kind.value = "htaccess";
      scan(text);
    });
  });

  // Start downloading the runtime as soon as the visitor shows intent.
  input.addEventListener("focus", function () { scanner().catch(function () {}); }, { once: true });
})();
