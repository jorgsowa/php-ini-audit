(function () {
  var PHP_WASM = "https://cdn.jsdelivr.net/npm/php-wasm@0.2.0/";
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

  var SCAN = [
    "<?php",
    "if (!class_exists('PhpIniAudit\\\\Paste', false)) require '/php-ini-audit.php';",
    "try {",
    "  $in = json_decode(file_get_contents('/input.json'), true);",
    "  $options = new PhpIniAudit\\Options();",
    "  $options->profile = $in['profile'];",
    "  $options->sapi = $in['sapi'] === '' ? null : $in['sapi'];",
    "  $options->phpVersion = PhpIniAudit\\Paste::parseVersion($in['version']);",
    "  [$kind, $result] = PhpIniAudit\\Paste::audit($in['text'], $in['kind'] === '' ? null : $in['kind'], $options);",
    "  $out = ['kind' => $kind, 'label' => PhpIniAudit\\Paste::KINDS[$kind][0],",
    "    'report' => json_decode(PhpIniAudit\\Report::renderJson($result, $in['profile']))];",
    "} catch (Throwable $e) {",
    "  $out = ['error' => $e->getMessage()];",
    "}",
    "file_put_contents('/output.json', json_encode($out));"
  ].join("\n");

  function scanner() {
    if (!runtime) {
      runtime = Promise.all([import(PHP_WASM + "PhpWeb.mjs"), fetch("assets/php-ini-audit.php")])
        .then(function (loaded) {
          if (!loaded[1].ok) throw new Error("could not load the scanner bundle");
          return loaded[1].text().then(function (bundle) {
            var php = new loaded[0].PhpWeb({ version: "8.4" });
            return php.writeFile("/php-ini-audit.php", bundle).then(function () { return php; });
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
      row("PHP version", !first.php_version ? "unknown — enter it to match known vulnerabilities"
        : first.php_version + (first.php_version_source === "--php-version" ? " (entered)" : " from " + first.php_version_source)),
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
      .then(function (php) {
        status.textContent = "Scanning…";
        var request = { text: text, kind: kind.value, sapi: sapi.value, version: version.value, profile: profile.value };
        return php.writeFile("/input.json", JSON.stringify(request))
          .then(function () { return php.run(SCAN); })
          .then(function () { return php.readFile("/output.json"); });
      })
      .then(function (output) {
        var result = JSON.parse(new TextDecoder().decode(output));
        if (result.error) throw new Error(result.error);
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
