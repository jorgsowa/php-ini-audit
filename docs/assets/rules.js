(function () {
  var search = document.getElementById("rule-search");
  var severity = document.getElementById("rule-severity");
  var category = document.getElementById("rule-category");
  var count = document.getElementById("rule-count");
  var noMatch = document.getElementById("no-match");
  var rules = Array.prototype.slice.call(document.querySelectorAll(".rule"));
  var sections = Array.prototype.slice.call(document.querySelectorAll(".category"));

  function apply() {
    var terms = search.value.toLowerCase().split(/\s+/).filter(Boolean);
    var shown = 0;
    rules.forEach(function (rule) {
      var text = rule.getAttribute("data-search");
      var visible =
        (!severity.value || rule.getAttribute("data-severity") === severity.value) &&
        (!category.value || rule.getAttribute("data-category") === category.value) &&
        terms.every(function (term) { return text.indexOf(term) !== -1; });
      rule.hidden = !visible;
      if (visible) shown++;
    });
    sections.forEach(function (section) {
      section.hidden = !section.querySelector(".rule:not([hidden])");
    });
    count.textContent = shown + " of " + rules.length;
    noMatch.hidden = shown !== 0;
  }

  function openTarget() {
    var id = decodeURIComponent(location.hash.slice(1));
    var target = id && document.getElementById(id);
    if (target && target.classList.contains("rule")) {
      target.open = true;
      target.scrollIntoView();
    }
  }

  [search, severity, category].forEach(function (control) {
    control.addEventListener("input", apply);
  });
  window.addEventListener("hashchange", openTarget);
  apply();
  openTarget();
})();
