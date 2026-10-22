(function () {
  "use strict";
  var rows = Array.prototype.slice.call(document.querySelectorAll("#controls tbody tr"));
  var text = document.getElementById("f-text");
  var status = document.getElementById("f-status");
  var severity = document.getElementById("f-severity");
  var category = document.getElementById("f-category");
  var visible = document.getElementById("visible-count");

  function apply() {
    var needle = text.value.trim().toLowerCase();
    var shown = 0;
    rows.forEach(function (row) {
      var ok = (!status.value || row.dataset.status === status.value) &&
        (!severity.value || row.dataset.severity === severity.value) &&
        (!category.value || row.dataset.category === category.value) &&
        (!needle || row.textContent.toLowerCase().indexOf(needle) !== -1);
      row.hidden = !ok;
      if (ok) { shown += 1; }
    });
    visible.textContent = shown;
  }

  [text, status, severity, category].forEach(function (el) {
    el.addEventListener("input", apply);
  });
  document.getElementById("filters").addEventListener("reset", function () {
    window.setTimeout(apply, 0);
  });
  document.querySelectorAll("button.cat").forEach(function (button) {
    button.addEventListener("click", function () {
      category.value = button.dataset.category;
      status.value = "";
      apply();
      document.getElementById("all-title").scrollIntoView({ behavior: "smooth" });
    });
  });

  // Widths are set through the CSSOM so the CSP needs no 'unsafe-inline' style attribute.
  document.querySelectorAll("[data-score]").forEach(function (el) {
    el.style.setProperty("--score", el.dataset.score);
  });
})();
