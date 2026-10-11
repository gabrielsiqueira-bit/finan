// Confirmações, seleção e navegação (sem JS inline por causa da CSP).
document.addEventListener("submit", function (e) {
  var form = e.target;
  var exige = form.dataset.exigeSelecao;
  if (exige && !form.querySelector('input[name="ids"]:checked')) {
    alert(exige);
    e.preventDefault();
    return;
  }
  var msg = form.dataset.confirm;
  if (msg && !confirm(msg)) e.preventDefault();
});

document.addEventListener("change", function (e) {
  var el = e.target;
  if (el.dataset.nav) {
    window.location.href = el.dataset.nav + encodeURIComponent(el.value);
  }
  if (el.hasAttribute("data-select-all")) {
    var form = el.closest("form");
    form.querySelectorAll('input[name="ids"]').forEach(function (c) {
      c.checked = el.checked;
    });
  }
});
