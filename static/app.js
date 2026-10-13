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

// Mostra "N selecionados" ao lado do botão de remover.
function atualizarSelecao() {
  var n = document.querySelectorAll('input[name="ids"]:checked').length;
  document.querySelectorAll("[data-sel-count]").forEach(function (el) {
    el.textContent = n + (n === 1 ? " selecionado" : " selecionados");
    el.hidden = n === 0;
  });
}

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
  if (el.name === "ids" || el.hasAttribute("data-select-all")) {
    atualizarSelecao();
  }
});

// Fechar avisos (flash).
document.addEventListener("click", function (e) {
  var botao = e.target.closest("[data-dismiss]");
  if (botao) {
    var aviso = botao.closest(".aviso");
    if (aviso) aviso.remove();
  }
});
