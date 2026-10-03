// Ask for confirmation before submitting a form marked data-confirm.
document.addEventListener("submit", function (e) {
  var msg = e.target.getAttribute && e.target.getAttribute("data-confirm");
  if (msg && !window.confirm(msg)) e.preventDefault();
});
// A submit button with data-confirm (formaction buttons) asks too.
document.addEventListener("click", function (e) {
  var b = e.target.closest && e.target.closest("button[data-confirm]");
  if (b && !window.confirm(b.getAttribute("data-confirm"))) e.preventDefault();
});
