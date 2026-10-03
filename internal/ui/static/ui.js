// Small enhancements; every page works without them.

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

document.addEventListener("DOMContentLoaded", function () {
  var root = document.documentElement;

  // Theme switch: auto (system), light or dark, remembered per browser.
  var group = document.querySelector(".theme");
  if (group) {
    var current = root.getAttribute("data-theme") || "auto";
    var buttons = group.querySelectorAll("button[data-theme-set]");
    var mark = function (t) {
      for (var i = 0; i < buttons.length; i++) {
        buttons[i].setAttribute("aria-pressed", buttons[i].getAttribute("data-theme-set") === t ? "true" : "false");
      }
    };
    mark(current);
    group.hidden = false;
    group.addEventListener("click", function (e) {
      var b = e.target.closest("button[data-theme-set]");
      if (!b) return;
      var t = b.getAttribute("data-theme-set");
      if (t === "auto") root.removeAttribute("data-theme");
      else root.setAttribute("data-theme", t);
      try {
        if (t === "auto") window.localStorage.removeItem("tls-broker-theme");
        else window.localStorage.setItem("tls-broker-theme", t);
      } catch (err) { /* not remembered; still applied */ }
      mark(t);
    });
  }

  // Narrow screens: the navigation folds behind a menu button.
  var side = document.getElementById("side");
  var btn = side && side.querySelector(".menu-btn");
  if (btn) {
    btn.hidden = false;
    btn.addEventListener("click", function () {
      var open = side.classList.toggle("open");
      btn.setAttribute("aria-expanded", open ? "true" : "false");
    });
  }
});
