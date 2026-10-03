// Applies the saved colour theme before the page paints (no flash), and
// marks the document as scripted so the narrow-screen menu can collapse.
// Loaded without defer from <head>; the CSP forbids inline scripts.
(function () {
  var d = document.documentElement;
  d.classList.add("js");
  try {
    var t = window.localStorage.getItem("tls-broker-theme");
    if (t === "light" || t === "dark") d.setAttribute("data-theme", t);
  } catch (e) { /* storage blocked: follow the system setting */ }
})();
