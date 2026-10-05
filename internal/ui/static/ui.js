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

// Documentation: a copy button on every code block.
document.addEventListener("DOMContentLoaded", function () {
  var blocks = document.querySelectorAll(".doc pre");
  var copy = function (text, done) {
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(done, function () { fallback(text, done); });
    } else {
      fallback(text, done);
    }
  };
  // Plain-HTTP pages have no clipboard API; a selected textarea still copies.
  var fallback = function (text, done) {
    var ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.className = "sr";
    document.body.appendChild(ta);
    ta.select();
    var ok = false;
    try { ok = document.execCommand("copy"); } catch (err) { ok = false; }
    document.body.removeChild(ta);
    if (ok) done();
  };
  for (var i = 0; i < blocks.length; i++) {
    (function (pre) {
      var wrap = document.createElement("div");
      wrap.className = "code-block";
      pre.parentNode.insertBefore(wrap, pre);
      wrap.appendChild(pre);
      var btn = document.createElement("button");
      btn.type = "button";
      btn.className = "copy-btn";
      btn.textContent = "Copy";
      btn.setAttribute("aria-label", "Copy code");
      btn.addEventListener("click", function () {
        copy(pre.textContent.replace(/\n$/, ""), function () {
          btn.textContent = "Copied";
          btn.classList.add("done");
          setTimeout(function () { btn.textContent = "Copy"; btn.classList.remove("done"); }, 1500);
        });
      });
      wrap.appendChild(btn);
    })(blocks[i]);
  }
});

// Documentation: mark the section being read in the contents column and
// keep that entry visible when the column scrolls by itself.
document.addEventListener("DOMContentLoaded", function () {
  var nav = document.querySelector(".docs-nav");
  if (!nav) return;
  var links = nav.querySelectorAll("a[href^='#']");
  var items = [];
  for (var i = 0; i < links.length; i++) {
    var h = document.getElementById(decodeURIComponent(links[i].getAttribute("href").slice(1)));
    if (h) items.push({ link: links[i], heading: h });
  }
  if (!items.length) return;
  var current = null;
  var update = function () {
    var active = items[0];
    for (var i = 0; i < items.length; i++) {
      if (items[i].heading.getBoundingClientRect().top > 96) break;
      active = items[i];
    }
    if (active === current) return;
    if (current) current.link.removeAttribute("aria-current");
    active.link.setAttribute("aria-current", "location");
    current = active;
    if (nav.scrollHeight > nav.clientHeight) {
      var top = active.link.offsetTop, h = active.link.offsetHeight;
      if (top < nav.scrollTop || top + h > nav.scrollTop + nav.clientHeight) {
        nav.scrollTop = top - nav.clientHeight / 3;
      }
    }
  };
  var queued = false;
  window.addEventListener("scroll", function () {
    if (queued) return;
    queued = true;
    window.requestAnimationFrame(function () { queued = false; update(); });
  }, { passive: true });
  window.addEventListener("hashchange", update);
  update();
});
