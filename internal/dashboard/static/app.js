// Tell the reader when new entries arrive, without reloading the page under
// them.
(function () {
  "use strict";
  var shown = Number(document.body.dataset.entries);
  var live = document.getElementById("live");
  var count = document.getElementById("live-count");
  function check() {
    fetch("/status.json", { cache: "no-store" })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (s) {
        if (!s) return;
        var added = s.entries - shown;
        if (added > 0) {
          count.textContent = added === 1 ? "1 new entry in the log." : added + " new entries in the log.";
          live.hidden = false;
        }
      })
      .catch(function () {});
  }
  setInterval(check, 5000);
})();
