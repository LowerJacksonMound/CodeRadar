// owner 2026-09-28: a plain scroll over the circuit graph scrolls the PAGE; it no longer gets caught by
// the graph's scroll-zoom (which left the viewer dragging the scrollbar past it). A trackpad pinch
// (the browser sends it as a wheel event with ctrlKey) or Cmd/Ctrl + scroll still zooms the graph.
// Capture phase on window runs before Plotly's own listener; stopping it there keeps Plotly from
// seeing the event, and since nothing calls preventDefault the browser scrolls the page as usual.
(function () {
    window.addEventListener('wheel', function (ev) {
        if (ev.ctrlKey || ev.metaKey) { return; }
        var t = ev.target;
        if (t && t.closest && t.closest('#circuit-graph')) { ev.stopImmediatePropagation(); }
    }, { capture: true, passive: true });
})();
