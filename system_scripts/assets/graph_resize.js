// owner 2026-09-28: the circuit graph's height is adjustable — drag the container's bottom-right corner
// (CSS `resize: vertical`, set in proof_dashboard.py). Plotly only re-fits on WINDOW resizes, so this
// re-fits it whenever the container changes size, and keeps the viewer's height per browser.
(function () {
    var KEY = 'cr_graph_height';

    function hook(box) {
        if (box.__crResize) { return; }
        box.__crResize = true;
        try { var h = localStorage.getItem(KEY); if (h) { box.style.height = h; } } catch (e) { /* per-viewer only */ }
        var t = null;
        new ResizeObserver(function () {
            clearTimeout(t);
            t = setTimeout(function () {
                var gd = box.querySelector('.js-plotly-plot');
                if (gd && window.Plotly) { window.Plotly.Plots.resize(gd); }
                try { localStorage.setItem(KEY, box.style.height || (box.offsetHeight + 'px')); } catch (e) { /* ignore */ }
            }, 80);
        }).observe(box);
    }

    function find() {
        var box = document.getElementById('circuit-graph-container');
        if (box) { hook(box); }
    }

    function start() { new MutationObserver(find).observe(document.body, { childList: true, subtree: true }); find(); }
    if (document.body) { start(); } else { document.addEventListener('DOMContentLoaded', start); }
})();
