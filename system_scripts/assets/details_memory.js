// I-199 (2026-09-28): the dash keeps every keyed <details> the viewer opened or closed that way
// across tab switches, WITHHELD page flips and panel re-renders. A group carries `data-crkey`
// (proof_dashboard.py); the viewer's own click on its <summary> records the wanted state per
// browser tab (sessionStorage), and any later render of that key is set back to it. A key the
// viewer never touched keeps the server's default (first file group open, the rest shut).
(function () {
    var STORE = 'cr_details_open';
    var wanted = {};
    try { wanted = JSON.parse(sessionStorage.getItem(STORE) || '{}') || {}; } catch (e) { wanted = {}; }

    function save() {
        try { sessionStorage.setItem(STORE, JSON.stringify(wanted)); } catch (e) { /* view-only memory */ }
    }

    function apply(el) {
        var k = el.getAttribute('data-crkey');
        if (k in wanted && el.open !== wanted[k]) { el.open = wanted[k]; }
    }

    function applyAll(root) {
        if (root.nodeType !== 1) { return; }
        if (root.matches('details[data-crkey]')) { apply(root); }
        root.querySelectorAll('details[data-crkey]').forEach(apply);
    }

    // the click lands before the browser flips `open`, so the wanted state is the opposite of now
    document.addEventListener('click', function (ev) {
        var sum = ev.target.closest && ev.target.closest('summary');
        var el = sum && sum.parentElement;
        if (!el || el.tagName !== 'DETAILS' || !el.hasAttribute('data-crkey')) { return; }
        wanted[el.getAttribute('data-crkey')] = !el.open;
        save();
    }, true);

    function start() {
        new MutationObserver(function (muts) {
            muts.forEach(function (m) {
                if (m.type === 'attributes') { if (m.target.hasAttribute('data-crkey')) { apply(m.target); } return; }
                m.addedNodes.forEach(applyAll);
            });
        }).observe(document.body, { childList: true, subtree: true, attributes: true,
                                    attributeFilter: ['open', 'data-crkey'] });
        applyAll(document.body);
    }

    if (document.body) { start(); } else { document.addEventListener('DOMContentLoaded', start); }
})();
