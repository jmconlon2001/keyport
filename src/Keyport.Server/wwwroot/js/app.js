// Small helpers for the Blazor UI. No inline scripts (CSP: script-src 'self').
window.sm = {
    copy: async function (text) {
        try {
            await navigator.clipboard.writeText(text);
            return true;
        } catch (e) {
            // Fallback for non-secure contexts / older browsers.
            var ta = document.createElement('textarea');
            ta.value = text; ta.setAttribute('readonly', ''); ta.style.position = 'fixed'; ta.style.opacity = '0';
            document.body.appendChild(ta); ta.select();
            var ok = false;
            try { ok = document.execCommand('copy'); } catch (e2) { }
            document.body.removeChild(ta);
            return ok;
        }
    },
    // Scroll an element into view and put the cursor in it (used to point at the next field to fill in).
    focus: function (id) {
        var el = document.getElementById(id);
        if (!el) return;
        el.scrollIntoView({ block: 'center', behavior: 'smooth' });
        try { el.focus({ preventScroll: true }); } catch (e) { el.focus(); }
    }
};

// Theme toggle (delegated so it works on enhanced-navigation page swaps).
document.addEventListener('click', function (e) {
    var btn = e.target.closest('[data-theme-toggle]');
    if (btn) {
        var next = document.documentElement.getAttribute('data-bs-theme') === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-bs-theme', next);
        try { localStorage.setItem('sm-theme', next); } catch (err) { }
        return;
    }
    // Close the mobile drawer after choosing a destination.
    if (e.target.closest('.sidebar a')) {
        var t = document.getElementById('nav-toggle');
        if (t) t.checked = false;
    }
});

// Clicking a row with data-href navigates (keeps tables keyboard-free of nested links).
document.addEventListener('click', function (e) {
    var row = e.target.closest('tr[data-href]');
    if (row && !e.target.closest('a,button,input,select,label')) {
        if (window.Blazor && Blazor.navigateTo) Blazor.navigateTo(row.getAttribute('data-href'));
        else location.href = row.getAttribute('data-href');
    }
});

// Enhanced navigation can replace <html> attributes; re-apply the theme afterwards.
function smApplyTheme() {
    var saved = null;
    try { saved = localStorage.getItem('sm-theme'); } catch (e) { }
    var theme = saved || (window.matchMedia && matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    if (document.documentElement.getAttribute('data-bs-theme') !== theme) document.documentElement.setAttribute('data-bs-theme', theme);
}
if (window.Blazor && Blazor.addEventListener) Blazor.addEventListener('enhancedload', smApplyTheme);
else document.addEventListener('DOMContentLoaded', function () { if (window.Blazor && Blazor.addEventListener) Blazor.addEventListener('enhancedload', smApplyTheme); });
