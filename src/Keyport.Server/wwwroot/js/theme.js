// Runs before first paint: apply the saved theme, or follow the OS preference.
(function () {
    var saved = null;
    try { saved = localStorage.getItem('sm-theme'); } catch (e) { }
    var theme = saved || (window.matchMedia && matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    document.documentElement.setAttribute('data-bs-theme', theme);
})();
