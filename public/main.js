(function () {
  document.body.classList.add('loading');
  var minDuration = 2000;
  var start = Date.now();
  var loader = document.getElementById('universeLoader');

  function hideLoader() {
    if (!loader) return;
    var elapsed = Date.now() - start;
    var remain = Math.max(0, minDuration - elapsed);
    setTimeout(function () {
      loader.classList.add('hidden');
      document.body.classList.remove('loading');
    }, remain);
  }

  if (document.readyState === 'complete') {
    hideLoader();
  } else {
    window.addEventListener('load', hideLoader, { once: true });
  }

  const root = document.documentElement;
  const key = 'bella-theme';
  const saved = localStorage.getItem(key);
  if (saved) root.setAttribute('data-theme', saved);

  const toggle = document.getElementById('themeToggle');
  if (toggle) {
    toggle.addEventListener('click', function () {
      const next = root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
      root.setAttribute('data-theme', next);
      localStorage.setItem(key, next);
    });
  }

  if ('serviceWorker' in navigator) {
    window.addEventListener('load', function () {
      navigator.serviceWorker.register('/service-worker.js').catch(function () {});
    });
  }
})();
