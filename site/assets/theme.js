/* Runs in <head> before the page paints: applies the saved color theme (no flash) and marks that
   scripts run. "auto" follows prefers-color-scheme; main.js handles the theme button. */
(function () {
  'use strict';
  var root = document.documentElement;
  var theme = 'auto';
  try {
    var saved = window.localStorage.getItem('passtunnel-theme');
    if (saved === 'light' || saved === 'dark') theme = saved;
  } catch (e) {
    /* Storage blocked: stay on auto. */
  }
  root.setAttribute('data-theme', theme);
  root.classList.add('js');
})();
