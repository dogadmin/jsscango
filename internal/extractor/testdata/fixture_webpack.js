/*
 * Stripped-down webpack runtime + a couple of consumer hooks.
 * Intentionally close in shape to what `webpack 5` outputs for a CRA-style
 * production build. Inline-min, with extra commentary added by hand so the
 * regex pass has realistic noise to ignore.
 */
(function (modules) {
    var installedChunks = {"main": 0};
    var publicPath = "/static/js/";

    function jsonp(t){return e.p+"static/js/"+{"42":"abc123","57":"def456","91":"deadbeef"}[t]+".js"}

    function loadChunk(chunkId) {
        var script = document.createElement("script");
        script.src = jsonp(chunkId);
        document.head.appendChild(script);
    }

    // Dynamic import shims emitted by @babel/plugin-syntax-dynamic-import.
    var deferredAdmin = import("/static/js/admin.7f2a.js");
    var deferredVendor = import("/static/js/vendor.9912.js");

    // Asset map kept around for the service worker.
    var manifest = {
        path: "/assets/app.entry.js",
        url:  "/static/css/app.b13d.css",
        polyfill: "/polyfills/legacy.4521.js"
    };

    // Routes table that gets passed to the SPA router.
    var routes = [
        { path: "/account/profile", chunk: "42" },
        { path: "/orders/history",  chunk: "57" },
        { path: "/admin/dashboard", chunk: "91" }
    ];

    function preload() {
        // require() forms — covered by js_2 / js_3.
        require("/chunks/runtime.7c1e.js");
        require("/chunks/polyfills.legacy.js");
    }

    // Plain assignment forms — `=...js` shapes.
    var fallback = "/static/js/fallback.0001.js";
    var hotUpdate = "/static/js/main.hot-update.js";

    window.__APP_CONFIG__ = {
        publicPath: publicPath,
        manifest: manifest,
        routes: routes,
        // mixed-quote API endpoints below
        apiBase: '/api/v1/config',
        loginUrl: "/api/auth/login"
    };

    preload();
    loadChunk("42");
})({});
