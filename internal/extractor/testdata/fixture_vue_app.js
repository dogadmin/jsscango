/*
 * Snippet from a Vue 2.x application bundle, post-vue-cli build.
 * Lots of quoted "path:" / "url:" / "index:" literals so the keyword-prefix
 * patterns from patterns_apiurl.go fire. A handful of decoy strings
 * (CSS class names, i18n keys) verify the false-positive predicates kick in.
 */
const ApiService = {
    user: {
        list:   { path: "/api/v1/user/list",   method: "GET"  },
        detail: { path: "/api/v1/user/detail", method: "GET"  },
        create: { path: "/api/v1/user/create", method: "POST" },
        update: { path: "/api/v1/user/update", method: "PUT"  }
    },
    order: {
        search:  { url: "/services/order/search",  method: "GET" },
        cancel:  { url: "/services/order/cancel",  method: "POST" },
        refund:  { url: "/services/order/refund",  method: "POST" }
    },
    config: {
        index: { path: "/api/v2/config/index", method: "GET" }
    }
};

// External CDN JS — js_patterns explicitly forbid ':' in the body, so this
// literal is NOT captured by the JS regexes, and it is also stripped from
// the static-paths output because of the .js suffix check.
const VENDOR_JQUERY = "https://cdn.acme-corp.com/lib/jquery.min.js";

// Locale dictionary — i18n keys (a.b.c shape) must NOT leak into api.
const messages = {
    en: {
        "common.button.submit":   "Submit",
        "common.button.cancel":   "Cancel",
        "common.dialog.title.ok": "Confirmed"
    }
};

// CSS class registry — single-segment kebab-case strings must NOT leak.
const themeClasses = {
    primary: "header-light",
    accent:  "btn-flat",
    footer:  "footer-dim"
};

// A couple of genuine routes pointing at the SPA's pages.
const router = [
    { path: "/dashboard/overview" },
    { path: "/reports/monthly" },
    { path: "/profile/settings" }
];

// AJAX helper using axios + a couple of in-flight URLs.
function fetchUser(id) {
    return axios.get("/api/v1/user/" + id);
}

function uploadAvatar(blob) {
    return axios.post({
        url: "/api/v1/user/avatar",
        data: blob,
        headers: { "Content-Type": "multipart/form-data" }
    });
}

export default { ApiService, fetchUser, uploadAvatar };
