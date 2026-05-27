/*
 * Synthetic body that exercises every patterns_extra.go shape.
 * Captures: Next/Nuxt build markers, Swagger / OpenAPI docs, Spring Cloud
 * actuator + Eureka discovery, source-maps, RPC schemes, internal hosts.
 * Also includes a couple of JWT-looking blobs that the extractor must drop.
 */

// ---- Next.js / Nuxt build-time metadata ------------------------------------
const NEXT_BUILD_MANIFEST = "/_next/static/abcd1234efgh5678/_buildManifest.js";
const NEXT_SSG_MANIFEST   = "/_next/static/abcd1234efgh5678/_ssgManifest.js";
const NUXT_ENTRY = "/_nuxt/entry.0987.mjs";
const NUXT_CHUNK = "/_nuxt/chunks/pages-index.4a3f.js";

// ---- API documentation -----------------------------------------------------
const SWAGGER_DOC   = "/v1/api-docs";
const SWAGGER_JSON  = "/swagger.json";
const OPENAPI_YAML  = "/openapi.yaml";
const OPENAPI_JSON  = "/openapi.json";
const GRAPHQL_URL   = "/graphql";

// ---- Spring Cloud service discovery ----------------------------------------
const SPRING_HEALTH = "/actuator/health";
const SPRING_INFO   = "/actuator/info";
const SPRING_ENV    = "/actuator/env";
const EUREKA_APPS   = "/eureka/apps";
const EUREKA_HOST   = "/eureka/apps/USER-SERVICE";

// ---- Vite manifest ---------------------------------------------------------
const VITE_MANIFEST = "/assets/manifest.json";

// ---- Internal hosts leaked from dev configs --------------------------------
const INTERNAL_IP   = "192.168.1.100";
const INTERNAL_DNS  = "user-service.intra:8443";
const PRIVATE_RFC   = "10.0.0.5";

// ---- RPC schemes -----------------------------------------------------------
const DUBBO_URI = "dubbo://nacos.intra:20880/com.acme.UserService";
const NACOS_URI = "nacos://nacos.intra:8848/cluster";
const GRPC_URI  = "grpc://payment.intra:6565/Pay";

// ---- Source-map breadcrumb -------------------------------------------------
function noop(){ /* intentionally empty */ }
//# sourceMappingURL=app.123.js.map

// ---- JWT-looking literals (extractor doesn't surface JWTs, but they must
// at least not crash the API patterns). ------------------------------------
const FAKE_JWT_A = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.dummy";
const FAKE_JWT_B = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjF9.signature_blob";

// ---- A few real /api/v1 endpoints so the fixture isn't only extras --------
const ENDPOINTS = {
    list:   "/api/v1/devices/list",
    detail: "/api/v1/devices/detail",
    config: "/api/v1/devices/config"
};

export {
    NEXT_BUILD_MANIFEST, NEXT_SSG_MANIFEST, NUXT_ENTRY, NUXT_CHUNK,
    SWAGGER_DOC, SWAGGER_JSON, OPENAPI_YAML, OPENAPI_JSON, GRAPHQL_URL,
    SPRING_HEALTH, SPRING_INFO, SPRING_ENV, EUREKA_APPS, EUREKA_HOST,
    VITE_MANIFEST, INTERNAL_IP, INTERNAL_DNS, PRIVATE_RFC,
    DUBBO_URI, NACOS_URI, GRPC_URI,
    ENDPOINTS
};
