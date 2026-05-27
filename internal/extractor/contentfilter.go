package extractor

import (
	"github.com/dogadmin/jsscango/internal/util/aho"
)

// contentTypeMatcher is built once from ContentTypeKeys and used by
// ContainsMIMELike to scan candidate API strings in O(N) instead of
// O(N * 246).
var contentTypeMatcher = aho.New(ContentTypeKeys)

// ContentTypeKeys is the literal list of MIME-type substrings from
// apiPathFind.py:8-245 (contentTypeListPure). When any of these appears inside
// a candidate API path, the candidate is rejected because the regex matched a
// MIME literal rather than a real path.
//
// Kept as plain []string for clarity; Phase 4 will replace the linear scan
// with an Aho-Corasick matcher.
var ContentTypeKeys = []string{
	"text/html", "application/json", "text/plain", "text/xml", "text/javascript",
	"image/gif", "image/jpeg", "image/jpg", "image/png", "image/*", "image/x-icon",
	"application/xhtml+xml", "application/xml", "application/atom+xml",
	"application/octet-stream", "binary/octet-stream", "audio/x-wav",
	"audio/x-ms-wma", "audio/mp3", "video/x-ms-wmv", "video/mpeg4", "video/avi",
	"application/pdf", "application/msword",
	"application/vnd.openxmlformats-officedocument.wordprocessingml.document",
	"application/vnd.ms-excel",
	"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
	"application/vnd.ms-powerpoint",
	"application/vnd.openxmlformats-officedocument.presentationml.presentation",
	"application/zip", "application/x-zip-compressed", "application/x-tar",
	"multipart/form-data", "application/vnd.tcpdump.pcap",
	"application/x-www-form-urlencoded",
	"application/vnd.spring-boot.actuator.v2+json",
	"text/x-cobol", "application/mbox", "application/n-triples", "text/x-gpsql",
	"text/x-chdr", "text/x-modelica", "text/babel$", "text/x-groovy",
	"text/x-sparksql", "text/x-octave", "x-shader/x-fragment", "text/x-haml",
	"text/x-c++hdr", "text/x-gfm", "text/x-esper", "stylesheet/less",
	"application/x-erb", "text/markdown", "application/pgp-encrypted",
	"text/x-latex", "text/x-python", "text/x-tiddlywiki", "text/x-squirrel",
	"text/mirc", "application/x-javascript", "text/troff", "text/x-nginx-conf",
	"text/typescript-jsx", "message/http", "text/x-hive", "text/x-xu",
	"text/x-clojure", "text/x-idl", "text/x-gql", "text/x-pug", "text/apl",
	"application/xquery", "audio/wav", "text/x-php", "video/mp4", "text/x-csharp",
	"text/x-go", "text/x-twig", "text/x-vue", "text/x-protobuf",
	"text/x-literate-haskell", "text/x-django", "text/x-smarty", "text/sass/i",
	"text/vbscript", "text/jsx", "text/x-rpm-spec", "application/ld+json",
	"application/x-powershell", "text/x-elm", "text/x-cmake", "text/x-erlang",
	"text/x-fsharp", "text/x-livescript", "text/x-pig", "text/x-sql",
	"text/coffeescript", "text/x-z80", "application/dart", "application/x-aspx",
	"text/x-gas", "text/typescript", "application/x-httpd-php", "text/x-csrc",
	"application/x-jsp", "text/x-perl", "application/x-json", "text/x-objectivec",
	"video/ogg", "text/x-webidl", "application/x-cypher-query", "text/x-puppet",
	"application/edn", "text/x-sas", "text/x-rst", "text/x-properties",
	"text/x-fortran", "auth/forge-password", "text/x-verilog", "text/x-ttcn-cfg",
	"text/x-lua", "text/x-cassandra", "text/x-sml", "text/x-brainfuck",
	"application/pgp", "text/x-d", "text/x-gss", "text/x-oz", "text/x-diff",
	"application/javascript", "text/x-fcl", "text/x-sqlite", "text/x-ecl",
	"text/x-scss", "text/jinja2", "application/sparql-query", "text/x-julia",
	"text/x-dockerfile", "text/x-mariadb", "text/yaml", "text/x-forth",
	"text/x-stex", "text/x-coffeescript", "text/x-vhdl", "text/x-kotlin",
	"text/x-java", "text/x-haxe", "text/x-rustsrc", "application/x-slim",
	"text/x-spreadsheet", "text/x-jade", "text/x-pgsql", "text/x-rpm-changes",
	"text/x-feature", "audio/x-m4a", "text/x-markdown", "text/x-eiffel",
	"text/x-yacas", "text/x-dylan", "text/x-dart", "text/x-sh", "text/x-asterisk",
	"text/x-systemverilog", "text/x-mumps", "script/x-vue", "text/velocity",
	"text/turtle", "text/x-ruby", "text/x-ttcn-asn", "application/x-shockwave-flash",
	"text/x-solr", "text/css", "text/x-pascal", "application/x-ejs", "text/x-nesc",
	"text/x-ocaml", "text/x-hxml", "text/x-swift", "application/xml-dtd",
	"text/tiki", "text/uri-list", "text/x-vb", "text/x-slim",
	"application/ecmascript", "text/x-ceylon", "text/x-nsis",
	"text/x-objectivec++", "text/x-cython", "application/sieve",
	"x-shader/x-vertex", "text/x-c", "text/x-crystal", "text/x-ebnf", "text/x-q",
	"application/n-quads", "text/x-msgenny", "application/pgp-signature",
	"text/x-scala", "application/vnd.coffeescript", "video/webm",
	"text/ecmascript-d+$", "text/x-sass", "text/x-handlebars-template",
	"text/x-scheme", "text/x-yaml", "text/x-mssql", "text/x-tcl",
	"application/pgp-keys", "application/x-sh", "application/typescript",
	"text/x-rsrc", "text/x-ttcn", "text/x-mathematica", "text/rtf",
	"text/x-mysql", "text/x-clojurescript", "text/x-stsrc", "text/n-triples",
	"text/x-haskell", "text/x-less", "text/ecmascript", "text/x-mscgen",
	"auth/register", "text/x-toml", "text/x-styl", "application/x-httpd-php-open",
	"text/x-tornado", "audio/mpeg", "text/x-soy", "text/x-factor",
	"text/x-common-lisp", "text/x-c++src", "text/x-plsql",
}

// ContainsMIMELike reports whether s contains a substring resembling any
// MIME literal in ContentTypeKeys. Used as a fast rejection for API-path
// regex matches per apiPathFind.py:280-281.
//
// Single Aho-Corasick scan, built once at package init.
func ContainsMIMELike(s string) bool {
	return contentTypeMatcher.ContainsString(s)
}
