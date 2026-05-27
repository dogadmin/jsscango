package extractor

import (
	"reflect"
	"testing"
)

func TestDetectBaseURLs_AxiosCreate(t *testing.T) {
	body := []byte(`const api = axios.create({ baseURL: "/api", timeout: 5000 });`)
	got := DetectBaseURLs(body)
	want := []string{"/api"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("DetectBaseURLs() = %v, want %v", got, want)
	}
}

func TestDetectBaseURLs_AxiosCreateSingleQuotes(t *testing.T) {
	body := []byte(`const api = axios.create({baseURL:'/v2/api'});`)
	got := DetectBaseURLs(body)
	want := []string{"/v2/api"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("DetectBaseURLs() = %v, want %v", got, want)
	}
}

func TestDetectBaseURLs_MultipleInstances(t *testing.T) {
	body := []byte(`
		const a = axios.create({ baseURL: "/api" });
		const b = axios.create({ baseURL: "/v2", timeout: 10 });
	`)
	got := DetectBaseURLs(body)
	want := []string{"/api", "/v2"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("DetectBaseURLs() = %v, want %v", got, want)
	}
}

func TestDetectBaseURLs_Minified(t *testing.T) {
	// A one-liner that mimics the shape we see after minification.
	body := []byte(`var t=axios.create({baseURL:"/api",timeout:1e4,headers:{"X-A":"y"}});`)
	got := DetectBaseURLs(body)
	want := []string{"/api"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("minified DetectBaseURLs() = %v, want %v", got, want)
	}
}

func TestDetectBaseURLs_DefaultsAssignment(t *testing.T) {
	body := []byte(`axios.defaults.baseURL = "/api"; doStuff();`)
	got := DetectBaseURLs(body)
	want := []string{"/api"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("DetectBaseURLs() = %v, want %v", got, want)
	}
}

func TestDetectBaseURLs_VuePrototype(t *testing.T) {
	body := []byte(`Vue.prototype.$http = axios.create({ baseURL: "/api/v1" });`)
	got := DetectBaseURLs(body)
	want := []string{"/api/v1"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("DetectBaseURLs() = %v, want %v", got, want)
	}
}

func TestDetectBaseURLs_AliasCreate(t *testing.T) {
	// Some codebases alias the factory as `request`, `http`, `api`, etc.
	body := []byte(`const r = request.create({ baseURL: "/services" });`)
	got := DetectBaseURLs(body)
	want := []string{"/services"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("DetectBaseURLs() = %v, want %v", got, want)
	}
}

func TestDetectBaseURLs_NoMatch(t *testing.T) {
	body := []byte(`const x = "/just-a-string"; function foo(){return 1;}`)
	got := DetectBaseURLs(body)
	if got != nil {
		t.Errorf("DetectBaseURLs() = %v, want nil", got)
	}
}

func TestDetectBaseURLs_EmptyBody(t *testing.T) {
	if got := DetectBaseURLs(nil); got != nil {
		t.Errorf("DetectBaseURLs(nil) = %v, want nil", got)
	}
	if got := DetectBaseURLs([]byte{}); got != nil {
		t.Errorf("DetectBaseURLs(empty) = %v, want nil", got)
	}
}

func TestDetectBaseURLs_DedupCollapses(t *testing.T) {
	body := []byte(`
		const a = axios.create({ baseURL: "/api" });
		const b = axios.create({ baseURL: "/api" });
	`)
	got := DetectBaseURLs(body)
	want := []string{"/api"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("DetectBaseURLs() = %v, want %v (duplicates should collapse)", got, want)
	}
}
