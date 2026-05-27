package extractor

import "testing"

func containsRoute(routes []RouteFound, want string) bool {
	for _, r := range routes {
		if r.Path == want {
			return true
		}
	}
	return false
}

func TestDetectRoutes_DirectArray(t *testing.T) {
	body := []byte(`var routes = [
		{path:"/leaveForm",name:"LeaveForm",component:r("xxx")},
		{path:"/myApproval",name:"MyApproval",component:e=>{}},
	];`)
	got := DetectRoutes(body)
	if len(got) != 2 {
		t.Fatalf("DetectRoutes: got %d routes, want 2: %+v", len(got), got)
	}
	if !containsRoute(got, "/leaveForm") {
		t.Errorf("missing /leaveForm in %+v", got)
	}
	if !containsRoute(got, "/myApproval") {
		t.Errorf("missing /myApproval in %+v", got)
	}
}

func TestDetectRoutes_ComponentFirst(t *testing.T) {
	// Some minifiers sort object members alphabetically, putting
	// `component` before `path`. The reverse branch of the regex must
	// catch this shape.
	body := []byte(`{component:r(123),path:"/foo",name:"F"}`)
	got := DetectRoutes(body)
	if len(got) != 1 || !containsRoute(got, "/foo") {
		t.Errorf("component-first: got %+v, want [/foo]", got)
	}
}

func TestDetectRoutes_NestedChildren(t *testing.T) {
	body := []byte(`{path:"/p",name:"P",component:c,children:[{path:"sub",name:"S",component:c}]}`)
	got := DetectRoutes(body)
	// We expect both routes — "/p" (parent, absolute) and "sub" (child,
	// relative). RoutePathSet will normalise "sub" → "/sub" for membership
	// checks, but the raw Path field preserves the original declaration.
	if !containsRoute(got, "/p") {
		t.Errorf("nested: missing /p in %+v", got)
	}
	if !containsRoute(got, "sub") {
		t.Errorf("nested: missing relative 'sub' in %+v", got)
	}
}

func TestDetectRoutes_WildcardDropped(t *testing.T) {
	body := []byte(`{path:"*",name:"NotFound",component:c}`)
	got := DetectRoutes(body)
	if len(got) != 0 {
		t.Errorf("wildcard '*' should be dropped, got %+v", got)
	}
}

func TestDetectRoutes_ParameterOnlyDropped(t *testing.T) {
	body := []byte(`{path:":id",name:"User",component:c}`)
	got := DetectRoutes(body)
	if len(got) != 0 {
		t.Errorf("':id' parameter-only path should be dropped, got %+v", got)
	}
}

func TestDetectRoutes_RootDropped(t *testing.T) {
	body := []byte(`{path:"/",name:"Home",component:c}`)
	got := DetectRoutes(body)
	if len(got) != 0 {
		t.Errorf("'/' root should be dropped, got %+v", got)
	}
}

func TestDetectRoutes_EmptyDropped(t *testing.T) {
	body := []byte(`{path:"",name:"Default",component:c}`)
	got := DetectRoutes(body)
	if len(got) != 0 {
		t.Errorf("empty path should be dropped, got %+v", got)
	}
}

func TestDetectRoutes_RealCpicCorpus(t *testing.T) {
	// Synthetic excerpt mirroring the shape we observed in
	// app.fdbee7c5.js — webpack-rewritten lazy-load `component:function(){
	// return r.e(N).then(r.bind(null,"xxx")) }`, with a meta:{...} block
	// between path and component.
	body := []byte(`{path:"/leaveForm",name:"LeaveForm",meta:{title:"请假"},component:function(){return r.e(123).then(r.bind(null,"xxx"))}}`)
	got := DetectRoutes(body)
	if len(got) != 1 || !containsRoute(got, "/leaveForm") {
		t.Errorf("cpic corpus shape: got %+v, want [/leaveForm]", got)
	}
}

func TestDetectRoutes_Dedup(t *testing.T) {
	// Same path declared twice (e.g. main routes table + a re-exported copy
	// in the build) should collapse to one entry.
	body := []byte(`
		{path:"/foo",name:"F1",component:c},
		{path:"/foo",name:"F2",component:c},
	`)
	got := DetectRoutes(body)
	if len(got) != 1 {
		t.Errorf("dedup: got %d entries, want 1: %+v", len(got), got)
	}
}

func TestDetectRoutes_EmptyBody(t *testing.T) {
	if got := DetectRoutes(nil); got != nil {
		t.Errorf("DetectRoutes(nil) = %+v, want nil", got)
	}
	if got := DetectRoutes([]byte{}); got != nil {
		t.Errorf("DetectRoutes(empty) = %+v, want nil", got)
	}
}

func TestRoutePathSet_NormalisesLeadingSlash(t *testing.T) {
	routes := []RouteFound{
		{Path: "/foo"},
		{Path: "bar"},
	}
	set := RoutePathSet(routes)
	if _, ok := set["/foo"]; !ok {
		t.Errorf("RoutePathSet: missing /foo in %+v", set)
	}
	if _, ok := set["/bar"]; !ok {
		t.Errorf("RoutePathSet: missing /bar (normalised from 'bar') in %+v", set)
	}
	if len(set) != 2 {
		t.Errorf("RoutePathSet: got %d entries, want 2: %+v", len(set), set)
	}
}
