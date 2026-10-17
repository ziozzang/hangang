//! Gateway API translation tests. Scenarios follow the upstream
//! conformance suite (`gateway-api/conformance/tests`), run offline against
//! the pure translation; see `docs/kubernetes-gateway-api.md`.
use super::*;
use serde_json::json;

fn class(name: &str, controller: &str) -> Value {
    json!({"kind":"GatewayClass","metadata":{"name":name,"generation":1},"spec":{"controllerName":controller}})
}
fn gateway(namespace: &str, name: &str, created: &str, listeners: Value) -> Value {
    json!({"kind":"Gateway","metadata":{"namespace":namespace,"name":name,"generation":2,
        "creationTimestamp":created,"uid":name},
        "spec":{"gatewayClassName":"hangang","listeners":listeners}})
}
fn http(name: &str) -> Value {
    json!({"name":name,"protocol":"HTTP","port":80})
}
fn route(namespace: &str, name: &str, spec: Value) -> Value {
    json!({"kind":"HTTPRoute","metadata":{"namespace":namespace,"name":name,"generation":3,
        "creationTimestamp":"2026-01-01T00:00:00Z","uid":format!("{namespace}-{name}")},"spec":spec})
}
fn service(namespace: &str, name: &str) -> Value {
    json!({"kind":"Service","metadata":{"namespace":namespace,"name":name},"spec":{"ports":[{"port":8080}]}})
}
fn backend(name: &str) -> Value {
    json!({"name":name,"port":8080})
}
fn parent(name: &str) -> Value {
    json!({"name":name})
}
fn basic(objects: Vec<Value>) -> Vec<Value> {
    let mut all = vec![
        class("hangang", CONTROLLER_NAME),
        gateway(
            "infra",
            "web",
            "2026-01-01T00:00:00Z",
            json!([http("http")]),
        ),
        service("infra", "app"),
    ];
    all.extend(objects);
    all
}

fn translate(objects: &[Value], tls: bool) -> (Plan, Translation) {
    translate_with(objects, tls, |plan| finalize(plan, None, None))
}
fn translate_with(
    objects: &[Value],
    tls: bool,
    finish: impl Fn(&Plan) -> Translation,
) -> (Plan, Translation) {
    let of = |kind: &str| -> Vec<&Value> { objects.iter().filter(|o| o["kind"] == kind).collect() };
    let find = |kind: &'static str| {
        move |namespace: &str, name: &str| {
            objects.iter().find(|o| {
                o["kind"] == kind
                    && o["metadata"]["namespace"] == namespace
                    && o["metadata"]["name"] == name
            })
        }
    };
    let service = find("Service");
    let secret = find("Secret");
    let certificate = |secret: &Value| -> Result<Vec<String>> {
        secret["sans"]
            .as_array()
            .map(|names| {
                names
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .ok_or_else(|| anyhow::anyhow!("not a TLS Secret"))
    };
    let plan = plan(&Inputs {
        classes: of("GatewayClass"),
        gateways: of("Gateway"),
        routes: of("HTTPRoute"),
        grants: of("ReferenceGrant"),
        service: &service,
        secret: &secret,
        certificate: &certificate,
        tls,
        publish_address: Some("192.0.2.10"),
    });
    let translation = finish(&plan);
    (plan, translation)
}

fn condition<'a>(conditions: &'a Value, kind: &str) -> (&'a str, &'a str) {
    let found = conditions
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["type"] == kind)
        .unwrap_or_else(|| panic!("no {kind} condition in {conditions}"));
    (
        found["status"].as_str().unwrap(),
        found["reason"].as_str().unwrap(),
    )
}
fn route_condition<'a>(
    t: &'a Translation,
    namespace: &str,
    name: &str,
    kind: &str,
) -> (&'a str, &'a str) {
    let status = &t.routes_status[&(namespace.to_owned(), name.to_owned())];
    let conditions = Value::Array(status.parents[0].1.clone());
    let (s, r) = condition(&conditions, kind);
    // Leak-free borrow: map back onto the stored conditions.
    let stored = status.parents[0]
        .1
        .iter()
        .find(|c| c["type"] == kind)
        .unwrap();
    assert_eq!(
        (
            stored["status"].as_str().unwrap(),
            stored["reason"].as_str().unwrap()
        ),
        (s, r)
    );
    (
        stored["status"].as_str().unwrap(),
        stored["reason"].as_str().unwrap(),
    )
}
fn listener<'a>(t: &'a Translation, namespace: &str, name: &str, listener: &str) -> &'a Value {
    t.gateways[&(namespace.to_owned(), name.to_owned())]["listeners"]
        .as_array()
        .unwrap()
        .iter()
        .find(|l| l["name"] == listener)
        .unwrap()
}

#[test]
fn gateway_class_ownership_and_parameters() {
    let objects = vec![
        class("hangang", CONTROLLER_NAME),
        class("other", "example.com/other"),
        json!({"kind":"GatewayClass","metadata":{"name":"tuned","generation":4},
            "spec":{"controllerName":CONTROLLER_NAME,"parametersRef":{"group":"","kind":"ConfigMap","name":"x"}}}),
    ];
    let (_, t) = translate(&objects, false);
    assert_eq!(
        t.classes.len(),
        2,
        "another controller's class is not touched"
    );
    let hangang = &t.classes[&(String::new(), "hangang".to_owned())];
    assert_eq!(
        condition(&hangang["conditions"], "Accepted"),
        ("True", "Accepted")
    );
    let tuned = &t.classes[&(String::new(), "tuned".to_owned())];
    assert_eq!(
        condition(&tuned["conditions"], "Accepted"),
        ("False", "InvalidParameters")
    );
    assert_eq!(tuned["conditions"][0]["observedGeneration"], 4);
}

#[test]
fn simple_same_namespace_route_attaches_and_programs() {
    // Conformance: HTTPRouteSimpleSameNamespace, GatewayObservedGenerationBump.
    let objects = basic(vec![route(
        "infra",
        "app",
        json!({"parentRefs":[parent("web")],"hostnames":["App.Example.test"],
            "rules":[{"matches":[{"path":{"type":"PathPrefix","value":"/api"}}],"backendRefs":[backend("app")]}]}),
    )]);
    let (_, t) = translate(&objects, false);
    assert_eq!(t.routes.len(), 1);
    let generated = &t.routes[0];
    assert_eq!(generated.host.as_deref(), Some("app.example.test"));
    assert_eq!(generated.path_prefix.as_deref(), Some("/api"));
    assert_eq!(generated.path_match, PathMatch::SegmentPrefix);
    assert!(generated.preserve_host);
    assert_eq!(generated.access_mode, AccessMode::Public);
    assert_eq!(
        generated.backends,
        vec![crate::pool_member::Backend::from(
            "http://app.infra.svc:8080"
        )]
    );
    assert_eq!(
        route_condition(&t, "infra", "app", "Accepted"),
        ("True", "Accepted")
    );
    assert_eq!(
        route_condition(&t, "infra", "app", "ResolvedRefs"),
        ("True", "ResolvedRefs")
    );
    let status = &t.gateways[&("infra".to_owned(), "web".to_owned())];
    assert_eq!(
        condition(&status["conditions"], "Accepted"),
        ("True", "Accepted")
    );
    assert_eq!(
        condition(&status["conditions"], "Programmed"),
        ("True", "Programmed")
    );
    assert_eq!(status["conditions"][0]["observedGeneration"], 2);
    assert_eq!(
        status["addresses"],
        json!([{"type":"IPAddress","value":"192.0.2.10"}])
    );
    let http = listener(&t, "infra", "web", "http");
    assert_eq!(http["attachedRoutes"], 1);
    assert_eq!(
        http["supportedKinds"],
        json!([{"group":GROUP,"kind":"HTTPRoute"}])
    );
    assert_eq!(
        condition(&http["conditions"], "Conflicted"),
        ("False", "NoConflicts")
    );
    assert_eq!(t.hosts, BTreeSet::from(["app.example.test".to_owned()]));
}

#[test]
fn allowed_routes_namespaces_and_kinds() {
    // Conformance: HTTPRouteDisallowedKind, GatewayInvalidRouteKind,
    // HTTPRouteCrossNamespace.
    let mut objects = basic(vec![
        service("team", "app"),
        route(
            "team",
            "app",
            json!({"parentRefs":[{"name":"web","namespace":"infra"}],
            "rules":[{"backendRefs":[backend("app")]}]}),
        ),
    ]);
    let (_, t) = translate(&objects, false);
    assert!(t.routes.is_empty());
    assert_eq!(
        route_condition(&t, "team", "app", "Accepted"),
        ("False", "NotAllowedByListeners")
    );

    objects[1] = gateway(
        "infra",
        "web",
        "2026-01-01T00:00:00Z",
        json!([{"name":"http","protocol":"HTTP","port":80,"allowedRoutes":{"namespaces":{"from":"All"}}}]),
    );
    let (_, t) = translate(&objects, false);
    assert_eq!(t.routes.len(), 1);
    assert_eq!(t.routes[0].host, None, "no hostnames: any host");
    assert_eq!(
        route_condition(&t, "team", "app", "Accepted"),
        ("True", "Accepted")
    );

    objects[1] = gateway(
        "infra",
        "web",
        "2026-01-01T00:00:00Z",
        json!([{"name":"http","protocol":"HTTP","port":80,"allowedRoutes":{"namespaces":{"from":"All"},
            "kinds":[{"kind":"GRPCRoute"}]}}]),
    );
    let (_, t) = translate(&objects, false);
    let http = listener(&t, "infra", "web", "http");
    assert_eq!(
        condition(&http["conditions"], "ResolvedRefs"),
        ("False", "InvalidRouteKinds")
    );
    assert_eq!(http["supportedKinds"], json!([]));
    assert_eq!(
        route_condition(&t, "team", "app", "Accepted"),
        ("False", "NotAllowedByListeners")
    );

    objects[1] = gateway(
        "infra",
        "web",
        "2026-01-01T00:00:00Z",
        json!([{"name":"http","protocol":"HTTP","port":80,"allowedRoutes":{"namespaces":{"from":"Selector",
            "selector":{"matchLabels":{"a":"b"}}}}}]),
    );
    let (_, t) = translate(&objects, false);
    let http = listener(&t, "infra", "web", "http");
    assert_eq!(
        condition(&http["conditions"], "Accepted"),
        ("False", "UnsupportedValue")
    );
}

#[test]
fn listener_hostname_intersection_and_section_names() {
    // Conformance: HTTPRouteListenerHostnameMatching, HTTPRouteHostnameIntersection,
    // HTTPRouteInvalidParentRefNotMatchingSectionName.
    let objects = vec![
        class("hangang", CONTROLLER_NAME),
        service("infra", "app"),
        gateway(
            "infra",
            "web",
            "2026-01-01T00:00:00Z",
            json!([
                {"name":"wild","protocol":"HTTP","port":80,"hostname":"*.example.test"},
                {"name":"exact","protocol":"HTTP","port":80,"hostname":"exact.other.test"}
            ]),
        ),
        route(
            "infra",
            "deep",
            json!({"parentRefs":[{"name":"web","sectionName":"wild"}],
            "hostnames":["a.b.example.test","nope.other.test"],"rules":[{"backendRefs":[backend("app")]}]}),
        ),
        route(
            "infra",
            "inherit",
            json!({"parentRefs":[{"name":"web","sectionName":"exact"}],
            "rules":[{"backendRefs":[backend("app")]}]}),
        ),
        route(
            "infra",
            "wider",
            json!({"parentRefs":[{"name":"web","sectionName":"wild"}],
            "hostnames":["*.test"],"rules":[{"backendRefs":[backend("app")]}]}),
        ),
        route(
            "infra",
            "miss",
            json!({"parentRefs":[{"name":"web","sectionName":"exact"}],
            "hostnames":["x.example.test"],"rules":[{"backendRefs":[backend("app")]}]}),
        ),
        route(
            "infra",
            "nosection",
            json!({"parentRefs":[{"name":"web","sectionName":"missing"}],
            "rules":[{"backendRefs":[backend("app")]}]}),
        ),
        route(
            "infra",
            "port",
            json!({"parentRefs":[{"name":"web","port":80}],
            "rules":[{"backendRefs":[backend("app")]}]}),
        ),
    ];
    let (_, t) = translate(&objects, false);
    let hosts: BTreeSet<(Option<String>, Option<String>)> = t
        .routes
        .iter()
        .map(|r| (r.host.clone(), r.host_regex.clone()))
        .collect();
    assert!(hosts.contains(&(Some("a.b.example.test".into()), None)));
    assert!(hosts.contains(&(Some("exact.other.test".into()), None)));
    // `*.test` narrowed to the listener's `*.example.test`, any depth.
    let wildcard = (None, Some(r"(?:[^.]+\.)+example\.test".to_owned()));
    assert!(hosts.contains(&wildcard), "{hosts:?}");
    assert_eq!(t.routes.len(), 3);
    assert_eq!(
        route_condition(&t, "infra", "miss", "Accepted"),
        ("False", "NoMatchingListenerHostname")
    );
    assert_eq!(
        route_condition(&t, "infra", "nosection", "Accepted"),
        ("False", "NoMatchingParent")
    );
    assert_eq!(
        route_condition(&t, "infra", "port", "Accepted"),
        ("False", "NoMatchingParent")
    );
    assert_eq!(listener(&t, "infra", "web", "wild")["attachedRoutes"], 2);
    assert_eq!(listener(&t, "infra", "web", "exact")["attachedRoutes"], 1);
    let regex = crate::host_match::compile_regex(&wildcard.1.unwrap()).unwrap();
    assert!(regex.is_match("a.b.example.test") && !regex.is_match("example.test"));
}

#[test]
fn backend_references_grants_and_weights() {
    // Conformance: HTTPRouteInvalidCrossNamespaceBackendRef,
    // HTTPRouteReferenceGrant, HTTPRouteInvalidNonExistentBackendRef,
    // HTTPRouteInvalidBackendRefUnknownKind, HTTPRouteWeight.
    let cross = |name: &str| {
        route(
            "infra",
            name,
            json!({"parentRefs":[parent("web")],"hostnames":[format!("{name}.example.test")],
            "rules":[{"backendRefs":[{"name":"api","namespace":"team","port":8080}]}]}),
        )
    };
    let mut objects = basic(vec![service("team", "api"), cross("cross")]);
    let (_, t) = translate(&objects, false);
    assert!(t.routes.is_empty());
    assert_eq!(
        route_condition(&t, "infra", "cross", "Accepted"),
        ("True", "Accepted")
    );
    assert_eq!(
        route_condition(&t, "infra", "cross", "ResolvedRefs"),
        ("False", "RefNotPermitted")
    );

    objects.push(json!({"kind":"ReferenceGrant","metadata":{"namespace":"team","name":"g"},
        "spec":{"from":[{"group":GROUP,"kind":"HTTPRoute","namespace":"infra"}],"to":[{"group":"","kind":"Service","name":"api"}]}}));
    let (_, t) = translate(&objects, false);
    assert_eq!(t.routes.len(), 1);
    assert_eq!(
        route_condition(&t, "infra", "cross", "ResolvedRefs"),
        ("True", "ResolvedRefs")
    );

    let objects = basic(vec![
        service("infra", "canary"),
        route(
            "infra",
            "missing",
            json!({"parentRefs":[parent("web")],"hostnames":["missing.example.test"],
            "rules":[{"backendRefs":[backend("nothing")]}]}),
        ),
        route(
            "infra",
            "kind",
            json!({"parentRefs":[parent("web")],"hostnames":["kind.example.test"],
            "rules":[{"backendRefs":[{"group":"example.com","kind":"Bucket","name":"b"}]}]}),
        ),
        route(
            "infra",
            "noport",
            json!({"parentRefs":[parent("web")],"hostnames":["noport.example.test"],
            "rules":[{"backendRefs":[{"name":"app"}]}]}),
        ),
        route(
            "infra",
            "weights",
            json!({"parentRefs":[parent("web")],"hostnames":["weights.example.test"],
            "rules":[{"backendRefs":[
                {"name":"app","port":8080,"weight":90000},
                {"name":"canary","port":8080,"weight":10000},
                {"name":"app","port":8080,"weight":0}]}]}),
        ),
    ]);
    let (_, t) = translate(&objects, false);
    assert_eq!(
        route_condition(&t, "infra", "missing", "ResolvedRefs"),
        ("False", "BackendNotFound")
    );
    assert_eq!(
        route_condition(&t, "infra", "kind", "ResolvedRefs"),
        ("False", "InvalidKind")
    );
    assert_eq!(
        route_condition(&t, "infra", "noport", "ResolvedRefs"),
        ("False", "BackendNotFound")
    );
    assert_eq!(
        t.routes.len(),
        1,
        "rules without a usable backend are not routed"
    );
    let weighted = &t.routes[0];
    assert_eq!(
        weighted.backends.len(),
        2,
        "zero-weight backends are dropped"
    );
    assert_eq!(weighted.balance.weights, vec![1000, 111]);
}

#[test]
fn https_listeners_certificates_and_protocols() {
    // Conformance: GatewayInvalidTLSConfiguration, GatewaySecretReferenceGrant*,
    // GatewaySecretInvalidReferenceGrant.
    let tls_listener = |name: &str, namespace: Option<&str>, secret: &str, host: Option<&str>| {
        let mut reference = json!({"name":secret});
        if let Some(namespace) = namespace {
            reference["namespace"] = namespace.into();
        }
        let mut listener = json!({"name":name,"protocol":"HTTPS","port":443,
            "tls":{"mode":"Terminate","certificateRefs":[reference]}});
        if let Some(host) = host {
            listener["hostname"] = host.into();
        }
        listener
    };
    let objects = vec![
        class("hangang", CONTROLLER_NAME),
        json!({"kind":"Secret","metadata":{"namespace":"infra","name":"cert"},"sans":["secure.example.test"]}),
        json!({"kind":"Secret","metadata":{"namespace":"certs","name":"shared"},"sans":["shared.example.test"]}),
        json!({"kind":"Secret","metadata":{"namespace":"infra","name":"bad"}}),
        gateway(
            "infra",
            "tls",
            "2026-01-01T00:00:00Z",
            json!([
                tls_listener("sans", None, "cert", None),
                tls_listener("named", None, "cert", Some("named.example.test")),
                tls_listener("cross", Some("certs"), "shared", None),
                tls_listener("missing", None, "absent", Some("missing.example.test")),
                tls_listener("invalid", None, "bad", Some("bad.example.test")),
                http("plain"),
            ]),
        ),
    ];
    let (_, t) = translate(&objects, true);
    let reason = |name: &str, kind: &str| {
        let l = listener(&t, "infra", "tls", name);
        let (s, r) = condition(&l["conditions"], kind);
        (s.to_owned(), r.to_owned())
    };
    assert_eq!(
        reason("sans", "ResolvedRefs"),
        ("True".into(), "ResolvedRefs".into())
    );
    assert_eq!(
        reason("cross", "ResolvedRefs"),
        ("False".into(), "RefNotPermitted".into())
    );
    assert_eq!(
        reason("missing", "ResolvedRefs"),
        ("False".into(), "InvalidCertificateRef".into())
    );
    assert_eq!(
        reason("invalid", "ResolvedRefs"),
        ("False".into(), "InvalidCertificateRef".into())
    );
    assert_eq!(
        reason("plain", "Accepted"),
        ("False".into(), "UnsupportedProtocol".into())
    );
    assert_eq!(
        reason("cross", "Programmed"),
        ("False".into(), "Invalid".into())
    );
    let served: BTreeSet<Vec<String>> = t
        .certificates
        .iter()
        .map(|(hosts, _)| hosts.clone())
        .collect();
    assert_eq!(
        served,
        BTreeSet::from([
            vec!["secure.example.test".to_owned()],
            vec!["named.example.test".to_owned()]
        ])
    );
    let status = &t.gateways[&("infra".to_owned(), "tls".to_owned())];
    assert_eq!(
        condition(&status["conditions"], "Programmed"),
        ("True", "Programmed")
    );

    let mut granted = objects.clone();
    granted.push(json!({"kind":"ReferenceGrant","metadata":{"namespace":"certs","name":"g"},
        "spec":{"from":[{"group":GROUP,"kind":"Gateway","namespace":"infra"}],"to":[{"group":"","kind":"Secret"}]}}));
    let (_, t) = translate(&granted, true);
    let cross = listener(&t, "infra", "tls", "cross");
    assert_eq!(
        condition(&cross["conditions"], "ResolvedRefs"),
        ("True", "ResolvedRefs")
    );

    // A plaintext gateway refuses HTTPS listeners.
    let (_, t) = translate(&objects, false);
    let sans = listener(&t, "infra", "tls", "sans");
    assert_eq!(
        condition(&sans["conditions"], "Accepted"),
        ("False", "UnsupportedProtocol")
    );
}

#[test]
fn listener_hostname_conflicts_are_decided_by_age() {
    // Conformance: GatewayWithAttachedRoutes (conflicts), GatewayModifyListeners.
    let objects = vec![
        class("hangang", CONTROLLER_NAME),
        gateway(
            "b",
            "young",
            "2026-02-01T00:00:00Z",
            json!([{"name":"x","protocol":"HTTP","port":80,"hostname":"same.example.test"}]),
        ),
        gateway(
            "a",
            "old",
            "2026-01-01T00:00:00Z",
            json!([{"name":"x","protocol":"HTTP","port":80,"hostname":"same.example.test"}]),
        ),
        gateway(
            "c",
            "twice",
            "2026-03-01T00:00:00Z",
            json!([
            {"name":"one","protocol":"HTTP","port":80,"hostname":"twice.example.test"},
            {"name":"two","protocol":"HTTP","port":80,"hostname":"twice.example.test"}]),
        ),
        json!({"kind":"Gateway","metadata":{"namespace":"d","name":"addressed","generation":1},
            "spec":{"gatewayClassName":"hangang","addresses":[{"type":"IPAddress","value":"10.0.0.1"}],
                "listeners":[{"name":"x","protocol":"HTTP","port":80,"hostname":"addr.example.test"}]}}),
        json!({"kind":"Gateway","metadata":{"namespace":"d","name":"foreign"},
            "spec":{"gatewayClassName":"other","listeners":[]}}),
    ];
    let (_, t) = translate(&objects, false);
    let conflicted = |ns: &str, gw: &str, l: &str| {
        let value = listener(&t, ns, gw, l);
        condition(&value["conditions"], "Conflicted").0.to_owned()
    };
    assert_eq!(conflicted("a", "old", "x"), "False");
    assert_eq!(conflicted("b", "young", "x"), "True");
    assert_eq!(conflicted("c", "twice", "one"), "False");
    assert_eq!(conflicted("c", "twice", "two"), "True");
    let addressed = &t.gateways[&("d".to_owned(), "addressed".to_owned())];
    assert_eq!(
        condition(&addressed["conditions"], "Accepted"),
        ("False", "UnsupportedAddress")
    );
    assert_eq!(condition(&addressed["conditions"], "Programmed").0, "False");
    assert!(
        !t.gateways
            .contains_key(&("d".to_owned(), "foreign".to_owned()))
    );
}

#[test]
fn matches_filters_and_precedence() {
    // Conformance: HTTPRouteExactPathMatching, HTTPRouteHeaderMatching,
    // HTTPRouteQueryParamMatching, HTTPRouteMethodMatching,
    // HTTPRouteMatchingAcrossRoutes, HTTPRouteRequestHeaderModifier,
    // HTTPRouteResponseHeaderModifier, HTTPRouteRedirect*, HTTPRouteRewrite*.
    let objects = basic(vec![route(
        "infra",
        "a",
        json!({"parentRefs":[parent("web")],"hostnames":["m.example.test"],"rules":[
            {"matches":[{"path":{"type":"PathPrefix","value":"/"}}],"backendRefs":[backend("app")]},
            {"matches":[{"path":{"type":"Exact","value":"/exact"}},
                        {"path":{"type":"PathPrefix","value":"/v2"},"method":"POST",
                         "headers":[{"name":"X-Version","value":"2"},{"name":"x-version","value":"ignored"}],
                         "queryParams":[{"name":"debug","value":"1"}]}],
             "filters":[
                {"type":"RequestHeaderModifier","requestHeaderModifier":{"set":[{"name":"X-Set","value":"s"}],
                    "add":[{"name":"x-add","value":"a"}],"remove":["x-drop"]}},
                {"type":"ResponseHeaderModifier","responseHeaderModifier":{"set":[{"name":"x-resp","value":"r"}],"remove":["server"]}},
                {"type":"URLRewrite","urlRewrite":{"hostname":"internal.example.test","path":{"type":"ReplacePrefixMatch","replacePrefixMatch":"/"}}}],
             "backendRefs":[backend("app")]},
            {"matches":[{"path":{"type":"PathPrefix","value":"/old"}}],
             "filters":[{"type":"RequestRedirect","requestRedirect":{"scheme":"https","hostname":"new.example.test",
                "statusCode":301,"path":{"type":"ReplaceFullPath","replaceFullPath":"/new"}}}]}
        ]}),
    )]);
    let (_, t) = translate(&objects, false);
    let summary: Vec<(String, PathMatch, Vec<String>, usize)> = t
        .routes
        .iter()
        .map(|r| {
            (
                r.path_prefix.clone().unwrap(),
                r.path_match,
                r.methods.clone(),
                r.headers.len(),
            )
        })
        .collect();
    assert_eq!(
        summary,
        vec![
            ("/exact".into(), PathMatch::Exact, vec![], 0),
            ("/old".into(), PathMatch::SegmentPrefix, vec![], 0),
            (
                "/v2".into(),
                PathMatch::SegmentPrefix,
                vec!["POST".into()],
                1
            ),
            ("/".into(), PathMatch::SegmentPrefix, vec![], 0),
        ]
    );
    let v2 = &t.routes[2];
    assert_eq!(
        v2.headers["x-version"], "2",
        "the first match of a repeated header wins"
    );
    assert_eq!(v2.query["debug"], "1");
    let modifier = v2.request_headers.as_ref().unwrap();
    assert_eq!(modifier.set["x-set"], "s");
    assert_eq!(modifier.add["x-add"], "a");
    assert_eq!(modifier.remove, vec!["x-drop".to_owned()]);
    assert_eq!(v2.response_set_headers["x-resp"], "r");
    assert_eq!(v2.response_remove_headers, vec!["server".to_owned()]);
    let rewrite = v2.rewrite.as_ref().unwrap();
    assert_eq!(rewrite.hostname.as_deref(), Some("internal.example.test"));
    assert_eq!(rewrite.path, Some(PathModifier::Prefix("/".into())));
    let redirect = t.routes[1].redirect.as_ref().unwrap();
    assert_eq!(redirect.scheme, Some(RedirectScheme::Https));
    assert_eq!(redirect.status_code, 301);
    assert_eq!(redirect.path, Some(PathModifier::Full("/new".into())));
    assert_eq!(
        route_condition(&t, "infra", "a", "Accepted"),
        ("True", "Accepted")
    );
}

#[test]
fn unsupported_features_refuse_the_whole_route() {
    for (name, rule) in [
        (
            "regex",
            json!({"matches":[{"path":{"type":"RegularExpression","value":"/.*"}}],"backendRefs":[backend("app")]}),
        ),
        (
            "header-regex",
            json!({"matches":[{"headers":[{"type":"RegularExpression","name":"x","value":".*"}]}],"backendRefs":[backend("app")]}),
        ),
        (
            "mirror",
            json!({"filters":[{"type":"RequestMirror","requestMirror":{"backendRef":backend("app")}}],"backendRefs":[backend("app")]}),
        ),
        (
            "backend-filter",
            json!({"backendRefs":[{"name":"app","port":8080,"filters":[{"type":"RequestHeaderModifier"}]}]}),
        ),
        (
            "reserved-header",
            json!({"filters":[{"type":"RequestHeaderModifier","requestHeaderModifier":{"set":[{"name":"x-forwarded-for","value":"1"}]}}],"backendRefs":[backend("app")]}),
        ),
    ] {
        let objects = basic(vec![route(
            "infra",
            name,
            json!({"parentRefs":[parent("web")],"hostnames":[format!("{name}.example.test")],"rules":[rule]}),
        )]);
        let (_, t) = translate(&objects, false);
        assert!(t.routes.is_empty(), "{name}");
        assert_eq!(
            route_condition(&t, "infra", name, "Accepted"),
            ("False", "UnsupportedValue"),
            "{name}"
        );
        assert_eq!(
            listener(&t, "infra", "web", "http")["attachedRoutes"],
            0,
            "{name}"
        );
    }
}

#[test]
fn protection_decisions_withhold_or_protect_whole_routes() {
    let objects = basic(vec![route(
        "infra",
        "open",
        json!({"parentRefs":[parent("web")],"hostnames":["open.example.test"],
            "rules":[{"backendRefs":[backend("app")]},{"name":"admin","matches":[{"path":{"value":"/admin"}}],"backendRefs":[backend("app")]}]}),
    )]);
    let (plan, _) = translate(&objects, false);
    assert_eq!(plan.units.len(), 2);
    assert_eq!(plan.units[1].rule_name.as_deref(), Some("admin"));
    assert_eq!(
        plan.units[0].parents,
        vec![(
            ("infra".to_owned(), "web".to_owned()),
            Some("http".to_owned())
        )]
    );
    assert_eq!(
        plan.units[1].paths,
        json!({"spec":{"rules":[{"host":"open.example.test","http":{"paths":[{"path":"/admin","pathType":"Prefix"}]}}]}})
    );
    // One withheld rule withholds the route: no partial programming.
    let decisions = BTreeMap::from([
        (("infra".to_owned(), "open".to_owned(), 0), Decision::Public),
        (
            ("infra".to_owned(), "open".to_owned(), 1),
            Decision::Withheld(protection::Withheld {
                reason: "ProtectionRequired",
                message: "no ProtectionPolicy".into(),
            }),
        ),
    ]);
    let (_, t) = translate_with(&objects, false, |plan| {
        finalize(plan, Some(&decisions), None)
    });
    assert!(t.routes.is_empty());
    assert_eq!(
        route_condition(&t, "infra", "open", "Accepted"),
        ("False", "ProtectionRequired")
    );
    assert_eq!(listener(&t, "infra", "web", "http")["attachedRoutes"], 0);
    // Missing decisions also withhold (fail closed).
    let (_, t) = translate_with(&objects, false, |plan| {
        finalize(plan, Some(&BTreeMap::new()), None)
    });
    assert!(t.routes.is_empty());
    assert_eq!(route_condition(&t, "infra", "open", "Accepted").0, "False");
}

#[test]
fn route_status_preserves_other_controllers_and_carries_times() {
    let ours = RouteStatus {
        generation: Some(3),
        parents: vec![(
            json!({"name":"web"}),
            vec![protection::condition(
                "Accepted",
                true,
                "Accepted",
                "",
                Some(3),
            )],
        )],
    };
    let current = json!({"status":{"parents":[
        {"parentRef":{"name":"theirs"},"controllerName":"example.com/other","conditions":[]},
        {"parentRef":{"name":"web"},"controllerName":CONTROLLER_NAME,
         "conditions":[{"type":"Accepted","status":"True","reason":"Accepted","lastTransitionTime":"2026-01-01T00:00:00Z"}]},
        {"parentRef":{"name":"gone"},"controllerName":CONTROLLER_NAME,"conditions":[]}
    ]}});
    assert!(has_our_parents(&current));
    let status = route_status(&current, &ours);
    let parents = status["parents"].as_array().unwrap();
    assert_eq!(parents.len(), 2, "our stale entry is dropped, theirs kept");
    assert_eq!(parents[0]["controllerName"], "example.com/other");
    assert_eq!(
        parents[1]["conditions"][0]["lastTransitionTime"],
        "2026-01-01T00:00:00Z"
    );
    let cleared = route_status(&current, &RouteStatus::default());
    assert_eq!(cleared["parents"].as_array().unwrap().len(), 1);

    let gateway = json!({"status":{"conditions":[{"type":"Accepted","status":"False","lastTransitionTime":"2026-01-01T00:00:00Z"}],
        "listeners":[{"name":"http","conditions":[{"type":"Accepted","status":"True","lastTransitionTime":"2026-01-02T00:00:00Z"}]}]}});
    let desired = json!({"conditions":[{"type":"Accepted","status":"True"}],
        "listeners":[{"name":"http","conditions":[{"type":"Accepted","status":"True"}]}]});
    let stamped = owned_status(&gateway, desired);
    assert_ne!(
        stamped["conditions"][0]["lastTransitionTime"],
        "2026-01-01T00:00:00Z"
    );
    assert_eq!(
        stamped["listeners"][0]["conditions"][0]["lastTransitionTime"],
        "2026-01-02T00:00:00Z"
    );
}

#[test]
fn budget_and_order_follow_route_age() {
    let mut objects = basic(Vec::new());
    for index in 0..600 {
        let mut item = route(
            "infra",
            &format!("r{index:03}"),
            json!({"parentRefs":[parent("web")],
            "hostnames":[format!("h{index}.example.test")],"rules":[{"backendRefs":[backend("app")]}]}),
        );
        item["metadata"]["creationTimestamp"] =
            format!("2026-01-01T00:{:02}:{:02}Z", index / 60, index % 60).into();
        objects.push(item);
    }
    let (_, t) = translate(&objects, false);
    assert_eq!(t.routes.len(), MAX_GATEWAY_ROUTES);
    assert_eq!(route_condition(&t, "infra", "r000", "Accepted").0, "True");
    assert_eq!(
        route_condition(&t, "infra", "r599", "Accepted"),
        ("False", "UnsupportedValue")
    );
}
