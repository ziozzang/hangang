use serde_json::Value;

#[test]
fn every_local_openapi_reference_resolves() {
    let document: Value = serde_json::from_str(include_str!("../docs/openapi.json")).unwrap();
    fn check(node: &Value, root: &Value) {
        match node {
            Value::Object(fields) => {
                if let Some(Value::String(reference)) = fields.get("$ref")
                    && let Some(pointer) = reference.strip_prefix('#')
                {
                    assert!(
                        root.pointer(pointer).is_some(),
                        "unresolved OpenAPI reference: {reference}"
                    );
                }
                for value in fields.values() {
                    check(value, root);
                }
            }
            Value::Array(items) => {
                for value in items {
                    check(value, root);
                }
            }
            _ => {}
        }
    }
    check(&document, &document);
    assert_eq!(
        document["components"]["schemas"]["TcpInboundTls"]["type"],
        "object"
    );
}
