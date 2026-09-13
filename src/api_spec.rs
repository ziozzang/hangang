/// The management API contract is compiled into the binary so it is always
/// served from the same build as the handlers it describes.
pub const OPENAPI_JSON: &str = include_str!("../docs/openapi.json");
