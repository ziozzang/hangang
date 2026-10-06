-- Application policy example, not a gateway-native Synology feature.
-- Configure the literal when_prefix from README so other APIs stream unchanged.
-- Decode JSON only: never evaluate JavaScript or execute response text.
local prefix = "if (typeof(SYNO) === 'undefined') {SYNO = {};}\nSYNO.SDS = SYNO.SDS || {};\nSYNO.SDS.Session = "
local body = hangang.body()
if hangang.phase() ~= "response" then
    error("SessionData policy requires a response")
end
if body:sub(1, #prefix) ~= prefix then
    if body:find("SYNO.SDS.Session", 1, true) then
        error("unsupported SessionData wrapper")
    end
    return body
end
-- Accept exactly one JSON object followed by the existing statement terminator.
-- Whitespace is allowed only around the final semicolon, never another statement.
local tail = body:sub(#prefix + 1)
local end_index = #tail
while end_index > 0 and tail:sub(end_index, end_index):find("[ \t\r\n]") do
    end_index = end_index - 1
end
if tail:sub(end_index, end_index) ~= ";" then
    error("invalid SessionData statement terminator")
end
local value = hangang.json_decode(tail:sub(1, end_index - 1))
if type(value) ~= "table" or type(value.isLogined) ~= "boolean"
    or type(value.enable_syno_token) ~= "string" then
    error("unsupported SessionData schema")
end
-- Preserve authenticated application capabilities. This profile minimizes the
-- public bootstrap only; it does not authenticate a client or replace DSM auth.
if value.isLogined then
    return body
end
for _, key in ipairs({
    "hostname", "fullversion", "version", "buildphase",
    "dsm_http_port", "dsm_https_port", "dsm_upgrade_pgsql_status"
}) do
    value[key] = nil
end
-- Keep feature-control booleans. Remove inactive provider names/URLs only when
-- every known provider is explicitly disabled; active SSO stays intact.
if value.cas_sso_enable == false and value.oidc_sso_enable == false
    and value.saml_sso_enable == false and value.enable_http_negotiate == false then
    for _, key in ipairs({
        "cas_name", "cas_service_ids", "saml_name", "saml_sso_acs",
        "sso_appid", "sso_name", "sso_server"
    }) do
        value[key] = nil
    end
end
return prefix .. hangang.json_encode(value) .. "\n;\n"
