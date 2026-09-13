-- Runs in a fresh isolated VM for this response or NDJSON record.
local document = hangang.json_decode(hangang.body())
document.secret = nil
document.processed = true
document.optional = hangang.null
hangang.set_body(hangang.json_encode(document))
