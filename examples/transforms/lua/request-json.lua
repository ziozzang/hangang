-- Buffered request: preserve JSON types, remove a client-controlled identity,
-- and add a field. Native headers are configured alongside this script.
local document = hangang.json_decode(hangang.body())
document.client_role = nil
document.source = "hangang"
document.tags = document.tags or hangang.array()
return hangang.json_encode(document)
