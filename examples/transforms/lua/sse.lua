-- The gateway preserves event/id/retry/comments and joins the data fields.
-- Handle a common application sentinel before trying to decode JSON.
if hangang.body() == "[DONE]" then
    return "[DONE]"
end
local event = hangang.json_decode(hangang.body())
event.secret = nil
event.gateway = true
return hangang.json_encode(event)
