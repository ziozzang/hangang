-- Existing routing policy API, independent of request/response body scripts.
-- A returned backend must be listed in this route's configured backends.
if hangang.header("x-deny") == "yes" then
    hangang.reject(403)
end
hangang.set_header("x-policy", "checked")
