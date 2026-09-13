-- Routing-policy example for an object-mode HTTP route with a member id "blue".
-- The policy selection pins this request; it does not retry another member.
hangang.select_member("blue")
return nil
