-- A complete bounded line arrives here, even if its bytes crossed HTTP chunks.
-- Lua patterns operate on bytes. Keep the output within max_output_bytes.
local line = string.gsub(hangang.body(), "token=[^%s]+", "token=[redacted]")
return line
