-- Binary-safe buffered transformation. This example writes a small envelope.
-- Do not use text/JSON media types for arbitrary binary output.
return "HG\0" .. hangang.body()
