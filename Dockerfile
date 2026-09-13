# Build first with `make static`; this image contains only the static binary.
FROM scratch
COPY --chmod=0555 target/x86_64-unknown-linux-gnu/release/hangang /hangang
USER 65532:65532
WORKDIR /data
EXPOSE 8080
ENTRYPOINT ["/hangang"]
CMD ["--listen", "0.0.0.0:8080", "--config", "/data/hangang.json"]
