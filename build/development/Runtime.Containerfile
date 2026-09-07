# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
ARG SOURCE_DATE_EPOCH
FROM gcr.io/distroless/static-debian12:nonroot@sha256:f5b485ea962d9bd1186b2f6b3a061191539b905b82ec395de78cbfae51f20e35

ARG SOURCE_REVISION
LABEL org.opencontainers.image.source="https://github.com/opencloudtech/CloudRING" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.title="CloudRING development API and portal"

COPY --chown=65532:65532 --chmod=0555 dist/development-inputs/cloudring-server /usr/local/bin/cloudring-server
COPY --chown=65532:65532 --chmod=0444 LICENSE NOTICE /usr/share/licenses/cloudring/

USER 65532:65532
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/cloudring-server"]
