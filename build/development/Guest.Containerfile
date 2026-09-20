# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
ARG SOURCE_DATE_EPOCH
FROM scratch

ARG SOURCE_REVISION
LABEL org.opencontainers.image.source="https://github.com/opencloudtech/CloudRING" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      org.opencontainers.image.title="CloudRING development Ubuntu 24.04 container disk"

# The unchanged Canonical image is verified against its signed SHA256SUMS
# before building. CDI imports /disk into the installation's owned PVC.
COPY --chown=107:107 --chmod=0444 dist/development-inputs/ubuntu.img /disk/ubuntu.qcow2
USER 107:107
