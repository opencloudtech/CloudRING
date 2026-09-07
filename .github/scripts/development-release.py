#!/usr/bin/env python3
"""Deterministic development release identities; no network or subprocesses."""

import hashlib
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import quote
import uuid


def read_json(path):
    return json.loads(Path(path).read_text())


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def sbom_serial(document):
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    document["serialNumber"] = uuid.uuid5(
        uuid.NAMESPACE_URL,
        "https://github.com/opencloudtech/CloudRING/development-sbom/"
        + hashlib.sha256(payload).hexdigest(),
    ).urn
    return document


def verified_guest(inputs, work):
    source = inputs["guestSource"]
    names = {
        "ubuntu-24.04-server-cloudimg-amd64.img": source["sha256"],
        "ubuntu-24.04-server-cloudimg-amd64.manifest": source["packageManifestSHA256"],
    }
    sums = {}
    for line in (work / "SHA256SUMS").read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64}) [ *](.+)", line)
        if match:
            checksum, name = match.groups()
            if name in sums:
                raise ValueError("ambiguous signed checksum entry")
            sums[name] = checksum
    for name, expected in names.items():
        if not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise ValueError("invalid reviewed input checksum")
        if sums.get(name) != expected or digest(work / name) != expected:
            raise ValueError("guest input differs from reviewed and signed checksum")
    image = work / "ubuntu-24.04-server-cloudimg-amd64.img"
    if image.stat().st_size != source["bytes"]:
        raise ValueError("guest image size differs from reviewed source")
    with image.open("rb") as stream:
        if stream.read(4) != b"QFI\xfb":
            raise ValueError("guest image is not QCOW2")


def guest_sbom(inputs):
    source = inputs["guestSource"]
    packages = []
    names = set()
    for line in Path("dist/development-guest-packages.manifest").read_text().splitlines():
        name, version = line.split("\t")
        if not re.fullmatch(r"[a-z0-9][a-z0-9+.:-]*", name) or not version or name in names:
            raise ValueError("invalid or duplicate Canonical package manifest entry")
        names.add(name)
        purl = "pkg:deb/ubuntu/" + quote(name, safe="") + "@" + quote(version, safe="")
        purl += "?distro=ubuntu-24.04"
        packages.append({"type": "library", "name": name, "version": version, "purl": purl, "bom-ref": purl})
    if len(packages) < 100:
        raise ValueError("incomplete guest package manifest")
    document = {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {
            "component": {"type": "operating-system", "name": source["name"],
                          "version": source["version"],
                          "hashes": [{"alg": "SHA-256", "content": source["sha256"]}]},
            "properties": [
                {"name": "cloudring.sbom.scope", "value": "unchanged-qcow2-signed-upstream-package-manifest"},
                {"name": "cloudring.sbom.package-manifest-sha256", "value": source["packageManifestSHA256"]},
                {"name": "cloudring.sbom.inventory-method", "value": "Canonical signed package manifest; guest filesystem not independently mounted or scanned"},
            ],
        },
        "components": sorted(packages, key=lambda package: package["name"]),
    }
    write_json("dist/development-guest.cdx.json", sbom_serial(document))


def finalize(inputs):
    source = os.environ["GITHUB_SHA"]
    if not re.fullmatch(r"[0-9a-f]{40}", source):
        raise ValueError("invalid source commit")
    version = inputs["releaseVersion"]
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+-[a-z0-9]+(?:[.-][a-z0-9]+)*", version):
        raise ValueError("development release must use an exact prerelease version")
    identities = {}
    for kind in ("runtime", "guest"):
        identity = read_json("dist/development-" + kind + "-image.json")
        if identity["sourceCommit"] != source or identity["imageName"] != "ghcr.io/opencloudtech/cloudring-development-" + kind:
            raise ValueError("image source identity conflict")
        for name in ("imageDigest", "imageSubjectDigest"):
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", identity[name]):
                raise ValueError("image digest is not immutable")
        identity["sbomSHA256"] = digest("dist/development-" + kind + ".cdx.json")
        identity["containerfileSHA256"] = digest("build/development/" + kind.title() + ".Containerfile")
        write_json("dist/development-" + kind + "-image.json", identity)
        identities[kind] = identity
    artifacts = dict(inputs["artifacts"])
    artifacts.update({
        "sourceCommit": source,
        "installer": {"version": version,
                      "url": "https://github.com/opencloudtech/CloudRING/releases/download/" + version + "/cloudring-linux-amd64",
                      "sha256": digest("dist/release-bundle/cloudring-linux-amd64")},
        "guestImage": identities["guest"]["imageName"] + "@" + identities["guest"]["imageDigest"],
        "runtimeImage": identities["runtime"]["imageName"] + "@" + identities["runtime"]["imageDigest"],
    })
    write_json("dist/cloudring-dev-artifacts.json", artifacts)
    domains = inputs["egressDomains"]
    if domains != sorted(set(domains)) or not all(
        re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", name) for name in domains
    ):
        raise ValueError("reviewed egress domains are not exact sorted DNS names")
    write_json("dist/cloudring-dev-egress-domains.json", domains)
    write_json("dist/development-guest-source.json", {
        "apiVersion": "cloudring.development-guest-source/v1",
        "sourceCommit": source, "guest": inputs["guestSource"],
        "signedChecksumsSHA256": digest("dist/development-ubuntu-SHA256SUMS"),
        "signatureSHA256": digest("dist/development-ubuntu-SHA256SUMS.gpg"),
        "signingKeySHA256": digest("build/development/ubuntu-cloud-key.asc"),
        "packageCount": len(read_json("dist/development-guest.cdx.json")["components"]),
        "guestImage": artifacts["guestImage"],
    })


def main():
    inputs = read_json("build/development/upstream.json")
    if inputs["apiVersion"] != "cloudring.development-release-inputs/v1":
        raise ValueError("unsupported development release input")
    if sys.argv[1:] and sys.argv[1] == "verify-guest" and len(sys.argv) == 3:
        verified_guest(inputs, Path(sys.argv[2]))
    elif sys.argv[1:] == ["guest-sbom"]:
        guest_sbom(inputs)
    elif sys.argv[1:] == ["finalize"]:
        finalize(inputs)
    else:
        raise ValueError("expected verify-guest DIRECTORY, guest-sbom, or finalize")


if __name__ == "__main__":
    main()
