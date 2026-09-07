# cyclonedx-gomod derives the main version from the available Git tags. Bind
# only that component and its graph references to the accepted source instead.
if ($source_sha | test("^[0-9a-f]{40}$")) | not then
  error("an exact source commit is required")
else . end
| .metadata.component as $root
| $root["bom-ref"] as $old_ref
| ("git-" + $source_sha) as $version
| ("pkg:golang/" + $root.name + "@" + $version + "?type=module") as $new_ref
| if ($old_ref | type) != "string" or ($root.name | type) != "string" then
    error("missing main module identity")
  else . end
| .metadata.component.version = $version
| .metadata.component["bom-ref"] = $new_ref
| .metadata.component.purl = ("pkg:golang/" + $root.name + "@" + $version
    + "?goarch=amd64&goos=linux&type=module")
| .dependencies |= map(
    .ref |= (if . == $old_ref then $new_ref else . end)
    | if has("dependsOn") then
        .dependsOn |= map(if . == $old_ref then $new_ref else . end)
      else . end)
