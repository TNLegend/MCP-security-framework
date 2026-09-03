import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync(new URL("./BuildSecurity.jsx", import.meta.url), "utf-8");
const appSource = readFileSync(new URL("../App.jsx", import.meta.url), "utf-8");

test("Build Security is a first-class Control Center page", () => {
  assert.match(appSource, /id: "build", label: "Build Security"/);
  assert.match(appSource, /<BuildSecurity/);
  assert.match(source, /<h2>Build Security<\/h2>/);
  assert.match(source, /Semgrep \+ Gitleaks \+ Trivy/);
});

test("Build Security opens a native local folder picker", () => {
  assert.match(source, /pickBuildLocalDirectory/);
  assert.match(source, /Choose MCP folder\.\.\./);
  assert.match(source, /No MCP folder selected/);
  assert.match(source, /localSourcePath/);
  assert.match(source, /bindingLocalPath/);
  assert.match(source, /Scan selected directory/);
  assert.doesNotMatch(source, /DirectoryBrowser/);
  assert.doesNotMatch(source, /webkitdirectory/i);
  assert.doesNotMatch(source, /FileReader/);
});

test("Build Security supports local Git and Inventory targets", () => {
  assert.match(source, /LOCAL_DIRECTORY/);
  assert.match(source, /GIT_REPOSITORY/);
  assert.match(source, /MCP Inventory/);
  assert.match(source, /startLocalBuildScan/);
  assert.match(source, /startGitBuildScan/);
  assert.match(source, /startInventoryBuildScan/);
  assert.match(source, /configureBuildSourceBinding/);
  assert.match(source, /Choose the source folder for this Inventory server/);
  assert.match(source, /matching saved binding required/);
  assert.match(source, /setBindingLocalPath\(""\)/);
  assert.match(source, /setBindingGitUrl\(""\)/);
  assert.match(source, /setBindingGitRef\("HEAD"\)/);
  assert.match(source, /Fetch immutable revision and scan/);
});

test("Build Security viewer is read-only and scanner evidence is normalized", () => {
  assert.match(
    source,
    /VIEWER can inspect Build Security evidence but cannot open the local folder picker/,
  );
  assert.match(source, /Normalized findings/);
  assert.match(source, /finding\.vulnerability_id \|\| finding\.rule_id/);
  assert.match(source, /finding\.remediation/);
  assert.match(source, /finding\.file_path/);
  assert.doesNotMatch(source, /finding\.secret/i);
  assert.doesNotMatch(source, /finding\.match/i);
  assert.doesNotMatch(source, /fetch\(/);
});


test("Build Security connects exact scan evidence to governed Runtime drafts", () => {
  assert.match(source, /attachBuildScanToDraft/);
  assert.match(source, /Runtime governance/);
  assert.match(source, /Attach exact Build evidence to DRAFT/);
  assert.match(source, /REQUIRE_PASS/);
  assert.match(source, /ALLOW_WARN/);
  assert.match(source, /DISABLED/);
  assert.match(source, /max_evidence_age_hours/);
  assert.match(source, /scan\.linked_server_id/);
  assert.match(source, /Validate and publish that draft before Runtime can enforce it/);
  assert.match(appSource, /revisions=\{configRevisions\}/);
  assert.match(appSource, /onRefresh=\{loadData\}/);
});

test("Build Security keeps MCP source location and finding remediation traceable", () => {
  assert.match(source, /fetchBuildSourceBindings/);
  assert.match(source, /fetchBuildScanSources/);
  assert.match(source, /scanSources/);
  assert.match(source, /Source location/);
  assert.match(source, /Source not configured/);
  assert.match(source, /Runtime endpoint/);
  assert.match(source, /serverOptionLabel/);
  assert.match(source, /source\.source_locator/);
  assert.match(source, /resolvedFindingLocation/);
  assert.match(source, /Open source at scanned revision/);
  assert.match(source, /Copy source location/);
  assert.match(source, /ADMIN only/);
  assert.match(source, /Search MCP, path, repository, endpoint, revision/);
});
