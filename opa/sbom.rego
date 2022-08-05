## This is the rego policy our ClusterImagePolicy is derived from
##  and is functional using the `cosign verify-attestation` command.
##  Slight alterations (noted in comments) are necesary before
##  use with the cosign policy-controller.

## rename package to 'sigstore' for ClusterImagePolicy
package signature
import future.keywords

## intialize a set of log4j-core versions infected by the log4shell CVE
bad_log4j_versions := {
    "2.0-alpha2",
    "2.0-beta1",
    "2.0-beta2",
    "2.0-beta3",
    "2.0-beta4",
    "2.0-beta5",
    "2.0-beta6",
    "2.0-beta7",
    "2.0-beta8",
    "2.0-beta9",
    "2.0",
    "2.0-rc1",
    "2.0-rc2",
    "2.0.1",
    "2.0.2",
    "2.1",
    "2.2",
    "2.3",
    "2.4",
    "2.4.1",
    "2.5",
    "2.6",
    "2.6.1",
    "2.6.2",
    "2.7",
    "2.8",
    "2.8.1",
    "2.8.2",
    "2.9.0",
    "2.9.1",
    "2.10.0",
    "2.11.0",
    "2.11.1",
    "2.11.2",
    "2.12.0",
    "2.12.1",
    "2.13.0",
    "2.13.1",
    "2.13.2",
    "2.13.3",
    "2.14.0",
    "2.14.1",
    "2.0-alpha1"
}

## check that any artifact is log4j-core AND the same artifact's version is infected with log4shell
infected_log4j_present(s) {
    some i
    pkg := s.artifacts[i]
    pkg.name == "log4j-core"
    pkg.version == bad_log4j_versions[_]
}

## input.predicate.Data comes in as a stringified JSON and must be unmarshal'd for dot references to work
inputData := json.unmarshal(input.predicate.Data)

## rename rule to 'isCompliant' in ClusterImagePolicy
default allow = "log4shell CVE detected"

## allow when SBOM does not contain infected log4j-core version
allow {
  not infected_log4j_present(inputData)
}
