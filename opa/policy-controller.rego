package sigstore
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


default isCompliant = "log4shell CVE detected"

## check that any artifact is log4j-core AND the same artifact's version is infected with log4shell
infected_log4j_present(predicateData) {
    some i
    pkg := predicateData.artifacts[i]
    pkg.name == "log4j-core"
    pkg.version == bad_log4j_versions[_]
}

## input.predicate.Data comes in as a stringified JSON and must be unmarshal'd for dot references to work
inputData := json.unmarshal(input.predicate.Data)

## allow when SBOM does not contain infected log4j-core version
isCompliant {
  not infected_log4j_present(inputData)
}

