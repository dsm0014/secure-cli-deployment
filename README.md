# secure-cli-deployment
Demonstration of how to use the Sigstore policy-controller to produce secure Kubernetes environments which
ensures that running container images are signed with known keys and validate attestations.

Take a look at the [secure-cli](https://github.com/dsm0014/secure-cli) example project for an introduction to Secure 
Software Supply Chains and how to produce an OCI image this deployment repo can leverage.

## Using Rego to Check for Log4shell
When interacting with an image that has attestations, you can utilize the [Rego policy language](https://www.openpolicyagent.org/docs/latest/policy-language/)
to verify the contents on the image's attestation. Something that is useful and common to attest to an image, is a Software
Bill of Materials.

If you still need to generate and attest an SBOM to a signed image, take a look at the [secure-cli repo](https://github.com/dsm0014/secure-cli).

### Rego for Cosign CLI
It's often said that SBOM's and attestations can be used to validate for the absence of vulnerabilities.
Let's take a look at a [Rego policy file](./opa/cosign.rego) that can be used with the `cosign verify-attestation` command
to verify that an attested SBOM does not contain a log4j package affected by [Log4Shell (CVE-2021-44228)](https://nvd.nist.gov/vuln/detail/CVE-2021-44228).

To start, your Rego policy needs to declare the `package` that the policy belongs to.
It is important to note that this package _cannot be whatever you want_ when working with `cosign` or the Sigstore Policy Controller.

For `cosign`, you should declare:
`package signature`

For the Sigstore Policy Controller, you should declare:
`package sigstore`

In both cases, you are going to want to add the line `import future.keywords` to enable some additional syntax elements.

Now, define a _set_ containing log4j versions infected with Log4Shell.
```
bad_log4j_versions := {
    "2.0-alpha2",
    "2.0-beta1",
    "2.0-beta2",
    ....
}
```
For the full declaration of these versions(there are 40+), take a look in the [Rego policy file](./opa/policy-controller.rego).
With our package, imports, and the bad log4j versions defined, let's look at the rule which performs our validation.

The rule for `cosign` _must be named_ `allow`. 
```
default allow = "log4shell CVE detected"
```
However, the rule for the Sigstore Policy Controller _must be named_ `isCompliant`.
```
default isCompliant = "log4shell CVE detected"
```

Wonderful, we now we just create an OPA function which checks for the `bad_log4j_versions` in the attested SBOM.
```
infected_log4j_present(predicateData) {
    some i
    pkg := predicateData.artifacts[i]
    pkg.name == "log4j-core"
    pkg.version == bad_log4j_versions[_]
}
```

Finally, let's store the SBOM attestation in a variable and define an additional stanza for our `allow` (or `isCompliant`) rule.
```
## input.predicate.Data comes in as a stringified JSON and must be unmarshal'd for dot references to work
inputData := json.unmarshal(input.predicate.Data)
allow {
  not infected_log4j_present(inputData)
}
```

We can test our rego policy with the following command:
`cosign verify-attestation --key cosign.pub --policy ./opa/cosign.rego <your-image-with-SBOM-attestation> | jq -r .payload | base64 -D | jq .`

Upon success, this will output the attested SBOM to your console.

## Using the Sigstore Policy Controller
We can quickly install the policy controller with:
```shell
helm repo add sigstore https://sigstore.github.io/helm-charts

helm repo update

helm install policy-controller -n cosign-system sigstore/policy-controller --devel --set cosign.secretKeyRef.name=cosign-pub --create-namespace -f values-overrides.yaml
```
Notice how we provide `values-overrides.yaml` to the chart.
<br>
I ran into timeout issues with the webhooks when using default values.

Create a Secret with your cosign public key.
<br>
This can be accomplished with `kubectl create secret generic cosign-pub -n cosign-system --from-file=cosign.pub=./cosign.pub`

If you haven't got cosign keys to use, take a look at the [secure-cli](https://github.com/dsm0014/secure-cli)
example repo and follow the README to produce your own signed image and SBOM.

Make sure pods in the `cosign-system` namespace are all running with `kubectl rollout -n cosign-system status deployment policy-controller-webhook ` otherwise you may experience issues.

Create a namespace with the appropriate label for the policy-controller to enforce signature in the namespace.
`kubectl apply -f ./kubernetes/secure-ns.yaml`

Attempt to create a pod in the `secure` namespace using a container image that does not have a signature known by the policy-controller
and watch how creation is denied because the image was not signed using your cosign private key.
`kubectl run pod nginx --image nginx:latest -n secure`
Try creating the same `nginx` pod in the `default` namespace and notice that it is allowed.
<br>
This is because of the `metadata.label: policy.sigstore.dev/include: "true"` attached to our `secure` namespace.

Notice how if you attempt to create the nginx pod in the `default` namespace it is allowed, because that namespace is 
not being protected by the policy-controller.

### Using Rego Policies with the Sigstore Policy Controller
Using the [policy controller compatible rego file](./opa/policy-controller.rego) we can perform attestations as an
admission controller in a Kubernetes cluster. This rego is included in the ClusterImagePolicy you create with:
`kubectl apply -f ./kubernetes/sbom-attestation-policy.yaml`

Now run the secure-cli as a job in the secure namespace, and see how it is allowed by the policy-controller.
`kubectl apply -f ./kubernetes/secure-job.yaml`
This is allowed because the container image was signed using the private key corresponding to the public key in the
secret that we created in the `cosign-system` namespace AND because the artifacts in the SBOM attested to the image do
not contain the log4shell CVE.

