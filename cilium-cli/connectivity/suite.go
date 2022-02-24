// SPDX-License-Identifier: Apache-2.0
// Copyright 2020-2021 Authors of Cilium

package connectivity

import (
	"context"
	_ "embed"

	"github.com/cilium/cilium/pkg/versioncheck"

	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/internal/utils"
)

var (
	//go:embed manifests/allow-all-except-world.yaml
	allowAllExceptWorldPolicyYAML string
	//go:embed manifests/allow-all-except-world-pre-v1.11.yaml
	allowAllExceptWorldPolicyPre1_11YAML string

	//go:embed manifests/client-egress-only-dns.yaml
	clientEgressOnlyDNSPolicyYAML string

	//go:embed manifests/client-egress-to-echo.yaml
	clientEgressToEchoPolicyYAML string

	//go:embed manifests/client-ingress-from-client2.yaml
	clientIngressFromClient2PolicyYAML string

	//go:embed manifests/client-egress-to-fqdns-one-one-one-one.yaml
	clientEgressToFQDNsCiliumIOPolicyYAML string

	//go:embed manifests/echo-ingress-from-other-client.yaml
	echoIngressFromOtherClientPolicyYAML string

	//go:embed manifests/client-egress-to-entities-world.yaml
	clientEgressToEntitiesWorldPolicyYAML string

	//go:embed manifests/client-egress-to-cidr-1111.yaml
	clientEgressToCIDR1111PolicyYAML string

	//go:embed manifests/client-egress-l7-http.yaml
	clientEgressL7HTTPPolicyYAML string

	//go:embed manifests/echo-ingress-l7-http.yaml
	echoIngressL7HTTPPolicyYAML string
)

func Run(ctx context.Context, ct *check.ConnectivityTest) error {
	ct.SetupAndValidate(ctx)

	version := ct.FetchCiliumPodImageTag()
	ct.Debugf("Cilium image version: %v", version)
	v, err := utils.ParseCiliumVersion(version, ct.CiliumBaseVersion())
	if err != nil {
		v = versioncheck.MustVersion(defaults.Version)
		ct.Warnf("Unable to parse Cilium version %q, assuming %v for connectivity tests", version, defaults.Version)
	}

	ct.Infof("Cilium version: %v", v)

	// Run all tests without any policies in place.
	ct.NewTest("no-policies").WithScenarios(
		tests.PodToPod(""),
		tests.ClientToClient(""),
		tests.PodToService(""),
		tests.PodToRemoteNodePort(""),
		tests.PodToLocalNodePort(""),
		tests.PodToWorld(""),
		tests.PodToHost(""),
		tests.PodToExternalWorkload(""),
		tests.PodToCIDR(""),
	)

	// Test with an allow-all-except-world (and unmanaged) policy.
	if v.GTE(versioncheck.MustVersion("1.11.0")) {
		ct.NewTest("allow-all-except-world").WithPolicy(allowAllExceptWorldPolicyYAML).
			WithScenarios(
				tests.PodToPod(""),
				tests.ClientToClient(""),
				tests.PodToService(""),
				// We are skipping the following checks because NodePort is
				// intended to be used for N-S traffic, which conflicts with
				// policies. See GH-17144.
				// tests.PodToRemoteNodePort(""),
				// tests.PodToLocalNodePort(""),
				tests.PodToHost(""),
				tests.PodToExternalWorkload(""),
			)
	} else {
		ct.NewTest("allow-all-except-world").WithPolicy(allowAllExceptWorldPolicyPre1_11YAML).
			WithScenarios(
				tests.PodToPod(""),
				tests.ClientToClient(""),
				tests.PodToService(""),
				// We are skipping the following checks because NodePort is
				// intended to be used for N-S traffic, which conflicts with
				// policies. See GH-17144.
				// tests.PodToRemoteNodePort(""),
				// tests.PodToLocalNodePort(""),
				tests.PodToHost(""),
				tests.PodToExternalWorkload(""),
			)
	}

	// This policy only allows ingress into client from client2.
	ct.NewTest("client-ingress").WithPolicy(clientIngressFromClient2PolicyYAML).
		WithScenarios(
			tests.ClientToClient(""),
		).WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
		if a.Source().HasLabel("other", "client") {
			return check.ResultOK, check.ResultOK
		}
		return check.ResultOK, check.ResultDrop
	})

	// This policy allows ingress to echo only from client with a label 'other:client'.
	ct.NewTest("echo-ingress").WithPolicy(echoIngressFromOtherClientPolicyYAML).
		WithScenarios(
			tests.PodToPod(""),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().HasLabel("kind", "echo") && !a.Source().HasLabel("other", "client") {
				// TCP handshake fails both in egress and ingress when
				// L3(/L4) policy drops at either location.
				return check.ResultDropCurlTimeout, check.ResultDropCurlTimeout
			}
			return check.ResultOK, check.ResultOK
		})

	// This policy allows port 8080 from client to echo, so this should succeed
	ct.NewTest("client-egress").WithPolicy(clientEgressToEchoPolicyYAML).
		WithScenarios(
			tests.PodToPod(""),
		)

	// This policy allows UDP to kube-dns and port 80 TCP to all 'world' endpoints.
	ct.NewTest("to-entities-world").
		WithPolicy(clientEgressToEntitiesWorldPolicyYAML).
		WithScenarios(
			tests.PodToWorld(""),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().Port() == 80 {
				return check.ResultOK, check.ResultNone
			}
			// PodToWorld traffic to port 443 will be dropped by the policy
			return check.ResultDropCurlTimeout, check.ResultNone
		})

	// This policy allows L3 traffic to 1.0.0.0/24 (including 1.1.1.1), with the
	// exception of 1.0.0.1.
	ct.NewTest("to-cidr-1111").
		WithPolicy(clientEgressToCIDR1111PolicyYAML).
		WithScenarios(
			tests.PodToCIDR(""),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().Address() == "1.0.0.1" {
				// Expect packets for 1.0.0.1 to be dropped.
				return check.ResultDropCurlTimeout, check.ResultNone
			}
			return check.ResultOK, check.ResultNone
		})

	// Test L7 HTTP introspection using an ingress policy on echo pods.
	ct.NewTest("echo-ingress-l7").
		WithPolicy(echoIngressL7HTTPPolicyYAML). // L7 allow policy with HTTP introspection
		WithScenarios(
			tests.PodToPod(""),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Source().HasLabel("other", "client") { // Only client2 is allowed to make HTTP calls.
				egress = check.ResultOK
				// Expect all curls from client2 to be proxied and to be GET calls.
				egress.HTTP = check.HTTP{
					Method: "GET",
				}
				return egress, check.ResultNone
			}
			return check.ResultDrop, check.ResultNone
		})

	// The following tests have DNS redirect policies. They should be executed last.

	// Test L7 HTTP introspection using an egress policy on the clients.
	ct.NewTest("client-egress-l7").
		WithPolicy(clientEgressOnlyDNSPolicyYAML). // DNS resolution only
		WithPolicy(clientEgressL7HTTPPolicyYAML).  // L7 allow policy with HTTP introspection
		WithScenarios(
			tests.PodToPod(""),
			tests.PodToWorld(""),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Source().HasLabel("other", "client") && // Only client2 is allowed to make HTTP calls.
				// Outbound HTTP to one.one.one.one is L7-introspected and allowed.
				(a.Destination().Port() == 80 && a.Destination().Address() == "one.one.one.one" ||
					a.Destination().Port() == 8080) { // 8080 is traffic to echo Pod.
				if a.Destination().Path() == "/" || a.Destination().Path() == "" {
					egress = check.ResultOK
					// Expect all curls from client2 to be proxied and to be GET calls.
					egress.HTTP = check.HTTP{
						Method: "GET",
					}
					return egress, check.ResultNone
				}
				// Else expect HTTP drop by proxy
				return check.ResultDNSOKDropCurlHTTPError, check.ResultNone
			}
			return check.ResultDrop, check.ResultNone
		})

	// Only allow UDP:53 to kube-dns, no DNS proxy enabled.
	ct.NewTest("dns-only").WithPolicy(clientEgressOnlyDNSPolicyYAML).
		WithScenarios(
			tests.PodToPod(""),   // connects to other Pods directly, no DNS
			tests.PodToWorld(""), // resolves one.one.one.one
		).
		WithExpectations(
			func(a *check.Action) (egress check.Result, ingress check.Result) {
				return check.ResultDropCurlTimeout, check.ResultNone
			})

	// This policy only allows port 80 to "one.one.one.one". DNS proxy enabled.
	ct.NewTest("to-fqdns").WithPolicy(clientEgressToFQDNsCiliumIOPolicyYAML).
		WithScenarios(
			tests.PodToWorld(""),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().Port() == 80 && a.Destination().Address() == "one.one.one.one" {
				if a.Destination().Path() == "/" || a.Destination().Path() == "" {
					egress = check.ResultDNSOK
					egress.HTTP = check.HTTP{
						Method: "GET",
						URL:    "http://one.one.one.one/",
					}
					return egress, check.ResultNone
				}
				// Else expect HTTP drop by proxy
				return check.ResultDNSOKDropCurlHTTPError, check.ResultNone
			}
			// No HTTP proxy on other ports
			return check.ResultDNSOKDropCurlTimeout, check.ResultNone
		})

	// Tests with DNS redirects to the proxy (e.g., client-egress-l7, dns-only,
	// and to-fqdns) should always be executed last. See #367 for details.

	return ct.Run(ctx)
}
