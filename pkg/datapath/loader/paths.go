// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"path/filepath"

	"github.com/vishvananda/netlink"

	datapath "github.com/cilium/cilium/pkg/datapath/types"
)

// bpffsDevicesDir returns the path to the 'devices' directory on bpffs, usually
// /sys/fs/bpf/cilium/devices. It does not ensure the directory exists.
//
// base is typically set to /sys/fs/bpf/cilium, but can be a temp directory
// during tests.
func bpffsDevicesDir(base string) string {
	return filepath.Join(base, "devices")
}

// bpffsDeviceLinksDir returns the bpffs path to the per-device links directory,
// usually /sys/fs/bpf/cilium/devices/<device>/links. It does not ensure the
// directory exists.
//
// base is typically set to /sys/fs/bpf/cilium, but can be a temp directory
// during tests.
func bpffsDeviceLinksDir(base string, device netlink.Link) string {
	return filepath.Join(bpffsDevicesDir(base), device.Attrs().Name, "links")
}

// bpffsEndpointsDir returns the path to the 'endpoints' directory on bpffs, usually
// /sys/fs/bpf/cilium/endpoints. It does not ensure the directory exists.
//
// base is typically set to /sys/fs/bpf/cilium, but can be a temp directory
// during tests.
func bpffsEndpointsDir(base string) string {
	return filepath.Join(base, "endpoints")
}

// bpffsEndpointLinksDir returns the bpffs path to the per-endpoint links directory,
// usually /sys/fs/bpf/cilium/endpoints/<endpoint-id>/links. It does not ensure the
// directory exists.
//
// base is typically set to /sys/fs/bpf/cilium, but can be a temp directory
// during tests.
func bpffsEndpointLinksDir(base string, ep datapath.Endpoint) string {
	return filepath.Join(bpffsEndpointsDir(base), ep.StringID(), "links")
}
