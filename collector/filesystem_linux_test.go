// Copyright 2015 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build !nofilesystem

package collector

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/alecthomas/kingpin/v2"

	"github.com/prometheus/procfs"
)

func Test_parseFilesystemLabelsError(t *testing.T) {
	tests := []struct {
		name string
		in   []*procfs.MountInfo
	}{
		{
			name: "malformed Major:Minor",
			in: []*procfs.MountInfo{
				{
					MajorMinorVer: "nope",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseFilesystemLabels(tt.in); err == nil {
				t.Fatal("expected an error, but none occurred")
			}
		})
	}
}

func Test_parseFilesystemLabelsSanitizesInvalidUTF8(t *testing.T) {
	in := []*procfs.MountInfo{
		{
			MajorMinorVer: "0:0",
			Source:        "/dev/sd\xe9",
			MountPoint:    "/mnt/cass\xe9",
			FSType:        "ext\xe9",
		},
	}

	got, err := parseFilesystemLabels(in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 filesystem, got %d", len(got))
	}

	for name, value := range map[string]string{
		"device":     got[0].device,
		"mountPoint": got[0].mountPoint,
		"fsType":     got[0].fsType,
	} {
		if !utf8.ValidString(value) {
			t.Errorf("expected %s to be valid UTF-8, got %q", name, value)
		}
	}
}

func Test_isFilesystemReadOnly(t *testing.T) {
	tests := map[string]struct {
		labels   filesystemLabels
		expected bool
	}{
		"/media/volume1": {
			labels: filesystemLabels{
				mountOptions: "rw,nosuid,nodev,noexec,relatime",
				superOptions: "rw,devices",
			},
			expected: false,
		},
		"/media/volume2": {
			labels: filesystemLabels{
				mountOptions: "ro,relatime",
				superOptions: "rw,fd=22,pgrp=1,timeout=300,minproto=5,maxproto=5,direct",
			}, expected: true,
		},
		"/media/volume3": {
			labels: filesystemLabels{
				mountOptions: "rw,user_id=1000,group_id=1000",
				superOptions: "ro",
			}, expected: true,
		},
		"/media/volume4": {
			labels: filesystemLabels{
				mountOptions: "ro,nosuid,noexec",
				superOptions: "ro,nodev",
			}, expected: true,
		},
		"/media/volume5": {
			labels: filesystemLabels{
				mountOptions: "rw,user_id=1000,group_id=1000",
				superOptions: "emergency_ro",
			}, expected: true,
		},
	}

	for _, tt := range tests {
		if got := isFilesystemReadOnly(tt.labels); got != tt.expected {
			t.Errorf("Expected %t, got %t", tt.expected, got)
		}
	}
}

func TestMountPointDetails(t *testing.T) {
	if _, err := kingpin.CommandLine.Parse([]string{"--path.procfs", "./fixtures/proc"}); err != nil {
		t.Fatal(err)
	}

	expected := map[string]string{
		"/":                               "",
		"/sys":                            "",
		"/proc":                           "",
		"/dev":                            "",
		"/dev/pts":                        "",
		"/run":                            "",
		"/sys/kernel/security":            "",
		"/dev/shm":                        "",
		"/run/lock":                       "",
		"/sys/fs/cgroup":                  "",
		"/sys/fs/cgroup/systemd":          "",
		"/sys/fs/pstore":                  "",
		"/sys/fs/cgroup/cpuset":           "",
		"/sys/fs/cgroup/cpu,cpuacct":      "",
		"/sys/fs/cgroup/devices":          "",
		"/sys/fs/cgroup/freezer":          "",
		"/sys/fs/cgroup/net_cls,net_prio": "",
		"/sys/fs/cgroup/blkio":            "",
		"/sys/fs/cgroup/perf_event":       "",
		"/proc/sys/fs/binfmt_misc":        "",
		"/dev/mqueue":                     "",
		"/sys/kernel/debug":               "",
		"/dev/hugepages":                  "",
		"/sys/fs/fuse/connections":        "",
		"/boot":                           "",
		"/run/rpc_pipefs":                 "",
		"/run/user/1000":                  "",
		"/run/user/1000/gvfs":             "",
		"/var/lib/kubelet/plugins/kubernetes.io/vsphere-volume/mounts/[vsanDatastore] bafb9e5a-8856-7e6c-699c-801844e77a4a/kubernetes-dynamic-pvc-3eba5bba-48a3-11e8-89ab-005056b92113.vmdk": "",
		"/var/lib/kubelet/plugins/kubernetes.io/vsphere-volume/mounts/[vsanDatastore]	bafb9e5a-8856-7e6c-699c-801844e77a4a/kubernetes-dynamic-pvc-3eba5bba-48a3-11e8-89ab-005056b92113.vmdk": "",
		"/var/lib/containers/storage/overlay": "",
	}

	filesystems, err := mountPointDetails(slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Log(err)
	}

	foundSet := map[string]bool{}
	for _, fs := range filesystems {
		if _, ok := expected[fs.mountPoint]; !ok {
			t.Errorf("Got unexpected %s", fs.mountPoint)
		}
		foundSet[fs.mountPoint] = true
	}

	for mountPoint := range expected {
		if _, ok := foundSet[mountPoint]; !ok {
			t.Errorf("Expected %s, got nothing", mountPoint)
		}
	}
}

func TestMountPointDetailsReadsMountInfoBeyond1MiB(t *testing.T) {
	const (
		mountCount      = 25000
		mountInfoLimit  = 1 << 20
		finalMountPoint = "/mnt/final-sentinel"
	)

	procDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(procDir, "1"), 0o755); err != nil {
		t.Fatal(err)
	}

	var mountInfo strings.Builder
	for i := 0; i < mountCount-1; i++ {
		fmt.Fprintf(&mountInfo, "%d 1 0:1 / /mnt/test-%d rw - tmpfs tmpfs rw\n", i+1, i)
	}
	finalMountOffset := mountInfo.Len()
	if finalMountOffset <= mountInfoLimit {
		t.Fatalf("final mount starts at byte %d, want beyond 1 MiB", finalMountOffset)
	}
	fmt.Fprintf(&mountInfo, "%d 1 0:1 / %s rw - tmpfs tmpfs rw\n", mountCount, finalMountPoint)
	if mountInfo.Len() <= mountInfoLimit {
		t.Fatalf("generated mountinfo is %d bytes, want more than 1 MiB", mountInfo.Len())
	}
	if err := os.WriteFile(filepath.Join(procDir, "1", "mountinfo"), []byte(mountInfo.String()), 0o600); err != nil {
		t.Fatal(err)
	}

	originalProcPath := *procPath
	t.Cleanup(func() { *procPath = originalProcPath })
	*procPath = procDir

	filesystems, err := mountPointDetails(slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if len(filesystems) != mountCount {
		t.Fatalf("got %d mount points, want %d", len(filesystems), mountCount)
	}
	if got := filesystems[len(filesystems)-1].mountPoint; got != finalMountPoint {
		t.Fatalf("final mount point is %q, want %q", got, finalMountPoint)
	}
}

func TestMountsFallback(t *testing.T) {
	if _, err := kingpin.CommandLine.Parse([]string{"--path.procfs", "./fixtures_hidepid/proc"}); err != nil {
		t.Fatal(err)
	}

	expected := map[string]string{
		"/": "",
	}

	filesystems, err := mountPointDetails(slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Log(err)
	}

	for _, fs := range filesystems {
		if _, ok := expected[fs.mountPoint]; !ok {
			t.Errorf("Got unexpected %s", fs.mountPoint)
		}
	}
}

func TestMountOptionsString(t *testing.T) {
	tests := []struct {
		name      string
		input     map[string]string
		wantParts []string
	}{
		{
			name:      "single flag option",
			input:     map[string]string{"ro": ""},
			wantParts: []string{"ro"},
		},
		{
			name:      "single key=value option",
			input:     map[string]string{"errors": "remount-ro"},
			wantParts: []string{"errors=remount-ro"},
		},
		{
			name:      "multiple options including ro",
			input:     map[string]string{"ro": "", "relatime": "", "errors": "remount-ro"},
			wantParts: []string{"errors=remount-ro", "relatime", "ro"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mountOptionsString(tt.input)
			parts := strings.Split(result, ",")
			sort.Strings(parts)
			sort.Strings(tt.wantParts)
			if len(parts) != len(tt.wantParts) {
				t.Fatalf("mountOptionsString(%v) = %q, got %d parts, want %d", tt.input, result, len(parts), len(tt.wantParts))
			}
			for i := range parts {
				if parts[i] != tt.wantParts[i] {
					t.Errorf("mountOptionsString(%v) = %q, sorted part[%d] = %q, want %q", tt.input, result, i, parts[i], tt.wantParts[i])
				}
			}
		})
	}
}

func TestMountOptionsStringReadOnlyDetection(t *testing.T) {
	tests := []struct {
		name         string
		mountOptions map[string]string
		superOptions map[string]string
		wantReadOnly bool
	}{
		{
			name:         "ro among multiple mount options (ZFS / remount-ro scenario)",
			mountOptions: map[string]string{"ro": "", "relatime": "", "errors": "remount-ro"},
			superOptions: map[string]string{"rw": ""},
			wantReadOnly: true,
		},
		{
			name:         "ro in super options only",
			mountOptions: map[string]string{"rw": "", "relatime": ""},
			superOptions: map[string]string{"ro": "", "user_id": "1000"},
			wantReadOnly: true,
		},
		{
			name:         "no ro anywhere",
			mountOptions: map[string]string{"rw": "", "nosuid": "", "nodev": ""},
			superOptions: map[string]string{"rw": ""},
			wantReadOnly: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			labels := filesystemLabels{
				mountOptions: mountOptionsString(tt.mountOptions),
				superOptions: mountOptionsString(tt.superOptions),
			}
			if got := isFilesystemReadOnly(labels); got != tt.wantReadOnly {
				t.Errorf("isFilesystemReadOnly(%+v) = %v, want %v (mountOptions=%q superOptions=%q)",
					tt, got, tt.wantReadOnly, labels.mountOptions, labels.superOptions)
			}
		})
	}
}

func TestPathRootfs(t *testing.T) {
	if _, err := kingpin.CommandLine.Parse([]string{"--path.procfs", "./fixtures_bindmount/proc", "--path.rootfs", "/host"}); err != nil {
		t.Fatal(err)
	}

	expected := map[string]string{
		// should modify these mountpoints (removes /host, see fixture proc file)
		"/":              "",
		"/media/volume1": "",
		"/media/volume2": "",
		// should not modify these mountpoints
		"/dev/shm":       "",
		"/run/lock":      "",
		"/sys/fs/cgroup": "",
	}

	filesystems, err := mountPointDetails(slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Log(err)
	}

	for _, fs := range filesystems {
		if _, ok := expected[fs.mountPoint]; !ok {
			t.Errorf("Got unexpected %s", fs.mountPoint)
		}
	}
}
