package bottlerocket

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

var pkgs = []types.Package{
	{
		ID:      "",
		Name:    "acpid",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "apiclient",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "apiserver",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "audit",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "aws-iam-authenticator",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "aws-signing-helper",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "bloodhound",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{ID: "",
		Name:    "bootstrap-containers",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "bork",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "ca-certificates",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "certdog",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "cfsignal",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "chrony",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "cni",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "cni-plugins",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "conntrack-tools",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "containerd",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "coreutils",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "corndog",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "dbus-broker",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "e2fsprogs",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "e2fsprogs-libs",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "early-boot-config",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "ecr-credential-provider-1.27",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "ethtool",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "filesystem",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "findutils",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "ghostdog",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "glibc",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "grep",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "grub",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "host-containers",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "host-ctr",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "iproute",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "iptables",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "kernel-5.15",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "kernel-5.15-devel",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "kernel-5.15-modules",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "kexec-tools",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "keyutils",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "kmod",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "kubelet-1.27",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "libacl",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "libattr",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "libaudit",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "libblkid",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "libbzip2",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "libcap",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "libdbus",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "libelf",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "libexpat",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "libfdisk",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "libgcc",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "libinih",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "libiw",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "liblzma",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "libmnl",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "libmount",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "libncurses",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "libnetfilter_conntrack",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "libnetfilter_cthelper",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "libnetfilter_cttimeout",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "libnetfilter_queue",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "libnfnetlink",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "libnftnl",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "libnl",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "libpcre",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "libseccomp",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "libselinux",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "libselinux-utils",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "libsemanage",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "libsepol",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "libsmartcols",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "libstd-rust",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "liburcu",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "libuuid",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "libxcrypt",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "libz",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "libzstd",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "logdog",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "makedumpfile",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "metricdog",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "microcode-amd-license",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "microcode-intel-license",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "microcode-licenses",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "migration",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "netdog",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "oci-add-hooks",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "os",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "pigz",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "pluto",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "policycoreutils",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "prairiedog",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "procps",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "release",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "runc",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "schnauzer",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "selinux-policy",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "settings-committer",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "shibaken",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "shim",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "shimpei",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "signpost",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "static-pods",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "storewolf",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "sundog",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "systemd",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "thar-be-settings",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "thar-be-updates",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "updog",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "util-linux",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "wicked",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "xfscli",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
	{
		ID:      "",
		Name:    "xfsprogs",
		Version: "1.19.2",
		Arch:    "x86_64",
	},
}

func TestParseApplicationInventory(t *testing.T) {
	var tests = []struct {
		name     string
		path     string
		wantPkgs []types.Package
	}{
		{
			name:     "happy path",
			path:     "./testdata/application-inventory.json",
			wantPkgs: pkgs,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := bottlerocketPkgAnalyzer{}
			f, err := os.Open(tt.path)
			require.NoError(t, err)
			defer f.Close()
			gotPkgs, err := a.parseApplicationInventory(context.Background(), f)
			require.NoError(t, err)

			assert.Equal(t, tt.wantPkgs, gotPkgs)
		})
	}
}
