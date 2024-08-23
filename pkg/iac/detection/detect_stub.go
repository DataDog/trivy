package detection

import (
	"path/filepath"
	"strings"
)

type FileType string

const (
	FileTypeCloudFormation        FileType = "cloudformation"
	FileTypeTerraform             FileType = "terraform"
	FileTypeTerraformPlanJSON     FileType = "terraformplan-json"
	FileTypeTerraformPlanSnapshot FileType = "terraformplan-snapshot"
	FileTypeDockerfile            FileType = "dockerfile"
	FileTypeKubernetes            FileType = "kubernetes"
	FileTypeRbac                  FileType = "rbac"
	FileTypeYAML                  FileType = "yaml"
	FileTypeTOML                  FileType = "toml"
	FileTypeJSON                  FileType = "json"
	FileTypeHelm                  FileType = "helm"
	FileTypeAzureARM              FileType = "azure-arm"
)

func IsTerraformFile(path string) bool {
	if strings.HasSuffix(path, filepath.ToSlash(".terraform/modules/modules.json")) {
		return true
	}

	for _, ext := range []string{".tf", ".tf.json", ".tfvars"} {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}

	return false
}
