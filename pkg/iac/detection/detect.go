package detection

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
