package platform

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/go-version"
	"github.com/hashicorp/hc-install/product"
	"github.com/hashicorp/hc-install/releases"
	"github.com/hashicorp/terraform-exec/tfexec"
	"github.com/humanitec/humctl-wizard/internal/message"
)


type terraformLogger struct{}
func (terraformLogger) Write(p []byte) (n int, err error) {
	message.Debug(strings.TrimSuffix(string(p), "\n")) //nolint:all
	return len(p), nil
}
func (terraformLogger) Printf(format string, v ...interface{}) {
	message.Debug("Terraform: " + format, v...)
}

func (p *HumanitecPlatform) ApplyTerraform(ctx context.Context, workingDir string, vars map[string]string) error {
	installer := &releases.ExactVersion{
		Product: product.Terraform,
		Version: version.Must(version.NewVersion("1.9.8")),
	}
	installer.SetLogger(log.New(&terraformLogger{}, "Terraform Installer: ", 0))

	execPath, err := installer.Install(context.Background())
	if err != nil {
		return fmt.Errorf("failed to install Terraform: %w", err)
	}

	tf, err := tfexec.NewTerraform(workingDir, execPath)
	if err != nil {
		return fmt.Errorf("failed to create Terraform: %w", err)
	}
	tf.SetLogger(&terraformLogger{})

	err = tf.SetEnv(map[string]string{
		"HUMANITEC_ORG":   p.OrganizationId,
		"HUMANITEC_TOKEN": p.Token,
	})
	if err != nil {
		return fmt.Errorf("failed to set Terraform environment variables: %w", err)
	}

	err = tf.Init(ctx, tfexec.Upgrade(true))
	if err != nil {
		return fmt.Errorf("failed to init Terraform: %w", err)
	}

	var tfVars []tfexec.ApplyOption
	for k, v := range vars {
		tfVars = append(tfVars, tfexec.Var(k+"="+v))
	}

	tfStatePath, err := calculateStatePath(workingDir)
	if err != nil {
		return fmt.Errorf("failed to calculate state path: %w", err)
	}

	tfVars = append(tfVars, tfexec.State(tfStatePath)) //nolint:all

	err = tf.Apply(ctx, tfVars...)
	if err != nil {
		return fmt.Errorf("failed to apply Terraform: %w", err)
	}

	return nil
}

func calculateStatePath(workingDir string) (string, error) {
	hash := sha256.New()
	_, err := hash.Write([]byte(workingDir))
	if err != nil {
		return "", fmt.Errorf("failed to hash workingDir path: %w", err)
	}

	path, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user home directory: %w", err)
	}
	path = filepath.Join(path, ".humctl-wizard", "resource-pack-states", fmt.Sprintf("%x", hash.Sum(nil)))

	err = os.MkdirAll(path, 0755)
	if err != nil {
		return "", fmt.Errorf("failed to create state directory: %w", err)
	}
	
	return filepath.Join(path, "terraform.tfstate"), nil
}