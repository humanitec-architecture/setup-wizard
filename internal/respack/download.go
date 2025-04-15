package respack

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

type ResourcePackType string

const (
	InCluster ResourcePackType = "in-cluster"
	AWS       ResourcePackType = "aws"
	Azure     ResourcePackType = "azure"
	GCP       ResourcePackType = "gcp"
)

type ResourcePack struct {
	Resources []Resource
}

type Resource struct {
	Name string
	Type string
	Path string
}

func Download(ctx context.Context, resourcePack ResourcePackType) (*ResourcePack, error) {
	var url string
	switch resourcePack {
	case InCluster:
		url = "https://github.com/humanitec-architecture/resource-packs-in-cluster/archive/refs/heads/main.zip"
	case AWS:
		return nil, ErrResourcePackNotSupported
	case Azure:
		return nil, ErrResourcePackNotSupported
	case GCP:
		return nil, ErrResourcePackNotSupported
	default:
		return nil, ErrUnknownResourcePack
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	resourcePackZipPath := filepath.Join(homeDir, ".humctl-wizard", "resource-pack.zip")
	err = os.RemoveAll(resourcePackZipPath)
	if err != nil {
		return nil, fmt.Errorf("failed to remove existing resource pack zip: %w", err)
	}

	err = download(url, resourcePackZipPath)
	if err != nil {
		return nil, fmt.Errorf("failed to download resource pack: %w", err)
	}

	resourcePackDir := filepath.Join(homeDir, ".humctl-wizard", "resource-pack")
	err = os.RemoveAll(resourcePackDir)
	if err != nil {
		return nil, fmt.Errorf("failed to remove existing resource pack directory: %w", err)
	}

	err = unzip(resourcePackZipPath, resourcePackDir)
	if err != nil {
		return nil, fmt.Errorf("failed to unzip resource pack: %w", err)
	}

	err = os.RemoveAll(resourcePackZipPath)
	if err != nil {
		return nil, fmt.Errorf("failed to remove resource pack zip: %w", err)
	}

	switch resourcePack {
	case InCluster:
		return &ResourcePack{
			Resources: []Resource{
				{
					Name: "mongodb",
					Type: "mongodb",
					Path: filepath.Join(resourcePackDir, "resource-packs-in-cluster-main", "humanitec-resource-defs", "mongodb", "basic"),
				},
				{
					Name: "mysql",
					Type: "mysql",
					Path: filepath.Join(resourcePackDir, "resource-packs-in-cluster-main", "humanitec-resource-defs", "mysql", "basic"),
				},
				{
					Name: "postgres",
					Type: "postgres",
					Path: filepath.Join(resourcePackDir, "resource-packs-in-cluster-main", "humanitec-resource-defs", "postgres", "basic"),
				},
				{
					Name: "rabbitmq",
					Type: "amqp",
					Path: filepath.Join(resourcePackDir, "resource-packs-in-cluster-main", "humanitec-resource-defs", "rabbitmq", "basic"),
				},
				{
					Name: "redis",
					Type: "redis",
					Path: filepath.Join(resourcePackDir, "resource-packs-in-cluster-main", "humanitec-resource-defs", "redis", "basic"),
				},
			},
		}, nil
	case AWS:
		return nil, ErrResourcePackNotSupported
	case Azure:
		return nil, ErrResourcePackNotSupported
	case GCP:
		return nil, ErrResourcePackNotSupported
	default:
		return nil, ErrUnknownResourcePack
	}
}

func download(url, dest string) error {
	out, err := os.Create(dest)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}

	defer func() {
		_ = out.Close()
	}()

	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download file: %w", err)
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

func unzip(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return fmt.Errorf("failed to open zip file: %w", err)
	}

	defer func() {
		_ = r.Close()
	}()

	err = os.MkdirAll(dest, 0755)
	if err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	extractAndWriteFile := func(f *zip.File) error {
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer func() {
			if err := rc.Close(); err != nil {
				panic(err)
			}
		}()

		path := filepath.Join(dest, f.Name)

		// Check for ZipSlip (Directory traversal)
		if !strings.HasPrefix(path, filepath.Clean(dest)+string(os.PathSeparator)) {
			return fmt.Errorf("illegal file path: %s", path)
		}

		if f.FileInfo().IsDir() {
			err = os.MkdirAll(path, f.Mode())
			if err != nil {
				return err
			}
		} else {
			err = os.MkdirAll(filepath.Dir(path), f.Mode())
			if err != nil {
				return err
			}
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
			if err != nil {
				return err
			}

			defer func() {
				_ = f.Close()
			}()

			_, err = io.Copy(f, rc)
			if err != nil {
				return err
			}
		}
		return nil
	}

	for _, f := range r.File {
		err := extractAndWriteFile(f)
		if err != nil {
			return fmt.Errorf("failed to extract file: %w", err)
		}
	}

	return nil
}
