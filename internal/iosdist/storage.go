package iosdist

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// AttachmentStorage is the interface for storing chat attachment files.
// Implementations: LocalAttachmentStorage (default) and R2AttachmentStorage (Cloudflare R2).
type AttachmentStorage interface {
	// Store saves a locally-staged file to the backing store and returns its public URL.
	// localPath is the path where the file has already been written to disk.
	// filename is the desired storage key / base filename.
	// mimeType is the content-type of the file.
	Store(ctx context.Context, localPath, filename, mimeType string) (publicURL string, err error)

	// IsRemote returns true when files are stored in remote object storage.
	// When true the caller is responsible for removing local staging files
	// after Store() succeeds.
	IsRemote() bool
}

// ─── Local storage ────────────────────────────────────────────────────────────

// LocalAttachmentStorage stores files on the local filesystem inside uploadDir.
// Files are already written to uploadDir by the handler before Store is called,
// so this implementation simply returns the public URL path.
type LocalAttachmentStorage struct {
	uploadDir string // absolute path, e.g. "data/uploads"
}

func NewLocalAttachmentStorage(uploadDir string) *LocalAttachmentStorage {
	return &LocalAttachmentStorage{uploadDir: uploadDir}
}

// Store returns the public URL for a file that is already in uploadDir.
func (s *LocalAttachmentStorage) Store(_ context.Context, _, filename, _ string) (string, error) {
	return "/uploads/" + filename, nil
}

func (s *LocalAttachmentStorage) IsRemote() bool { return false }

// ─── Cloudflare R2 storage ─────────────────────────────────────────────────

// R2AttachmentStorage uploads files to Cloudflare R2 (S3-compatible) and
// returns public URLs based on a configurable publicBase.
type R2AttachmentStorage struct {
	client     *s3.Client
	bucket     string
	publicBase string // e.g. "https://pub-xxxx.r2.dev" — no trailing slash
}

// NewR2AttachmentStorage creates an R2AttachmentStorage.
// accountID:   Cloudflare account ID
// accessKeyID: R2 access key ID
// secretKey:   R2 secret access key
// bucket:      R2 bucket name
// publicBase:  public URL base, e.g. "https://pub-xxxx.r2.dev" or a custom domain
func NewR2AttachmentStorage(accountID, accessKeyID, secretKey, bucket, publicBase string) (*R2AttachmentStorage, error) {
	if accountID == "" || accessKeyID == "" || secretKey == "" || bucket == "" || publicBase == "" {
		return nil, fmt.Errorf("storage: all Cloudflare R2 parameters are required")
	}

	endpoint := fmt.Sprintf("https://%s.r2.cloudflarestorage.com", accountID)
	creds := credentials.NewStaticCredentialsProvider(accessKeyID, secretKey, "")

	cfg := aws.Config{
		Region:      "auto",
		Credentials: creds,
	}
	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(endpoint)
		o.UsePathStyle = true
	})

	return &R2AttachmentStorage{
		client:     client,
		bucket:     bucket,
		publicBase: strings.TrimRight(publicBase, "/"),
	}, nil
}

// Store uploads the file at localPath to R2 and returns the public URL.
func (s *R2AttachmentStorage) Store(ctx context.Context, localPath, filename, mimeType string) (string, error) {
	f, err := os.Open(localPath)
	if err != nil {
		return "", fmt.Errorf("r2 open local file: %w", err)
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("r2 stat local file: %w", err)
	}

	_, err = s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(s.bucket),
		Key:           aws.String(filename),
		Body:          f,
		ContentLength: aws.Int64(stat.Size()),
		ContentType:   aws.String(mimeType),
	})
	if err != nil {
		return "", fmt.Errorf("r2 put object %q: %w", filename, err)
	}

	return s.publicBase + "/" + filename, nil
}

func (s *R2AttachmentStorage) IsRemote() bool { return true }


// ─── iosdist-svc local helpers ────────────────────────────────────────────

// newAttachmentStorage picks the right backend based on whether R2 is
// configured. iosdist-svc reads R2_* env vars directly (no dock Config
// dependency).
func newAttachmentStorage(uploadDir, r2AccountID, r2AccessKeyID, r2Secret, r2Bucket, r2PublicURL string) (AttachmentStorage, error) {
	if r2AccountID != "" && r2AccessKeyID != "" && r2Secret != "" && r2Bucket != "" && r2PublicURL != "" {
		return NewR2AttachmentStorage(r2AccountID, r2AccessKeyID, r2Secret, r2Bucket, r2PublicURL)
	}
	return NewLocalAttachmentStorage(uploadDir), nil
}

// removeLocalFile is a best-effort helper to delete a staging file.
func removeLocalFile(path string) {
	if path != "" {
		_ = os.Remove(path)
	}
}

// copyFile copies src → dst, creating dst.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return nil
}
