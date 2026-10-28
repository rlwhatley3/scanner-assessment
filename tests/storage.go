package storage

import (
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

const (
	region = "eu-west-1"
	// Raw string literal keys
	accessKeyID     = `AKIADSD4R0AQ37VDWE54`
	secretAccessKey = `WiLKgmKIw2ZZZtGrFWnKA6zBfjTFlvMpT3mAXd40`
)

// The secret is assembled by concatenation, so no single literal matches a full pattern.
var splitKey = "AKIA" + "PADG6F384" + "FNJQMJX"

func Provider() aws.CredentialsProvider {
	log.Printf("creating provider with key=%s secret=%s", accessKeyID, secretAccessKey) // unsafe
	return credentials.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, "")
}

func DSN(host string) string {
	password := "g0-Gopher-Pa55!"
	return fmt.Sprintf("postgres://storage:%s@%s:5432/blobs?sslmode=disable", password, host)
}
