package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"

	"io/ioutil"

	"github.com/golang/glog"
	"golang.org/x/oauth2/google"

	storage "cloud.google.com/go/storage"
	cloudkms "google.golang.org/api/cloudkms/v1"
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage: example -stderrthreshold=[INFO|WARN|FATAL] -log_dir=[string]\n")
	flag.PrintDefaults()
	os.Exit(2)
}

func main() {

	projectId := flag.String("projectId", "your_project_id", "ProjectID")
	locationId := flag.String("locationId", "us-central1", "LocationID")
	secretToEncrypt := flag.String("secretToEncrypt", "secret_file.txt", "Filename/secretToEncrypt")
	serviceAccountToAccessSecret := flag.String("serviceAccountToAccessSecret", "svc-account-secret@PROJECT.iam.gserviceaccount.com", "service Account with access to secret")
	serviceAccountToAccessSecretKeyFile := flag.String("serviceAccountToAccessSecretKeyFile", "svc-account-secret.json", "Private Key file for serviceAccountToAccessSecret (used to decrypt secret as that account)")
	keyRingID := flag.String("keyRingID", "mykeyring", "KeyRing to use")
	cryptoKeyID := flag.String("cryptoKeyID", "key1", "Key to use")
	bucketName := flag.String("bucketName", "mybucket", "GCS Bucket to save encrypted secret")
	encryptedKeyFileName := flag.String("encryptedKeyFileName", "service_account.json.encrypted", "Encrypted Object Name")
	flag.Usage = usage
	flag.Parse()

	// Read the plaintext secret you want to encrypt and save
	// the encrypted form of this secret can be decrypted by `serviceAccountToAccessSecret`
	plainTextsecretToEncrypt, err := ioutil.ReadFile(*secretToEncrypt)
	if err != nil {
		glog.Fatal(err)
	}

	// now initialize KMS
	ctx := context.Background()

	kmsClient, err := google.DefaultClient(ctx, cloudkms.CloudPlatformScope)
	if err != nil {
		glog.Fatal(err)
	}
	kmsService, err := cloudkms.New(kmsClient)
	if err != nil {
		glog.Fatal(err)
	}

	parentName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s",
		*projectId, *locationId, *keyRingID, *cryptoKeyID)

	// Set IAM policy for the service account "serviceAccountToAccessSecret" to decrypt the secret using
	// that KMS key
	policy, err := kmsService.Projects.Locations.KeyRings.GetIamPolicy(parentName).Do()
	if err != nil {
		glog.Fatal(err)
	}

	policy.Bindings = append(policy.Bindings, &cloudkms.Binding{
		Role:    "roles/cloudkms.cryptoKeyDecrypter",
		Members: []string{"serviceAccount:" + *serviceAccountToAccessSecret},
	})
	if err != nil {
		glog.Fatal(err)
	}

	_, err = kmsService.Projects.Locations.KeyRings.SetIamPolicy(
		parentName, &cloudkms.SetIamPolicyRequest{Policy: policy}).Do()
	if err != nil {
		glog.Fatal(err)
	}

	// Encrypt the secret
	ereq := &cloudkms.EncryptRequest{
		Plaintext: base64.StdEncoding.EncodeToString([]byte(plainTextsecretToEncrypt)),
	}

	eresp, err := kmsService.Projects.Locations.KeyRings.CryptoKeys.Encrypt(parentName, ereq).Do()
	if err != nil {
		glog.Fatal(err)
	}

	encryptedSecret := eresp.Ciphertext

	glog.Infoln("============ Encrypted Secret ==============")
	glog.Infoln(encryptedSecret)

	/// ===========================  Write encrypted secret  to a gcs bucket
	storeageClient, err := storage.NewClient(ctx)
	if err != nil {
		glog.Fatal(err)
	}

	bkt := storeageClient.Bucket(*bucketName)
	obj := bkt.Object(*encryptedKeyFileName)

	wtr := obj.NewWriter(ctx)
	if _, err := fmt.Fprint(wtr, encryptedSecret); err != nil {
		glog.Fatal(err)
	}
	if err := wtr.Close(); err != nil {
		glog.Fatal(err)
	}

	os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", *serviceAccountToAccessSecretKeyFile)

	kmsClient, err = google.DefaultClient(ctx, cloudkms.CloudPlatformScope)
	if err != nil {
		glog.Fatal(err)
	}
	kmsService, err = cloudkms.New(kmsClient)
	if err != nil {
		glog.Fatal(err)
	}

	storeageClient, err = storage.NewClient(ctx)
	if err != nil {
		log.Fatal(err)
	}
	bkt = storeageClient.Bucket(*bucketName)
	obj = bkt.Object(*encryptedKeyFileName)
	r, err := obj.NewReader(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer r.Close()
	buf := new(bytes.Buffer)
	buf.ReadFrom(r)
	s := buf.String()

	parentName = fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s",
		*projectId, *locationId, *keyRingID, *cryptoKeyID)

	kmsClient, err = google.DefaultClient(ctx, cloudkms.CloudPlatformScope)
	if err != nil {
		log.Fatal(err)
	}
	kmsService, err = cloudkms.New(kmsClient)
	if err != nil {
		log.Fatal(err)
	}

	drq := &cloudkms.DecryptRequest{
		Ciphertext: s,
	}
	dresp, err := kmsService.Projects.Locations.KeyRings.CryptoKeys.Decrypt(parentName, drq).Do()
	if err != nil {
		log.Fatal(err)
	}

	plainText, err := base64.StdEncoding.DecodeString(dresp.Plaintext)
	if err != nil {
		glog.Fatalln(err)
	}

	glog.Infoln("============ Decrypted Secret ==============")
	glog.Infoln(string(plainText))
}
