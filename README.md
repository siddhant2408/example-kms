# example-kms
The package provides an example how to encrypt a secret file and store it in GCP using KMS, then decrypt and get the file contents

## Init ##

**Export the following variables**

```
export PROJECT_ID=project-id
export KMS_KEYRING=keyring
export KMS_KEY=key
export KMS_LOCATION=location

export SERVICE_ACCOUNT_A=service-account
export SERVICE_ACCOUNT_A_EMAIL=email
export SERVICE_ACCOUNT_A_KEY=path/to/service-account.json

export BUCKET_NAME=bucket-name
export GOOGLE_APPLICATION_CREDENTIALS=path/to/service-account.json

```

## Execute ##

```
go run main.go  -stderrthreshold=INFO \
          -projectId=$PROJECT_ID \
          -locationId=$KMS_LOCATION \
          -secretToEncrypt=secret_file.txt \
          -serviceAccountToAccessSecret=$SERVICE_ACCOUNT_A_EMAIL \
          -serviceAccountToAccessSecretKeyFile=$SERVICE_ACCOUNT_A_KEY \
          -keyRingID=$KMS_KEYRING \
          -cryptoKeyID=$KMS_KEY \
          -bucketName=$BUCKET_NAME \
          -encryptedKeyFileName=secret_file.encrypted
```
