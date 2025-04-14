package main

import (
	"bufio"
	"fmt"
	"log"
	"main/getawstokens"
	"os"

	"github.com/alecthomas/kingpin/v2"
)

var (
	privateKeyFile = kingpin.Flag("private-key-file", "Sets the private key file used to sign the JWT token").Short('f').File()
	privateKey     = kingpin.Flag("private-key", "Sets the private key used to sign the JWT token").Short('k').Envar("PRIVATE_KEY").String()
	region         = kingpin.Flag("region", "AWS Region to be used").Short('r').Envar("AWS_REGION").String()
	oidcEndpoint   = kingpin.Flag("endpoint", "Open Id Endpoint to be used").Short('e').Envar("OIDC_ENDPOINT").String()
	roleArn        = kingpin.Flag("role-arn", "Role ARN to assume").Short('a').Envar("AWS_ROLE_ARN").String()
	sessionId      = kingpin.Flag("session-id", "AWS Session Id").Short('s').Envar("AWS_SESSION_ID").String()
	outputFile     = kingpin.Flag("output-file", "").Short('o').String()
	stdout         = kingpin.Flag("stdout", "").Bool()
)

func main() {
	kingpin.Parse()
	var (
		err         error
		credentials *getawstokens.Credentials
	)

	if privateKey != nil && len(*privateKey) > 0 {
		credentials, err = getawstokens.AssumeRoleWithWebIdentity([]byte(*privateKey), *oidcEndpoint, *region, *roleArn, *sessionId)
	} else if privateKeyFile != nil {
		credentials, err = getawstokens.AssumeRoleWithWebIdentityWithFile(*privateKeyFile, *oidcEndpoint, *region, *roleArn, *sessionId)
	} else {
		log.Printf("You should set Private Key with -f or -k Arguments")
		return
	}

	if err != nil {
		log.Printf("Error assuming aws role, %v", err)
		return
	}

	if *stdout {
		fmt.Printf("AccessKeyId: %s\n", *credentials.AccessKeyID)
		fmt.Printf("SecretAccessKey: %s\n", *credentials.SecretAccessKey)
		fmt.Printf("SessionToken: %s\n", *credentials.SessionToken)
	} else {
		outFile, err := os.Create(*outputFile)
		if err != nil {
			log.Fatalf("Error creating file, %v", err)
			return
		}
		defer outFile.Close()

		writer := bufio.NewWriter(outFile)
		fmt.Fprint(writer, "[default]\n")
		fmt.Fprintf(writer, "aws_access_key_id = %s\n", *credentials.AccessKeyID)
		fmt.Fprintf(writer, "aws_secret_access_key = %s\n", *credentials.SecretAccessKey)
		fmt.Fprintf(writer, "aws_session_token = %s\n", *credentials.SessionToken)

		err = writer.Flush()
		if err != nil {
			log.Fatalf("Error writing file %v", err)
			return
		}
	}

}
