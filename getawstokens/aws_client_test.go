package getawstokens

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetStsClient(t *testing.T) {
	instance := NewAwsClient()

	err := instance.getStsClient("us-east-1")
	if err != nil {
		fmt.Printf("Error: %v", err)
	}

	assert.NotNil(t, instance.stsClient)
}

func TestAssumeRoleWithWebIdentity(t *testing.T) {
	instance := NewAwsClient()

	// Cargar la clave privada RSA (asegúrate de tener el archivo de clave privado en el lugar correcto)
	privKey, err := instance.loadPrivateKeyWithString([]byte("/Users/rramirez/Documents/git-tqsft/tqsft-aws-irsa/oidc/sa-signer.key"))
	if err != nil {
		fmt.Printf("Error al cargar la llave privada: %v", err)
	}

	// Crear el Web Identity Token
	token, err := instance.createWebIdentityToken("https://oidc-irsa-wkitwzav.s3.us-east-1.amazonaws.com", "irsa-oidc-wkitwzav", privKey)
	if err != nil {
		fmt.Printf("Error al crear el Web Identity Token: %v", err)
	}

	// Asumir el rol con el Web Identity Token
	credentials, err := instance.assumeRoleWithWebIdentity("us-east-1", "arn:aws:iam::680104390282:role/irsaOidcRole", "ExampleSession", token)
	if err != nil {
		fmt.Printf("Error al asumir el rol: %v", err)
	}
	assert.NotNil(t, credentials)

}
