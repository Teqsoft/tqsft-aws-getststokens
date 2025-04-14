package getawstokens

import (
	"context"
	"crypto/rsa"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/golang-jwt/jwt/v4"
)

type STSClient interface {
	AssumeRoleWithWebIdentity(ctx context.Context, params *sts.AssumeRoleWithWebIdentityInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error)
}

type AwsClientImpl struct {
	stsClient STSClient
}

type Credentials struct {
	AccessKeyID     *string
	SecretAccessKey *string
	SessionToken    *string
	Expires         *time.Time
}

// type AwsClientImpl struct {
// 	stsClient *sts.Client
// 	s3Client  *s3.Client
// 	creds     *aws.Credentials
// }

func NewAwsClient() *AwsClientImpl {
	return &AwsClientImpl{}
}

func (awsClient *AwsClientImpl) loadPrivateKeyWithString(privKeyBytes []byte) (*rsa.PrivateKey, error) {
	// Parseamos la clave privada
	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("loadPrivateKey(): Error parsing private key: %v", err)
	}

	return privKey, nil
}

func (awsClient *AwsClientImpl) loadPrivateKeyWithFile(file *os.File) (*rsa.PrivateKey, error) {
	// Aquí cargarías la clave privada RSA desde un archivo
	// Asumimos que la clave privada está en el archivo "private_key.pem"
	privKeyBytes, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("loadPrivateKey(): reading private key: %v", err)
	}

	privKey, err := awsClient.loadPrivateKeyWithString(privKeyBytes)
	if err != nil {
		return nil, err
	}
	return privKey, nil
}

// Función para crear un Web Identity Token (JWT) firmado con la clave privada
func (awsClient *AwsClientImpl) createWebIdentityToken(oidcProvider string, entity string, privKey *rsa.PrivateKey) (string, error) {
	// Crear los claims del token (información que incluirá el JWT)
	mapClaims := &jwt.RegisteredClaims{
		Issuer:    oidcProvider,                                      // Emisor del token
		Subject:   entity,                                            // El sujeto (puede ser un usuario o entidad)
		Audience:  []string{"sts.amazonaws.com"},                     // Público al que va dirigido
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)), // Expiración del token (1 hora)
		IssuedAt:  jwt.NewNumericDate(time.Now()),                    // Fecha de emisión
	}

	// Crear un nuevo token JWT utilizando la clave privada RSA
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, mapClaims)

	// Firmar el token con la clave privada RSA
	tokenString, err := token.SignedString(privKey)
	if err != nil {
		return "", fmt.Errorf("createWebIdentityToken(): error al firmar el token JWT, %v", err)
	}

	return tokenString, nil
}

func (awsClient *AwsClientImpl) assumeRoleWithWebIdentity(region string, roleArn string, sessionName string, token string) (*Credentials, error) {
	err := awsClient.getStsClient(region)

	if err != nil {
		log.Printf("assumeRoleWithWebIdentity(): error assuming role, %v", err)
		return nil, err
	}
	// Hacer la llamada AssumeRoleWithWebIdentity
	resp, err := awsClient.stsClient.AssumeRoleWithWebIdentity(context.TODO(), &sts.AssumeRoleWithWebIdentityInput{
		RoleArn:          &roleArn,
		RoleSessionName:  &sessionName,
		WebIdentityToken: &token,
	})

	if err != nil {
		log.Printf("assumeRoleWithWebIdentity(): error assuming role, %v", err)
		return nil, err
	}

	credentials := Credentials{
		AccessKeyID:     resp.Credentials.AccessKeyId,
		SecretAccessKey: resp.Credentials.SecretAccessKey,
		SessionToken:    resp.Credentials.SessionToken,
		Expires:         resp.Credentials.Expiration,
	}

	return &credentials, nil
}

func (awsClient *AwsClientImpl) getStsClient(region string) error {
	// Cargar la configuración predeterminada de AWS
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(region))
	if err != nil {
		log.Printf("getStstClient(); unable to load SDK config, %v", err)
		return err
	}

	// Crear un cliente STS
	stsClient := sts.NewFromConfig(cfg)

	awsClient.stsClient = stsClient

	return nil
}

func AssumeRoleWithWebIdentity(privateKey []byte, oidcEndpoint string, region string, roleArn string, sessionId string) (*Credentials, error) {
	// Cargar la clave privada RSA (asegúrate de tener el archivo de clave privado en el lugar correcto)
	instance := NewAwsClient()
	privKey, err := instance.loadPrivateKeyWithString(privateKey)
	if err != nil {
		log.Printf("Error loading private key, %v", err)
	}

	// Crear el Web Identity Token
	token, err := instance.createWebIdentityToken("https://"+oidcEndpoint+".s3."+region+".amazonaws.com", oidcEndpoint, privKey)
	if err != nil {
		log.Printf("Error creating Web Identity Token: %v", err)
	}

	// Asumir el rol con el Web Identity Token
	credendials, err := instance.assumeRoleWithWebIdentity(region, roleArn, sessionId, token)
	if err != nil {
		log.Printf("Error Assuming AWS Role: %v", err)
		return nil, err
	}

	return credendials, err
}

func AssumeRoleWithWebIdentityWithFile(privateKeyFile *os.File, oidcEndpoint string, region string, roleArn string, sessionId string) (*Credentials, error) {
	// Cargar la clave privada RSA (asegúrate de tener el archivo de clave privado en el lugar correcto)
	instance := NewAwsClient()
	privKey, err := instance.loadPrivateKeyWithFile(privateKeyFile)
	if err != nil {
		log.Printf("Error loading private key, %v", err)
	}

	// Crear el Web Identity Token
	token, err := instance.createWebIdentityToken("https://"+oidcEndpoint+".s3."+region+".amazonaws.com", oidcEndpoint, privKey)
	if err != nil {
		log.Printf("Error creating Web Identity Token: %v", err)
	}

	// Asumir el rol con el Web Identity Token
	credendials, err := instance.assumeRoleWithWebIdentity(region, roleArn, sessionId, token)
	if err != nil {
		log.Printf("Error Assuming AWS Role: %v", err)
		return nil, err
	}

	return credendials, err
}
