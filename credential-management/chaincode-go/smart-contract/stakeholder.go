package cuckoofilter

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	"github.com/multiformats/go-multibase"
	"math/big"
	"os"
	"time"
)

// StakeholderManagementContract struct for handling stakeholder-related transactions
type StakeholderManagementContract struct {
	contractapi.Contract
}

// DIDResponse is a response structure for GenerateDID function
type DIDResponse struct {
	DID        string `json:"did"`
	PrivateKey string `json:"privateKey"`
}

// GenerateDID creates a new decentralized identifier (DID) and associated private key
func (s *StakeholderManagementContract) GenerateDID(ctx contractapi.TransactionContextInterface, role string) (*DIDResponse, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("error generating key: %v", err)
	}

	// Serialize the public key X and Y coordinates
	publicKeyBytes, err := json.Marshal(struct {
		X, Y *big.Int
	}{X: privateKey.PublicKey.X, Y: privateKey.PublicKey.Y})
	if err != nil {
		return nil, fmt.Errorf("error marshalling public key: %v", err)
	}
	publicKeyString := base64.StdEncoding.EncodeToString(publicKeyBytes)

	// Prepend the Multicodec identifier for P-256
	multicodecValue := []byte{0x12, 0x00}
	combinedBytes := append(multicodecValue, privateKey.PublicKey.X.Bytes()...)
	combinedBytes = append(combinedBytes, privateKey.PublicKey.Y.Bytes()...)

	// Encode with Multibase (base58-btc)
	encodedValue, err := multibase.Encode(multibase.Base58BTC, combinedBytes)
	if err != nil {
		return nil, fmt.Errorf("error encoding public key: %v", err)
	}

	did := "did:key:" + encodedValue

	// Encode the private key as well
	privateKeyBytes, err := json.Marshal(privateKey)
	if err != nil {
		return nil, fmt.Errorf("error marshalling private key: %v", err)
	}
	privateKeyString := base64.StdEncoding.EncodeToString(privateKeyBytes)

	// Determine the filename based on the role
	var filename string
	switch role {
	case "issuer":
		filename = "./keys/issuer_keys.json"
	case "holder":
		filename = "./keys/holder_keys.json"
	case "verifier":
		filename = "./keys/verifier_keys.json"
	default:
		return nil, fmt.Errorf("invalid role: %v", role)
	}

	// Create a map to hold the DID, public key, and private key
	keyData := map[string]string{
		"DID":        did,
		"PrivateKey": privateKeyString,
		"PublicKey":  publicKeyString,
	}

	// Convert the map to JSON
	keyDataJSON, err := json.Marshal(keyData)
	if err != nil {
		return nil, fmt.Errorf("error marshalling key data: %v", err)
	}

	// Write the JSON data to the file
	err = os.WriteFile(filename, keyDataJSON, 0600)
	if err != nil {
		return nil, fmt.Errorf("error writing key data to file: %v", err)
	}

	return &DIDResponse{
		DID:        did,
		PrivateKey: privateKeyString,
	}, nil
}

// IssuingCredential creates and signs a new credential
func (s *StakeholderManagementContract) IssuingCredential(ctx contractapi.TransactionContextInterface, issuerDID string, holderDID string) (*VerifiableCredential, error) {
	// Load the issuer's private key from the ledger
	privateKey, err := s.loadPrivateKey(ctx, "issuer", issuerDID)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %v", err)
	}

	// Create and sign the credential
	credential, err := CreateAndSignCredential(issuerDID, privateKey, holderDID)
	if err != nil {
		return nil, fmt.Errorf("failed to create and sign credential: %v", err)
	}

	// Convert the credential to a JWT
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"credential": credential,
	})

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign JWT: %v", err)
	}

	// Issuer stores issued credential in a file (Simulation)
	filenameIssuer := "./issuedCredentials/" + holderDID + ".jwt"
	err = os.WriteFile(filenameIssuer, []byte(tokenString), 0600)
	if err != nil {
		return nil, fmt.Errorf("error writing JWT to file: %v", err)
	}

	// Holder stores issued credential in a file as well (Simulation)
	filenameHolder := "./holderCredentials/" + holderDID + ".jwt"
	err = os.WriteFile(filenameHolder, []byte(tokenString), 0600)
	if err != nil {
		return nil, fmt.Errorf("error writing JWT to file: %v", err)
	}

	return credential, nil
}

// VerifyingCredential verifies the signature of a given credential
func (s *StakeholderManagementContract) VerifyingCredential(ctx contractapi.TransactionContextInterface, jwtString string, role string, holderDID string, issuerDID string) (bool, error) {
	// Determine the filename based on the role
	if jwtString == "" {
		var filename string
		switch role {
		case "issuer":
			filename = "./issuedCredentials/" + holderDID + ".jwt"
		case "holder":
			filename = "./holderCredentials/" + holderDID + ".jwt"
		case "verifier":
			filename = "./holderCredentials/" + holderDID + ".jwt"
		default:
			return false, fmt.Errorf("invalid role: %v", role)
		}

		// Read the JWT from the file
		jwtBytes, err := os.ReadFile(filename)
		if err != nil {
			return false, fmt.Errorf("error reading JWT from file: %v", err)
		}
		jwtString = string(jwtBytes)
	}

	// Parse the JWT
	token, err := jwt.Parse(jwtString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Load the issuer's public key from the ledger (folder ./keys/issuer_keys.json)
		publicKey, err := s.loadPublicKey(ctx, "issuer", issuerDID)
		if err != nil {
			return nil, fmt.Errorf("failed to load public key: %v", err)
		}

		return publicKey, nil
	})

	if err != nil {
		return false, fmt.Errorf("error parsing JWT: %v", err)
	}

	// Check if the token is valid
	if !token.Valid {
		return false, fmt.Errorf("JWT is not valid")
	}

	// Get the credential from the JWT
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return false, fmt.Errorf("failed to get claims from JWT")
	}

	credential, ok := claims["credential"].(map[string]interface{})
	if !ok {
		return false, fmt.Errorf("failed to get credential from claims")
	}

	// Check the credential fields
	issuer, ok := credential["issuer"].(string)
	if !ok {
		return false, fmt.Errorf("credential issuer is not a string")
	}

	if issuer != issuerDID {
		return false, fmt.Errorf("credential issuer does not match role")
	}

	credentialSubject, ok := credential["credentialSubject"].(map[string]interface{})
	if !ok {
		return false, fmt.Errorf("credential subject is not present")
	}

	subjectID, ok := credentialSubject["id"].(string)
	if !ok {
		return false, fmt.Errorf("credential subject ID is not present")
	}

	if subjectID != holderDID {
		return false, fmt.Errorf("credential subject ID does not match holderDID")
	}

	expirationDateString, ok := credential["expirationDate"].(string)
	if !ok {
		return false, fmt.Errorf("credential expiration date is not present")
	}

	expirationDate, err := time.Parse(time.RFC3339, expirationDateString)
	if err != nil {
		return false, fmt.Errorf("expiration date is not a valid time.Time")
	}

	if expirationDate.Before(time.Now()) {
		return false, fmt.Errorf("credential is expired")
	}
	fmt.Println("Credential is valid ", jwtString[0:10])
	return true, nil
}

// loadPrivateKey loads the private key of the role from the ledger
func (s *StakeholderManagementContract) loadPrivateKey(ctx contractapi.TransactionContextInterface, role string, did string) (*ecdsa.PrivateKey, error) {
	// Determine the filename based on the role
	filename := "./keys/" + role + "_keys.json"

	// Read the JSON file
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	// Decode the JSON file
	keyData := make(map[string]string)
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JSON: %v", err)
	}

	// Check if the DID matches
	if keyData["DID"] != did {
		return nil, fmt.Errorf("DID does not match")
	}

	// Get the private key string
	privateKeyString, ok := keyData["PrivateKey"]
	if !ok {
		return nil, fmt.Errorf("private key not found in JSON")
	}

	// Base64 decode the private key string
	privateKeyBytes, err := base64.StdEncoding.DecodeString(privateKeyString)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 private key: %v", err)
	}

	// Define a temporary struct to unmarshal the private key
	type tempPrivateKey struct {
		D *big.Int
		X *big.Int
		Y *big.Int
	}

	// Unmarshal the private key into the temporary struct
	var tempKey tempPrivateKey
	err = json.Unmarshal(privateKeyBytes, &tempKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal private key: %v", err)
	}

	// Create a new ecdsa.PrivateKey and manually set the Curve field
	privateKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     tempKey.X,
			Y:     tempKey.Y,
		},
		D: tempKey.D,
	}

	return privateKey, nil
}

// loadPublicKey loads the public key of the role from the ledger
func (s *StakeholderManagementContract) loadPublicKey(ctx contractapi.TransactionContextInterface, role string, did string) (*ecdsa.PublicKey, error) {
	// Determine the filename based on the role
	filename := "./keys/" + role + "_keys.json"

	// Read the JSON file
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	// Decode the JSON file
	keyData := make(map[string]string)
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JSON: %v", err)
	}

	// Get the public key string
	publicKeyString, ok := keyData["PublicKey"]
	if !ok {
		return nil, fmt.Errorf("public key not found in JSON")
	}

	// Decode the public key string
	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyString)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 public key: %v", err)
	}

	// Define a temporary struct to unmarshal the public key
	type tempPublicKey struct {
		X *big.Int
		Y *big.Int
	}

	// Unmarshal the public key into the temporary struct
	var tempKey tempPublicKey
	err = json.Unmarshal(publicKeyBytes, &tempKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal public key: %v", err)
	}

	// Create a new ecdsa.PublicKey and manually set the Curve field
	publicKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     tempKey.X,
		Y:     tempKey.Y,
	}

	return publicKey, nil
}

// TODO: DEPLOYMENT TO HL FABRIC
