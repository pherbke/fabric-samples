package cuckoofilter

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

type VerifiableCredential struct {
	Context           []string          `json:"@context"`
	ID                string            `json:"id"`
	Type              []string          `json:"type"`
	Issuer            string            `json:"issuer"`
	IssuanceDate      time.Time         `json:"issuanceDate"`
	ExpirationDate    time.Time         `json:"expirationDate"`
	CredentialSubject CredentialSubject `json:"credentialSubject"`
	Proof             Proof             `json:"proof,omitempty"`
}

type CredentialSubject struct {
	ID       string `json:"id"`
	AlumniOf Alumni `json:"alumniOf"`
}

type Alumni struct {
	ID   string `json:"id"`
	Name []Name `json:"name"`
}

type Name struct {
	Value string `json:"value"`
	Lang  string `json:"lang"`
}

type Proof struct {
	Type               string    `json:"type"`
	Created            time.Time `json:"created"`
	ProofPurpose       string    `json:"proofPurpose"`
	VerificationMethod string    `json:"verificationMethod"`
	JWS                string    `json:"jws"`
}

// CreateAndSignCredential creates and signs a credential
func CreateAndSignCredential(issuerDID string, issuerPrivateKey *ecdsa.PrivateKey, subjectID string) (*VerifiableCredential, error) {
	// Create the credential
	credential := VerifiableCredential{
		Context: []string{
			"https://www.w3.org/2018/credentials/v1",
			"https://www.w3.org/2018/credentials/examples/v1",
		},
		ID:             "http://example.edu/credentials/1872",
		Type:           []string{"VerifiableCredential", "AlumniCredential"},
		Issuer:         issuerDID,
		IssuanceDate:   time.Now(),
		ExpirationDate: time.Now().AddDate(10, 0, 0),
		CredentialSubject: CredentialSubject{
			ID: subjectID,
			AlumniOf: Alumni{
				ID: "did:example:c276e12ec21ebfeb1f712ebc6f1",
				Name: []Name{
					{Value: "Example University", Lang: "en"},
					{Value: "Exemple d'Université", Lang: "fr"},
				},
			},
		},
	}

	// Sign the credential
	signedCredential, err := SignCredential(&credential, issuerPrivateKey)
	if err != nil {
		return nil, err
	}

	return signedCredential, nil
}

func CreateAndSignBatchCredential(issuerDID string, issuerPrivateKey *ecdsa.PrivateKey, subjectID string, credentialID string) (*VerifiableCredential, error) {
	// Create the credential
	credential := VerifiableCredential{
		Context: []string{
			"https://www.w3.org/2018/credentials/v1",
			"https://www.w3.org/2018/credentials/examples/v1",
		},
		ID:             "http://example.edu/credentials/1872" + credentialID,
		Type:           []string{"VerifiableCredential", "AlumniCredential"},
		Issuer:         issuerDID,
		IssuanceDate:   time.Now(),
		ExpirationDate: time.Now().AddDate(10, 0, 0),
		CredentialSubject: CredentialSubject{
			ID: subjectID,
			AlumniOf: Alumni{
				ID: "did:example:c276e12ec21ebfeb1f712ebc6f1",
				Name: []Name{
					{Value: "Example University", Lang: "en"},
					{Value: "Exemple d'Université", Lang: "fr"},
				},
			},
		},
	}

	// Sign the credential
	signedCredential, err := SignCredential(&credential, issuerPrivateKey)
	if err != nil {
		return nil, err
	}
	return signedCredential, nil
}

// SignCredential signs the credential and returns it
func SignCredential(credential *VerifiableCredential, privateKey *ecdsa.PrivateKey) (*VerifiableCredential, error) {
	// Serialize the credential excluding the Proof
	credentialCopy := *credential
	credentialCopy.Proof = Proof{} // Exclude the Proof for signing
	data, err := json.Marshal(credentialCopy)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal credential: %v", err)
	}

	// Hash the serialized data
	hash := sha256.Sum256(data)

	// Sign the hash
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign credential: %v", err)
	}

	// Convert the signature to a format suitable for JSON encoding
	signature := append(r.Bytes(), s.Bytes()...)
	encodedSignature := base64.StdEncoding.EncodeToString(signature)

	// Add the proof to the credential
	credential.Proof = Proof{
		Type:               "EcdsaSecp256k1VerificationKey2019",
		Created:            time.Now(),
		ProofPurpose:       "assertionMethod",
		VerificationMethod: "https://example.edu/issuers/565049#keys-1",
		JWS:                encodedSignature,
	}

	return credential, nil
}
