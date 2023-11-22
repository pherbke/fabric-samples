package cuckoofilter_test

import (
	"encoding/base64"
	"github.com/multiformats/go-multibase"
	"github.com/pherbke/credential-management/chaincode-go/mocks"
	stakeholder "github.com/pherbke/credential-management/chaincode-go/smart-contract"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func TestGenerateDID(t *testing.T) {
	contract := new(stakeholder.StakeholderManagementContract)
	mockCtx := new(mocks.MockTransactionContext)

	// Call the GenerateDID function
	didResponse, err := contract.GenerateDID(mockCtx, "issuer")

	// Assert no error was returned
	require.NoError(t, err, "GenerateDID should not return an error")

	// Assert the DID response is not nil
	require.NotNil(t, didResponse, "GenerateDID should return a DID response")

	// Assert the DID and Private Key are not empty
	require.NotEmpty(t, didResponse.DID, "DID should not be empty")
	require.NotEmpty(t, didResponse.PrivateKey, "Private key should not be empty")

	// Extract the base58 encoded part of the DID
	encodedPart := strings.TrimPrefix(didResponse.DID, "did:key:")
	t.Logf("Encoded part of DID: %s", encodedPart)

	// Decode the encoded part from base58
	encoding, decoded, err := multibase.Decode(encodedPart)
	require.NoError(t, err, "Encoded part of DID should be in valid base58 encoding")
	require.Equal(t, int32(multibase.Base58BTC), int32(encoding), "Encoded part should use base58-btc encoding")

	// Verify the Multicodec identifier for P-256 (0x1200)
	require.GreaterOrEqual(t, len(decoded), 2, "Decoded data should be at least 2 bytes long")
	require.Equal(t, byte(0x12), decoded[0], "First byte should match the Multicodec identifier")
	require.Equal(t, byte(0x00), decoded[1], "Second byte should match the Multicodec identifier")

	// Check if the Private Key is in valid base64 encoding
	_, err = base64.StdEncoding.DecodeString(didResponse.PrivateKey)
	require.NoError(t, err, "Private key should be in valid base64 encoding")
}

// Tst issuing credential from issuer to subject (holder)
// test if the credential is signed by issuer
// test if the credential is valid
// test if the credential is stored in the ledger
// test if the credential is stored in the wallet

func TestCredentialLifecycle(t *testing.T) {
	contract := new(stakeholder.StakeholderManagementContract)
	mockCtx := new(mocks.MockTransactionContext)

	// Generate a DID for the issuer
	issuerDIDResponse, err := contract.GenerateDID(mockCtx, "issuer")
	require.NoError(t, err, "GenerateDID should not return an error for issuer")
	require.NotNil(t, issuerDIDResponse, "GenerateDID should return a DID response for issuer")

	// Generate a DID for the holder
	holderDIDResponse, err := contract.GenerateDID(mockCtx, "holder")
	require.NoError(t, err, "GenerateDID should not return an error for holder")
	require.NotNil(t, holderDIDResponse, "GenerateDID should return a DID response for holder")

	// Generate a DID for the verifier
	verifierDIDResponse, err := contract.GenerateDID(mockCtx, "verifier")
	require.NoError(t, err, "GenerateDID should not return an error for verifier")
	require.NotNil(t, verifierDIDResponse, "GenerateDID should return a DID response for verifier")

	// Issue a credential from the issuer to the holder
	credential, err := contract.IssuingCredential(mockCtx, issuerDIDResponse.DID, holderDIDResponse.DID)
	require.NoError(t, err, "IssuingCredential should not return an error")
	require.NotNil(t, credential, "IssuingCredential should return a credential")

	// TODO: Revoke credential from holder, pass filter to tests for revocation, verif

	// Verify the credential from the issuer's perspective
	isValid, err := contract.VerifyingCredential(mockCtx, "", "issuer", holderDIDResponse.DID, issuerDIDResponse.DID)
	require.NoError(t, err, "VerifyingCredential should not return an error")
	require.True(t, isValid, "VerifyingCredential should return true for a valid credential")

	// Verify the credential from the holder's perspective
	isValid, err = contract.VerifyingCredential(mockCtx, "", "holder", holderDIDResponse.DID, issuerDIDResponse.DID)
	require.NoError(t, err, "VerifyingCredential should not return an error")
	require.True(t, isValid, "VerifyingCredential should return true for a valid credential")

	// Verify the credential from the verifier's perspective
	isValid, err = contract.VerifyingCredential(mockCtx, "", "verifier", holderDIDResponse.DID, issuerDIDResponse.DID)
	require.NoError(t, err, "VerifyingCredential should not return an error")
	require.True(t, isValid, "VerifyingCredential should return true for a valid credential")

	// Verify credential content and signature and check if the credential is revoked or not

	// Revoke credential from holder and verify if the credential is revoked or not

	// Verify credential content and signature and check if the credential is revoked or not
}
