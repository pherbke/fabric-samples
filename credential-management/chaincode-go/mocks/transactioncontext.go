package mocks

import (
	"github.com/hyperledger/fabric-chaincode-go/pkg/cid"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/stretchr/testify/mock"
)

// MockTransactionContext is a mock of TransactionContextInterface
type MockTransactionContext struct {
	mock.Mock
	Stub *MockChaincodeStubInterface
}

// NewMockTransactionContext creates a new instance of MockTransactionContext
func NewMockTransactionContext() *MockTransactionContext {
	return &MockTransactionContext{
		Stub: new(MockChaincodeStubInterface),
	}
}

// GetStub returns the mocked ChaincodeStubInterface
func (m *MockTransactionContext) GetStub() shim.ChaincodeStubInterface {
	m.Called()
	return m.Stub
}

// SetStub sets the ChaincodeStubInterface for the transaction context
func (m *MockTransactionContext) SetStub(stub shim.ChaincodeStubInterface) {
	if mockStub, ok := stub.(*MockChaincodeStubInterface); ok {
		m.Stub = mockStub
	}
}

// GetClientIdentity mocks the GetClientIdentity method
func (m *MockTransactionContext) GetClientIdentity() cid.ClientIdentity {
	args := m.Called()
	return args.Get(0).(cid.ClientIdentity)
}

// Add other methods and properties as needed
