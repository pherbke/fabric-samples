package mocks

import (
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-protos-go/peer"
	"github.com/stretchr/testify/mock"
)

// MockChaincodeStubInterface is a mock of ChaincodeStubInterface
type MockChaincodeStubInterface struct {
	mock.Mock
}

// GetArgsSlice mocks the GetArgsSlice method
func (m *MockChaincodeStubInterface) GetArgsSlice() ([]byte, error) {
	args := m.Called()
	return args.Get(0).([]byte), args.Error(1)
}

// GetArgs mocks the GetArgs method
func (m *MockChaincodeStubInterface) GetArgs() [][]byte {
	args := m.Called()
	return args.Get(0).([][]byte)
}

// GetStringArgs mocks the GetStringArgs method
func (m *MockChaincodeStubInterface) GetStringArgs() []string {
	args := m.Called()
	return args.Get(0).([]string)
}

// GetFunctionAndParameters mocks the GetFunctionAndParameters method
func (m *MockChaincodeStubInterface) GetFunctionAndParameters() (string, []string) {
	args := m.Called()
	return args.String(0), args.Get(1).([]string)
}

// GetTxID mocks the GetTxID method
func (m *MockChaincodeStubInterface) GetTxID() string {
	args := m.Called()
	return args.String(0)
}

// GetChannelID mocks the GetChannelID method
func (m *MockChaincodeStubInterface) GetChannelID() string {
	args := m.Called()
	return args.String(0)
}

// GetState mocks the GetState method
func (m *MockChaincodeStubInterface) GetState(key string) ([]byte, error) {
	args := m.Called(key)
	return args.Get(0).([]byte), args.Error(1)
}

// PutState mocks the PutState method
func (m *MockChaincodeStubInterface) PutState(key string, value []byte) error {
	args := m.Called(key, value)
	return args.Error(0)
}

// DelState mocks the DelState method
func (m *MockChaincodeStubInterface) DelState(key string) error {
	args := m.Called(key)
	return args.Error(0)
}

// SetEvent mocks the SetEvent method
func (m *MockChaincodeStubInterface) SetEvent(name string, payload []byte) error {
	args := m.Called(name, payload)
	return args.Error(0)
}

// InvokeChaincode mocks the InvokeChaincode method
func (m *MockChaincodeStubInterface) InvokeChaincode(chaincodeName string, args [][]byte, channel string) peer.Response {
	mockArgs := m.Called(chaincodeName, args, channel) // Renamed variable to mockArgs
	return mockArgs.Get(0).(peer.Response)             // Using mockArgs here
}

// GetStateByRange mocks the GetStateByRange method
func (m *MockChaincodeStubInterface) GetStateByRange(startKey, endKey string) (shim.StateQueryIteratorInterface, error) {
	args := m.Called(startKey, endKey)
	return args.Get(0).(shim.StateQueryIteratorInterface), args.Error(1)
}

// CreateCompositeKey mocks the CreateCompositeKey method
func (m *MockChaincodeStubInterface) CreateCompositeKey(objectType string, attributes []string) (string, error) {
	args := m.Called(objectType, attributes)
	return args.String(0), args.Error(1)
}

// SplitCompositeKey mocks the SplitCompositeKey method
func (m *MockChaincodeStubInterface) SplitCompositeKey(compositeKey string) (string, []string, error) {
	args := m.Called(compositeKey)
	return args.String(0), args.Get(1).([]string), args.Error(2)
}

// GetQueryResult mocks the GetQueryResult method
func (m *MockChaincodeStubInterface) GetQueryResult(query string) (shim.StateQueryIteratorInterface, error) {
	args := m.Called(query)
	return args.Get(0).(shim.StateQueryIteratorInterface), args.Error(1)
}

// GetHistoryForKey mocks the GetHistoryForKey method
func (m *MockChaincodeStubInterface) GetHistoryForKey(key string) (shim.HistoryQueryIteratorInterface, error) {
	args := m.Called(key)
	return args.Get(0).(shim.HistoryQueryIteratorInterface), args.Error(1)
}

// SetStateValidationParameter mocks the SetStateValidationParameter method
func (m *MockChaincodeStubInterface) SetStateValidationParameter(key string, ep []byte) error {
	args := m.Called(key, ep)
	return args.Error(0)
}

// GetStateValidationParameter mocks the GetStateValidationParameter method
func (m *MockChaincodeStubInterface) GetStateValidationParameter(key string) ([]byte, error) {
	args := m.Called(key)
	return args.Get(0).([]byte), args.Error(1)
}

// GetStateByRangeWithPagination mocks the GetStateByRangeWithPagination method
func (m *MockChaincodeStubInterface) GetStateByRangeWithPagination(startKey string, endKey string, pageSize int32, bookmark string) (shim.StateQueryIteratorInterface, *peer.QueryResponseMetadata, error) {
	args := m.Called(startKey, endKey, pageSize, bookmark)
	return args.Get(0).(shim.StateQueryIteratorInterface), args.Get(1).(*peer.QueryResponseMetadata), args.Error(2)
}

// GetStateByPartialCompositeKey mocks the GetStateByPartialCompositeKey method
func (m *MockChaincodeStubInterface) GetStateByPartialCompositeKey(objectType string, keys []string) (shim.StateQueryIteratorInterface, error) {
	args := m.Called(objectType, keys)
	return args.Get(0).(shim.StateQueryIteratorInterface), args.Error(1)
}

// GetStateByPartialCompositeKeyWithPagination mocks the GetStateByPartialCompositeKeyWithPagination method
func (m *MockChaincodeStubInterface) GetStateByPartialCompositeKeyWithPagination(objectType string, keys []string, pageSize int32, bookmark string) (shim.StateQueryIteratorInterface, *peer.QueryResponseMetadata, error) {
	args := m.Called(objectType, keys, pageSize, bookmark)
	return args.Get(0).(shim.StateQueryIteratorInterface), args.Get(1).(*peer.QueryResponseMetadata), args.Error(2)
}

// GetQueryResultWithPagination mocks the GetQueryResultWithPagination method
func (m *MockChaincodeStubInterface) GetQueryResultWithPagination(query string, pageSize int32, bookmark string) (shim.StateQueryIteratorInterface, *peer.QueryResponseMetadata, error) {
	args := m.Called(query, pageSize, bookmark)
	return args.Get(0).(shim.StateQueryIteratorInterface), args.Get(1).(*peer.QueryResponseMetadata), args.Error(2)
}

// GetPrivateData mocks the GetPrivateData method
func (m *MockChaincodeStubInterface) GetPrivateData(collection string, key string) ([]byte, error) {
	args := m.Called(collection, key)
	return args.Get(0).([]byte), args.Error(1)
}

// GetPrivateDataHash mocks the GetPrivateDataHash method
func (m *MockChaincodeStubInterface) GetPrivateDataHash(collection string, key string) ([]byte, error) {
	args := m.Called(collection, key)
	return args.Get(0).([]byte), args.Error(1)
}

// PutPrivateData mocks the PutPrivateData method
func (m *MockChaincodeStubInterface) PutPrivateData(collection string, key string, value []byte) error {
	args := m.Called(collection, key, value)
	return args.Error(0)
}

// DelPrivateData mocks the DelPrivateData method
func (m *MockChaincodeStubInterface) DelPrivateData(collection string, key string) error {
	args := m.Called(collection, key)
	return args.Error(0)
}

// PurgePrivateData mocks the PurgePrivateData method (if applicable)
func (m *MockChaincodeStubInterface) PurgePrivateData(collection string, key string) error {
	args := m.Called(collection, key)
	return args.Error(0)
}

// SetPrivateDataValidationParameter mocks the SetPrivateDataValidationParameter method
func (m *MockChaincodeStubInterface) SetPrivateDataValidationParameter(collection string, key string, ep []byte) error {
	args := m.Called(collection, key, ep)
	return args.Error(0)
}

// GetPrivateDataValidationParameter mocks the GetPrivateDataValidationParameter method
func (m *MockChaincodeStubInterface) GetPrivateDataValidationParameter(collection string, key string) ([]byte, error) {
	args := m.Called(collection, key)
	return args.Get(0).([]byte), args.Error(1)
}

// GetPrivateDataByRange mocks the GetPrivateDataByRange method
func (m *MockChaincodeStubInterface) GetPrivateDataByRange(collection string, startKey string, endKey string) (shim.StateQueryIteratorInterface, error) {
	args := m.Called(collection, startKey, endKey)
	return args.Get(0).(shim.StateQueryIteratorInterface), args.Error(1)
}

// GetPrivateDataByPartialCompositeKey mocks the GetPrivateDataByPartialCompositeKey method
func (m *MockChaincodeStubInterface) GetPrivateDataByPartialCompositeKey(collection string, objectType string, keys []string) (shim.StateQueryIteratorInterface, error) {
	args := m.Called(collection, objectType, keys)
	return args.Get(0).(shim.StateQueryIteratorInterface), args.Error(1)
}

// GetPrivateDataQueryResult mocks the GetPrivateDataQueryResult method
func (m *MockChaincodeStubInterface) GetPrivateDataQueryResult(collection string, query string) (shim.StateQueryIteratorInterface, error) {
	args := m.Called(collection, query)
	return args.Get(0).(shim.StateQueryIteratorInterface), args.Error(1)
}

// GetCreator mocks the GetCreator method
func (m *MockChaincodeStubInterface) GetCreator() ([]byte, error) {
	args := m.Called()
	return args.Get(0).([]byte), args.Error(1)
}

// GetTransient mocks the GetTransient method
func (m *MockChaincodeStubInterface) GetTransient() (map[string][]byte, error) {
	args := m.Called()
	return args.Get(0).(map[string][]byte), args.Error(1)
}

// GetBinding mocks the GetBinding method
func (m *MockChaincodeStubInterface) GetBinding() ([]byte, error) {
	args := m.Called()
	return args.Get(0).([]byte), args.Error(1)
}

// GetDecorations mocks the GetDecorations method
func (m *MockChaincodeStubInterface) GetDecorations() map[string][]byte {
	args := m.Called()
	return args.Get(0).(map[string][]byte)
}

// GetSignedProposal mocks the GetSignedProposal method
func (m *MockChaincodeStubInterface) GetSignedProposal() (*peer.SignedProposal, error) {
	args := m.Called()
	return args.Get(0).(*peer.SignedProposal), args.Error(1)
}

// GetTxTimestamp mocks the GetTxTimestamp method
func (m *MockChaincodeStubInterface) GetTxTimestamp() (*timestamp.Timestamp, error) {
	args := m.Called()
	return args.Get(0).(*timestamp.Timestamp), args.Error(1)
}
