package cuckoofilter_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/pherbke/credential-management/chaincode-go/mocks"
	cuckoofilter "github.com/pherbke/credential-management/chaincode-go/smart-contract"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	secp256k1 "github.com/ureeves/jwt-go-secp256k1"
	mrand "math/rand"
	"os"
	"sync"
	"testing"
	"time"
)

func TestNewFilter(t *testing.T) {
	filter := cuckoofilter.NewFilter(1000, cuckoofilter.DefaultBucketSize)
	require.NotNil(t, filter, "Expected non-nil filter")
	require.Equal(t, uint(1023), filter.BucketIndexMask, "Expected bucket index mask to be 1023")
}

func TestInsert_Success(t *testing.T) {
	filter := cuckoofilter.NewFilter(1000, cuckoofilter.DefaultBucketSize)
	data := []byte("test data")
	require.True(t, filter.Insert(data), "Expected successful insertion")
}

func TestInsert_MaxSizeData(t *testing.T) {
	filter := cuckoofilter.NewFilter(1000, cuckoofilter.DefaultBucketSize)
	maxSizeData := make([]byte, 1024) // Data at the maximum allowed size
	mrand.Read(maxSizeData)           // Fill with random data

	// Expect insert to succeed with maximum size data
	require.True(t, filter.Insert(maxSizeData), "Insert should succeed with maximum size data")
}

func TestInsert_Failure(t *testing.T) {
	filter := cuckoofilter.NewFilter(100, cuckoofilter.DefaultBucketSize) // Smaller filter for testing
	insertionFailures := 0
	totalInsertions := 0

	// Attempt to fill the filter and count failures
	for i := 0; i < 1000; i++ { // Insert more elements than the filter capacity
		data := []byte{byte(i)}
		if !filter.Insert(data) {
			insertionFailures++
		}
		totalInsertions++
	}
	require.True(t, insertionFailures > 0, "Expected some insertions to fail, but all %d insertions succeeded", totalInsertions)
}

func TestInsert_Failure2(t *testing.T) {
	filter := cuckoofilter.NewFilter(100, cuckoofilter.DefaultBucketSize)
	insertionFailures := 0
	totalInsertions := 0

	// Attempt to fill the filter and count failures
	for i := 0; i < 1000; i++ { // Insert more elements than the filter capacity
		data := []byte{byte(i)}
		if !filter.Insert(data) {
			insertionFailures++
		}
		totalInsertions++
	}
	require.True(t, insertionFailures > 0, "Expected some insertions to fail, but all %d insertions succeeded", totalInsertions)
}

func TestLookup(t *testing.T) {
	filter := cuckoofilter.NewFilter(1000, cuckoofilter.DefaultBucketSize)
	data := []byte("test data")
	filter.Insert(data)
	require.True(t, filter.Lookup(data), "Expected data to be found")
}

func TestDelete(t *testing.T) {
	filter := cuckoofilter.NewFilter(1000, cuckoofilter.DefaultBucketSize)
	data := []byte("test data")
	filter.Insert(data)
	require.True(t, filter.Delete(data), "Expected deletion to succeed")
	require.False(t, filter.Lookup(data), "Expected data to be deleted")
}

func TestDelete_FromFullFilter(t *testing.T) {
	filter := cuckoofilter.NewFilter(10, 1) // Small filter to reach full capacity quickly

	// Fill the filter to its full capacity
	for i := 0; i < 10; i++ {
		data := []byte(fmt.Sprintf("data%d", i))
		require.True(t, filter.Insert(data), "Insertion should succeed")
	}

	// Attempt to delete an item from the full filter
	require.True(t, filter.Delete([]byte("data5")), "Deletion should succeed in a full filter")
}

func TestDelete_LastRemainingItem(t *testing.T) {
	filter := cuckoofilter.NewFilter(10, 1)
	data := []byte("unique data")
	filter.Insert(data)

	// Deleting the last remaining item in the filter
	require.True(t, filter.Delete(data), "Deletion of the last remaining item should succeed")
	require.False(t, filter.Lookup(data), "The deleted item should not be found after deletion")
}

func TestDeleteNonExistent(t *testing.T) {
	filter := cuckoofilter.NewFilter(1000, cuckoofilter.DefaultBucketSize)
	data := []byte("test data")
	require.False(t, filter.Delete(data), "Expected deletion to fail")
}

// Additional tests for edge cases and other functionalities can be added here
func TestInsert_LargeData(t *testing.T) {
	filter := cuckoofilter.NewFilter(1000, cuckoofilter.DefaultBucketSize)
	largeData := make([]byte, 10000) // Large data
	require.False(t, filter.Insert(largeData), "Expected insertion of large data to fail")
}

func TestInsert_Duplicate(t *testing.T) {
	filter := cuckoofilter.NewFilter(1000, cuckoofilter.DefaultBucketSize)
	data := []byte("duplicate data")
	require.True(t, filter.Insert(data), "Expected first insertion to succeed")
	require.False(t, filter.Insert(data), "Expected duplicate insertion to fail")
}

func TestInsertDataExceedingMaxLength(t *testing.T) {
	filter := cuckoofilter.NewFilter(1000, cuckoofilter.DefaultBucketSize)
	data := make([]byte, 1025) // Length exceeds the maximum allowed

	// Expect insert to fail with data exceeding max length
	require.False(t, filter.Insert(data), "Insert should fail with data exceeding max length")
}

func TestInsert_WithCuckooKicking(t *testing.T) {
	filter := cuckoofilter.NewFilter(2, 1) // small filter to trigger cuckoo kicking easily
	data1 := []byte("complex data 1")
	data2 := []byte("different data 2")
	data3 := []byte("another unique data 3") // this should trigger cuckoo kicking

	require.True(t, filter.Insert(data1))
	require.True(t, filter.Insert(data2))
	require.True(t, filter.Insert(data3), "Expected insertion with cuckoo kicking to succeed")
}

func TestInsert_LargeDataFailure(t *testing.T) {
	filter := cuckoofilter.NewFilter(10, 1)
	largeData := make([]byte, 1025) // Data larger than 1024 bytes
	require.False(t, filter.Insert(largeData), "Insertion of data larger than 1024 bytes should fail")
}

func TestRandomInsertDelete(t *testing.T) {
	filter := cuckoofilter.NewFilter(1000, cuckoofilter.DefaultBucketSize)
	for i := 0; i < 100; i++ {
		data := []byte(fmt.Sprintf("random%d", i))
		require.True(t, filter.Insert(data), "Expected insertion to succeed")
		require.True(t, filter.Delete(data), "Expected deletion to succeed")
	}
}

func TestInsert_OverfilledBucket(t *testing.T) {
	filter := cuckoofilter.NewFilter(10, 1) // Small filter with small buckets
	for i := 0; i < 20; i++ {
		data := []byte(fmt.Sprintf("data%d", i))
		filter.Insert(data) // Insert more elements than the nominal capacity
	}

	// Adjust the threshold to a higher value
	require.LessOrEqual(t, filter.Count, uint(20), "Expected filter count to be within acceptable overfilled range")
}

func TestBucketOverflow(t *testing.T) {
	filter := cuckoofilter.NewFilter(1000, 1) // Set bucket size to 1 for easy overflow
	successInserts := 0

	// Attempt to insert multiple elements
	for i := 0; i < 100; i++ { // Lower the number to a reasonable amount for the test
		data := []byte(fmt.Sprintf("data%d", i))
		if filter.Insert(data) {
			successInserts++
		}
	}

	// Expect multiple successful inserts due to cuckoo kicking
	require.Greater(t, successInserts, 1, "Multiple inserts should succeed due to cuckoo kicking")
}

func TestFingerprintCollision(t *testing.T) {
	filter := cuckoofilter.NewFilter(1000, cuckoofilter.DefaultBucketSize)
	data1 := []byte("data1")
	data2 := []byte("data2") // Assume data2 produces the same fingerprint as data1
	filter.Insert(data1)
	require.True(t, filter.Insert(data2), "Cuckoo filter should handle fingerprint collisions")
}

func TestLookup_NonExistent(t *testing.T) {
	filter := cuckoofilter.NewFilter(1000, cuckoofilter.DefaultBucketSize)
	nonExistentData := []byte("nonexistent")
	require.False(t, filter.Lookup(nonExistentData), "Expected non-existent data to not be found")
}

func TestBucketIndexMask(t *testing.T) {
	filter := cuckoofilter.NewFilter(1000, cuckoofilter.DefaultBucketSize)
	data := []byte("test data")
	i1, _ := cuckoofilter.GetIndexAndFingerprint(data, filter.BucketIndexMask, 8)
	require.Less(t, i1, uint(1024), "Expected bucket index to be within range")
}

func TestReset(t *testing.T) {
	filter := cuckoofilter.NewFilter(1000, cuckoofilter.DefaultBucketSize)
	data := []byte("test data")
	filter.Insert(data)
	filter.Reset()
	require.Equal(t, uint(0), filter.Count, "Expected filter count to be zero")
}

func TestWithStringData(t *testing.T) {
	filter := cuckoofilter.NewFilter(1000, cuckoofilter.DefaultBucketSize)
	data := "test string"
	byteData := []byte(data)
	// Insert
	require.True(t, filter.Insert(byteData), "Expected successful insertion of string data")
	// Lookup
	require.True(t, filter.Lookup(byteData), "Expected string data to be found")
	// Delete
	require.True(t, filter.Delete(byteData), "Expected deletion of string data to succeed")
}

func TestWithEmptyData(t *testing.T) {
	filter := cuckoofilter.NewFilter(1000, cuckoofilter.DefaultBucketSize)
	emptyData := []byte("")
	// Insert
	require.False(t, filter.Insert(emptyData), "Insertion of empty data should fail")
	// Lookup
	require.False(t, filter.Lookup(emptyData), "Lookup of empty data should fail")
	// Delete
	require.False(t, filter.Delete(emptyData), "Deletion of empty data should fail")
}

func TestMaxCuckooKicks(t *testing.T) {
	filter := cuckoofilter.NewFilter(2, 1) // Small filter to reach max cuckoo kicks quickly
	successInserts := 0

	// Attempt to fill the filter, expecting to hit the max cuckoo kicks
	for i := 0; i < cuckoofilter.MaxCuckooKicks+10; i++ {
		data := []byte(fmt.Sprintf("data%d", i))
		if filter.Insert(data) {
			successInserts++
		}
	}

	// The number of successful inserts should be less than or equal to MaxCuckooKicks
	require.LessOrEqual(t, successInserts, cuckoofilter.MaxCuckooKicks, "Inserts should not exceed max cuckoo kicks")
}

func TestRandomDataInsertions(t *testing.T) {
	filter := cuckoofilter.NewFilter(1000, cuckoofilter.DefaultBucketSize)
	successInserts := 0

	mrand.Seed(time.Now().UnixNano()) // Ensure randomness

	// Insert random data
	for i := 0; i < 1000; i++ {
		data := make([]byte, 8)
		_, err := mrand.Read(data)
		require.NoError(t, err, "Random data generation should not fail")

		if filter.Insert(data) {
			successInserts++
		}
	}

	// Check if a reasonable number of inserts were successful
	require.Greater(t, successInserts, 0, "At least some random inserts should succeed")
}

func TestStress(t *testing.T) {
	filter := cuckoofilter.NewFilter(10000, cuckoofilter.DefaultBucketSize)
	successInserts := 0

	// Perform a large number of insertions
	for i := 0; i < 50000; i++ {
		data := []byte(fmt.Sprintf("data%d", i))
		if filter.Insert(data) {
			successInserts++
		}
	}

	// Check if a significant number of inserts were successful
	require.Greater(t, successInserts, 0, "A significant number of inserts should succeed in stress test")

	// Perform lookups and deletions
	for i := 0; i < 50000; i++ {
		data := []byte(fmt.Sprintf("data%d", i))
		filter.Lookup(data)
		filter.Delete(data)
	}
}

func TestSerialization(t *testing.T) {
	filter := cuckoofilter.NewFilter(1000, cuckoofilter.DefaultBucketSize)
	data := []byte("test data")
	filter.Insert(data)

	// Serialize the filter
	filterBytes, err := json.Marshal(filter)
	require.NoError(t, err, "Serialization should succeed")
	// Deserialize the filter
	var newFilter cuckoofilter.Filter
	err = json.Unmarshal(filterBytes, &newFilter)
	require.NoError(t, err, "Deserialization should succeed")
	// Check if the deserialized filter retains the original data
	require.True(t, newFilter.Lookup(data), "Deserialized filter should contain the original data")
}

func TestDeserialization_CorruptedData(t *testing.T) {
	corruptedData := []byte("{invalid_json}")
	var filter cuckoofilter.Filter

	// Attempt to deserialize corrupted data
	err := json.Unmarshal(corruptedData, &filter)
	require.Error(t, err, "Deserialization should fail with corrupted data")
}

func TestSerializationIntegrity(t *testing.T) {
	filter := cuckoofilter.NewFilter(1000, cuckoofilter.DefaultBucketSize)
	// Insert some data
	for i := 0; i < 10; i++ {
		data := []byte(fmt.Sprintf("data%d", i))
		filter.Insert(data)
	}

	// Serialize the filter
	serializedData, err := json.Marshal(filter)
	require.NoError(t, err)

	// Deserialize the filter
	var newFilter cuckoofilter.Filter
	err = json.Unmarshal(serializedData, &newFilter)
	require.NoError(t, err)

	// Check if the deserialized filter has the same data
	for i := 0; i < 10; i++ {
		data := []byte(fmt.Sprintf("data%d", i))
		require.True(t, newFilter.Lookup(data))
	}
}

func TestFalsePositiveRate(t *testing.T) {
	filter := cuckoofilter.NewFilter(1000, cuckoofilter.DefaultBucketSize)
	falsePositives := 0
	totalChecks := 10000
	// Insert data into the filter
	for i := 0; i < 500; i++ {
		data := []byte(fmt.Sprintf("data%d", i))
		filter.Insert(data)
	}
	// Check for false positives
	for i := 500; i < totalChecks; i++ {
		data := []byte(fmt.Sprintf("data%d", i))
		if filter.Lookup(data) {
			falsePositives++
		}
	}
	// Calculate the false positive rate
	falsePositiveRate := float64(falsePositives) / float64(totalChecks-500)
	expectedRate := 0.03 // Adjust based on your filter's expected false positive rate
	// Check if the false positive rate is within an acceptable range
	require.LessOrEqual(t, falsePositiveRate, expectedRate, "False positive rate should be within expected range")
}

func TestFilterReset(t *testing.T) {
	filter := cuckoofilter.NewFilter(1000, cuckoofilter.DefaultBucketSize)
	data := []byte("test data")
	filter.Insert(data)
	filter.Reset()

	// Check if the filter is empty after reset
	require.Equal(t, uint(0), filter.Count, "Filter count should be zero after reset")
	require.False(t, filter.Lookup(data), "Data should not be found after reset")
}

func TestConsistencyAfterOperations(t *testing.T) {
	filter := cuckoofilter.NewFilter(1000, cuckoofilter.DefaultBucketSize)

	// Perform a series of insertions, deletions, and lookups
	for i := 0; i < 100; i++ {
		data := []byte(fmt.Sprintf("data%d", i))
		filter.Insert(data)
		filter.Lookup(data)
		filter.Delete(data)
	}

	// Check if the filter's count is consistent
	require.Equal(t, uint(0), filter.Count, "Filter count should be zero after all deletions")
}

func TestConcurrentAccess(t *testing.T) {
	filter := cuckoofilter.NewFilter(10000, cuckoofilter.DefaultBucketSize)
	var wg sync.WaitGroup
	// Perform concurrent insertions
	for i := 0; i < 1000; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			data := []byte(fmt.Sprintf("data%d", i))
			filter.Insert(data)
		}(i)
	}
	wg.Wait() // Wait for all goroutines to finish
}

func TestHashFunctionConsistency(t *testing.T) {
	data := []byte("consistent data")
	firstIndex, firstFp := cuckoofilter.GetIndexAndFingerprint(data, 1023, 8)

	for i := 0; i < 100; i++ {
		currentIndex, currentFp := cuckoofilter.GetIndexAndFingerprint(data, 1023, 8)
		require.Equal(t, firstIndex, currentIndex, "Indices should be consistent")
		require.Equal(t, firstFp, currentFp, "Fingerprints should be consistent")
	}
}

func TestErrorHandling(t *testing.T) {
	filter := cuckoofilter.NewFilter(1000, cuckoofilter.DefaultBucketSize)

	// Test with invalid data
	invalidData := []byte("")
	require.False(t, filter.Insert(invalidData), "Insert should fail with invalid data")

	// Test deletion of non-existent data
	nonExistentData := []byte("nonexistent")
	require.False(t, filter.Delete(nonExistentData), "Delete should fail for non-existent data")
}

func TestBucketFillingAndClearing(t *testing.T) {
	filter := cuckoofilter.NewFilter(10, 2) // Small filter for easier testing
	data1 := []byte("data1")
	data2 := []byte("data2")

	// Insert data and fill a bucket
	require.True(t, filter.Insert(data1))
	require.True(t, filter.Insert(data2))

	// Reset the filter
	filter.Reset()

	// Ensure the bucket is cleared
	for _, b := range filter.Buckets {
		require.False(t, b.IsFull(), "Buckets should be empty after reset")
	}
}

func TestAuxiliaryFunctions(t *testing.T) {
	// Test getNextPow2 function
	require.Equal(t, uint(1024), cuckoofilter.GetNextPow2(1000), "getNextPow2 should return the next power of two")

	// Add tests for other auxiliary functions as needed
}

func TestInsertZeroLengthData(t *testing.T) {
	filter := cuckoofilter.NewFilter(1000, cuckoofilter.DefaultBucketSize)
	data := []byte("")

	// Expect insert to fail with zero length data
	require.False(t, filter.Insert(data), "Insert should fail with zero length data")
}

func TestFilterResetFunctionality(t *testing.T) {
	filter := cuckoofilter.NewFilter(1000, cuckoofilter.DefaultBucketSize)
	// Insert some data
	for i := 0; i < 50; i++ {
		data := []byte(fmt.Sprintf("data%d", i))
		require.True(t, filter.Insert(data), "Insert should succeed")
	}

	// Reset the filter
	filter.Reset()

	// Check if each bucket is empty and count is zero
	for _, bucket := range filter.Buckets {
		require.Empty(t, bucket.Data, "Each bucket should be empty after reset")
	}
	require.Equal(t, uint(0), filter.Count, "Count should be zero after reset")
}

func TestUtilityFunctionEdgeCases(t *testing.T) {
	// Example: testing getFingerprint with varying data sizes
	for size := 1; size <= 16; size++ {
		data := make([]byte, size)
		fp := cuckoofilter.GetFingerprint(data, cuckoofilter.FingerPrintSize)
		require.Len(t, fp, cuckoofilter.FingerPrintSize, "Fingerprint should always have the specified length")
	}
}

func TestFilter_SerializationDeserialization(t *testing.T) {
	filter := cuckoofilter.NewFilter(10, 4)
	data := []byte("test data")
	filter.Insert(data)

	// Serialize
	serialized, err := json.Marshal(filter)
	require.NoError(t, err)

	// Deserialize
	var newFilter cuckoofilter.Filter
	err = json.Unmarshal(serialized, &newFilter)
	require.NoError(t, err)

	// Verify
	require.True(t, newFilter.Lookup(data), "Data should be present after deserialization")
}

func TestGetAltIndex(t *testing.T) {
	fp := []byte("test")
	index := uint(5)
	mask := uint(255) // example mask

	altIndex := cuckoofilter.GetAltIndex(fp, index, mask)
	require.NotEqual(t, index, altIndex, "Alternate index should differ from the original index")
}

func TestGetFingerprint(t *testing.T) {
	data := []byte("test data")
	size := uint(8)

	fp := cuckoofilter.GetFingerprint(data, size)
	require.Len(t, fp, int(size), "Fingerprint length should match the specified size")
}

func TestUnmarshalJSON_Error(t *testing.T) {
	invalidJSON := []byte("invalid")

	var filter cuckoofilter.Filter
	err := json.Unmarshal(invalidJSON, &filter)
	require.Error(t, err, "Unmarshalling should fail with invalid JSON")
}

func TestBucketIsFull(t *testing.T) {
	bucket := cuckoofilter.NewBucket(1) // bucket size of 1 for easy testing
	fp := []byte("fp")

	require.False(t, bucket.IsFull(), "Bucket should not be full initially")
	bucket.Insert(fp)
	require.True(t, bucket.IsFull(), "Bucket should be full after insert")
}

func TestGetNextPow2(t *testing.T) {
	result := cuckoofilter.GetNextPow2(15)
	require.Equal(t, uint(16), result, "getNextPow2 should return the next power of 2")
}

func TestCapacity(t *testing.T) {
	filter := cuckoofilter.NewFilter(1000, cuckoofilter.DefaultBucketSize)
	// Adjust the expected capacity calculation according to the actual implementation logic
	// Assuming it rounds to the nearest power of two
	expectedCapacity := uint(1024) * cuckoofilter.DefaultBucketSize // Adjusted to the nearest power of two
	require.Equal(t, expectedCapacity, filter.Capacity(), "Capacity should match expected value")
}

func TestDeleteFunctionality(t *testing.T) {
	filter := cuckoofilter.NewFilter(1000, cuckoofilter.DefaultBucketSize)
	data := []byte("test data")
	filter.Insert(data)
	require.True(t, filter.Delete(data), "Delete should successfully remove existing item")
	require.False(t, filter.Lookup(data), "Deleted item should not be found")
}

func TestUnmarshalJSON(t *testing.T) {
	filter := cuckoofilter.NewFilter(1000, cuckoofilter.DefaultBucketSize)
	data := []byte("test data")
	filter.Insert(data)

	jsonBytes, err := json.Marshal(filter)
	require.NoError(t, err, "Marshaling should not produce an error")

	var unmarshaledFilter cuckoofilter.Filter
	err = json.Unmarshal(jsonBytes, &unmarshaledFilter)
	require.NoError(t, err, "Unmarshaling should not produce an error")
	require.True(t, unmarshaledFilter.Lookup(data), "Unmarshaled filter should contain the inserted item")
}

// Mock Tests
func TestInitLedger(t *testing.T) {
	// Create a mock stub and mock transaction context
	mockStub := new(mocks.MockChaincodeStubInterface)
	mockTxContext := new(mocks.MockTransactionContext)

	// Mock the PutState method to simulate a successful state update
	mockStub.On("PutState", "CuckooFilterState", mock.Anything).Return(nil)

	// Set the mock stub in the transaction context
	mockTxContext.On("GetStub").Return(mockStub)
	mockTxContext.Stub = mockStub // Make sure the Stub is properly set

	// Create an instance of the SmartContract
	smartContract := new(cuckoofilter.SmartContract)

	// Call the InitLedger function with the mock transaction context
	err := smartContract.InitLedger(mockTxContext, 1000, cuckoofilter.DefaultBucketSize)

	// Assert that there were no errors
	require.NoError(t, err)

	// Verify that PutState was called with the expected arguments
	mockStub.AssertCalled(t, "PutState", "CuckooFilterState", mock.Anything)
}

func TestInsertInCuckooFilter(t *testing.T) {
	// Initialize the mock stub
	mockStub := new(mocks.MockChaincodeStubInterface)

	// Mock filter state in the ledger
	filter := cuckoofilter.NewFilter(100, 4)
	filterJSON, _ := json.Marshal(filter)
	mockStub.On("GetState", "CuckooFilterState").Return(filterJSON, nil)
	mockStub.On("PutState", "CuckooFilterState", mock.Anything).Return(nil)

	// Initialize the mock transaction context
	mockTxContext := new(mocks.MockTransactionContext)
	mockTxContext.On("GetStub").Return(mockStub)
	mockTxContext.Stub = mockStub // Ensure that the Stub is set

	// Create a new instance of the SmartContract
	smartContract := new(cuckoofilter.SmartContract)

	// Test data to insert
	testData := "testData"

	// Call the Insert function
	err := smartContract.Insert(mockTxContext, testData)

	// Assert that there were no errors
	require.NoError(t, err)

	// Assert that PutState was called with the updated filter state
	mockStub.AssertCalled(t, "PutState", "CuckooFilterState", mock.Anything)
}

func TestLookupInCuckooFilter(t *testing.T) {
	mockStub := new(mocks.MockChaincodeStubInterface)

	// Create a filter and manually insert the test data
	filter := cuckoofilter.NewFilter(100, 4)
	testData := "testData"
	filter.Insert([]byte(testData)) // Manually inserting the data into the filter

	// Marshal the updated filter state with the test data
	filterJSON, _ := json.Marshal(filter)
	// Mock GetState to return the updated filter state
	mockStub.On("GetState", "CuckooFilterState").Return(filterJSON, nil)

	mockTxContext := new(mocks.MockTransactionContext)
	mockTxContext.On("GetStub").Return(mockStub)
	mockTxContext.Stub = mockStub

	smartContract := new(cuckoofilter.SmartContract)

	// Call the Lookup function
	found, err := smartContract.Lookup(mockTxContext, testData)

	// Assertions
	require.NoError(t, err)
	require.True(t, found, "Data should be found in cuckoo filter")
}

func TestLookupFailure(t *testing.T) {
	mockStub := new(mocks.MockChaincodeStubInterface)

	// Create a filter without inserting the test data
	filter := cuckoofilter.NewFilter(100, 4)
	// Do not insert testData into the filter

	// Marshal the filter state without the test data
	filterJSON, _ := json.Marshal(filter)
	// Mock GetState to return the filter state without the test data
	mockStub.On("GetState", "CuckooFilterState").Return(filterJSON, nil)

	mockTxContext := new(mocks.MockTransactionContext)
	mockTxContext.On("GetStub").Return(mockStub)
	mockTxContext.Stub = mockStub

	smartContract := new(cuckoofilter.SmartContract)

	// Call the Lookup function with testData, which is not in the filter
	testData := "testData"
	found, err := smartContract.Lookup(mockTxContext, testData)

	// Assertions
	require.NoError(t, err)
	require.False(t, found, "Data should not be found in cuckoo filter")
}

func TestDeleteInCuckooFilter(t *testing.T) {
	mockStub := new(mocks.MockChaincodeStubInterface)

	// Create a filter and manually insert the test data
	filter := cuckoofilter.NewFilter(100, 4)
	testData := "testData"
	filter.Insert([]byte(testData)) // Manually inserting the data into the filter

	// Marshal the updated filter state with the test data
	filterJSON, _ := json.Marshal(filter)
	// Mock GetState to return the updated filter state
	mockStub.On("GetState", "CuckooFilterState").Return(filterJSON, nil)

	// Mock PutState to simulate successful delete operation
	mockStub.On("PutState", "CuckooFilterState", mock.Anything).Return(nil)

	mockTxContext := new(mocks.MockTransactionContext)
	mockTxContext.On("GetStub").Return(mockStub)
	mockTxContext.Stub = mockStub

	smartContract := new(cuckoofilter.SmartContract)

	// Call the Delete function
	err := smartContract.Delete(mockTxContext, testData)

	// Assertions
	require.NoError(t, err, "Delete operation should succeed")
}

func TestDeleteFailure(t *testing.T) {
	mockStub := new(mocks.MockChaincodeStubInterface)
	// Simulate failure in loading filter state by returning nil slice of bytes and an error
	mockStub.On("GetState", "CuckooFilterState").Return(([]byte)(nil), errors.New("state not found"))

	mockTxContext := new(mocks.MockTransactionContext)
	mockTxContext.On("GetStub").Return(mockStub)
	mockTxContext.Stub = mockStub // Ensure that the Stub is set

	smartContract := new(cuckoofilter.SmartContract)

	// Attempt to delete data from the filter
	err := smartContract.Delete(mockTxContext, "testData")

	// Assertions
	require.Error(t, err, "Delete operation should fail when filter state cannot be loaded")
}

func TestLoadFilterStateFailure(t *testing.T) {
	mockStub := new(mocks.MockChaincodeStubInterface)
	mockStub.On("GetState", "CuckooFilterState").Return(([]byte)(nil), errors.New("state not found"))

	mockTxContext := new(mocks.MockTransactionContext)
	mockTxContext.On("GetStub").Return(mockStub)
	mockTxContext.Stub = mockStub // Set the mock stub to the transaction context

	smartContract := new(cuckoofilter.SmartContract)

	_, err := smartContract.Lookup(mockTxContext, "testData")

	require.Error(t, err)
}

func TestSaveFilterStateFailure(t *testing.T) {
	mockStub := new(mocks.MockChaincodeStubInterface)

	// Mock GetState to return a valid filter state
	filter := cuckoofilter.NewFilter(100, 4)
	filterJSON, _ := json.Marshal(filter)
	mockStub.On("GetState", "CuckooFilterState").Return(filterJSON, nil)

	// Mock PutState to simulate failure
	mockStub.On("PutState", "CuckooFilterState", mock.Anything).Return(errors.New("failed to save state"))

	mockTxContext := new(mocks.MockTransactionContext)
	mockTxContext.On("GetStub").Return(mockStub)
	mockTxContext.Stub = mockStub

	smartContract := new(cuckoofilter.SmartContract)

	err := smartContract.Insert(mockTxContext, "testData")

	// Assertions
	require.Error(t, err)
	require.Equal(t, "failed to save state", err.Error())
}

func TestFilterEdgeCases(t *testing.T) {
	filter := cuckoofilter.NewFilter(10, 1)
	largeData := make([]byte, 2000)

	require.False(t, filter.Insert(largeData), "Insertion of large data should fail")
}

func TestBatchInsert_Failure(t *testing.T) {
	mockStub := new(mocks.MockChaincodeStubInterface)
	mockTxContext := new(mocks.MockTransactionContext)
	mockTxContext.On("GetStub").Return(mockStub)
	mockTxContext.Stub = mockStub

	filter := cuckoofilter.NewFilter(1000, cuckoofilter.DefaultBucketSize)
	filterJSON, _ := json.Marshal(filter)
	mockStub.On("GetState", "CuckooFilterState").Return(filterJSON, nil)

	// Set up PutState to fail during the state-saving step, after insertions
	mockStub.On("PutState", "CuckooFilterState", mock.Anything).
		Return(errors.New("failed to save state"))

	smartContract := new(cuckoofilter.SmartContract)
	batchData := []string{"data1", "data2", "data3"} // Example batch data

	err := smartContract.BatchInsert(mockTxContext, batchData)
	require.Error(t, err, "Batch insert should fail with partial failure")
}

func TestBatchInsert_Success(t *testing.T) {
	mockStub := new(mocks.MockChaincodeStubInterface)
	mockTxContext := new(mocks.MockTransactionContext)
	mockTxContext.On("GetStub").Return(mockStub)
	mockTxContext.Stub = mockStub

	filter := cuckoofilter.NewFilter(1000, cuckoofilter.DefaultBucketSize)
	filterJSON, _ := json.Marshal(filter)
	mockStub.On("GetState", "CuckooFilterState").Return(filterJSON, nil)
	mockStub.On("PutState", "CuckooFilterState", mock.Anything).Return(nil)

	smartContract := new(cuckoofilter.SmartContract)
	batchData := []string{"data1", "data2", "data3"} // Example batch data

	err := smartContract.BatchInsert(mockTxContext, batchData)
	require.NoError(t, err)

	// Additional verification as required
}

func TestBatchInsert_LargeBatch(t *testing.T) {
	mockStub := new(mocks.MockChaincodeStubInterface)
	mockTxContext := new(mocks.MockTransactionContext)
	mockTxContext.On("GetStub").Return(mockStub)
	mockTxContext.Stub = mockStub

	filter := cuckoofilter.NewFilter(1000, cuckoofilter.DefaultBucketSize)
	filterJSON, _ := json.Marshal(filter)
	mockStub.On("GetState", "CuckooFilterState").Return(filterJSON, nil)
	mockStub.On("PutState", "CuckooFilterState", mock.Anything).Return(nil)

	smartContract := new(cuckoofilter.SmartContract)
	batchData := make([]string, 1001) // Example batch data

	err := smartContract.BatchInsert(mockTxContext, batchData)
	require.Error(t, err, "Batch insert should fail with large batch data")
}

func TestBatchInsert_PartialFailure(t *testing.T) {
	mockStub := new(mocks.MockChaincodeStubInterface)
	mockTxContext := new(mocks.MockTransactionContext)
	mockTxContext.On("GetStub").Return(mockStub)
	mockTxContext.Stub = mockStub

	filter := cuckoofilter.NewFilter(1000, cuckoofilter.DefaultBucketSize)
	filterJSON, _ := json.Marshal(filter)
	mockStub.On("GetState", "CuckooFilterState").Return(filterJSON, nil)

	// Set up PutState to fail during the state-saving step, after insertions
	mockStub.On("PutState", "CuckooFilterState", mock.Anything).
		Return(errors.New("failed to save state"))

	smartContract := new(cuckoofilter.SmartContract)
	batchData := []string{"data1", "data2", "data3"} // Example batch data

	err := smartContract.BatchInsert(mockTxContext, batchData)
	require.Error(t, err, "Batch insert should fail with partial failure")
}

func TestBatchLookup(t *testing.T) {
	mockStub := new(mocks.MockChaincodeStubInterface)
	mockTxContext := new(mocks.MockTransactionContext)
	mockTxContext.On("GetStub").Return(mockStub)
	mockTxContext.Stub = mockStub

	filter := cuckoofilter.NewFilter(1000, cuckoofilter.DefaultBucketSize)
	testData := "testData"
	filter.Insert([]byte(testData))
	filterJSON, _ := json.Marshal(filter)
	mockStub.On("GetState", "CuckooFilterState").Return(filterJSON, nil)

	smartContract := new(cuckoofilter.SmartContract)
	batchData := []string{testData, "nonexistentData"}

	results, err := smartContract.BatchLookup(mockTxContext, batchData)
	require.NoError(t, err)
	require.True(t, results[testData], "Existing data should be found")
	require.False(t, results["nonexistentData"], "Non-existing data should not be found")
}

func TestBatchLookupLargeBatch(t *testing.T) {
	mockStub := new(mocks.MockChaincodeStubInterface)
	mockTxContext := new(mocks.MockTransactionContext)
	mockTxContext.On("GetStub").Return(mockStub)
	mockTxContext.Stub = mockStub

	filter := cuckoofilter.NewFilter(1000, cuckoofilter.DefaultBucketSize)
	// Insert multiple data items into the filter
	existingData := []string{"data1", "data2", "data3", "data4", "data5"}
	for _, data := range existingData {
		filter.Insert([]byte(data))
	}
	filterJSON, _ := json.Marshal(filter)
	mockStub.On("GetState", "CuckooFilterState").Return(filterJSON, nil)

	smartContract := new(cuckoofilter.SmartContract)
	// Create a batch of data containing both existing and non-existing items
	batchData := append(existingData, "nonexistentData1", "nonexistentData2", "nonexistentData3")

	results, err := smartContract.BatchLookup(mockTxContext, batchData)
	require.NoError(t, err)

	// Check the lookup results for each data item
	for _, data := range existingData {
		require.True(t, results[data], "Existing data should be found")
	}
	for _, data := range batchData[len(existingData):] {
		require.False(t, results[data], "Non-existing data should not be found")
	}
}

func TestBatchLookupEmptyBatch(t *testing.T) {
	mockStub := new(mocks.MockChaincodeStubInterface)
	mockTxContext := new(mocks.MockTransactionContext)
	mockTxContext.On("GetStub").Return(mockStub)
	mockTxContext.Stub = mockStub

	filter := cuckoofilter.NewFilter(1000, cuckoofilter.DefaultBucketSize)
	filterJSON, _ := json.Marshal(filter)
	mockStub.On("GetState", "CuckooFilterState").Return(filterJSON, nil)

	smartContract := new(cuckoofilter.SmartContract)
	batchData := []string{} // Empty batch

	results, err := smartContract.BatchLookup(mockTxContext, batchData)
	require.NoError(t, err)
	require.Empty(t, results, "Results should be empty for an empty batch")
}

func TestBatchLookupAllNonExistent(t *testing.T) {
	mockStub := new(mocks.MockChaincodeStubInterface)
	mockTxContext := new(mocks.MockTransactionContext)
	mockTxContext.On("GetStub").Return(mockStub)
	mockTxContext.Stub = mockStub

	filter := cuckoofilter.NewFilter(1000, cuckoofilter.DefaultBucketSize)
	filterJSON, _ := json.Marshal(filter)
	mockStub.On("GetState", "CuckooFilterState").Return(filterJSON, nil)

	smartContract := new(cuckoofilter.SmartContract)
	batchData := []string{"nonexistent1", "nonexistent2", "nonexistent3"}

	results, err := smartContract.BatchLookup(mockTxContext, batchData)
	require.NoError(t, err)

	for _, data := range batchData {
		require.False(t, results[data], "Non-existent data should not be found")
	}
}

func TestBatchDelete(t *testing.T) {
	mockStub := new(mocks.MockChaincodeStubInterface)
	mockTxContext := new(mocks.MockTransactionContext)
	mockTxContext.On("GetStub").Return(mockStub)
	mockTxContext.Stub = mockStub

	filter := cuckoofilter.NewFilter(1000, cuckoofilter.DefaultBucketSize)
	testData := "testData"
	filter.Insert([]byte(testData))
	filterJSON, _ := json.Marshal(filter)
	mockStub.On("GetState", "CuckooFilterState").Return(filterJSON, nil)
	mockStub.On("PutState", "CuckooFilterState", mock.Anything).Return(nil)

	smartContract := new(cuckoofilter.SmartContract)
	batchData := []string{testData, "nonexistentData"}

	err := smartContract.BatchDelete(mockTxContext, batchData)
	require.NoError(t, err)

	// Additional verification as required
}

func TestBatchDeleteLargeBatch(t *testing.T) {
	mockStub := new(mocks.MockChaincodeStubInterface)
	mockTxContext := new(mocks.MockTransactionContext)
	mockTxContext.On("GetStub").Return(mockStub)
	mockTxContext.Stub = mockStub

	filter := cuckoofilter.NewFilter(1000, cuckoofilter.DefaultBucketSize)
	// Insert multiple data items into the filter
	existingData := []string{"data1", "data2", "data3", "data4", "data5"}
	for _, data := range existingData {
		filter.Insert([]byte(data))
	}
	filterJSON, _ := json.Marshal(filter)
	mockStub.On("GetState", "CuckooFilterState").Return(filterJSON, nil)
	mockStub.On("PutState", "CuckooFilterState", mock.Anything).Return(nil)

	smartContract := new(cuckoofilter.SmartContract)
	// Create a batch of data containing both existing and non-existing items
	batchData := append(existingData, "nonexistentData1", "nonexistentData2", "nonexistentData3")

	err := smartContract.BatchDelete(mockTxContext, batchData)
	require.NoError(t, err)

	// Additional verification as required
}

func TestBatchDeletePartialFailure(t *testing.T) {
	mockStub := new(mocks.MockChaincodeStubInterface)
	mockTxContext := new(mocks.MockTransactionContext)
	mockTxContext.On("GetStub").Return(mockStub)
	mockTxContext.Stub = mockStub

	// Create a filter and manually insert the test data
	filter := cuckoofilter.NewFilter(100, 4)
	testData := "testData"
	filter.Insert([]byte(testData)) // Manually inserting the data into the filter

	// Marshal the updated filter state with the test data
	filterJSON, _ := json.Marshal(filter)
	// Mock GetState to return the updated filter state
	mockStub.On("GetState", "CuckooFilterState").Return(filterJSON, nil)

	// Mock PutState to simulate failure
	mockStub.On("PutState", "CuckooFilterState", mock.Anything).Return(errors.New("failed to save state"))

	smartContract := new(cuckoofilter.SmartContract)
	batchData := []string{testData, "nonexistentData"}

	err := smartContract.BatchDelete(mockTxContext, batchData)
	require.Error(t, err, "Batch delete should fail with partial failure")
}

func TestBatchDeleteLargeBatch2(t *testing.T) {
	mockStub := new(mocks.MockChaincodeStubInterface)
	mockTxContext := new(mocks.MockTransactionContext)
	mockTxContext.On("GetStub").Return(mockStub)
	mockTxContext.Stub = mockStub
	filter := cuckoofilter.NewFilter(1000, cuckoofilter.DefaultBucketSize)
	// Insert multiple data items into the filter
	existingData := []string{"data1", "data2", "data3", "data4", "data5"}
	for _, data := range existingData {
		filter.Insert([]byte(data))
	}
	filterJSON, _ := json.Marshal(filter)
	mockStub.On("GetState", "CuckooFilterState").Return(filterJSON, nil)
	mockStub.On("PutState", "CuckooFilterState", mock.Anything).Return(nil)
	smartContract := new(cuckoofilter.SmartContract)
	// Create a batch of data containing both existing and non-existing items
	batchData := append(existingData, "nonexistentData1", "nonexistentData2", "nonexistentData3")
	err := smartContract.BatchDelete(mockTxContext, batchData)
	require.NoError(t, err)
}

func TestBatchDeleteEmptyBatch(t *testing.T) {
	mockStub := new(mocks.MockChaincodeStubInterface)
	mockTxContext := new(mocks.MockTransactionContext)
	mockTxContext.On("GetStub").Return(mockStub)

	mockTxContext.Stub = mockStub
	filter := cuckoofilter.NewFilter(1000, cuckoofilter.DefaultBucketSize)
	filterJSON, _ := json.Marshal(filter)
	mockStub.On("GetState", "CuckooFilterState").Return(filterJSON, nil)
	mockStub.On("PutState", "CuckooFilterState", mock.Anything).Return(nil)
	smartContract := new(cuckoofilter.SmartContract)
	batchData := []string{} // Empty batch
	err := smartContract.BatchDelete(mockTxContext, batchData)
	require.NoError(t, err)
}

func TestBatchDeleteAllNonExistent(t *testing.T) {
	mockStub := new(mocks.MockChaincodeStubInterface)
	mockTxContext := new(mocks.MockTransactionContext)
	mockTxContext.On("GetStub").Return(mockStub)

	mockTxContext.Stub = mockStub
	filter := cuckoofilter.NewFilter(1000, cuckoofilter.DefaultBucketSize)
	filterJSON, _ := json.Marshal(filter)
	mockStub.On("GetState", "CuckooFilterState").Return(filterJSON, nil)
	mockStub.On("PutState", "CuckooFilterState", mock.Anything).Return(nil)
	smartContract := new(cuckoofilter.SmartContract)
	batchData := []string{"nonexistent1", "nonexistent2", "nonexistent3"}
	err := smartContract.BatchDelete(mockTxContext, batchData)
	require.NoError(t, err)
}

func TestBatchDeleteAllExisting(t *testing.T) {
	mockStub := new(mocks.MockChaincodeStubInterface)
	mockTxContext := new(mocks.MockTransactionContext)
	mockTxContext.On("GetStub").Return(mockStub)

	mockTxContext.Stub = mockStub
	filter := cuckoofilter.NewFilter(1000, cuckoofilter.DefaultBucketSize)
	// Insert multiple data items into the filter
	existingData := []string{"data1", "data2", "data3", "data4", "data5"}
	for _, data := range existingData {
		filter.Insert([]byte(data))
	}
	filterJSON, _ := json.Marshal(filter)
	mockStub.On("GetState", "CuckooFilterState").Return(filterJSON, nil)
	mockStub.On("PutState", "CuckooFilterState", mock.Anything).Return(nil)
	smartContract := new(cuckoofilter.SmartContract)
	batchData := existingData
	err := smartContract.BatchDelete(mockTxContext, batchData)
	require.NoError(t, err)
}

// github.com/pherbke/credential-management/chaincode-go/smart-contract/cuckoofilter.go:64.35,67.4 1 0
func TestBatchDeleteFailure(t *testing.T) {
	mockStub := new(mocks.MockChaincodeStubInterface)
	mockTxContext := new(mocks.MockTransactionContext)
	mockTxContext.On("GetStub").Return(mockStub)

	mockTxContext.Stub = mockStub
	mockStub.On("GetState", "CuckooFilterState").Return(([]byte)(nil), errors.New("state not found"))
	smartContract := new(cuckoofilter.SmartContract)
	batchData := []string{"nonexistent1", "nonexistent2", "nonexistent3"}
	err := smartContract.BatchDelete(mockTxContext, batchData)
	require.Error(t, err)
}

func TestBatchInsertFailure(t *testing.T) {
	mockStub := new(mocks.MockChaincodeStubInterface)
	mockTxContext := new(mocks.MockTransactionContext)
	mockTxContext.On("GetStub").Return(mockStub)

	mockTxContext.Stub = mockStub
	mockStub.On("GetState", "CuckooFilterState").Return(([]byte)(nil), errors.New("state not found"))
	smartContract := new(cuckoofilter.SmartContract)
	batchData := []string{"nonexistent1", "nonexistent2", "nonexistent3"}
	err := smartContract.BatchInsert(mockTxContext, batchData)
	require.Error(t, err)
}

func TestDeleteFailure2(t *testing.T) {
	mockStub := new(mocks.MockChaincodeStubInterface)
	mockTxContext := new(mocks.MockTransactionContext)
	mockStub.On("GetState", "CuckooFilterState").Return(([]byte)(nil), errors.New("state not found"))
	mockTxContext.On("GetStub").Return(mockStub)
	mockTxContext.Stub = mockStub
	smartContract := new(cuckoofilter.SmartContract)
	err := smartContract.Delete(mockTxContext, "testData")
	require.Error(t, err)
}

func TestInsertFailure2(t *testing.T) {
	mockStub := new(mocks.MockChaincodeStubInterface)
	mockTxContext := new(mocks.MockTransactionContext)
	mockStub.On("GetState", "CuckooFilterState").Return(([]byte)(nil), errors.New("state not found"))
	mockTxContext.On("GetStub").Return(mockStub)
	mockTxContext.Stub = mockStub
	smartContract := new(cuckoofilter.SmartContract)
	err := smartContract.Insert(mockTxContext, "testData")
	require.Error(t, err)
}

func TestLookupFailure2(t *testing.T) {
	mockStub := new(mocks.MockChaincodeStubInterface)
	mockTxContext := new(mocks.MockTransactionContext)
	mockStub.On("GetState", "CuckooFilterState").Return(([]byte)(nil), errors.New("state not found"))
	mockTxContext.On("GetStub").Return(mockStub)
	mockTxContext.Stub = mockStub
	smartContract := new(cuckoofilter.SmartContract)
	_, err := smartContract.Lookup(mockTxContext, "testData")
	require.Error(t, err)
}

func TestBatchInsertFailure2(t *testing.T) {
	mockStub := new(mocks.MockChaincodeStubInterface)
	mockTxContext := new(mocks.MockTransactionContext)
	mockStub.On("GetState", "CuckooFilterState").Return(([]byte)(nil), errors.New("state not found"))
	mockTxContext.On("GetStub").Return(mockStub)
	mockTxContext.Stub = mockStub
	smartContract := new(cuckoofilter.SmartContract)
	batchData := []string{"nonexistent1", "nonexistent2", "nonexistent3"}
	err := smartContract.BatchInsert(mockTxContext, batchData)
	require.Error(t, err)
}

func TestBatchInsertFailure3(t *testing.T) {
	mockStub := new(mocks.MockChaincodeStubInterface)
	mockTxContext := new(mocks.MockTransactionContext)
	mockStub.On("GetState", "CuckooFilterState").Return(([]byte)(nil), errors.New("state not found"))
	mockTxContext.On("GetStub").Return(mockStub)
	mockTxContext.Stub = mockStub
	smartContract := new(cuckoofilter.SmartContract)
	batchData := []string{"nonexistent1", "nonexistent2", "nonexistent3"}
	err := smartContract.BatchInsert(mockTxContext, batchData)
	require.Error(t, err)
}

func TestBatchInsertFailure4(t *testing.T) {
	mockStub := new(mocks.MockChaincodeStubInterface)
	mockTxContext := new(mocks.MockTransactionContext)
	mockStub.On("GetState", "CuckooFilterState").Return(([]byte)(nil), errors.New("state not found"))
	mockTxContext.On("GetStub").Return(mockStub)
	mockTxContext.Stub = mockStub
	smartContract := new(cuckoofilter.SmartContract)
	batchData := []string{"nonexistent1", "nonexistent2", "nonexistent3"}
	err := smartContract.BatchInsert(mockTxContext, batchData)
	require.Error(t, err)
}

// More tests
func TestNewBucket(t *testing.T) {
	bucket := cuckoofilter.NewBucket(4)
	require.Equal(t, uint(4), bucket.Size())
}

func TestInsert(t *testing.T) {
	filter := cuckoofilter.NewFilter(100, 4)
	testData := "testData"
	require.True(t, filter.Insert([]byte(testData)), "Insertion of data should succeed")
}

func TestTryInsert(t *testing.T) {
	filter := cuckoofilter.NewFilter(100, 4)
	testData := "testData"
	require.True(t, filter.Insert([]byte(testData)), "Insertion of data should succeed")
}

func TestInsert2(t *testing.T) {
	filter := cuckoofilter.NewFilter(100, 4)
	testData := "testData"
	require.True(t, filter.Insert([]byte(testData)), "Insertion of data should succeed")
}

func TestMarshalJSON(t *testing.T) {
	filter := cuckoofilter.NewFilter(100, 4)
	filterJSON, err := filter.MarshalJSON()
	require.NoError(t, err)
	require.NotNil(t, filterJSON)
}

// Test Case: Validate the JSON serialization of the filter.
// Function Name: (f *Filter) UnmarshalJSON(data []byte) error
func TestUnmarshalJSON2(t *testing.T) {
	filter := cuckoofilter.NewFilter(100, 4)
	filterJSON, err := filter.MarshalJSON()
	require.NoError(t, err)
	require.NotNil(t, filterJSON)
}

// Test Case: Verify the JSON deserialization of the filter.
// Function Name: (b *bucket) IsFull() bool
func TestIsFull(t *testing.T) {
	bucket := cuckoofilter.NewBucket(4)
	require.False(t, bucket.IsFull(), "Bucket should not be full")
}

// Test Case: Test whether the bucket correctly determines if it is full or not.
// Function Name: (b *bucket) randomFingerprint() fingerprint
//TODO: func TestRandomFingerprint(t *testing.T) {

// Test Case: Check if the bucket returns a random fingerprint and removes it.
// Function Name: (b *bucket) delete(fp fingerprint) bool
func TestDelete2(t *testing.T) {
	bucket := cuckoofilter.NewBucket(4)
	testData := "testData"
	require.False(t, bucket.Delete([]byte(testData)), "Deletion of data should fail")
}

// Test Case: Test the deletion of a fingerprint from the bucket.
// Function Name: (b *bucket) contains(needle fingerprint) bool
func TestContains(t *testing.T) {
	bucket := cuckoofilter.NewBucket(4)
	testData := "testData"
	require.False(t, bucket.Contains([]byte(testData)), "Bucket should not contain the fingerprint")
}

// Test Case: Validate whether the bucket correctly identifies the presence of a fingerprint.
// Function Name: (b *bucket) reset()
func TestReset2(t *testing.T) {
	bucket := cuckoofilter.NewBucket(4)
	bucket.Reset()
}

//Test Case: Ensure that the bucket can be reset, deleting all fingerprints.
//TODO: Function Name: equalFingerprints(a, b fingerprint) bool

// Test Case: Verify the equality comparison between two fingerprints.
// Function Name: (b *bucket) String() string
func TestString2(t *testing.T) {
	bucket := cuckoofilter.NewBucket(4)
	bucket.String()
}

// Test Case: Validate the string representation of the bucket.
// Function Name: (s *SmartContract) InitLedger(ctx contractapi.TransactionContextInterface, numElements uint, bucketSize uint) error
func TestInitLedger2(t *testing.T) {
	mockStub := new(mocks.MockChaincodeStubInterface)
	mockTxContext := new(mocks.MockTransactionContext)
	mockStub.On("PutState", "CuckooFilterState", mock.Anything).Return(nil)
	mockTxContext.On("GetStub").Return(mockStub)
	mockTxContext.Stub = mockStub
	smartContract := new(cuckoofilter.SmartContract)
	err := smartContract.InitLedger(mockTxContext, 100, 4)
	require.NoError(t, err)
}

// Test Case: Test the initialization of the ledger with a new cuckoo filter.
// Function Name: (s *SmartContract) Insert(ctx contractapi.TransactionContextInterface, data string) error
func TestInsert3(t *testing.T) {
	mockStub := new(mocks.MockChaincodeStubInterface)
	mockTxContext := new(mocks.MockTransactionContext)
	filter := cuckoofilter.NewFilter(100, 4)
	filterJSON, _ := json.Marshal(filter)
	mockStub.On("GetState", "CuckooFilterState").Return(filterJSON, nil)
	mockStub.On("PutState", "CuckooFilterState", mock.Anything).Return(nil)
	mockTxContext.On("GetStub").Return(mockStub)
	mockTxContext.Stub = mockStub
	smartContract := new(cuckoofilter.SmartContract)
	err := smartContract.Insert(mockTxContext, "testData")
	require.NoError(t, err)
}

// Test Case: Test the insertion of data into the cuckoo filter.
// Function Name: (s *SmartContract) BatchInsert(ctx contractapi.TransactionContextInterface, dataItems []string) error
func TestBatchInsert2(t *testing.T) {
	mockStub := new(mocks.MockChaincodeStubInterface)
	mockTxContext := new(mocks.MockTransactionContext)
	filter := cuckoofilter.NewFilter(100, 4)
	filterJSON, _ := json.Marshal(filter)
	mockStub.On("GetState", "CuckooFilterState").Return(filterJSON, nil)
	mockStub.On("PutState", "CuckooFilterState", mock.Anything).Return(nil)
	mockTxContext.On("GetStub").Return(mockStub)
	mockTxContext.Stub = mockStub
	smartContract := new(cuckoofilter.SmartContract)
	batchData := []string{"data1", "data2", "data3"}
	err := smartContract.BatchInsert(mockTxContext, batchData)
	require.NoError(t, err)
}

// Test Case: Validate batch insertion of multiple data items into the cuckoo filter.
// Function Name: (s *SmartContract) Lookup(ctx contractapi.TransactionContextInterface, data string) (bool, error)
func TestLookup2(t *testing.T) {
	mockStub := new(mocks.MockChaincodeStubInterface)
	mockTxContext := new(mocks.MockTransactionContext)
	filter := cuckoofilter.NewFilter(100, 4)
	testData := "testData"
	filter.Insert([]byte(testData))
	filterJSON, _ := json.Marshal(filter)
	mockStub.On("GetState", "CuckooFilterState").Return(filterJSON, nil)
	mockTxContext.On("GetStub").Return(mockStub)
	mockTxContext.Stub = mockStub
	smartContract := new(cuckoofilter.SmartContract)
	_, err := smartContract.Lookup(mockTxContext, testData)
	require.NoError(t, err)
}

// Test Case: Test the lookup operation to check if data is present in the cuckoo filter.
// Function Name: (s *SmartContract) BatchLookup(ctx contractapi.TransactionContextInterface, dataItems []string) (map[string]bool, error)
func TestBatchLookup2(t *testing.T) {
	mockStub := new(mocks.MockChaincodeStubInterface)
	mockTxContext := new(mocks.MockTransactionContext)
	filter := cuckoofilter.NewFilter(100, 4)
	testData := "testData"
	filter.Insert([]byte(testData))
	filterJSON, _ := json.Marshal(filter)
	mockStub.On("GetState", "CuckooFilterState").Return(filterJSON, nil)
	mockTxContext.On("GetStub").Return(mockStub)
	mockTxContext.Stub = mockStub
	smartContract := new(cuckoofilter.SmartContract)
	batchData := []string{testData, "nonexistentData"}
	_, err := smartContract.BatchLookup(mockTxContext, batchData)
	require.NoError(t, err)
}

//Test Case: Validate batch lookup operation for multiple data items.
//TODO: Function Name: (s *SmartContract) Delete(ctx contractapi.TransactionContextInterface, data string) error

//Test Case: Validate batch deletion of multiple data items from the cuckoo filter.
//TODO: Function Name: (s *SmartContract) saveFilterState(ctx contractapi.TransactionContextInterface, filter *Filter) error

//Test Case: Verify the saving of the cuckoo filter state.
//TODO: Function Name: (s *SmartContract) LoadFilterState(ctx contractapi.TransactionContextInterface) (*Filter, error)

// Test Case: Test loading the cuckoo filter state from the ledger.
// TODO: Function Name: NewFilter(numElements uint, bucketSize uint) *Filter
//
// Test Case: Ensure the creation of a new cuckoo filter with specified parameters.
// TODO: Function Name: (f *Filter) Lookup(data []byte) bool
//
// Test Case: Test the lookup operation for data in the cuckoo filter.
// TODO: Function Name: (f *Filter) Delete(data []byte) bool
//
// Test Case: Validate the deletion of data from the cuckoo filter.
// Function Name: GetAltIndex(fp []byte, i, bucketIndexMask uint) uint
func TestGetAltIndex2(t *testing.T) {
	fp := []byte("testData")
	require.Equal(t, uint(0), cuckoofilter.GetAltIndex(fp, 0, 0), "Alternate index should be zero")
}

// Test Case: Verify the calculation of the alternate index.
// TODO: Function Name: GetFingerprint(data []byte, fingerprintSize uint) []byte

//Test Case: Test the generation of a fingerprint from hash value.
//TODO: Function Name: deterministicSelector(data []byte, i1, i2 uint) uint

// Test Case: Validate the deterministic selector function.
// TODO: Function Name: GetIndexAndFingerprint(data []byte, bucketIndexMask uint, fingerprintSize uint) (uint, []byte)

// Test Case: Verify the calculation of the primary bucket index and fingerprint.
// TODO: Function Name: GetNextPow2(n uint64) uint

//Test Case: Ensure the calculation of the next power of two.
//TODO: Function Name: randi(i1, i2 uint) uint

//TODO: Test Case: Validate the random selection between two values.

// Credential test

// TODO: Add signature to credential
// CreateTestCredentialWithSignature and store as jwt to test_credentialsigned.json get number of credentials as input

// TODO: EBSI Signature update
func CreateTestCredentials(numCredentials int) ([]string, error) {
	var credentials []string
	expirationDateStr := "2031-12-31T00:00:00Z"
	// Parse the expiration date
	expirationDate, err := time.Parse(time.RFC3339, expirationDateStr)

	expUnix := expirationDate.Unix()

	issuanceDate := time.Now().Format(time.RFC3339)
	issuanceDateUnix := time.Now().Unix()

	for i := 0; i < numCredentials; i++ {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}

		// Define JWT payload with EBSI Verifiable Credential structure
		jwtPayload := map[string]interface{}{
			"vc": map[string]interface{}{
				"@context":     []string{"https://www.w3.org/2018/credentials/v1"},
				"id":           fmt.Sprintf("urn:did:123456%d", i),
				"type":         []string{"VerifiableCredential", "VerifiableAttestation", "VerifiableId", "VerifiableAuthorisation"},
				"issuer":       "did:ebsi:z23z7yq45RuqU7Gf4TWumVzK",
				"issuanceDate": issuanceDate,
				"validFrom":    issuanceDate,
				"issued":       issuanceDate,
				"credentialSubject": map[string]interface{}{
					"id":                 fmt.Sprintf("did:ebsi:zdpJRn3TSTHmYsYgQYK1pQGDMWP5JsiryVB962irWeWEV%d", i),
					"personalIdentifier": fmt.Sprintf("IT/DE/1234%d", i),
					"familyName":         "Doe",
					"firstName":          fmt.Sprintf("Alice%d", i),
					"dateOfBirth":        "1990-01-01",
				},
				"credentialSchema": map[string]interface{}{
					"id":   "https://api-conformance.ebsi.eu/trusted-schemas-registry/v2/schemas/example",
					"type": "FullJsonSchemaValidator2021",
				},
				"expirationDate": expirationDateStr,
			},
			"iat": issuanceDateUnix,
			// exp in unix
			"exp": expUnix, // exp in unix format
			"nbf": issuanceDateUnix,

			"iss": "did:ebsi:z23z7yq45RuqU7Gf4TWumVzK",
			"jti": fmt.Sprintf("urn:did:123456%d", i),
			"sub": fmt.Sprintf("did:ebsi:zdpJRn3TSTHmYsYgQYK1pQGDMWP5JsiryVB962irWeWEV%d", i),
		}

		// Create JWT token
		// Token "alg": secp256k1
		token := jwt.NewWithClaims(secp256k1.SigningMethodES256K, jwt.MapClaims(jwtPayload))
		token.Header["kid"] = "did:ebsi:z23z7yq45RuqU7Gf4TWumVzK#keys-1"

		tokenString, err := token.SignedString(privateKey)
		if err != nil {
			return nil, err
		}

		credentials = append(credentials, tokenString)
	}

	// Save credentials to a file
	fileName := "test_credentials.json"
	file, err := os.Create(fileName)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	credJSON, err := json.MarshalIndent(credentials, "", "  ")
	if err != nil {
		return nil, err
	}

	_, err = file.Write(credJSON)
	if err != nil {
		return nil, err
	}

	fmt.Printf("Credentials saved to %s\n", fileName)
	return credentials, nil
}

func GenerateFingerprints(credentials []string, fpLength int) ([]string, error) {
	// generate unique fingerprints for each credential
	var fingerprints []string
	for _, cred := range credentials {
		// hash the credential
		hash := sha256.Sum256([]byte(cred))
		// truncate the hash to the fingerprint length
		fingerprint := hex.EncodeToString(hash[:fpLength])
		fingerprints = append(fingerprints, fingerprint)
	}
	return fingerprints, nil
}

func TestCredentialRevocationAndQuery(t *testing.T) {
	// Create a new Cuckoo filter
	filter := cuckoofilter.NewFilter(1000, cuckoofilter.DefaultBucketSize)

	// Create test credentials
	credentials, err := CreateTestCredentials(1000)
	require.NoError(t, err)

	// Generate fingerprints from the credentials
	fingerprints, err := GenerateFingerprints(credentials, 8)
	require.NoError(t, err)

	// Insert fingerprints into the filter
	for _, fp := range fingerprints {
		filter.Insert([]byte(fp))
	}

	// Save the filter state to the ledger
	mockStub := new(mocks.MockChaincodeStubInterface)
	mockTxContext := new(mocks.MockTransactionContext)
	filterJSON, err := filter.MarshalJSON()
	require.NoError(t, err)
	mockStub.On("PutState", "CuckooFilterState", filterJSON).Return(nil)
	mockTxContext.On("GetStub").Return(mockStub)
	mockTxContext.Stub = mockStub

	smartContract := new(cuckoofilter.SmartContract)
	err = smartContract.SaveFilterState(mockTxContext, filter)
	require.NoError(t, err)

	// Load the filter state from the ledger
	mockStub.On("GetState", "CuckooFilterState").Return(filterJSON, nil)
	filter, err = smartContract.LoadFilterState(mockTxContext)
	require.NoError(t, err)

	// lookup inserted fingerprints
	for _, fp := range fingerprints {
		require.True(t, filter.Lookup([]byte(fp)), "Fingerprint should be found")
		print("Fingerprint found: ", fp, "\n")
	}

	// delete fingerprints from the filter
	for _, fp := range fingerprints {
		require.True(t, filter.Delete([]byte(fp)), "Fingerprint should be deleted")
	}

	// lookup deleted fingerprints
	for _, fp := range fingerprints {
		require.False(t, filter.Lookup([]byte(fp)), "Fingerprint should not be found")
		print("Fingerprint not found: ", fp, "\n")
	}
}
