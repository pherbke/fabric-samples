package cuckoofilter

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	metro "github.com/dgryski/go-metro"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	"math/rand"
	"time"
)

const MaxCuckooKicks = 500  // Define a constant for maximum cuckoo kicks
const DefaultBucketSize = 4 // Define a default bucket size
const FingerPrintSize = 8   // Define a default fingerprint size

// Filter represents the cuckoo filter structure
type Filter struct {
	Buckets         []*bucket
	Count           uint
	BucketIndexMask uint
}

type bucket struct {
	Data []fingerprint
	size uint
}

type fingerprint []byte

func NewBucket(size uint) *bucket {
	return &bucket{
		Data: make([]fingerprint, size),
		size: size,
	}
}

func (f *Filter) Capacity() uint {
	return uint(len(f.Buckets)) * DefaultBucketSize
}

// insert a fingerprint into a bucket. Returns true if there was enough space and insertion succeeded.
func (f *Filter) Insert(data []byte) bool {
	if len(data) == 0 || len(data) > 1024 || f.Lookup(data) {
		return false
	}

	// Set a stricter threshold for overfilling
	overfillThreshold := uint(float32(f.Capacity()) * 1.7)

	i1, fp := GetIndexAndFingerprint(data, f.BucketIndexMask, FingerPrintSize) // Assuming a fixed fingerprint size of 8
	i2 := GetAltIndex(fp, i1, f.BucketIndexMask)

	if f.tryInsert(i1, fp) || f.tryInsert(i2, fp) {
		if f.Count < overfillThreshold {
			f.Count++
		}
		return true
	}

	// Cuckoo Kicking Logic
	for i := 0; i < MaxCuckooKicks; i++ {
		if f.Count >= overfillThreshold {
			// Stop if overfill threshold is reached
			return false
		}

		j := randi(i1, i2)
		if f.Buckets[j].IsFull() {
			oldFp := f.Buckets[j].randomFingerprint()
			altIndex := GetAltIndex(oldFp, j, f.BucketIndexMask) // Get alternate index for the kicked out fingerprint

			if f.tryInsert(altIndex, oldFp) {
				// Successfully inserted in the alternate location
				return f.tryInsert(j, fp) // Now try to insert the new fingerprint
			}
		} else if f.tryInsert(j, fp) {
			f.Count++
			return true
		}
	}
	return false
}

// tryInsert attempts to insert a fingerprint into a specified bucket.
// It returns true if insertion was successful.
func (f *Filter) tryInsert(index uint, fp fingerprint) bool {
	if index >= uint(len(f.Buckets)) || f.Buckets[index] == nil {
		return false
	}

	return f.Buckets[index].Insert(fp)
}

func (b *bucket) Insert(fp fingerprint) bool {
	for i := range b.Data {
		if len(b.Data[i]) == 0 {
			b.Data[i] = make(fingerprint, len(fp))
			copy(b.Data[i], fp)
			return true
		}
	}
	return false
}

// MarshalJSON customizes the JSON serialization of the Filter.
func (f *Filter) MarshalJSON() ([]byte, error) {
	type Alias Filter
	return json.Marshal(&struct {
		*Alias
		SerializedBuckets [][][]byte // Serialized representation of Buckets
	}{
		Alias:             (*Alias)(f),
		SerializedBuckets: serializeBuckets(f.Buckets),
	})
}

func serializeBuckets(buckets []*bucket) [][][]byte {
	serializedBuckets := make([][][]byte, len(buckets))
	for i, b := range buckets {
		serializedBuckets[i] = make([][]byte, len(b.Data))
		for j, fp := range b.Data {
			serializedBuckets[i][j] = fp // fp is of type fingerprint, which is []byte
		}
	}
	return serializedBuckets
}

// UnmarshalJSON customizes the JSON deserialization of the Filter.
func (f *Filter) UnmarshalJSON(data []byte) error {
	type Alias Filter
	aux := &struct {
		*Alias
		SerializedBuckets [][][]byte `json:"SerializedBuckets"`
	}{
		Alias: (*Alias)(f),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	f.Buckets = deserializeBuckets(aux.SerializedBuckets)
	return nil
}

func deserializeBuckets(serializedBuckets [][][]byte) []*bucket {
	buckets := make([]*bucket, len(serializedBuckets))
	for i, sb := range serializedBuckets {
		bucketData := make([]fingerprint, len(sb))
		for j, fp := range sb {
			bucketData[j] = fingerprint(fp) // Convert []byte to fingerprint
		}
		buckets[i] = &bucket{Data: bucketData}
	}
	return buckets
}

func (b *bucket) IsFull() bool {
	// A bucket with no data is not full
	if len(b.Data) == 0 {
		return false
	}

	for _, fp := range b.Data {
		if len(fp) == 0 {
			return false
		}
	}
	return true
}

// randomFingerprint returns a random fingerprint from the bucket and removes it
func (b *bucket) randomFingerprint() fingerprint {
	rand.Seed(time.Now().UnixNano())
	var nonEmptyFingerprints []int
	for i, fp := range b.Data {
		if len(fp) != 0 {
			nonEmptyFingerprints = append(nonEmptyFingerprints, i)
		}
	}
	if len(nonEmptyFingerprints) == 0 {
		return nil
	}
	index := nonEmptyFingerprints[rand.Intn(len(nonEmptyFingerprints))]
	fp := b.Data[index]
	b.Data[index] = nil // Remove the fingerprint
	return fp
}

// delete a fingerprint from a bucket.
// Returns true if the fingerprint was present and successfully removed.
func (b *bucket) delete(fp fingerprint) bool {
	for i, tfp := range b.Data {
		if equalFingerprints(tfp, fp) {
			b.Data[i] = nil
			return true
		}
	}
	return false
}

func (b *bucket) contains(needle fingerprint) bool {
	for _, fp := range b.Data {
		if equalFingerprints(fp, needle) {
			return true
		}
	}
	return false
}

// reset deletes all fingerprints in the bucket.
func (b *bucket) reset() {
	b.Data = make([]fingerprint, 0, len(b.Data)) // Set to an empty slice with the same capacity
}

func equalFingerprints(a, b fingerprint) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// String returns a string representation of the bucket
func (b *bucket) String() string {
	var buf bytes.Buffer
	buf.WriteString("[")
	for _, fp := range b.Data {
		if len(fp) == 0 {
			buf.WriteString("null ")
		} else {
			buf.WriteString(fmt.Sprintf("%v ", fp))
		}
	}
	buf.WriteString("]")
	return buf.String()
}

func (b *bucket) Size() interface{} {
	return b.size
}

func (b *bucket) RandomFingerprint() interface{} {
	return b.randomFingerprint()
}

func (b *bucket) Delete(i []byte) bool {
	return b.delete(i)
}

func (b *bucket) Contains(i []byte) bool {
	return b.contains(i)
}

func (b *bucket) Reset() {
	b.reset()
}

// SmartContract provides the contract implementation for managing the cuckoo filter
type SmartContract struct {
	contractapi.Contract
}

// InitLedger initializes the ledger with a new cuckoo filter
func (s *SmartContract) InitLedger(ctx contractapi.TransactionContextInterface, numElements uint, bucketSize uint) error {
	filter := NewFilter(numElements, bucketSize)
	return s.saveFilterState(ctx, filter)
}

// Insert adds data to the cuckoo filter
func (s *SmartContract) Insert(ctx contractapi.TransactionContextInterface, data string) error {
	filter, err := s.LoadFilterState(ctx)
	if err != nil {
		return fmt.Errorf("error loading filter state: %v", err)
	}
	if !filter.Insert([]byte(data)) {
		return fmt.Errorf("failed to insert data '%s' into cuckoo filter", data)
	}
	return s.saveFilterState(ctx, filter)
}

func (s *SmartContract) BatchInsert(ctx contractapi.TransactionContextInterface, dataItems []string) error {
	filter, err := s.LoadFilterState(ctx)
	if err != nil {
		return fmt.Errorf("error loading filter state: %v", err)
	}
	successfulInserts := 0
	for _, data := range dataItems {
		if !filter.Insert([]byte(data)) {
			return fmt.Errorf("failed to insert data '%s' into cuckoo filter after %d successful insertions", data, successfulInserts)
		}
		successfulInserts++
	}
	if err := s.saveFilterState(ctx, filter); err != nil {
		return fmt.Errorf("error saving filter state after %d successful insertions: %v", successfulInserts, err)
	}
	return nil
}

// Lookup checks if data is present in the cuckoo filter
func (s *SmartContract) Lookup(ctx contractapi.TransactionContextInterface, data string) (bool, error) {
	filter, err := s.LoadFilterState(ctx)
	if err != nil {
		return false, err
	}

	return filter.Lookup([]byte(data)), nil
}

func (s *SmartContract) BatchLookup(ctx contractapi.TransactionContextInterface, dataItems []string) (map[string]bool, error) {
	filter, err := s.LoadFilterState(ctx)
	if err != nil {
		return nil, fmt.Errorf("error loading filter state: %v", err)
	}
	results := make(map[string]bool)
	for _, data := range dataItems {
		results[data] = filter.Lookup([]byte(data))
	}
	return results, nil
}

// Delete removes data from the cuckoo filter
func (s *SmartContract) Delete(ctx contractapi.TransactionContextInterface, data string) error {
	filter, err := s.LoadFilterState(ctx)
	if err != nil {
		return err
	}

	if !filter.Delete([]byte(data)) {
		return errors.New("failed to delete data from cuckoo filter")
	}

	return s.saveFilterState(ctx, filter)
}

func (s *SmartContract) BatchDelete(ctx contractapi.TransactionContextInterface, dataItems []string) error {
	filter, err := s.LoadFilterState(ctx)
	if err != nil {
		return fmt.Errorf("error loading filter state: %v", err)
	}
	for _, data := range dataItems {
		filter.Delete([]byte(data)) // Ignore the result; attempt to delete whether it exists or not
	}
	if err := s.saveFilterState(ctx, filter); err != nil {
		return fmt.Errorf("error saving filter state: %v", err)
	}
	return nil
}

// saveFilterState saves the current state of the cuckoo filter to the ledger
func (s *SmartContract) saveFilterState(ctx contractapi.TransactionContextInterface, filter *Filter) error {
	filterJSON, err := json.Marshal(filter)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState("CuckooFilterState", filterJSON)
}

// LoadFilterState retrieves the cuckoo filter state from the ledger
func (s *SmartContract) LoadFilterState(ctx contractapi.TransactionContextInterface) (*Filter, error) {
	filterJSON, err := ctx.GetStub().GetState("CuckooFilterState")
	if err != nil {
		return nil, err
	}
	if filterJSON == nil {
		return nil, errors.New("filter state not found")
	}

	var filter Filter
	err = json.Unmarshal(filterJSON, &filter)
	if err != nil {
		return nil, err
	}

	return &filter, nil
}

// NewFilter creates a new cuckoo filter with the specified number of elements
func NewFilter(numElements uint, bucketSize uint) *Filter {
	numBuckets := GetNextPow2(uint64(numElements))
	buckets := make([]*bucket, numBuckets)
	for i := range buckets {
		buckets[i] = NewBucket(bucketSize)
	}
	return &Filter{
		Buckets:         buckets,
		Count:           0,
		BucketIndexMask: uint(numBuckets - 1),
	}
}

// Lookup checks if the data is present in the cuckoo filter
func (f *Filter) Lookup(data []byte) bool {
	// Check if Buckets slice is initialized and not empty
	if f.Buckets == nil || len(f.Buckets) == 0 {
		return false
	}
	i1, fp := GetIndexAndFingerprint(data, f.BucketIndexMask, FingerPrintSize)
	if i1 >= uint(len(f.Buckets)) {
		return false
	}
	i2 := GetAltIndex(fp, i1, f.BucketIndexMask)
	if i2 >= uint(len(f.Buckets)) {
		return false
	}
	return f.Buckets[i1].contains(fp) || f.Buckets[i2].contains(fp)
}

// Delete removes data from the cuckoo filter
func (f *Filter) Delete(data []byte) bool {
	i1, fp := GetIndexAndFingerprint(data, f.BucketIndexMask, 8) // Assuming a fixed fingerprint size of 8
	i2 := GetAltIndex(fp, i1, f.BucketIndexMask)
	if f.Buckets[i1].delete(fp) || f.Buckets[i2].delete(fp) {
		f.Count--
		return true
	}
	return false
}

func (f *Filter) Reset() {
	for _, b := range f.Buckets {
		b.reset() // Clear each bucket
	}
	f.Count = 0 // Reset the count to zero
}

// Util.go
// GetAltIndex calculates the alternate index for a given fingerprint and index.
func GetAltIndex(fp []byte, i, bucketIndexMask uint) uint {
	hash := metro.Hash64(fp, 1337)
	return (i ^ uint(hash)) & bucketIndexMask
}

// GetFingerprint generates a fingerprint from a given hash value.
func GetFingerprint(data []byte, fingerprintSize uint) []byte {
	hash := metro.Hash64(data, 1337)
	fp := make([]byte, fingerprintSize)

	for i := uint(0); i < fingerprintSize; i++ {
		if i < 8 {
			fp[i] = byte(hash >> (8 * i))
		} else {
			// If the fingerprint size is larger than the hash size, pad with zeros.
			fp[i] = 0
		}
	}

	return fp
}

func deterministicSelector(data []byte, i1, i2 uint) uint {
	hash := metro.Hash64(data, 1337)
	if hash&1 == 0 {
		return i1
	}
	return i2
}

// GetIndexAndFingerprint calculates the primary bucket index and fingerprint for given data.
func GetIndexAndFingerprint(data []byte, bucketIndexMask uint, fingerprintSize uint) (uint, []byte) {
	fp := GetFingerprint(data, fingerprintSize)
	// Use least significant bits for deriving index.
	i1 := uint(metro.Hash64(data, 1337)) & bucketIndexMask
	return i1, fp
}

// GetNextPow2 calculates the next power of two greater than or equal to n.
func GetNextPow2(n uint64) uint {
	n--
	n |= n >> 1
	n |= n >> 2
	n |= n >> 4
	n |= n >> 8
	n |= n >> 16
	n |= n >> 32
	n++
	return uint(n)
}

// randi returns either i1 or i2 randomly.
func randi(i1, i2 uint) uint {
	rand.Seed(time.Now().UnixNano())
	if rand.Intn(2) == 0 {
		return i1
	}
	return i2
}

// Additional helper functions from util.go and bucket.go go here
