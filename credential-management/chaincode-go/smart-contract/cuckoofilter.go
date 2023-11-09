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

// Filter represents the cuckoo filter structure
type Filter struct {
	Buckets         []*bucket
	Count           uint
	BucketIndexMask uint
}

type bucket struct {
	data []fingerprint
	size uint
}

type fingerprint []byte

func newBucket(size uint) *bucket {
	return &bucket{
		data: make([]fingerprint, size),
		size: size,
	}
}

// insert a fingerprint into a bucket. Returns true if there was enough space and insertion succeeded.
func (f *Filter) Insert(data []byte) bool {
	i1, fp := getIndexAndFingerprint(data, f.BucketIndexMask, 8) // Assuming a fixed fingerprint size of 8
	i2 := getAltIndex(fp, i1, f.BucketIndexMask)

	if f.Buckets[i1].insert(fp) || f.Buckets[i2].insert(fp) {
		f.Count++
		return true
	}

	// Cuckoo Kicking Logic
	for i := 0; i < MaxCuckooKicks; i++ {
		j := randi(i1, i2)
		if f.Buckets[j].isFull() {
			continue // Skip this iteration if the selected bucket is full
		}

		fp, i1 = f.Buckets[j].randomFingerprint(), j
		i2 = getAltIndex(fp, i1, f.BucketIndexMask)

		if f.Buckets[i1].insert(fp) || f.Buckets[i2].insert(fp) {
			f.Count++
			return true
		}
	}

	// If we reach here, it means we couldn't find a spot after MaxCuckooKicks
	return false
}

func (b *bucket) insert(fp fingerprint) bool {
	for i, tfp := range b.data {
		if len(tfp) == 0 {
			b.data[i] = make(fingerprint, len(fp))
			copy(b.data[i], fp)
			return true
		}
	}
	return false
}

func (b *bucket) isFull() bool {
	for _, fp := range b.data {
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
	for i, fp := range b.data {
		if len(fp) != 0 {
			nonEmptyFingerprints = append(nonEmptyFingerprints, i)
		}
	}
	if len(nonEmptyFingerprints) == 0 {
		return nil
	}
	index := nonEmptyFingerprints[rand.Intn(len(nonEmptyFingerprints))]
	fp := b.data[index]
	b.data[index] = nil // Remove the fingerprint
	return fp
}

// delete a fingerprint from a bucket.
// Returns true if the fingerprint was present and successfully removed.
func (b *bucket) delete(fp fingerprint) bool {
	for i, tfp := range b.data {
		if equalFingerprints(tfp, fp) {
			b.data[i] = nil
			return true
		}
	}
	return false
}

func (b *bucket) contains(needle fingerprint) bool {
	for _, fp := range b.data {
		if equalFingerprints(fp, needle) {
			return true
		}
	}
	return false
}

// reset deletes all fingerprints in the bucket.
func (b *bucket) reset() {
	for i := range b.data {
		b.data[i] = nil
	}
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

func (b *bucket) String() string {
	var buf bytes.Buffer
	buf.WriteString("[")
	for _, fp := range b.data {
		if len(fp) == 0 {
			buf.WriteString("null ")
		} else {
			buf.WriteString(fmt.Sprintf("%v ", fp))
		}
	}
	buf.WriteString("]")
	return buf.String()
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
	filter, err := s.loadFilterState(ctx)
	if err != nil {
		return fmt.Errorf("error loading filter state: %v", err)
	}

	if !filter.Insert([]byte(data)) {
		return fmt.Errorf("failed to insert data '%s' into cuckoo filter", data)
	}

	return s.saveFilterState(ctx, filter)
}

// Lookup checks if data is present in the cuckoo filter
func (s *SmartContract) Lookup(ctx contractapi.TransactionContextInterface, data string) (bool, error) {
	filter, err := s.loadFilterState(ctx)
	if err != nil {
		return false, err
	}

	return filter.Lookup([]byte(data)), nil
}

// Delete removes data from the cuckoo filter
func (s *SmartContract) Delete(ctx contractapi.TransactionContextInterface, data string) error {
	filter, err := s.loadFilterState(ctx)
	if err != nil {
		return err
	}

	if !filter.Delete([]byte(data)) {
		return errors.New("failed to delete data from cuckoo filter")
	}

	return s.saveFilterState(ctx, filter)
}

// saveFilterState saves the current state of the cuckoo filter to the ledger
func (s *SmartContract) saveFilterState(ctx contractapi.TransactionContextInterface, filter *Filter) error {
	filterJSON, err := json.Marshal(filter)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState("CuckooFilterState", filterJSON)
}

// loadFilterState retrieves the cuckoo filter state from the ledger
func (s *SmartContract) loadFilterState(ctx contractapi.TransactionContextInterface) (*Filter, error) {
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
	numBuckets := getNextPow2(uint64(numElements))
	buckets := make([]*bucket, numBuckets)
	for i := range buckets {
		buckets[i] = newBucket(bucketSize)
	}
	return &Filter{
		Buckets:         buckets,
		Count:           0,
		BucketIndexMask: uint(numBuckets - 1),
	}
}

// Lookup checks if the data is present in the cuckoo filter
func (f *Filter) Lookup(data []byte) bool {
	i1, fp := getIndexAndFingerprint(data, f.BucketIndexMask, 8) // Assuming a fixed fingerprint size of 8
	i2 := getAltIndex(fp, i1, f.BucketIndexMask)
	return f.Buckets[i1].contains(fp) || f.Buckets[i2].contains(fp)
}

// Delete removes data from the cuckoo filter
func (f *Filter) Delete(data []byte) bool {
	i1, fp := getIndexAndFingerprint(data, f.BucketIndexMask, 8) // Assuming a fixed fingerprint size of 8
	i2 := getAltIndex(fp, i1, f.BucketIndexMask)
	if f.Buckets[i1].delete(fp) || f.Buckets[i2].delete(fp) {
		f.Count--
		return true
	}
	return false
}

// getAltIndex calculates the alternate index for a given fingerprint and index.
func getAltIndex(fp []byte, i, bucketIndexMask uint) uint {
	hash := metro.Hash64(fp, 1337)
	return (i ^ uint(hash)) & bucketIndexMask
}

// getFingerprint generates a fingerprint from a given hash value.
func getFingerprint(data []byte, fingerprintSize uint) []byte {
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

// getIndexAndFingerprint calculates the primary bucket index and fingerprint for given data.
func getIndexAndFingerprint(data []byte, bucketIndexMask uint, fingerprintSize uint) (uint, []byte) {
	fp := getFingerprint(data, fingerprintSize)
	// Use least significant bits for deriving index.
	i1 := uint(metro.Hash64(data, 1337)) & bucketIndexMask
	return i1, fp
}

// getNextPow2 calculates the next power of two greater than or equal to n.
func getNextPow2(n uint64) uint {
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
