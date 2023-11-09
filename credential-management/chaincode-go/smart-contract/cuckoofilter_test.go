package cuckoofilter

import (
	"testing"
)

func TestNewFilter(t *testing.T) {
	filter := NewFilter(1000, DefaultBucketSize)
	if filter == nil {
		t.Error("Expected non-nil filter")
	}
}

func TestInsert(t *testing.T) {
	filter := NewFilter(1000, DefaultBucketSize)
	data := []byte("test data")
	success := filter.Insert(data)
	if !success {
		t.Error("Expected successful insertion")
	}
}

func TestLookup(t *testing.T) {
	filter := NewFilter(1000, DefaultBucketSize)
	data := []byte("test data")
	filter.Insert(data)
	found := filter.Lookup(data)
	if !found {
		t.Error("Expected data to be found")
	}
}

func TestDelete(t *testing.T) {
	filter := NewFilter(1000, DefaultBucketSize)
	data := []byte("test data")
	filter.Insert(data)
	success := filter.Delete(data)
	if !success {
		t.Error("Expected successful deletion")
	}
	notFound := filter.Lookup(data)
	if notFound {
		t.Error("Expected data to not be found after deletion")
	}
}

func TestInsertionFailure(t *testing.T) {
	filter := NewFilter(100, DefaultBucketSize) // Smaller filter for testing
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

	if insertionFailures == 0 {
		t.Errorf("Expected some insertions to fail, but all %d insertions succeeded", totalInsertions)
	}
}

func TestDeleteNonExistent(t *testing.T) {
	filter := NewFilter(1000, DefaultBucketSize)
	data := []byte("non-existent data")
	success := filter.Delete(data)
	if success {
		t.Error("Expected deletion of non-existent data to fail")
	}
}

// Additional tests for edge cases and other functionalities can be added here
