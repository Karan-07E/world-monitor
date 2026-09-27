// Package metrics provides basic Prometheus-compatible metrics.
package metrics

import (
	"sync"
	"sync/atomic"
	"time"
)

// Metrics holds application-level counters and timing.
type Metrics struct {
	DecryptionsTotal         atomic.Int64
	WatermarkEmbeddingsTotal atomic.Int64
	WatermarkExtractionsTotal atomic.Int64
	AttributionSuccessTotal  atomic.Int64
	AttributionFailureTotal  atomic.Int64
	FabricTransactionsTotal  atomic.Int64
	CryptoOperations         sync.Map
}

// CryptoTiming records duration of a crypto operation.
type CryptoTiming struct {
	Operation string
	Duration  time.Duration
}

// Global metrics instance.
var Global = &Metrics{}

// RecordCryptoOp records a crypto operation's duration.
func (m *Metrics) RecordCryptoOp(operation string, d time.Duration) {
	m.CryptoOperations.Store(operation+"-last", d)
}

// Snapshot returns a snapshot of all metrics.
func (m *Metrics) Snapshot() map[string]interface{} {
	snap := map[string]interface{}{
		"decryptions_total":            m.DecryptionsTotal.Load(),
		"watermark_embeddings_total":   m.WatermarkEmbeddingsTotal.Load(),
		"watermark_extractions_total":  m.WatermarkExtractionsTotal.Load(),
		"attribution_success_total":    m.AttributionSuccessTotal.Load(),
		"attribution_failure_total":    m.AttributionFailureTotal.Load(),
		"fabric_transactions_total":    m.FabricTransactionsTotal.Load(),
	}
	m.CryptoOperations.Range(func(key, value interface{}) bool {
		snap[key.(string)] = value
		return true
	})
	return snap
}
