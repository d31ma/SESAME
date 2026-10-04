type SystemMetrics struct {
	UptimeSeconds      float64          `json:"uptime_seconds"`
	Goroutines         int64            `json:"goroutines"`
	HeapAllocatedBytes uint64           `json:"heap_alloc_bytes"`
	StorageConfigured  bool             `json:"storage_configured"`
	RequestsTotal      map[string]int64 `json:"requests_total"`
	ErrorsTotal        map[string]int64 `json:"errors_total"`
}
