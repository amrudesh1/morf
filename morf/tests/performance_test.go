/*
Copyright [2023] [Amrudesh Balakrishnan]

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package tests

import (
	"context"
	"fmt"
	"morf/apk"
	"morf/utils"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

// PerformanceMetrics stores performance test results
type PerformanceMetrics struct {
	TestName      string
	APKSize       string
	TotalDuration time.Duration
	P50Latency    time.Duration
	P95Latency    time.Duration
	P99Latency    time.Duration
	MinLatency    time.Duration
	MaxLatency    time.Duration
	SuccessRate   float64
	ErrorCount    int
}

// calculatePercentile calculates the percentile latency from sorted durations
func calculatePercentile(durations []time.Duration, percentile float64) time.Duration {
	if len(durations) == 0 {
		return 0
	}
	index := int(float64(len(durations)) * percentile / 100.0)
	if index >= len(durations) {
		index = len(durations) - 1
	}
	return durations[index]
}

// TestPerformanceBaseline tests performance with different APK sizes
func TestPerformanceBaseline(t *testing.T) {
	// Skip if no test APKs available
	testAPKs := []struct {
		name string
		size string
		path string
	}{
		{"small", "5MB", "testdata/small.apk"},
		{"medium", "20MB", "testdata/medium.apk"},
		{"large", "100MB", "testdata/large.apk"},
	}

	var results []PerformanceMetrics

	for _, testAPK := range testAPKs {
		// Check if test APK exists
		if _, err := os.Stat(testAPK.path); os.IsNotExist(err) {
			t.Logf("Skipping %s APK test - file not found: %s", testAPK.size, testAPK.path)
			continue
		}

		t.Run(fmt.Sprintf("APK_%s", testAPK.size), func(t *testing.T) {
			metrics := runPerformanceTest(t, testAPK.path, testAPK.size, 10)
			results = append(results, metrics)
			printPerformanceMetrics(metrics)
		})
	}

	// Print summary
	if len(results) > 0 {
		printPerformanceSummary(results)
	}
}

// runPerformanceTest runs multiple iterations of APK scanning and collects metrics
func runPerformanceTest(t *testing.T, apkPath string, apkSize string, iterations int) PerformanceMetrics {
	var durations []time.Duration
	errorCount := 0

	log.WithFields(log.Fields{
		"apk_path":   apkPath,
		"apk_size":   apkSize,
		"iterations": iterations,
	}).Info("Starting performance test")

	for i := 0; i < iterations; i++ {
		start := time.Now()

		// Create job context
		jobCtx := utils.NewJobContext()
		if err := jobCtx.CreateWorkspace(); err != nil {
			t.Errorf("Failed to create workspace: %v", err)
			errorCount++
			continue
		}
		defer jobCtx.CleanupWorkspace()

		// Run extraction process (using internal function via test helper)
		// For now, we'll test the individual components
		_, _, _ = apk.ExtractMetadataAndPackageData(context.Background(), apkPath, jobCtx)
		results := apk.StartSecScan(apkPath, jobCtx)
		if results == nil {
			t.Logf("Iteration %d failed: no results returned", i+1)
			errorCount++
			continue
		}

		duration := time.Since(start)
		durations = append(durations, duration)

		log.WithFields(log.Fields{
			"iteration": i + 1,
			"duration":  duration,
		}).Debug("Performance test iteration completed")
	}

	// Calculate metrics
	sort.Slice(durations, func(i, j int) bool {
		return durations[i] < durations[j]
	})

	var totalDuration time.Duration
	for _, d := range durations {
		totalDuration += d
	}

	successRate := float64(len(durations)) / float64(iterations) * 100.0

	metrics := PerformanceMetrics{
		TestName:      fmt.Sprintf("APK_%s", apkSize),
		APKSize:       apkSize,
		TotalDuration: totalDuration,
		P50Latency:    calculatePercentile(durations, 50),
		P95Latency:    calculatePercentile(durations, 95),
		P99Latency:    calculatePercentile(durations, 99),
		MinLatency:    durations[0],
		MaxLatency:    durations[len(durations)-1],
		SuccessRate:   successRate,
		ErrorCount:    errorCount,
	}

	return metrics
}

// printPerformanceMetrics prints performance metrics for a single test
func printPerformanceMetrics(metrics PerformanceMetrics) {
	fmt.Printf("\n=== Performance Metrics: %s ===\n", metrics.TestName)
	fmt.Printf("APK Size: %s\n", metrics.APKSize)
	fmt.Printf("Total Duration: %v\n", metrics.TotalDuration)
	fmt.Printf("P50 Latency: %v\n", metrics.P50Latency)
	fmt.Printf("P95 Latency: %v\n", metrics.P95Latency)
	fmt.Printf("P99 Latency: %v\n", metrics.P99Latency)
	fmt.Printf("Min Latency: %v\n", metrics.MinLatency)
	fmt.Printf("Max Latency: %v\n", metrics.MaxLatency)
	fmt.Printf("Success Rate: %.2f%%\n", metrics.SuccessRate)
	fmt.Printf("Error Count: %d\n", metrics.ErrorCount)
	fmt.Println("=====================================")
}

// printPerformanceSummary prints summary of all performance tests
func printPerformanceSummary(results []PerformanceMetrics) {
	fmt.Printf("\n=== Performance Test Summary ===\n")
	fmt.Printf("Total Tests: %d\n", len(results))
	for _, result := range results {
		fmt.Printf("\n%s:\n", result.TestName)
		fmt.Printf("  P50: %v\n", result.P50Latency)
		fmt.Printf("  P95: %v\n", result.P95Latency)
		fmt.Printf("  P99: %v\n", result.P99Latency)
		fmt.Printf("  Success Rate: %.2f%%\n", result.SuccessRate)
	}
	fmt.Println("===============================")
}

// TestPerformanceParallelDecompile tests the performance improvement from parallel decompilation
func TestPerformanceParallelDecompile(t *testing.T) {
	// This test would compare sequential vs parallel decompilation
	// For now, it's a placeholder that verifies parallel decompilation works
	t.Log("Parallel decompilation is implemented in StartSecScan")
	t.Log("This test verifies that parallel decompilation completes successfully")

	// Create a test APK path (would need actual test APK)
	testAPK := "testdata/test.apk"
	if _, err := os.Stat(testAPK); os.IsNotExist(err) {
		t.Skip("Test APK not found, skipping parallel decompile test")
		return
	}

	jobCtx := utils.NewJobContext()
	if err := jobCtx.CreateWorkspace(); err != nil {
		t.Fatalf("Failed to create workspace: %v", err)
	}
	defer jobCtx.CleanupWorkspace()

	start := time.Now()
	results := apk.StartSecScan(testAPK, jobCtx)
	duration := time.Since(start)

	t.Logf("Parallel decompilation completed in %v", duration)
	t.Logf("Found %d secrets", len(results))

	if duration > 5*time.Minute {
		t.Errorf("Parallel decompilation took too long: %v", duration)
	}
}

// TestPerformanceBatchPatternScan tests the performance improvement from batch pattern scanning
func TestPerformanceBatchPatternScan(t *testing.T) {
	// This test verifies that batch pattern scanning works correctly
	t.Log("Batch pattern scanning is implemented in StartScan")
	t.Log("This test verifies that batch scanning completes successfully")

	// Point the scanner at the repo's pattern set. MED-hardcoded-paths made the
	// pattern directory configurable via MORF_PATTERNS_DIR (default /app/tools'
	// sibling /app/patterns, which only exists in the container image); without
	// this the scan loads zero patterns and finds nothing. Resolve the in-repo
	// patterns dir relative to this test package (morf/tests -> ../patterns).
	if abs, err := filepath.Abs("../patterns"); err == nil {
		t.Setenv("MORF_PATTERNS_DIR", abs)
	}

	// Create a test workspace
	jobCtx := utils.NewJobContext()
	if err := jobCtx.CreateWorkspace(); err != nil {
		t.Fatalf("Failed to create workspace: %v", err)
	}
	defer jobCtx.CleanupWorkspace()

	// Create a test file with some content
	testFile := filepath.Join(jobCtx.GetFilesDir(), "test.java")
	testContent := `public class Test {
		private String apiKey = "AKIAIOSFODNN7EXAMPLE";
		private String secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
	}`
	os.WriteFile(testFile, []byte(testContent), 0644)

	start := time.Now()
	results := apk.StartScan(jobCtx)
	duration := time.Since(start)

	t.Logf("Batch pattern scan completed in %v", duration)
	t.Logf("Found %d secrets", len(results))

	if len(results) == 0 {
		t.Error("Expected to find secrets in test file")
	}
}

// BenchmarkAPKScan benchmarks the APK scanning process
func BenchmarkAPKScan(b *testing.B) {
	testAPK := "testdata/benchmark.apk"
	if _, err := os.Stat(testAPK); os.IsNotExist(err) {
		b.Skip("Benchmark APK not found")
		return
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		jobCtx := utils.NewJobContext()
		jobCtx.CreateWorkspace()
		_, _, _ = apk.ExtractMetadataAndPackageData(context.Background(), testAPK, jobCtx)
		_ = apk.StartSecScan(testAPK, jobCtx)
		jobCtx.CleanupWorkspace()
	}
}

// BenchmarkPatternScan benchmarks the pattern scanning process
func BenchmarkPatternScan(b *testing.B) {
	jobCtx := utils.NewJobContext()
	jobCtx.CreateWorkspace()
	defer jobCtx.CleanupWorkspace()

	// Create test files
	for i := 0; i < 100; i++ {
		testFile := filepath.Join(jobCtx.GetFilesDir(), fmt.Sprintf("test%d.java", i))
		testContent := fmt.Sprintf(`public class Test%d {
			private String key = "AKIAIOSFODNN7EXAMPLE%d";
		}`, i, i)
		os.WriteFile(testFile, []byte(testContent), 0644)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		apk.StartScan(jobCtx)
	}
}
