package orchestrator

import (
	"context"
	"sync"
)

// RunnerFactory creates an isolated Runner per task (e.g. a fresh Docker
// container / forge project), so concurrent attempts never share sandbox
// state.
type RunnerFactory func(task ExploitTask) Runner

// RunAll executes tasks concurrently, bounded by maxConcurrent (a cap on
// simultaneous sandbox containers / RPC calls), using the default retry
// budget. Result order matches task order; Result.Hypothesis.ID also
// identifies each.
func RunAll(ctx context.Context, spark Completer, newRunner RunnerFactory, tasks []ExploitTask, maxConcurrent int) []Result {
	return RunAllWith(ctx, spark, newRunner, tasks, maxConcurrent, MaxAttemptsDefault)
}

// RunAllWith is RunAll with an explicit per-task retry budget (maxAttempts
// <= 0 falls back to the default).
func RunAllWith(ctx context.Context, spark Completer, newRunner RunnerFactory, tasks []ExploitTask, maxConcurrent, maxAttempts int) []Result {
	if maxConcurrent < 1 {
		maxConcurrent = 1
	}
	if maxAttempts <= 0 {
		maxAttempts = MaxAttemptsDefault
	}
	sem := make(chan struct{}, maxConcurrent)
	results := make([]Result, len(tasks))
	var wg sync.WaitGroup

	for i, task := range tasks {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, task ExploitTask) {
			defer wg.Done()
			defer func() { <-sem }()
			loop := New(spark, newRunner(task))
			loop.MaxAttempts = maxAttempts
			results[i] = loop.Execute(ctx, task)
		}(i, task)
	}
	wg.Wait()
	return results
}
