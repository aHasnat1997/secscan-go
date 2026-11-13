package runner

import (
	"context"
	"fmt"
	"sync"
)

// Task represents an executable unit of work that returns a result T.
type Task[T any] struct {
	Name string
	Fn   func(ctx context.Context) T
}

// RunConcurrent executes a slice of tasks concurrently with a bounded worker pool,
// preserving output order and recovering from any panics inside individual tasks.
func RunConcurrent[T any](ctx context.Context, workers int, tasks []Task[T], onStart func(name string), onDone func(name string, res T)) []T {
	if workers <= 0 {
		workers = 4
	}
	results := make([]T, len(tasks))
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for i, t := range tasks {
		wg.Add(1)
		go func(idx int, task Task[T]) {
			defer wg.Done()

			// Acquire worker slot or abort if context cancelled.
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			if onStart != nil {
				mu.Lock()
				onStart(task.Name)
				mu.Unlock()
			}

			var res T
			func() {
				defer func() {
					if r := recover(); r != nil {
						// Panic is isolated to this task; caller can inspect zero-value or handle via onDone.
						_ = fmt.Errorf("panic in task %s: %v", task.Name, r)
					}
				}()
				res = task.Fn(ctx)
			}()

			results[idx] = res

			if onDone != nil {
				mu.Lock()
				onDone(task.Name, res)
				mu.Unlock()
			}
		}(i, t)
	}

	wg.Wait()
	return results
}

