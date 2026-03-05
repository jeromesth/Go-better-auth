// Package memory provides an in-memory database adapter for testing.
package memory

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/jeromesth/go-better-auth/adapter"
)

// Adapter is a thread-safe in-memory database adapter.
type Adapter struct {
	mu     sync.RWMutex
	tables map[string][]map[string]any
}

// New creates a new in-memory adapter.
func New() *Adapter {
	return &Adapter{
		tables: make(map[string][]map[string]any),
	}
}

func (a *Adapter) table(model string) []map[string]any {
	if a.tables[model] == nil {
		a.tables[model] = []map[string]any{}
	}
	return a.tables[model]
}

func matchesQuery(record map[string]any, q adapter.Query) bool {
	for _, w := range q.Where {
		val, ok := record[w.Field]
		if !ok {
			return false
		}
		switch w.Operator {
		case "=":
			if fmt.Sprintf("%v", val) != fmt.Sprintf("%v", w.Value) {
				return false
			}
		case "!=":
			if fmt.Sprintf("%v", val) == fmt.Sprintf("%v", w.Value) {
				return false
			}
		case "like":
			pattern := strings.ReplaceAll(fmt.Sprintf("%v", w.Value), "%", "")
			if !strings.Contains(fmt.Sprintf("%v", val), pattern) {
				return false
			}
		}
	}
	return true
}

func copyRecord(r map[string]any) map[string]any {
	out := make(map[string]any, len(r))
	for k, v := range r {
		out[k] = v
	}
	return out
}

func (a *Adapter) FindOne(ctx context.Context, model string, q adapter.Query) (map[string]any, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	for _, rec := range a.table(model) {
		if matchesQuery(rec, q) {
			return copyRecord(rec), nil
		}
	}
	return nil, nil
}

func (a *Adapter) FindMany(ctx context.Context, model string, q adapter.Query) ([]map[string]any, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var results []map[string]any
	for _, rec := range a.table(model) {
		if matchesQuery(rec, q) {
			results = append(results, copyRecord(rec))
		}
	}

	if q.SortBy != "" {
		sort.Slice(results, func(i, j int) bool {
			vi := fmt.Sprintf("%v", results[i][q.SortBy])
			vj := fmt.Sprintf("%v", results[j][q.SortBy])
			if q.SortDir == "desc" {
				return vi > vj
			}
			return vi < vj
		})
	}

	if q.Offset > 0 && q.Offset < len(results) {
		results = results[q.Offset:]
	} else if q.Offset >= len(results) {
		return nil, nil
	}

	if q.Limit > 0 && q.Limit < len(results) {
		results = results[:q.Limit]
	}

	return results, nil
}

func (a *Adapter) Create(ctx context.Context, model string, data map[string]any) (map[string]any, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	rec := copyRecord(data)
	a.tables[model] = append(a.table(model), rec)
	return copyRecord(rec), nil
}

func (a *Adapter) Update(ctx context.Context, model string, q adapter.Query, data map[string]any) (map[string]any, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i, rec := range a.tables[model] {
		if matchesQuery(rec, q) {
			for k, v := range data {
				a.tables[model][i][k] = v
			}
			return copyRecord(a.tables[model][i]), nil
		}
	}
	return nil, nil
}

func (a *Adapter) Delete(ctx context.Context, model string, q adapter.Query) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	filtered := a.tables[model][:0]
	for _, rec := range a.tables[model] {
		if !matchesQuery(rec, q) {
			filtered = append(filtered, rec)
		}
	}
	a.tables[model] = filtered
	return nil
}

func (a *Adapter) CreateMany(ctx context.Context, model string, data []map[string]any) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, d := range data {
		a.tables[model] = append(a.table(model), copyRecord(d))
	}
	return nil
}

func (a *Adapter) UpdateMany(ctx context.Context, model string, q adapter.Query, data map[string]any) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i, rec := range a.tables[model] {
		if matchesQuery(rec, q) {
			for k, v := range data {
				a.tables[model][i][k] = v
			}
		}
	}
	return nil
}

func (a *Adapter) DeleteMany(ctx context.Context, model string, q adapter.Query) error {
	return a.Delete(ctx, model, q)
}

func (a *Adapter) Count(ctx context.Context, model string, q adapter.Query) (int64, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	var count int64
	for _, rec := range a.table(model) {
		if matchesQuery(rec, q) {
			count++
		}
	}
	return count, nil
}
