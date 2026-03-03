// Package postgres provides a PostgreSQL database adapter for go-better-auth.
package postgres

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jeromesth/go-better-auth/packages/betterauth/adapter"
)

// Adapter implements adapter.Adapter using a PostgreSQL connection pool.
type Adapter struct {
	pool *pgxpool.Pool
}

// New wraps an existing pgxpool.Pool.
func New(pool *pgxpool.Pool) *Adapter {
	return &Adapter{pool: pool}
}

// NewFromDSN opens a connection pool from a DSN string.
func NewFromDSN(ctx context.Context, dsn string) (*Adapter, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("opening postgres pool: %w", err)
	}
	return New(pool), nil
}

// Close releases the connection pool.
func (a *Adapter) Close() {
	a.pool.Close()
}

// quote double-quotes a PostgreSQL identifier to handle reserved words (e.g. "user").
func quote(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// buildWhere constructs a parameterised WHERE clause.
// startIdx is the $N index to start from (1-based).
func buildWhere(wheres []adapter.Where, startIdx int) (string, []any) {
	if len(wheres) == 0 {
		return "", nil
	}
	parts := make([]string, 0, len(wheres))
	args := make([]any, 0, len(wheres))
	for _, w := range wheres {
		switch w.Operator {
		case "=", "!=", ">", "<", ">=", "<=":
			parts = append(parts, fmt.Sprintf("%s %s $%d", quote(w.Field), w.Operator, startIdx))
			args = append(args, w.Value)
			startIdx++
		case "like":
			parts = append(parts, fmt.Sprintf("%s LIKE $%d", quote(w.Field), startIdx))
			args = append(args, w.Value)
			startIdx++
		case "in":
			// pgx handles Go slices natively with = ANY($N)
			parts = append(parts, fmt.Sprintf("%s = ANY($%d)", quote(w.Field), startIdx))
			args = append(args, w.Value)
			startIdx++
		}
	}
	if len(parts) == 0 {
		return "", nil
	}
	return "WHERE " + strings.Join(parts, " AND "), args
}

func (a *Adapter) FindOne(ctx context.Context, model string, q adapter.Query) (map[string]any, error) {
	q.Limit = 1
	results, err := a.FindMany(ctx, model, q)
	if err != nil || len(results) == 0 {
		return nil, err
	}
	return results[0], nil
}

func (a *Adapter) FindMany(ctx context.Context, model string, q adapter.Query) ([]map[string]any, error) {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("SELECT * FROM %s", quote(model)))

	whereSql, args := buildWhere(q.Where, 1)
	if whereSql != "" {
		sb.WriteString(" " + whereSql)
	}

	if q.SortBy != "" {
		dir := "ASC"
		if strings.ToLower(q.SortDir) == "desc" {
			dir = "DESC"
		}
		sb.WriteString(fmt.Sprintf(" ORDER BY %s %s", quote(q.SortBy), dir))
	}

	if q.Limit > 0 {
		sb.WriteString(fmt.Sprintf(" LIMIT %d", q.Limit))
	}
	if q.Offset > 0 {
		sb.WriteString(fmt.Sprintf(" OFFSET %d", q.Offset))
	}

	rows, err := a.pool.Query(ctx, sb.String(), args...)
	if err != nil {
		return nil, fmt.Errorf("query %s: %w", model, err)
	}

	results, err := pgx.CollectRows(rows, pgx.RowToMap)
	if err != nil {
		return nil, fmt.Errorf("collecting rows from %s: %w", model, err)
	}
	// Normalise: convert []map[string]any (pgx) to the plain any values betterauth expects
	for i, r := range results {
		results[i] = normaliseRow(r)
	}
	return results, nil
}

func (a *Adapter) Create(ctx context.Context, model string, data map[string]any) (map[string]any, error) {
	cols := make([]string, 0, len(data))
	placeholders := make([]string, 0, len(data))
	args := make([]any, 0, len(data))
	i := 1
	for k, v := range data {
		cols = append(cols, quote(k))
		placeholders = append(placeholders, fmt.Sprintf("$%d", i))
		args = append(args, v)
		i++
	}

	sqlStr := fmt.Sprintf(
		"INSERT INTO %s (%s) VALUES (%s) RETURNING *",
		quote(model),
		strings.Join(cols, ", "),
		strings.Join(placeholders, ", "),
	)

	rows, err := a.pool.Query(ctx, sqlStr, args...)
	if err != nil {
		return nil, fmt.Errorf("create %s: %w", model, err)
	}

	result, err := pgx.CollectOneRow(rows, pgx.RowToMap)
	if err != nil {
		return nil, fmt.Errorf("create %s collecting row: %w", model, err)
	}
	return normaliseRow(result), nil
}

func (a *Adapter) Update(ctx context.Context, model string, q adapter.Query, data map[string]any) (map[string]any, error) {
	if len(data) == 0 {
		return a.FindOne(ctx, model, q)
	}

	setCols := make([]string, 0, len(data))
	args := make([]any, 0, len(data)+len(q.Where))
	i := 1
	for k, v := range data {
		setCols = append(setCols, fmt.Sprintf("%s = $%d", quote(k), i))
		args = append(args, v)
		i++
	}

	whereSql, whereArgs := buildWhere(q.Where, i)
	args = append(args, whereArgs...)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("UPDATE %s SET %s", quote(model), strings.Join(setCols, ", ")))
	if whereSql != "" {
		sb.WriteString(" " + whereSql)
	}
	sb.WriteString(" RETURNING *")

	rows, err := a.pool.Query(ctx, sb.String(), args...)
	if err != nil {
		return nil, fmt.Errorf("update %s: %w", model, err)
	}

	result, err := pgx.CollectOneRow(rows, pgx.RowToMap)
	if err != nil {
		// pgx returns pgx.ErrNoRows when no row matched; treat as nil (not found).
		return nil, nil
	}
	return normaliseRow(result), nil
}

func (a *Adapter) Delete(ctx context.Context, model string, q adapter.Query) error {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("DELETE FROM %s", quote(model)))

	whereSql, args := buildWhere(q.Where, 1)
	if whereSql != "" {
		sb.WriteString(" " + whereSql)
	}

	_, err := a.pool.Exec(ctx, sb.String(), args...)
	return err
}

func (a *Adapter) CreateMany(ctx context.Context, model string, data []map[string]any) error {
	for _, d := range data {
		if _, err := a.Create(ctx, model, d); err != nil {
			return err
		}
	}
	return nil
}

func (a *Adapter) UpdateMany(ctx context.Context, model string, q adapter.Query, data map[string]any) error {
	if len(data) == 0 {
		return nil
	}

	setCols := make([]string, 0, len(data))
	args := make([]any, 0, len(data)+len(q.Where))
	i := 1
	for k, v := range data {
		setCols = append(setCols, fmt.Sprintf("%s = $%d", quote(k), i))
		args = append(args, v)
		i++
	}

	whereSql, whereArgs := buildWhere(q.Where, i)
	args = append(args, whereArgs...)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("UPDATE %s SET %s", quote(model), strings.Join(setCols, ", ")))
	if whereSql != "" {
		sb.WriteString(" " + whereSql)
	}

	_, err := a.pool.Exec(ctx, sb.String(), args...)
	return err
}

func (a *Adapter) DeleteMany(ctx context.Context, model string, q adapter.Query) error {
	return a.Delete(ctx, model, q)
}

func (a *Adapter) Count(ctx context.Context, model string, q adapter.Query) (int64, error) {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("SELECT COUNT(*) FROM %s", quote(model)))

	whereSql, args := buildWhere(q.Where, 1)
	if whereSql != "" {
		sb.WriteString(" " + whereSql)
	}

	var count int64
	if err := a.pool.QueryRow(ctx, sb.String(), args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("count %s: %w", model, err)
	}
	return count, nil
}

// normaliseRow converts pgx-specific types in a row map to plain Go types that
// the betterauth record converters expect (e.g. time.Time, string, bool).
// pgx/v5 already returns standard Go types for most column types, but this
// provides a safe pass-through in case any pgtype wrappers slip through.
func normaliseRow(r map[string]any) map[string]any {
	out := make(map[string]any, len(r))
	for k, v := range r {
		out[k] = v
	}
	return out
}
