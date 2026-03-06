// Package sqlxadapter provides a sqlx-based database adapter supporting
// PostgreSQL, MySQL, and SQLite for go-better-auth.
package sqlxadapter

import (
	"context"
	"fmt"
	"strings"

	"github.com/jeromesth/go-better-auth/adapter"
	"github.com/jmoiron/sqlx"
)

// Adapter implements adapter.Adapter using sqlx.
type Adapter struct {
	db *sqlx.DB
}

// New creates a new sqlx adapter wrapping the given *sqlx.DB.
func New(db *sqlx.DB) *Adapter {
	return &Adapter{db: db}
}

// placeholder returns the appropriate positional placeholder for the driver.
// Postgres uses $N; everything else uses ?.
func (a *Adapter) placeholder(n int) string {
	if a.db.DriverName() == "postgres" {
		return fmt.Sprintf("$%d", n)
	}
	return "?"
}

// buildWhere builds a SQL WHERE clause from adapter.Query.Where conditions.
// Returns the clause (without the "WHERE" keyword) and bound values.
func (a *Adapter) buildWhere(q adapter.Query) (string, []any) {
	if len(q.Where) == 0 {
		return "", nil
	}
	parts := make([]string, 0, len(q.Where))
	vals := make([]any, 0, len(q.Where))
	for i, w := range q.Where {
		var op string
		switch strings.ToLower(w.Operator) {
		case "!=":
			op = "!="
		case ">":
			op = ">"
		case "<":
			op = "<"
		case ">=":
			op = ">="
		case "<=":
			op = "<="
		case "like":
			op = "LIKE"
		default:
			op = "="
		}
		parts = append(parts, fmt.Sprintf("%s %s %s", w.Field, op, a.placeholder(i+1)))
		vals = append(vals, w.Value)
	}
	return strings.Join(parts, " AND "), vals
}

// FindOne returns the first record matching query, or nil if not found.
func (a *Adapter) FindOne(ctx context.Context, model string, q adapter.Query) (map[string]any, error) {
	rows, err := a.findRows(ctx, model, q, 1)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return rows[0], nil
}

// FindMany returns all records matching query.
func (a *Adapter) FindMany(ctx context.Context, model string, q adapter.Query) ([]map[string]any, error) {
	return a.findRows(ctx, model, q, 0)
}

func (a *Adapter) findRows(ctx context.Context, model string, q adapter.Query, limit int) ([]map[string]any, error) {
	where, vals := a.buildWhere(q)

	query := fmt.Sprintf("SELECT * FROM %s", model)
	if where != "" {
		query += " WHERE " + where
	}
	if q.SortBy != "" {
		dir := "ASC"
		if strings.EqualFold(q.SortDir, "desc") {
			dir = "DESC"
		}
		query += fmt.Sprintf(" ORDER BY %s %s", q.SortBy, dir)
	}
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	} else if q.Limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", q.Limit)
	}
	if q.Offset > 0 {
		query += fmt.Sprintf(" OFFSET %d", q.Offset)
	}

	rows, err := a.db.QueryxContext(ctx, query, vals...)
	if err != nil {
		return nil, fmt.Errorf("findRows %s: %w", model, err)
	}
	defer rows.Close()

	var results []map[string]any
	for rows.Next() {
		row := make(map[string]any)
		if err := rows.MapScan(row); err != nil {
			return nil, fmt.Errorf("scanning row: %w", err)
		}
		// SQLite returns []byte for text columns; convert to string.
		for k, v := range row {
			if b, ok := v.([]byte); ok {
				row[k] = string(b)
			}
		}
		results = append(results, row)
	}
	return results, rows.Err()
}

// Create inserts a new record and returns it.
func (a *Adapter) Create(ctx context.Context, model string, data map[string]any) (map[string]any, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("create %s: no data provided", model)
	}

	cols := make([]string, 0, len(data))
	placeholders := make([]string, 0, len(data))
	vals := make([]any, 0, len(data))

	i := 1
	for col, val := range data {
		cols = append(cols, col)
		placeholders = append(placeholders, a.placeholder(i))
		vals = append(vals, val)
		i++
	}

	query := fmt.Sprintf(
		"INSERT INTO %s (%s) VALUES (%s)",
		model,
		strings.Join(cols, ", "),
		strings.Join(placeholders, ", "),
	)

	if _, err := a.db.ExecContext(ctx, query, vals...); err != nil {
		return nil, fmt.Errorf("create %s: %w", model, err)
	}

	return copyMap(data), nil
}

// Update applies data to the first record matching query. Returns updated record or nil.
func (a *Adapter) Update(ctx context.Context, model string, q adapter.Query, data map[string]any) (map[string]any, error) {
	if len(data) == 0 {
		return nil, nil
	}

	setCols := make([]string, 0, len(data))
	vals := make([]any, 0, len(data)+len(q.Where))
	i := 1
	for col, val := range data {
		setCols = append(setCols, fmt.Sprintf("%s = %s", col, a.placeholder(i)))
		vals = append(vals, val)
		i++
	}

	where, whereVals := a.buildWhereFrom(q, i)
	vals = append(vals, whereVals...)

	query := fmt.Sprintf("UPDATE %s SET %s", model, strings.Join(setCols, ", "))
	if where != "" {
		query += " WHERE " + where
	}

	if _, err := a.db.ExecContext(ctx, query, vals...); err != nil {
		return nil, fmt.Errorf("update %s: %w", model, err)
	}

	// Fetch the updated record to return it.
	return a.FindOne(ctx, model, q)
}

// Delete removes records matching query.
func (a *Adapter) Delete(ctx context.Context, model string, q adapter.Query) error {
	where, vals := a.buildWhere(q)
	query := fmt.Sprintf("DELETE FROM %s", model)
	if where != "" {
		query += " WHERE " + where
	}
	if _, err := a.db.ExecContext(ctx, query, vals...); err != nil {
		return fmt.Errorf("delete %s: %w", model, err)
	}
	return nil
}

// CreateMany inserts multiple records in a single transaction.
func (a *Adapter) CreateMany(ctx context.Context, model string, data []map[string]any) error {
	if len(data) == 0 {
		return nil
	}
	tx, err := a.db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("createMany %s: begin tx: %w", model, err)
	}
	for _, row := range data {
		cols := make([]string, 0, len(row))
		placeholders := make([]string, 0, len(row))
		vals := make([]any, 0, len(row))
		i := 1
		for col, val := range row {
			cols = append(cols, col)
			placeholders = append(placeholders, a.placeholder(i))
			vals = append(vals, val)
			i++
		}
		query := fmt.Sprintf(
			"INSERT INTO %s (%s) VALUES (%s)",
			model,
			strings.Join(cols, ", "),
			strings.Join(placeholders, ", "),
		)
		if _, err := tx.ExecContext(ctx, query, vals...); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("createMany %s: %w", model, err)
		}
	}
	return tx.Commit()
}

// UpdateMany applies data to all records matching query.
func (a *Adapter) UpdateMany(ctx context.Context, model string, q adapter.Query, data map[string]any) error {
	if len(data) == 0 {
		return nil
	}
	setCols := make([]string, 0, len(data))
	vals := make([]any, 0, len(data)+len(q.Where))
	i := 1
	for col, val := range data {
		setCols = append(setCols, fmt.Sprintf("%s = %s", col, a.placeholder(i)))
		vals = append(vals, val)
		i++
	}
	where, whereVals := a.buildWhereFrom(q, i)
	vals = append(vals, whereVals...)

	query := fmt.Sprintf("UPDATE %s SET %s", model, strings.Join(setCols, ", "))
	if where != "" {
		query += " WHERE " + where
	}
	if _, err := a.db.ExecContext(ctx, query, vals...); err != nil {
		return fmt.Errorf("updateMany %s: %w", model, err)
	}
	return nil
}

// DeleteMany removes all records matching query.
func (a *Adapter) DeleteMany(ctx context.Context, model string, q adapter.Query) error {
	return a.Delete(ctx, model, q)
}

// Count returns the number of records matching query.
func (a *Adapter) Count(ctx context.Context, model string, q adapter.Query) (int64, error) {
	where, vals := a.buildWhere(q)
	query := fmt.Sprintf("SELECT COUNT(*) FROM %s", model)
	if where != "" {
		query += " WHERE " + where
	}
	var count int64
	if err := a.db.QueryRowxContext(ctx, query, vals...).Scan(&count); err != nil {
		return 0, fmt.Errorf("count %s: %w", model, err)
	}
	return count, nil
}

// buildWhereFrom builds WHERE clause with placeholders starting at startN.
func (a *Adapter) buildWhereFrom(q adapter.Query, startN int) (string, []any) {
	if len(q.Where) == 0 {
		return "", nil
	}
	parts := make([]string, 0, len(q.Where))
	vals := make([]any, 0, len(q.Where))
	for i, w := range q.Where {
		var op string
		switch strings.ToLower(w.Operator) {
		case "!=":
			op = "!="
		case ">":
			op = ">"
		case "<":
			op = "<"
		case ">=":
			op = ">="
		case "<=":
			op = "<="
		case "like":
			op = "LIKE"
		default:
			op = "="
		}
		parts = append(parts, fmt.Sprintf("%s %s %s", w.Field, op, a.placeholder(startN+i)))
		vals = append(vals, w.Value)
	}
	return strings.Join(parts, " AND "), vals
}

func copyMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
