package sqlxadapter

import (
	"fmt"
	"strings"

	"github.com/jeromesth/go-better-auth/plugin"
	"github.com/jmoiron/sqlx"
)

// AutoMigrate creates tables defined by the given schemas if they don't exist.
// It uses CREATE TABLE IF NOT EXISTS so it is safe to call on each startup.
func AutoMigrate(db *sqlx.DB, schemas map[string]plugin.TableSchema) error {
	for table, schema := range schemas {
		if err := createTableIfNotExists(db, table, schema); err != nil {
			return err
		}
	}
	return nil
}

func createTableIfNotExists(db *sqlx.DB, table string, schema plugin.TableSchema) error {
	cols := make([]string, 0, len(schema.Fields))
	for _, f := range schema.Fields {
		col := fieldToSQL(db.DriverName(), f)
		cols = append(cols, col)
	}
	query := fmt.Sprintf(
		"CREATE TABLE IF NOT EXISTS %s (\n  %s\n)",
		table,
		strings.Join(cols, ",\n  "),
	)
	if _, err := db.Exec(query); err != nil {
		return fmt.Errorf("migrate table %s: %w", table, err)
	}
	return nil
}

func fieldToSQL(driver string, f plugin.FieldDef) string {
	sqlType := goTypeToSQL(driver, f.Type)
	col := fmt.Sprintf("%s %s", f.Name, sqlType)
	if f.Required {
		col += " NOT NULL"
	}
	if f.Unique {
		col += " UNIQUE"
	}
	if f.Name == "id" {
		col += " PRIMARY KEY"
	}
	return col
}

func goTypeToSQL(driver, typ string) string {
	switch typ {
	case "text", "string":
		return "TEXT"
	case "boolean", "bool":
		if driver == "postgres" {
			return "BOOLEAN"
		}
		return "INTEGER" // SQLite/MySQL use INTEGER for booleans
	case "integer", "int":
		return "INTEGER"
	case "timestamp", "time":
		if driver == "postgres" {
			return "TIMESTAMPTZ"
		}
		return "DATETIME"
	default:
		return "TEXT"
	}
}
