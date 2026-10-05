package store

import (
	"fmt"
	"strings"
)

// placeholder returns the bind marker for the index-th argument: $n on
// PostgreSQL, ? on SQLite.
func (store *Store) placeholder(index int) string {
	if store.driver == "postgres" {
		return fmt.Sprintf("$%d", index)
	}
	return "?"
}

// placeholders returns count comma-separated markers starting at the first.
func (store *Store) placeholders(count int) string {
	values := make([]string, count)
	for index := range count {
		values[index] = store.placeholder(index + 1)
	}
	return strings.Join(values, ", ")
}

// sqlBuilder collects the arguments of a query assembled in pieces. Bind
// appends a value and returns its marker, so markers always number in the
// order the values appear, which SQLite's positional ? needs.
type sqlBuilder struct {
	store     *Store
	arguments []any
}

func (store *Store) newSQLBuilder() *sqlBuilder {
	return &sqlBuilder{store: store}
}

func (builder *sqlBuilder) Bind(value any) string {
	builder.arguments = append(builder.arguments, value)
	return builder.store.placeholder(len(builder.arguments))
}

// Values binds one row of a multi-row INSERT and returns its tuple, such as
// "($1, $2, $3)".
func (builder *sqlBuilder) Values(row ...any) string {
	markers := make([]string, len(row))
	for index, value := range row {
		markers[index] = builder.Bind(value)
	}
	return "(" + strings.Join(markers, ", ") + ")"
}

// Args returns the bound values in order.
func (builder *sqlBuilder) Args() []any {
	return builder.arguments
}
