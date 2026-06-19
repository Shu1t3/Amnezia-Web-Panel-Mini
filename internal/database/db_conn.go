package database

import (
	"database/sql"
	_ "embed"
	"fmt"
	"log"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schemaSQL string

var (
	DB    *sql.DB
	Query *Queries
)

func InitDB(dsn string) error {
	var err error
	DB, err = sql.Open("sqlite", dsn)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	if err := DB.Ping(); err != nil {
		return fmt.Errorf("failed to ping database: %w", err)
	}

	// PRAGMA journal_mode=WAL is recommended for SQLite
	if _, err := DB.Exec("PRAGMA journal_mode=WAL"); err != nil {
		return fmt.Errorf("failed to set journal_mode: %w", err)
	}

	if _, err := DB.Exec("PRAGMA foreign_keys=ON"); err != nil {
		return fmt.Errorf("failed to set foreign_keys: %w", err)
	}

	// Read and execute schema.sql to ensure tables exist
	if _, err := DB.Exec(schemaSQL); err != nil {
		return fmt.Errorf("failed to execute schema: %w", err)
	}

	Query = New(DB)

	return nil
}

func CloseDB() {
	if DB != nil {
		if err := DB.Close(); err != nil {
			log.Printf("Error closing DB: %v\n", err)
		}
	}
}
