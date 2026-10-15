package main

import "github.com/jrsamsanchez/signalith/internal/shared"

// sharedMigrations are the one-time migrations of the cluster's levels:
// the server running the background jobs runs each once, when the cluster
// reaches its level, and records it in the cluster document (see
// shared.LevelMigration). Data a level moves into the shared settings is
// an importer's (sharedImporters) instead.
func sharedMigrations() []shared.LevelMigration {
	return []shared.LevelMigration{
		// Append a level's one-time migration here.
	}
}
