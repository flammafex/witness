-- Add status column to attestations table
ALTER TABLE attestations ADD COLUMN status TEXT NOT NULL DEFAULT 'confirmed';

-- Index for pending lookups
CREATE INDEX IF NOT EXISTS idx_attestations_status ON attestations(status);

-- Log state table for O(1) STH computation
CREATE TABLE IF NOT EXISTS log_state (
    network_id TEXT PRIMARY KEY,
    current_root BLOB NOT NULL,
    tree_size INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
