-- Durable, lease-based attestation jobs. The hash primary key remains the
-- global canonical reservation key; a tuple is never rewritten on retry.

ALTER TABLE attestations ADD COLUMN lease_token TEXT;
ALTER TABLE attestations ADD COLUMN lease_expires_at INTEGER;
ALTER TABLE attestations ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE attestations ADD COLUMN next_attempt_at INTEGER;
ALTER TABLE attestations ADD COLUMN last_error TEXT;
ALTER TABLE attestations ADD COLUMN completed_at INTEGER;

-- Preserve signed legacy results and make pending work immediately due and
-- unlocked. A legacy "confirmed" row is accepted only when it has an Ed25519
-- signature row (including the old BLS_AGGREGATED encoding) or a complete BLS
-- aggregate representation. Unsigned and unknown states become terminal rather
-- than being exposed as verified results.
UPDATE attestations
SET status = CASE
        WHEN status = 'confirmed' AND (
            EXISTS (
                SELECT 1 FROM signatures s
                WHERE s.hash = attestations.hash
                  AND (
                      (s.witness_id NOT LIKE 'BLS_AGGREGATED:%' AND length(s.signature) = 64)
                      OR (s.witness_id LIKE 'BLS_AGGREGATED:%' AND length(s.signature) = 96)
                  )
            )
            OR (
                EXISTS (
                    SELECT 1 FROM aggregated_signatures a
                    WHERE a.hash = attestations.hash
                      AND a.scheme = 'bls'
                      AND length(a.signature) = 96
                )
                AND EXISTS (
                    SELECT 1 FROM aggregated_signers a
                    WHERE a.hash = attestations.hash AND length(a.witness_id) > 0
                )
            )
        ) THEN 'confirmed'
        WHEN status = 'pending' THEN 'pending'
        ELSE 'failed'
    END,
    lease_token = NULL,
    lease_expires_at = NULL,
    next_attempt_at = CASE WHEN status = 'pending' THEN 0 ELSE NULL END,
    last_error = CASE
        WHEN status = 'pending' THEN NULL
        WHEN status = 'confirmed' AND NOT (
            EXISTS (
                SELECT 1 FROM signatures s
                WHERE s.hash = attestations.hash
                  AND (
                      (s.witness_id NOT LIKE 'BLS_AGGREGATED:%' AND length(s.signature) = 64)
                      OR (s.witness_id LIKE 'BLS_AGGREGATED:%' AND length(s.signature) = 96)
                  )
            )
            OR (
                EXISTS (
                    SELECT 1 FROM aggregated_signatures a
                    WHERE a.hash = attestations.hash
                      AND a.scheme = 'bls'
                      AND length(a.signature) = 96
                )
                AND EXISTS (
                    SELECT 1 FROM aggregated_signers a
                    WHERE a.hash = attestations.hash AND length(a.witness_id) > 0
                )
            )
        ) THEN 'legacy confirmed row has no signatures'
        WHEN status = 'confirmed' THEN NULL
        ELSE 'unsupported legacy attestation status'
    END,
    completed_at = CASE
        WHEN status = 'confirmed' AND (
            EXISTS (
                SELECT 1 FROM signatures s
                WHERE s.hash = attestations.hash
                  AND (
                      (s.witness_id NOT LIKE 'BLS_AGGREGATED:%' AND length(s.signature) = 64)
                      OR (s.witness_id LIKE 'BLS_AGGREGATED:%' AND length(s.signature) = 96)
                  )
            )
            OR (
                EXISTS (
                    SELECT 1 FROM aggregated_signatures a
                    WHERE a.hash = attestations.hash
                      AND a.scheme = 'bls'
                      AND length(a.signature) = 96
                )
                AND EXISTS (
                    SELECT 1 FROM aggregated_signers a
                    WHERE a.hash = attestations.hash AND length(a.witness_id) > 0
                )
            )
        ) THEN created_at
        ELSE NULL
    END;

-- Existing signed tuples cannot safely be renumbered. Refuse a migration with
-- duplicate tuples rather than invalidating signatures.
CREATE UNIQUE INDEX idx_attestations_network_sequence
ON attestations(network_id, sequence);

CREATE INDEX idx_attestation_jobs_due
ON attestations(status, next_attempt_at, lease_expires_at, sequence, hash);

-- Repair counters that lag canonical tuples, but never rewind a higher counter
-- left by an earlier deployment (including networks with no attestation rows).
UPDATE sequences
SET next_val = MAX(
    next_val,
    COALESCE((
        SELECT MAX(a.sequence)
        FROM attestations a
        WHERE a.network_id = sequences.network_id
    ), 0) + 1
);

INSERT INTO sequences(network_id, next_val)
SELECT network_id, MAX(sequence) + 1
FROM attestations
GROUP BY network_id
ON CONFLICT(network_id) DO NOTHING;

-- SQLite cannot add a CHECK constraint to the existing table without a table
-- rebuild (which would disturb foreign keys). Equivalent triggers reject any
-- future invalid durable state.
CREATE TRIGGER attestations_status_insert
BEFORE INSERT ON attestations
WHEN NEW.status NOT IN ('pending', 'retryable', 'confirmed', 'failed')
BEGIN
    SELECT RAISE(ABORT, 'invalid attestation job status');
END;

CREATE TRIGGER attestations_status_update
BEFORE UPDATE OF status ON attestations
WHEN NEW.status NOT IN ('pending', 'retryable', 'confirmed', 'failed')
BEGIN
    SELECT RAISE(ABORT, 'invalid attestation job status');
END;
