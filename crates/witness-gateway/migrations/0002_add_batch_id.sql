ALTER TABLE attestations ADD COLUMN batch_id INTEGER REFERENCES batches(id);
