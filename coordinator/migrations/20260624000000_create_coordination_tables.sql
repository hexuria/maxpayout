-- 1. Coordination state table (tracks graduation and matrix cycles)
CREATE TABLE orchestrator_coordination_states (
    account_id UUID PRIMARY KEY,
    is_flushline_graduated BOOLEAN NOT NULL DEFAULT FALSE,
    is_matrix_cycled BOOLEAN NOT NULL DEFAULT FALSE,
    new_account_spawned BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Index to quickly query accounts qualified for free account spawning
CREATE INDEX idx_orchestrator_coordination_qualified 
ON orchestrator_coordination_states (is_flushline_graduated, is_matrix_cycled)
WHERE (is_flushline_graduated = TRUE AND is_matrix_cycled = TRUE AND new_account_spawned = FALSE);

-- 2. Idempotent Inbox Log (deduplication of consumed events)
CREATE TABLE orchestrator_inbox_log (
    event_id UUID PRIMARY KEY,
    event_type VARCHAR(50) NOT NULL,
    consumed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
