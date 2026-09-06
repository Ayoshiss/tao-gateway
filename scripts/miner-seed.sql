-- The dataset every honest miner on netuid 554 serves.
--
-- Correctness is scored by agreement between miners, so honest miners have to
-- hold identical rows or they penalise each other for telling the truth. On the
-- testnet that makes this file part of the protocol rather than sample data:
-- change it and every miner still running the old copy looks like a liar.
--
-- It is also the clearest statement of what the testnet is not. A real
-- deployment has each miner reaching a customer's own database, where no two
-- miners see the same rows and consensus cannot be the correctness signal.
-- Replacing consensus with something that survives that is open work, and it is
-- tracked in ROADMAP.md rather than solved here.

CREATE TABLE customers (
    id    INTEGER PRIMARY KEY,
    email TEXT NOT NULL,
    plan  TEXT NOT NULL
);

INSERT INTO customers (id, email, plan) VALUES
    (1, 'ada@example.com',   'enterprise'),
    (2, 'grace@example.com', 'pro'),
    (3, 'alan@example.com',  'free');
