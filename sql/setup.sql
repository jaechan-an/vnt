DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'vns') THEN
        CREATE ROLE vns WITH LOGIN PASSWORD 'vns';
    END IF;
END $$;

-- Grant the CREATEDB privilege to the user
ALTER ROLE vns CREATEDB;

-- Check if the database exists and create it if it does not
SELECT 'CREATE DATABASE vns OWNER vns'
WHERE NOT EXISTS (
    SELECT FROM pg_database WHERE datname = 'vns'
) \gexec

-- Connect to the database
\c vns

DROP TABLE node_ips;
DROP TABLE node_connections;
DROP TABLE routes;
DROP TABLE all_logs;

-- Grant all privileges on the "public" schema to the user
GRANT ALL ON SCHEMA public TO vns;

-- Create the tables with ownership assigned to "vns"
CREATE TABLE IF NOT EXISTS node_ips (
    node_id SERIAL PRIMARY KEY,
    ip VARCHAR(15) NOT NULL UNIQUE,
    port INT NOT NULL
);

CREATE TABLE IF NOT EXISTS node_connections (
    from_node_id INTEGER NOT NULL REFERENCES node_ips(node_id) ON DELETE CASCADE,
    to_node_id INTEGER NOT NULL REFERENCES node_ips(node_id) ON DELETE CASCADE,
    PRIMARY KEY (from_node_id, to_node_id)
);

CREATE TABLE IF NOT EXISTS routes (
    id SERIAL PRIMARY KEY,
    src_ip VARCHAR(15) NOT NULL,  -- Source IP
    dst_ip VARCHAR(15) NOT NULL,  -- Destination IP
    node_ip VARCHAR(15) NOT NULL,  -- Routing IP (1 of N mapping)

    UNIQUE (src_ip, dst_ip, node_ip)
    -- PRIMARY KEY (src_ip, dst_ip, node_ip)
);

CREATE TABLE IF NOT EXISTS all_logs (
    id SERIAL PRIMARY KEY,
    src_ip VARCHAR(15) NOT NULL,
    dst_ip VARCHAR(15) NOT NULL,
    node_ip VARCHAR(15) NOT NULL,
    data INT NOT NULL,

    UNIQUE (src_ip, dst_ip, node_ip)
    -- PRIMARY KEY (src_ip, dst_ip, node_ip)
);

-- Change the owner of the tables to "vns"
ALTER TABLE node_ips OWNER TO vns;
ALTER TABLE node_connections OWNER TO vns;
ALTER TABLE routes OWNER TO vns;
ALTER TABLE all_logs OWNER TO vns;

-- Insert initial data into "node_ips"
INSERT INTO node_ips (node_id, ip, port) VALUES
    (0, '20.121.137.95', 11000), -- Master node
    (1, '172.210.11.93', 11000), -- node 1 (vns-node-1)
    (2, '48.217.241.39', 11000), -- node 2 (vns-node-2)
    (3, '20.62.166.184', 11000)  -- node 3 (vns-node-3)
ON CONFLICT DO NOTHING; -- Prevent duplicate insertion if the script is rerun

-- Insert initial data into "node_connections"
INSERT INTO node_connections (from_node_id, to_node_id) -- For master node
SELECT 0, node_id
FROM node_ips
WHERE node_id != 0
ON CONFLICT DO NOTHING;

INSERT INTO node_connections (from_node_id, to_node_id) VALUES
    (1, 0), -- Node 1 connected to Master node
    (2, 0), -- Node 2 connected to Master node
    (3, 0), -- Node 3 connected to Master node
    (1, 3), -- Node 1 connected to Node 3
    (3, 1), -- Node 3 connected to Node 1
    (2, 3), -- Node 2 connected to Node 3
    (3, 2)  -- Node 3 connected to Node 2
ON CONFLICT DO NOTHING;

INSERT INTO routes (src_ip, dst_ip, node_ip) VALUES
    ('1.1.1.1', '9.9.9.9', '172.210.11.93'), -- node 1
    ('1.1.1.1', '9.9.9.9', '48.217.241.39'), -- node 2
    ('1.1.1.1', '8.8.8.8', '172.210.11.93')  -- node 1
ON CONFLICT DO NOTHING;

INSERT INTO all_logs (src_ip, dst_ip, node_ip, data) VALUES
    ('1.1.1.1', '9.9.9.9', '172.210.11.93', 1),
    ('1.1.1.1', '9.9.9.9', '48.217.241.39', 2),
    ('1.1.1.1', '8.8.8.8', '172.210.11.93', 1)
ON CONFLICT DO NOTHING;

-- SELECT * FROM node_ips;
-- SELECT * FROM node_connections;
SELECT * FROM routes;
SELECT * FROM all_logs;
