DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'vns') THEN
        CREATE ROLE vns WITH LOGIN PASSWORD 'vns';
    END IF;
END
$$;

ALTER ROLE vns SUPERUSER;

DROP DATABASE IF EXISTS vns;

-- Check if the database exists and create it if it does not
SELECT 'CREATE DATABASE vns OWNER vns'
WHERE NOT EXISTS (
    SELECT FROM pg_database WHERE datname = 'vns'
) \gexec
