\set ON_ERROR_STOP on

SELECT 'CREATE ROLE keycloak_owner LOGIN'
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'keycloak_owner')
\gexec
ALTER ROLE keycloak_owner WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD :'keycloak_password';

SELECT 'CREATE ROLE deviceidentity_migrator LOGIN'
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'deviceidentity_migrator')
\gexec
ALTER ROLE deviceidentity_migrator WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD :'migrator_password';

SELECT 'CREATE ROLE deviceidentity_app LOGIN'
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'deviceidentity_app')
\gexec
ALTER ROLE deviceidentity_app WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD :'app_password';

SELECT 'CREATE DATABASE keycloak OWNER keycloak_owner'
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'keycloak')
\gexec
SELECT 'CREATE DATABASE deviceidentity OWNER deviceidentity_migrator'
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'deviceidentity')
\gexec

REVOKE ALL ON DATABASE deviceidentity FROM PUBLIC;
GRANT CONNECT ON DATABASE deviceidentity TO deviceidentity_app;
\connect deviceidentity
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO deviceidentity_app;
