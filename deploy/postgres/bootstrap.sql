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

SELECT format('REVOKE %I FROM %I', granted.rolname, member.rolname)
FROM pg_auth_members membership
JOIN pg_roles granted ON granted.oid = membership.roleid
JOIN pg_roles member ON member.oid = membership.member
WHERE member.rolname IN ('keycloak_owner', 'deviceidentity_migrator', 'deviceidentity_app')
\gexec

SELECT 'CREATE DATABASE keycloak OWNER keycloak_owner'
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'keycloak')
\gexec
SELECT 'CREATE DATABASE deviceidentity OWNER deviceidentity_migrator'
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'deviceidentity')
\gexec

ALTER DATABASE keycloak OWNER TO keycloak_owner;
ALTER DATABASE deviceidentity OWNER TO deviceidentity_migrator;
REVOKE ALL ON DATABASE keycloak FROM PUBLIC;
REVOKE ALL ON DATABASE deviceidentity FROM PUBLIC;
GRANT CONNECT ON DATABASE keycloak TO keycloak_owner;

GRANT CONNECT ON DATABASE deviceidentity TO deviceidentity_app;
\connect deviceidentity
ALTER SCHEMA public OWNER TO deviceidentity_migrator;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM deviceidentity_app;
GRANT USAGE ON SCHEMA public TO deviceidentity_app;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM deviceidentity_app;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM deviceidentity_app;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM deviceidentity_app;
