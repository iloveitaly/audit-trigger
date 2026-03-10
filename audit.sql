-- ============================================================================
-- FLEXIBLE POSTGRESQL AUDIT SYSTEM
-- ============================================================================
-- Supports TWO modes:
-- 1. DATABASE-LEVEL: All audit objects in dedicated 'audit' schema (default)
-- 2. SCHEMA-SPECIFIC: All audit objects within a specific schema
--
-- Usage:
--   Database-level:  SELECT audit_initialize();
--   Schema-specific: SELECT audit_initialize('myschema');
-- ============================================================================

-- ============================================================================
-- INITIALIZATION FUNCTION
-- ============================================================================
-- This function creates all audit objects in the specified schema
-- If no schema specified, defaults to 'audit' schema (database-level mode)
-- ============================================================================

CREATE OR REPLACE FUNCTION audit_initialize(
    p_audit_schema text DEFAULT 'audit'
)
RETURNS void AS $body$
DECLARE
    _sql text;
    _schema_exists boolean;
BEGIN
    -- Check if schema exists
    SELECT EXISTS(
        SELECT 1 FROM information_schema.schemata 
        WHERE schema_name = p_audit_schema
    ) INTO _schema_exists;
    
    -- Create schema if it doesn't exist (for database-level mode)
    IF NOT _schema_exists THEN
        IF p_audit_schema = 'audit' THEN
            EXECUTE format('CREATE SCHEMA %I', p_audit_schema);
            EXECUTE format('REVOKE ALL ON SCHEMA %I FROM public', p_audit_schema);
            EXECUTE format('COMMENT ON SCHEMA %I IS ''Audit/history logging tables and trigger functions''', p_audit_schema);
            RAISE NOTICE 'Created schema: %', p_audit_schema;
        ELSE
            RAISE EXCEPTION 'Schema % does not exist. Please create it first or use ''audit'' for database-level auditing.', p_audit_schema;
        END IF;
    ELSE
        RAISE NOTICE 'Using existing schema: %', p_audit_schema;
    END IF;

    -- ========================================================================
    -- Create logged_actions table
    -- ========================================================================
    _sql := format($sql$
        CREATE TABLE IF NOT EXISTS %I.logged_actions (
            event_id bigserial PRIMARY KEY,
            schema_name text NOT NULL,
            table_name text NOT NULL,
            relid oid NOT NULL,
            session_user_name text,
            action_tstamp_tx TIMESTAMP WITH TIME ZONE NOT NULL,
            action_tstamp_stm TIMESTAMP WITH TIME ZONE NOT NULL,
            action_tstamp_clk TIMESTAMP WITH TIME ZONE NOT NULL,
            transaction_id bigint,
            application_name text,
            client_addr inet,
            client_port integer,
            client_query text,
            action TEXT NOT NULL CHECK (action IN ('I', 'D', 'U', 'T')),
            row_data jsonb,
            changed_fields jsonb,
            statement_only boolean NOT NULL,
            row_id text
        )
    $sql$, p_audit_schema);
    EXECUTE _sql;
    
    _sql := format('REVOKE ALL ON %I.logged_actions FROM public', p_audit_schema);
    EXECUTE _sql;

    -- Create indexes
    _sql := format('CREATE INDEX IF NOT EXISTS logged_actions_relid_idx ON %I.logged_actions(relid)', p_audit_schema);
    EXECUTE _sql;
    
    _sql := format('CREATE INDEX IF NOT EXISTS logged_actions_action_tstamp_tx_stm_idx ON %I.logged_actions(action_tstamp_stm)', p_audit_schema);
    EXECUTE _sql;
    
    _sql := format('CREATE INDEX IF NOT EXISTS logged_actions_action_idx ON %I.logged_actions(action)', p_audit_schema);
    EXECUTE _sql;
    
    _sql := format('CREATE INDEX IF NOT EXISTS logged_actions_table_row_idx ON %I.logged_actions(table_name, row_id) WHERE row_id IS NOT NULL', p_audit_schema);
    EXECUTE _sql;

    -- ========================================================================
    -- Create logged_relations table
    -- ========================================================================
    _sql := format($sql$
        CREATE TABLE IF NOT EXISTS %I.logged_relations (
            relation_name regclass NOT NULL,
            uid_column text NOT NULL,
            PRIMARY KEY (relation_name, uid_column)
        )
    $sql$, p_audit_schema);
    EXECUTE _sql;

    -- ========================================================================
    -- Create get_transaction_id function
    -- ========================================================================
    _sql := format($sql$
        CREATE OR REPLACE FUNCTION %I.get_transaction_id()
        RETURNS bigint AS $func$
        BEGIN
            BEGIN
                RETURN pg_current_xact_id();
            EXCEPTION WHEN undefined_function THEN
                RETURN txid_current();
            END;
        END;
        $func$ LANGUAGE plpgsql STABLE
    $sql$, p_audit_schema);
    EXECUTE _sql;

    -- ========================================================================
    -- Create main trigger function
    -- ========================================================================
    _sql := format($sql$
        CREATE OR REPLACE FUNCTION %I.if_modified_func()
        RETURNS TRIGGER AS $trigger$
        DECLARE
            audit_row %I.logged_actions;
            excluded_cols text[] = ARRAY[]::text[];
            pk_col_names text[] = ARRAY[]::text[];
            pk_col_name text;
            pk_value text;
            composite_key_value text DEFAULT NULL;
            i integer;
            h_old jsonb;
            h_new jsonb;
        BEGIN
            IF TG_WHEN <> 'AFTER' THEN
                RAISE EXCEPTION '%%.if_modified_func() may only run as an AFTER trigger', '%s';
            END IF;

            -- Get primary key column names
            SELECT array_agg(a.attname ORDER BY array_position(i.indkey, a.attnum))
            INTO pk_col_names
            FROM pg_index i
            JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
            WHERE i.indrelid = (TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME)::regclass
              AND i.indisprimary;

            -- Build composite key value
            IF pk_col_names IS NOT NULL AND array_length(pk_col_names, 1) > 0 THEN
                composite_key_value := '';
                FOR i IN 1..array_length(pk_col_names, 1) LOOP
                    pk_col_name := pk_col_names[i];
                    IF TG_OP = 'INSERT' THEN
                        EXECUTE format('SELECT ($1).%%I::text', pk_col_name) INTO pk_value USING NEW;
                    ELSE
                        EXECUTE format('SELECT ($1).%%I::text', pk_col_name) INTO pk_value USING OLD;
                    END IF;
                    IF i > 1 THEN
                        composite_key_value := composite_key_value || '|';
                    END IF;
                    composite_key_value := composite_key_value || COALESCE(pk_value, 'NULL');
                END LOOP;
            ELSE
                IF TG_LEVEL = 'ROW' THEN
                    RAISE NOTICE '%%.if_modified_func: No primary key found for table %%.%%. Replay/rollback will not be available.', 
                        '%s', TG_TABLE_SCHEMA, TG_TABLE_NAME;
                END IF;
            END IF;

            -- Build audit row
            audit_row = ROW(
                nextval('%I.logged_actions_event_id_seq'),
                TG_TABLE_SCHEMA::text,
                TG_TABLE_NAME::text,
                TG_RELID,
                session_user::text,
                current_timestamp,
                statement_timestamp(),
                clock_timestamp(),
                %I.get_transaction_id(),
                current_setting('application_name'),
                inet_client_addr(),
                inet_client_port(),
                current_query(),
                substring(TG_OP, 1, 1),
                NULL,
                NULL,
                'f',
                composite_key_value
            );

            IF NOT TG_ARGV[0]::boolean IS DISTINCT FROM 'f'::boolean THEN
                audit_row.client_query = NULL;
            END IF;

            IF TG_ARGV[1] IS NOT NULL THEN
                excluded_cols = TG_ARGV[1]::text[];
            END IF;


            IF (TG_OP = 'UPDATE' AND TG_LEVEL = 'ROW') THEN
                h_old := to_jsonb(OLD);
                h_new := to_jsonb(NEW);
                
                IF array_length(excluded_cols, 1) > 0 THEN
                    h_old := h_old - excluded_cols;
                    h_new := h_new - excluded_cols;
                END IF;
                
                audit_row.row_data := h_old;
                
                SELECT jsonb_object_agg(n.key, n.value)
                INTO audit_row.changed_fields
                FROM jsonb_each(h_new) n
                WHERE h_old->n.key IS DISTINCT FROM n.value;
                
                audit_row.changed_fields := COALESCE(audit_row.changed_fields, '{}'::jsonb);
                
                -- Skip if no relevant changes
                IF audit_row.changed_fields = '{}'::jsonb THEN
                    RETURN NULL;
                END IF;

            ELSIF (TG_OP = 'DELETE' AND TG_LEVEL = 'ROW') THEN
                audit_row.row_data = to_jsonb(OLD) - excluded_cols;
            ELSIF (TG_OP = 'INSERT' AND TG_LEVEL = 'ROW') THEN
                audit_row.row_data = to_jsonb(NEW) - excluded_cols;
            ELSIF (TG_LEVEL = 'STATEMENT' AND TG_OP IN ('INSERT', 'UPDATE', 'DELETE', 'TRUNCATE')) THEN
                audit_row.statement_only = 't';
            ELSE
                RAISE EXCEPTION '[%%.if_modified_func] - Trigger func added as trigger for unhandled case: %%, %%', '%s', TG_OP, TG_LEVEL;
            END IF;

            INSERT INTO %I.logged_actions VALUES (audit_row.*);
            RETURN NULL;
        END;
        $trigger$
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
    $sql$, p_audit_schema, p_audit_schema, p_audit_schema, p_audit_schema, p_audit_schema, p_audit_schema, p_audit_schema, p_audit_schema, p_audit_schema);
    EXECUTE _sql;

    -- ========================================================================
    -- Create audit_table function
    -- ========================================================================
    _sql := format($sql$
        CREATE OR REPLACE FUNCTION %I.audit_table(
            target_table regclass,
            audit_rows boolean DEFAULT true,
            audit_query_text boolean DEFAULT true,
            audit_inserts boolean DEFAULT true,
            ignored_cols text[] DEFAULT ARRAY[]::text[]
        ) RETURNS void AS $func$
        DECLARE
            stm_targets text = 'INSERT OR UPDATE OR DELETE OR TRUNCATE';
            _q_txt text;
            _ignored_cols_snip text = '';
            pk_exists boolean;
        BEGIN
            EXECUTE 'DROP TRIGGER IF EXISTS audit_trigger_row ON ' || target_table;
            EXECUTE 'DROP TRIGGER IF EXISTS audit_trigger_stm ON ' || target_table;

            SELECT EXISTS (
                SELECT 1 FROM pg_index i
                WHERE i.indrelid = target_table AND i.indisprimary
            ) INTO pk_exists;

            IF NOT pk_exists THEN
                RAISE WARNING 'Table %% has no primary key. Audit logging will work but replay/rollback functions will not be available.', target_table;
            END IF;

            IF audit_rows THEN
                IF array_length(ignored_cols, 1) > 0 THEN
                    _ignored_cols_snip = ', ' || quote_literal(ignored_cols);
                END IF;
                _q_txt = 'CREATE TRIGGER audit_trigger_row AFTER ' ||
                         CASE WHEN audit_inserts THEN 'INSERT OR ' ELSE '' END ||
                         'UPDATE OR DELETE ON ' || target_table ||
                         ' FOR EACH ROW EXECUTE PROCEDURE %I.if_modified_func(' ||
                         quote_literal(audit_query_text) || _ignored_cols_snip || ');';
                RAISE NOTICE '%%', _q_txt;
                EXECUTE _q_txt;
                stm_targets = 'TRUNCATE';
            END IF;

            _q_txt = 'CREATE TRIGGER audit_trigger_stm AFTER ' || stm_targets || ' ON ' ||
                     target_table ||
                     ' FOR EACH STATEMENT EXECUTE PROCEDURE %I.if_modified_func(' ||
                     quote_literal(audit_query_text) || ');';
            RAISE NOTICE '%%', _q_txt;
            EXECUTE _q_txt;

            IF pk_exists THEN
                INSERT INTO %I.logged_relations (relation_name, uid_column)
                SELECT target_table, a.attname
                FROM pg_index i
                JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
                WHERE i.indrelid = target_table AND i.indisprimary
                ON CONFLICT (relation_name, uid_column) DO NOTHING;
            END IF;
        END;
        $func$ LANGUAGE plpgsql
    $sql$, p_audit_schema, p_audit_schema, p_audit_schema, p_audit_schema);
    EXECUTE _sql;

    -- ========================================================================
    -- Create deaudit_table function
    -- ========================================================================
    _sql := format($sql$
        CREATE OR REPLACE FUNCTION %I.deaudit_table(target_table regclass)
        RETURNS void AS $func$
        BEGIN
            EXECUTE 'DROP TRIGGER IF EXISTS audit_trigger_row ON ' || target_table;
            EXECUTE 'DROP TRIGGER IF EXISTS audit_trigger_stm ON ' || target_table;
            DELETE FROM %I.logged_relations WHERE relation_name = target_table;
            RAISE NOTICE 'Auditing removed from table %%', target_table;
        END;
        $func$ LANGUAGE plpgsql
    $sql$, p_audit_schema, p_audit_schema);
    EXECUTE _sql;

    -- ========================================================================
    -- Create replay_event function
    -- ========================================================================
    _sql := format($sql$
        CREATE OR REPLACE FUNCTION %I.replay_event(pevent_id bigint)
        RETURNS void AS $func$
        DECLARE
            query text;
            event record;
        BEGIN
            SELECT * INTO event FROM %I.logged_actions WHERE event_id = pevent_id;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'Event ID %% not found in %I.logged_actions', pevent_id;
            END IF;
            IF event.statement_only THEN
                RAISE EXCEPTION 'Cannot replay statement-level events (event_id: %%)', pevent_id;
            END IF;

            WITH pk_columns AS (
                SELECT array_agg(uid_column ORDER BY uid_column) AS columns
                FROM %I.logged_relations
                WHERE relation_name = (event.schema_name || '.' || event.table_name)::regclass
            ),
            where_clause AS (
                SELECT string_agg(
                    uid_column || ' = ' || quote_literal(event.row_data->>uid_column),
                    ' AND ' ORDER BY uid_column
                ) AS clause
                FROM %I.logged_relations
                WHERE relation_name = (event.schema_name || '.' || event.table_name)::regclass
            )
            SELECT INTO query
                CASE
                    WHEN event.action = 'I' THEN
                        'INSERT INTO ' || event.schema_name || '.' || event.table_name ||
                        ' (' || (SELECT string_agg(key, ', ') FROM jsonb_object_keys(event.row_data) AS key) || ') VALUES ' ||
                        '(' || (SELECT string_agg(
                            CASE WHEN value = 'null'::jsonb THEN 'NULL' ELSE quote_literal(value #>> '{}') END, ', '
                        ) FROM jsonb_each(event.row_data)) || ')'
                    WHEN event.action = 'D' THEN
                        'INSERT INTO ' || event.schema_name || '.' || event.table_name ||
                        ' (' || (SELECT string_agg(key, ', ') FROM jsonb_object_keys(event.row_data) AS key) || ') VALUES ' ||
                        '(' || (SELECT string_agg(
                            CASE WHEN value = 'null'::jsonb THEN 'NULL' ELSE quote_literal(value #>> '{}') END, ', '
                        ) FROM jsonb_each(event.row_data)) || ')'
                    WHEN event.action = 'U' THEN
                        'UPDATE ' || event.schema_name || '.' || event.table_name ||
                        ' SET ' || (SELECT string_agg(
                            key || ' = ' || CASE WHEN value = 'null'::jsonb THEN 'NULL' ELSE quote_literal(value #>> '{}') END, ', '
                        ) FROM jsonb_each(event.changed_fields)) ||
                        ' WHERE ' || (SELECT clause FROM where_clause)
                END
            FROM where_clause;

            IF query IS NULL THEN
                RAISE EXCEPTION 'Could not build replay query for event_id: %%. Table may not have primary key defined in %I.logged_relations.', pevent_id;
            END IF;

            RAISE NOTICE 'Executing: %%', query;
            EXECUTE query;
        END;
        $func$ LANGUAGE plpgsql
    $sql$, p_audit_schema, p_audit_schema, p_audit_schema, p_audit_schema, p_audit_schema, p_audit_schema);
    EXECUTE _sql;

    -- ========================================================================
    -- Create rollback_event function
    -- ========================================================================
    _sql := format($sql$
        CREATE OR REPLACE FUNCTION %I.rollback_event(pevent_id bigint)
        RETURNS void AS $func$
        DECLARE
            event record;
            last_event record;
            query text;
            pk_where_clause text;
        BEGIN
            SELECT * INTO event FROM %I.logged_actions WHERE event_id = pevent_id;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'Event ID %% not found in %I.logged_actions', pevent_id;
            END IF;
            IF event.statement_only THEN
                RAISE EXCEPTION 'Cannot rollback statement-level events (event_id: %%)', pevent_id;
            END IF;

            WITH pk_where AS (
                SELECT string_agg(
                    uid_column || ' = ' || quote_literal(event.row_data->>uid_column),
                    ' AND ' ORDER BY uid_column
                ) AS clause
                FROM %I.logged_relations
                WHERE relation_name = (event.schema_name || '.' || event.table_name)::regclass
            )
            SELECT clause INTO pk_where_clause FROM pk_where;

            IF pk_where_clause IS NULL THEN
                RAISE EXCEPTION 'Cannot rollback event %% - no primary key information found in %I.logged_relations', pevent_id;
            END IF;

            SELECT la.event_id INTO last_event
            FROM %I.logged_actions la
            WHERE la.schema_name = event.schema_name
              AND la.table_name = event.table_name
              AND la.row_id = event.row_id
              AND la.statement_only = false
            ORDER BY la.action_tstamp_clk DESC
            LIMIT 1;

            IF last_event.event_id != pevent_id THEN
                RAISE EXCEPTION 'Cannot rollback event %% - a more recent event (%%) exists for this row. Use row_id: %%', 
                    pevent_id, last_event.event_id, event.row_id;
            END IF;

            SELECT INTO query
                CASE
                    WHEN event.action = 'I' THEN
                        'DELETE FROM ' || event.schema_name || '.' || event.table_name ||
                        ' WHERE ' || pk_where_clause
                    WHEN event.action = 'D' THEN
                        'INSERT INTO ' || event.schema_name || '.' || event.table_name ||
                        ' (' || (SELECT string_agg(key, ', ') FROM jsonb_object_keys(event.row_data) AS key) || ') VALUES ' ||
                        '(' || (SELECT string_agg(
                            CASE WHEN value = 'null'::jsonb THEN 'NULL' ELSE quote_literal(value #>> '{}') END, ', '
                        ) FROM jsonb_each(event.row_data)) || ')'
                    WHEN event.action = 'U' THEN
                        'UPDATE ' || event.schema_name || '.' || event.table_name ||
                        ' SET ' || (SELECT string_agg(
                            key || ' = ' || CASE 
                                WHEN event.row_data->key = 'null'::jsonb THEN 'NULL' 
                                ELSE quote_literal(event.row_data->>key) 
                            END, ', '
                        ) FROM jsonb_object_keys(event.changed_fields) AS key) ||
                        ' WHERE ' || pk_where_clause
                END;

            IF query IS NULL THEN
                RAISE EXCEPTION 'Could not build rollback query for event_id: %%', pevent_id;
            END IF;

            RAISE NOTICE 'Executing rollback: %%', query;
            EXECUTE query;
        END;
        $func$ LANGUAGE plpgsql
    $sql$, p_audit_schema, p_audit_schema, p_audit_schema, p_audit_schema, p_audit_schema, p_audit_schema);
    EXECUTE _sql;

    -- ========================================================================
    -- Create audit_view function
    -- ========================================================================
    _sql := format($sql$
        CREATE OR REPLACE FUNCTION %I.audit_view(
            target_view regclass,
            audit_query_text boolean DEFAULT true,
            ignored_cols text[] DEFAULT ARRAY[]::text[],
            uid_cols text[] DEFAULT ARRAY[]::text[]
        ) RETURNS void AS $func$
        DECLARE
            _q_txt text;
            _ignored_cols_snip text = '';
        BEGIN
            EXECUTE 'DROP TRIGGER IF EXISTS audit_trigger_row ON ' || target_view;
            EXECUTE 'DROP TRIGGER IF EXISTS audit_trigger_stm ON ' || target_view;

            IF array_length(ignored_cols, 1) > 0 THEN
                _ignored_cols_snip = ', ' || quote_literal(ignored_cols);
            END IF;
            
            _q_txt = 'CREATE TRIGGER audit_trigger_row INSTEAD OF INSERT OR UPDATE OR DELETE ON ' ||
                     target_view::text ||
                     ' FOR EACH ROW EXECUTE PROCEDURE %I.if_modified_func(' ||
                     quote_literal(audit_query_text) || _ignored_cols_snip || ');';
            RAISE NOTICE '%%', _q_txt;
            EXECUTE _q_txt;

            INSERT INTO %I.logged_relations (relation_name, uid_column)
            SELECT target_view, unnest(uid_cols)
            ON CONFLICT (relation_name, uid_column) DO NOTHING;
        END;
        $func$ LANGUAGE plpgsql
    $sql$, p_audit_schema, p_audit_schema, p_audit_schema);
    EXECUTE _sql;

    -- ========================================================================
    -- Create utility view: tableslist
    -- ========================================================================
    _sql := format($sql$
        CREATE OR REPLACE VIEW %I.tableslist AS
        SELECT DISTINCT 
            triggers.trigger_schema AS schema,
            triggers.event_object_table AS auditedtable,
            CASE 
                WHEN EXISTS (
                    SELECT 1 FROM pg_index i
                    WHERE i.indrelid = (triggers.trigger_schema || '.' || triggers.event_object_table)::regclass
                      AND i.indisprimary
                ) THEN 'Yes'
                ELSE 'No (replay/rollback unavailable)'
            END AS has_primary_key
        FROM information_schema.triggers
        WHERE triggers.trigger_name IN ('audit_trigger_row', 'audit_trigger_stm')
        ORDER BY schema, auditedtable
    $sql$, p_audit_schema);
    EXECUTE _sql;

    -- ========================================================================
    -- Create get_row_history helper function
    -- ========================================================================
    _sql := format($sql$
        CREATE OR REPLACE FUNCTION %I.get_row_history(
            p_schema text,
            p_table text,
            p_row_id text
        )
        RETURNS TABLE (
            event_id bigint,
            action text,
            action_time timestamp with time zone,
            user_name text,
            old_values jsonb,
            new_values jsonb
        ) AS $func$
        BEGIN
            RETURN QUERY
            SELECT 
                la.event_id,
                CASE la.action
                    WHEN 'I' THEN 'INSERT'
                    WHEN 'U' THEN 'UPDATE'
                    WHEN 'D' THEN 'DELETE'
                    WHEN 'T' THEN 'TRUNCATE'
                END AS action,
                la.action_tstamp_clk,
                la.session_user_name,
                la.row_data,
                la.changed_fields
            FROM %I.logged_actions la
            WHERE la.schema_name = p_schema
              AND la.table_name = p_table
              AND la.row_id = p_row_id
              AND la.statement_only = false
            ORDER BY la.action_tstamp_clk;
        END;
        $func$ LANGUAGE plpgsql
    $sql$, p_audit_schema, p_audit_schema);
    EXECUTE _sql;

    RAISE NOTICE '========================================';
    RAISE NOTICE 'Audit system initialized in schema: %', p_audit_schema;
    RAISE NOTICE '========================================';
    RAISE NOTICE 'Available functions:';
    RAISE NOTICE '  - %.audit_table(regclass)', p_audit_schema;
    RAISE NOTICE '  - %.deaudit_table(regclass)', p_audit_schema;
    RAISE NOTICE '  - %.replay_event(bigint)', p_audit_schema;
    RAISE NOTICE '  - %.rollback_event(bigint)', p_audit_schema;
    RAISE NOTICE '  - %.audit_view(regclass, text[])', p_audit_schema;
    RAISE NOTICE '  - %.get_row_history(text, text, text)', p_audit_schema;
    RAISE NOTICE 'Available views:';
    RAISE NOTICE '  - %.tableslist', p_audit_schema;
    RAISE NOTICE 'Available tables:';
    RAISE NOTICE '  - %.logged_actions', p_audit_schema;
    RAISE NOTICE '  - %.logged_relations', p_audit_schema;
    RAISE NOTICE '========================================';

END;
$body$ LANGUAGE plpgsql;

COMMENT ON FUNCTION audit_initialize(text) IS $body$
Initialize the audit system in a specific schema.

Usage:
  -- Database-level auditing (creates 'audit' schema):
  SELECT audit_initialize();
  
  -- Schema-specific auditing (uses existing schema):
  SELECT audit_initialize('myschema');

Arguments:
  p_audit_schema: Schema name where audit objects will be created.
                  Defaults to 'audit' for database-level auditing.
                  For schema-specific auditing, the schema must already exist.
$body$;

-- ============================================================================
-- EXAMPLE USAGE
-- ============================================================================

/*
-- ============================================================================
-- MODE 1: DATABASE-LEVEL AUDITING (Default)
-- ============================================================================
-- All audit objects in dedicated 'audit' schema
-- Recommended for: Multi-schema databases, centralized audit management

-- Initialize
SELECT audit_initialize();  -- Creates 'audit' schema

-- Enable auditing on tables from any schema
SELECT audit.audit_table('public.users'::regclass);
SELECT audit.audit_table('sales.orders'::regclass);
SELECT audit.audit_table('hr.employees'::regclass);

-- Query centralized audit log
SELECT * FROM audit.logged_actions 
WHERE schema_name = 'public' AND table_name = 'users';

-- View all audited tables across all schemas
SELECT * FROM audit.tableslist;


-- ============================================================================
-- MODE 2: SCHEMA-SPECIFIC AUDITING
-- ============================================================================
-- All audit objects within a specific schema
-- Recommended for: Single-schema apps, isolated audit per business unit

-- First, create your schema if it doesn't exist
CREATE SCHEMA myapp;

-- Initialize audit system within that schema
SELECT audit_initialize('myapp');

-- Enable auditing on tables in the same schema
SELECT myapp.audit_table('myapp.users'::regclass);
SELECT myapp.audit_table('myapp.orders'::regclass);

-- Query schema-specific audit log
SELECT * FROM myapp.logged_actions 
WHERE table_name = 'users';

-- View audited tables in this schema
SELECT * FROM myapp.tableslist;


-- ============================================================================
-- MULTIPLE SCHEMA-SPECIFIC AUDIT SYSTEMS
-- ============================================================================
-- You can have separate audit systems for different schemas!

-- Sales department audit
CREATE SCHEMA sales;
SELECT audit_initialize('sales');
SELECT sales.audit_table('sales.orders'::regclass);
SELECT sales.audit_table('sales.customers'::regclass);

-- HR department audit (completely separate)
CREATE SCHEMA hr;
SELECT audit_initialize('hr');
SELECT hr.audit_table('hr.employees'::regclass);
SELECT hr.audit_table('hr.payroll'::regclass);

-- Each has its own audit tables and functions
SELECT * FROM sales.logged_actions;  -- Only sales data
SELECT * FROM hr.logged_actions;     -- Only HR data


-- ============================================================================
-- MIXING MODES
-- ============================================================================
-- You can even mix database-level and schema-specific auditing!

-- Database-level for shared/common tables
SELECT audit_initialize();
SELECT audit.audit_table('public.users'::regclass);

-- Schema-specific for isolated business units
CREATE SCHEMA finance;
SELECT audit_initialize('finance');
SELECT finance.audit_table('finance.transactions'::regclass);

-- Now you have:
--   - audit.logged_actions (database-level audit log)
--   - finance.logged_actions (finance-specific audit log)
*/
