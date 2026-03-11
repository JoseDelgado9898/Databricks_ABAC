-- Databricks notebook source
-- MAGIC %md
-- MAGIC # Attribute-Based Access Control (ABAC) Demo
-- MAGIC
-- MAGIC Demonstrates **governed tags** and **ABAC policies** in Unity Catalog to dynamically
-- MAGIC mask PII columns and filter rows based on data attributes.
-- MAGIC
-- MAGIC **Requirements:** DBR 16.4+ or Serverless | Account admin for governed tag creation

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## 1. Setup — Catalog, Schema, and Table

-- COMMAND ----------

-- MAGIC %md
-- MAGIC **1.1 Ensure you have a catalog created and set the catalog_param widget to the correct value**

-- COMMAND ----------

-- MAGIC %python
-- MAGIC dbutils.widgets.text("catalog_param", "abac")
-- MAGIC dbutils.widgets.text("schema_param", "pii")

-- COMMAND ----------

CREATE SCHEMA IF NOT EXISTS ${catalog_param}.${schema_param};


-- COMMAND ----------

USE CATALOG ${catalog_param};
USE SCHEMA ${schema_param}

-- COMMAND ----------

CREATE OR REPLACE TABLE customers (
  first_name   STRING,
  last_name    STRING,
  email        STRING,
  ssn          STRING,
  address      STRING,
  region       STRING
)
USING DELTA;

-- COMMAND ----------

INSERT INTO customers VALUES
  ('John',    'Doe',       'john.doe@example.com',     '123-45-6789', '123 Main St, New York, NY',                'US'),
  ('Jane',    'Smith',     'jane.smith@corp.net',      '234-56-7890', '456 Oak Ave, Los Angeles, CA',             'US'),
  ('Alice',   'Johnson',   'alice.j@mail.org',         '345-67-8901', '789 Pine Rd, Austin, TX',                  'US'),
  ('Bob',     'Brown',     'bob.brown@biz.io',         '456-78-9012', '321 Maple Dr, Miami, FL',                  'US'),
  ('Charlie', 'Davis',     'charlie.d@inbox.com',      '567-89-0123', '654 Cedar Ln, Chicago, IL',                'US'),
  ('Emily',   'White',     'emily.w@webmail.com',      '678-90-1234', '987 Birch Blvd, Seattle, WA',              'US'),
  ('Frank',   'Miller',    'frank.m@company.com',      '789-01-2345', '741 Spruce Way, Portland, OR',             'US'),
  ('Grace',   'Wilson',    'grace.w@startup.io',       '890-12-3456', '852 Elm Ct, Las Vegas, NV',                'US'),
  ('Hank',    'Moore',     'hank.moore@tech.co',       '901-23-4567', '963 Walnut St, Denver, CO',                'US'),
  ('Ivy',     'Taylor',    'ivy.t@design.net',         '012-34-5678', '159 Aspen Pl, Phoenix, AZ',                'US'),
  ('Liam',    'Connor',    'liam.c@dubmail.ie',        '111-22-3333', '12 Abbey Street, Dublin, Ireland EU',      'EU'),
  ('Sophie',  'Dubois',    'sophie.d@parismail.fr',    '222-33-4444', '45 Rue de Rivoli, Paris, France Europe',   'EU'),
  ('Hans',    'Mueller',   'hans.m@berlinpost.de',     '333-44-5555', '78 Berliner Str., Berlin, Germany E.U.',   'EU'),
  ('Elena',   'Rossi',     'elena.r@milanmail.it',     '444-55-6666', '23 Via Roma, Milan, Italy Europe',         'EU'),
  ('Johan',   'Andersson', 'johan.a@stockholmmail.se', '555-66-7777', '56 Drottninggatan, Stockholm, Sweden EU',  'EU');

-- COMMAND ----------

SELECT * FROM customers;

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## 2. Create the Governed Tag (UI Steps)
-- MAGIC
-- MAGIC 1. Click **Catalog** in the left sidebar
-- MAGIC 2. Click **Govern** → **Governed Tags**
-- MAGIC 3. Click **Create governed tag**
-- MAGIC 4. Tag key: **`pii`**
-- MAGIC 5. Allowed values: `ssn`, `email`, `address`
-- MAGIC 6. Click **Create**

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## 3. Apply Governed Tags to PII Columns

-- COMMAND ----------

ALTER TABLE customers ALTER COLUMN ssn     SET TAGS ('pii' = 'ssn');
ALTER TABLE customers ALTER COLUMN email   SET TAGS ('pii' = 'email');
ALTER TABLE customers ALTER COLUMN address SET TAGS ('pii' = 'address');

-- COMMAND ----------

SELECT column_name, tag_name, tag_value
FROM system.information_schema.column_tags
WHERE catalog_name = CURRENT_CATALOG()
  AND schema_name  = CURRENT_SCHEMA()
  AND table_name   = 'customers';

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## 4. Create UDFs — Masking and Row Filtering

-- COMMAND ----------

CREATE OR REPLACE FUNCTION mask_ssn(ssn STRING)
RETURNS STRING
RETURN CASE
  WHEN ssn IS NULL THEN NULL
  ELSE CONCAT('***-**-', RIGHT(REGEXP_REPLACE(ssn, '[^0-9]', ''), 4))
END;

-- COMMAND ----------

CREATE OR REPLACE FUNCTION mask_email(email STRING)
RETURNS STRING
RETURN CASE
  WHEN email IS NULL THEN NULL
  ELSE CONCAT('****@', SUBSTRING_INDEX(email, '@', -1))
END;

-- COMMAND ----------

CREATE OR REPLACE FUNCTION is_not_eu(address STRING)
RETURNS BOOLEAN
RETURN CASE
  WHEN LOWER(address) LIKE '%eu%'     THEN FALSE
  WHEN LOWER(address) LIKE '%e.u.%'   THEN FALSE
  WHEN LOWER(address) LIKE '%europe%' THEN FALSE
  ELSE TRUE
END;

-- COMMAND ----------

-- Quick UDF test
SELECT
  mask_ssn('123-45-6789')                        AS masked_ssn,
  mask_email('john@example.com')                  AS masked_email,
  is_not_eu('12 Abbey Street, Dublin, Ireland EU') AS eu_filtered;

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## 5. Policy Creation

-- COMMAND ----------

-- DBTITLE 1,Policy: Mask SSN
CREATE OR REPLACE POLICY mask_ssn_policy
ON CATALOG ${catalog_param}
COMMENT 'Mask SSN columns tagged pii:ssn'
COLUMN MASK mask_ssn
TO `account users`
FOR TABLES
MATCH COLUMNS hasTagValue('pii', 'ssn') AS ssn_col
ON COLUMN ssn_col;

-- COMMAND ----------

-- DBTITLE 1,Policy: Mask Email
CREATE OR REPLACE POLICY mask_email_policy
ON CATALOG ${catalog_param}
COMMENT 'Mask email columns tagged pii:email'
COLUMN MASK mask_email
TO `account users`
FOR TABLES
MATCH COLUMNS hasTagValue('pii', 'email') AS email_col
ON COLUMN email_col;

-- COMMAND ----------

-- DBTITLE 1,Policy: Hide EU Rows
CREATE OR REPLACE POLICY hide_eu_rows_policy
ON CATALOG ${catalog_param}
COMMENT 'Filter out EU rows based on address tag'
ROW FILTER is_not_eu
TO `account users`
FOR TABLES
MATCH COLUMNS hasTagValue('pii', 'address') AS addr_col
USING COLUMNS (addr_col);

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## 6. Verify after creating the policies

-- COMMAND ----------

-- SSN and email should be masked; EU rows should be hidden
SELECT * FROM customers;

-- COMMAND ----------

SHOW POLICIES ON CATALOG ${catalog_param};

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## 7. Cleanup
-- MAGIC **Run only when the demo is finished.**

-- COMMAND ----------

-- DROP FUNCTION IF EXISTS mask_ssn;
-- DROP FUNCTION IF EXISTS mask_email;
-- -- DROP FUNCTION IF EXISTS is_not_eu;

-- COMMAND ----------

-- drop schema ${catalog_param}.${schema_param} cascade;
