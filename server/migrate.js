import "./load-env.js";
import {
  createDatabasePool,
  resolveDatabaseConfig,
  runMigrations,
} from "./database.js";
import {
  createPostgresPool,
  resolvePostgresConfig,
  runPostgresMigrations,
} from "./audit.js";

async function migrateMysql() {
  const config = resolveDatabaseConfig(process.env);
  if (!config) {
    console.log(
      "MySQL is not configured; database migration skipped (optional mode).",
    );
    return;
  }

  const pool = createDatabasePool(config);
  try {
    const result = await runMigrations(pool);
    const summary =
      result.applied.length > 0
        ? result.applied.join(", ")
        : "schema already current";
    console.log(`SiteSealed MySQL migration complete: ${summary}.`);
  } finally {
    await pool.end();
  }
}

async function migratePostgres() {
  const config = resolvePostgresConfig(process.env);
  if (!config) {
    console.log(
      "PostgreSQL is not configured; audit migration skipped (optional mode).",
    );
    return;
  }

  const pool = createPostgresPool(config);
  try {
    const result = await runPostgresMigrations(pool);
    const summary =
      result.applied.length > 0
        ? result.applied.join(", ")
        : "schema already current";
    console.log(`SiteSealed PostgreSQL audit migration complete: ${summary}.`);
  } finally {
    await pool.end();
  }
}

Promise.all([migrateMysql(), migratePostgres()]).catch((error) => {
  console.error(`SiteSealed database migration failed: ${error.message}`);
  process.exitCode = 1;
});
