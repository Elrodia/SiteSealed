import {
  createDatabasePool,
  resolveDatabaseConfig,
  runMigrations,
} from "./database.js";

async function migrate() {
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

migrate().catch((error) => {
  console.error(`SiteSealed MySQL migration failed: ${error.message}`);
  process.exitCode = 1;
});
