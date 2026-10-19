function handler(req) {
  const db = { query() {} };
  const raw = getUserInput();
  db.query(raw);
  const safe = escapeSql(req.query.name);
  db.query(safe);
  require('fs').readFile(safe);
}
