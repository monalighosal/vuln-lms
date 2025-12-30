const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./lms.db');

db.all(`
  SELECT up.user_id, u.username, up.preferences 
  FROM user_preferences up
  JOIN users u ON up.user_id = u.id
`, (err, rows) => {
  if (err) {
    console.error('Error:', err);
  } else {
    console.log('Stored preferences:');
    if (rows.length === 0) {
      console.log('No preferences found in the database.');
    } else {
      rows.forEach(row => {
        console.log(`User ID: ${row.user_id} (${row.username}), Preferences: ${row.preferences}`);
      });
    }
  }
  db.close();
});