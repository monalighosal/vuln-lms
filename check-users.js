const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./lms.db');

db.all('SELECT id, username, password, email, role FROM users', (err, rows) => {
  if (err) {
    console.error('Error:', err);
  } else {
    console.log('Users in database:');
    rows.forEach(row => {
      console.log(`ID: ${row.id}, Username: ${row.username}, Password: ${row.password}, Email: ${row.email}, Role: ${row.role}`);
    });
  }
  db.close();
});