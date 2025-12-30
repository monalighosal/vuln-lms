const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const cors = require('cors');
const multer = require('multer');
const config = require('./config');
const fs = require('fs');
const security = require('./security');
const { updateSecurityMode } = require('./utils');

const app = express();
const PORT = config.PORT;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(session({
  secret: config.SESSION_SECRET,
  resave: false,
  saveUninitialized: true
}));
app.use(express.static(path.join(__dirname, 'public')));

// Serve CSS file
app.get('/style.css', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'style.css'));
});

// Set up SQLite database
const db = new sqlite3.Database('./lms.db');

// Create tables
db.serialize(() => {
  // Users table
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    email TEXT,
    role TEXT DEFAULT 'student',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Courses table
  db.run(`CREATE TABLE IF NOT EXISTS courses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT,
    instructor_id INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Enrollments table for access control
  db.run(`CREATE TABLE IF NOT EXISTS enrollments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    course_id INTEGER,
    enrolled_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id),
    FOREIGN KEY (course_id) REFERENCES courses (id),
    UNIQUE(user_id, course_id)
  )`);

  // Lessons table
  db.run(`CREATE TABLE IF NOT EXISTS lessons (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    course_id INTEGER,
    title TEXT NOT NULL,
    content TEXT,
    order_num INTEGER,
    FOREIGN KEY (course_id) REFERENCES courses (id)
  )`);

  // Assignments table
  db.run(`CREATE TABLE IF NOT EXISTS assignments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    course_id INTEGER,
    title TEXT NOT NULL,
    description TEXT,
    due_date DATETIME,
    FOREIGN KEY (course_id) REFERENCES courses (id)
  )`);

  // User progress table
  db.run(`CREATE TABLE IF NOT EXISTS user_progress (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    lesson_id INTEGER,
    completed BOOLEAN DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users (id),
    FOREIGN KEY (lesson_id) REFERENCES lessons (id)
  )`);

  // Certificates table
  db.run(`CREATE TABLE IF NOT EXISTS certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    course_id INTEGER,
    issued_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    certificate_code TEXT UNIQUE,
    FOREIGN KEY (user_id) REFERENCES users (id),
    FOREIGN KEY (course_id) REFERENCES courses (id)
  )`);

  // User preferences table
  db.run(`CREATE TABLE IF NOT EXISTS user_preferences (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER UNIQUE,
    preferences TEXT,
    FOREIGN KEY (user_id) REFERENCES users (id)
  )`);
});

// Middleware to check if user is logged in
function isLoggedIn(req, res, next) {
  if (req.session.user) {
    next();
  } else {
    res.redirect('/login');
  }
}

// Get current user info
app.get('/api/user', isLoggedIn, (req, res) => {
  // Return current user info
  res.json({
    id: req.session.user.id,
    username: req.session.user.username,
    email: req.session.user.email,
    role: req.session.user.role
  });
});

// Middleware to check if user is admin
function isAdmin(req, res, next) {
  if (req.session.user && req.session.user.role === 'admin') {
    next();
  } else {
    res.status(403).send('Access denied. Admin privileges required.');
  }
}

// Routes

// Home page
app.get('/', (req, res) => {
  if (req.session.user) {
    res.redirect('/dashboard');
  } else {
    res.redirect('/login');
  }
});

// Login page
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Login route - with SQL injection protection based on config
app.post('/login', (req, res) => {
  let { username, password } = req.body;
  
  if (config.SECURE_MODE) {
    // In secure mode, use parameterized queries to prevent SQL injection
    const query = `SELECT * FROM users WHERE username = ? AND password = ?`;
    
    db.get(query, [username, password], (err, user) => {
      if (err) {
        // In secure mode, don't expose internal error details
        console.error('Login error:', err);
        return res.status(500).json({ error: 'Internal server error' });
      }
      
      if (user) {
        req.session.user = user;
        res.redirect(`/dashboard/${user.id}`);
      } else {
        res.status(401).send('Invalid credentials');
      }
    });
  } else {
    // In vulnerable mode, use the original vulnerable code
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    
    db.get(query, (err, user) => {
      if (err) {
        // Information disclosure: exposing error details
        return res.status(500).json({ error: err.message });
      }
      
      if (user) {
        req.session.user = user;
        res.redirect(`/dashboard/${user.id}`);
      } else {
        res.status(401).send('Invalid credentials');
      }
    });
  }
});

// Registration page
app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

// Registration route - with SQL injection protection based on config
app.post('/register', (req, res) => {
  let { username, password, email } = req.body;
  
  if (config.SECURE_MODE) {
    // In secure mode, use parameterized queries to prevent SQL injection
    const query = `INSERT INTO users (username, password, email) VALUES (?, ?, ?)`;
    
    db.run(query, [username, password, email], function(err) {
      if (err) {
        // In secure mode, don't expose internal error details
        console.error('Registration error:', err);
        return res.status(500).json({ error: 'Registration failed' });
      }
      
      // Redirect to login after registration
      res.redirect('/login');
    });
  } else {
    // In vulnerable mode, use the original vulnerable code
    const query = `INSERT INTO users (username, password, email) VALUES ('${username}', '${password}', '${email}')`;
    
    db.run(query, function(err) {
      if (err) {
        // Information disclosure: exposing error details
        return res.status(500).json({ error: err.message });
      }
      
      // Redirect to login after registration
      res.redirect('/login');
    });
  }
});

// Dashboard - user-specific
app.get('/dashboard/:userId', isLoggedIn, (req, res) => {
  const userId = req.params.userId;
  
  // No access control - vulnerable to IDOR
  // Users can access any dashboard by changing the URL parameter
  
  res.sendFile(path.join(__dirname, 'public', 'user-dashboard.html'));
});

// Dashboard redirect for backward compatibility
app.get('/dashboard', isLoggedIn, (req, res) => {
  res.redirect(`/dashboard/${req.session.user.id}`);
});

// Courses page
app.get('/courses', isLoggedIn, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'courses.html'));
});

// Get all courses
app.get('/api/courses', isLoggedIn, (req, res) => {
  db.all('SELECT * FROM courses', (err, courses) => {
    if (err) {
      // Information disclosure: exposing error details
      return res.status(500).json({ error: err.message });
    }
    res.json(courses);
  });
});

// Get specific course by ID - with IDOR protection based on config
app.get('/api/courses/:id', isLoggedIn, (req, res) => {
  const courseId = req.params.id;
  
  if (config.SECURE_MODE) {
    // In secure mode, check if user has access to the course
    security.validateCourseAccess(req, courseId, db, (hasAccess) => {
      if (!hasAccess) {
        return res.status(403).json({ error: 'Access denied' });
      }
      
      // User has access, return the course
      db.get('SELECT * FROM courses WHERE id = ?', [courseId], (err, course) => {
        if (err) {
          // In secure mode, don't expose internal error details
          console.error('Course access error:', err);
          return res.status(500).json({ error: 'Internal server error' });
        }
        
        if (!course) {
          return res.status(404).json({ error: 'Course not found' });
        }
        
        res.json(course);
      });
    });
  } else {
    // In vulnerable mode, use the original vulnerable code
    db.get('SELECT * FROM courses WHERE id = ?', [courseId], (err, course) => {
      if (err) {
        // Information disclosure: exposing error details
        return res.status(500).json({ error: err.message });
      }
      
      if (!course) {
        return res.status(404).json({ error: 'Course not found' });
      }
      
      res.json(course);
    });
  }
});

// Get lessons for a course - with IDOR protection based on config
app.get('/api/courses/:courseId/lessons', isLoggedIn, (req, res) => {
  const courseId = req.params.courseId;
  
  if (config.SECURE_MODE) {
    // In secure mode, check if user has access to the course
    security.validateCourseAccess(req, courseId, db, (hasAccess) => {
      if (!hasAccess) {
        return res.status(403).json({ error: 'Access denied' });
      }
      
      // User has access, return the lessons
      db.all('SELECT * FROM lessons WHERE course_id = ?', [courseId], (err, lessons) => {
        if (err) {
          // In secure mode, don't expose internal error details
          console.error('Lessons access error:', err);
          return res.status(500).json({ error: 'Internal server error' });
        }
        
        res.json(lessons);
      });
    });
  } else {
    // In vulnerable mode, use the original vulnerable code
    db.all('SELECT * FROM lessons WHERE course_id = ?', [courseId], (err, lessons) => {
      if (err) {
        // Information disclosure: exposing error details
        return res.status(500).json({ error: err.message });
      }
      
      res.json(lessons);
    });
  }
});

// Get assignments for a course - with IDOR protection based on config
app.get('/api/courses/:courseId/assignments', isLoggedIn, (req, res) => {
  const courseId = req.params.courseId;
  
  if (config.SECURE_MODE) {
    // In secure mode, check if user has access to the course
    security.validateCourseAccess(req, courseId, db, (hasAccess) => {
      if (!hasAccess) {
        return res.status(403).json({ error: 'Access denied' });
      }
      
      // User has access, return the assignments
      db.all('SELECT * FROM assignments WHERE course_id = ?', [courseId], (err, assignments) => {
        if (err) {
          // In secure mode, don't expose internal error details
          console.error('Assignments access error:', err);
          return res.status(500).json({ error: 'Internal server error' });
        }
        
        res.json(assignments);
      });
    });
  } else {
    // In vulnerable mode, use the original vulnerable code
    db.all('SELECT * FROM assignments WHERE course_id = ?', [courseId], (err, assignments) => {
      if (err) {
        // Information disclosure: exposing error details
        return res.status(500).json({ error: err.message });
      }
      
      res.json(assignments);
    });
  }
});

// Get user progress - with IDOR protection based on config
app.get('/api/progress/:userId', isLoggedIn, (req, res) => {
  const userId = req.params.userId;
  
  if (config.SECURE_MODE) {
    // In secure mode, check if user has access to this progress data
    if (!security.validateUserAccess(req, userId)) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    // User has access, return the progress
    db.all(`
      SELECT up.*, l.title as lesson_title, c.title as course_title 
      FROM user_progress up
      JOIN lessons l ON up.lesson_id = l.id
      JOIN courses c ON l.course_id = c.id
      WHERE up.user_id = ?
    `, [userId], (err, progress) => {
      if (err) {
        // In secure mode, don't expose internal error details
        console.error('Progress access error:', err);
        return res.status(500).json({ error: 'Internal server error' });
      }
      
      res.json(progress);
    });
  } else {
    // In vulnerable mode, use the original vulnerable code
    db.all(`
      SELECT up.*, l.title as lesson_title, c.title as course_title 
      FROM user_progress up
      JOIN lessons l ON up.lesson_id = l.id
      JOIN courses c ON l.course_id = c.id
      WHERE up.user_id = ?
    `, [userId], (err, progress) => {
      if (err) {
        // Information disclosure: exposing error details
        return res.status(500).json({ error: err.message });
      }
      
      res.json(progress);
    });
  }
});

// Get user certificates - with IDOR protection based on config
app.get('/api/certificates/:userId', isLoggedIn, (req, res) => {
  const userId = req.params.userId;
  
  if (config.SECURE_MODE) {
    // In secure mode, check if user has access to this certificate data
    if (!security.validateUserAccess(req, userId)) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    // User has access, return the certificates
    db.all(`
      SELECT c.*, co.title as course_title 
      FROM certificates c
      JOIN courses co ON c.course_id = co.id
      WHERE c.user_id = ?
    `, [userId], (err, certificates) => {
      if (err) {
        // In secure mode, don't expose internal error details
        console.error('Certificates access error:', err);
        return res.status(500).json({ error: 'Internal server error' });
      }
      
      res.json(certificates);
    });
  } else {
    // In vulnerable mode, use the original vulnerable code
    db.all(`
      SELECT c.*, co.title as course_title 
      FROM certificates c
      JOIN courses co ON c.course_id = co.id
      WHERE c.user_id = ?
    `, [userId], (err, certificates) => {
      if (err) {
        // Information disclosure: exposing error details
        return res.status(500).json({ error: err.message });
      }
      
      res.json(certificates);
    });
  }
});

// Get user profile by ID - IDOR vulnerability
app.get('/api/users/:userId', isLoggedIn, (req, res) => {
  const userId = req.params.userId;
  
  // No access control - vulnerable to IDOR
  // Users can access any user profile by changing the URL parameter
  const query = 'SELECT id, username, email, role, created_at FROM users WHERE id = ?';
  
  db.get(query, [userId], (err, user) => {
    if (err) {
      // Information disclosure: exposing error details
      return res.status(500).json({ error: err.message });
    }
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json(user);
  });
});

// Update profile - with mass assignment protection based on config
app.put('/api/profile/:id', isLoggedIn, (req, res) => {
  let userId = req.params.id;
  let updates = req.body;
  
  // Check if user is updating their own profile or is admin
  if (req.session.user.id != userId && req.session.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied' });
  }
  
  // Always allow mass assignment (vulnerable mode)
  // Mass assignment vulnerability: no field validation
  let setClause = [];
  let values = [];
  
  for (const field in updates) {
    // This is vulnerable to mass assignment - any field can be updated
    setClause.push(`${field} = ?`);
    values.push(updates[field]);
  }
  
  if (setClause.length === 0) {
    return res.status(400).json({ error: 'No fields to update' });
  }
  
  // Add the user ID to the end of values array for WHERE clause
  values.push(userId);
  
  const query = `UPDATE users SET ${setClause.join(', ')} WHERE id = ?`;
  
  db.run(query, values, function(err) {
    if (err) {
      // Information disclosure: exposing error details
      return res.status(500).json({ error: err.message });
    }
    
    res.json({ message: 'Profile updated successfully', changes: this.changes });
  });
});

app.get('/admin', (req, res) => {
  // Always render dynamic admin panel without authentication (vulnerable mode)
  db.all('SELECT id, username, email, role, created_at FROM users', (err, users) => {
    if (err) {
      console.error('Error fetching users:', err);
      return res.status(500).send('Error loading users');
    }
    
    // Create dynamic admin panel HTML
    const html = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Panel - Vulnerable LMS</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="/style.css">
</head>
<body>
    <div class="sidebar">
        <div class="text-center mb-4">
            <h4><i class="fas fa-graduation-cap me-2"></i>Vulnerable LMS</h4>
            <p class="small mb-0">Security Training Platform</p>
        </div>
        <ul class="nav flex-column">
            <li class="nav-item">
                <a class="nav-link" href="/dashboard"><i class="fas fa-home me-2"></i>Dashboard</a>
            </li>
            <li class="nav-item">
                <a class="nav-link" href="/courses"><i class="fas fa-book me-2"></i>Courses</a>
            </li>
            <li class="nav-item">
                <a class="nav-link" href="/admin"><i class="fas fa-cogs me-2"></i>Admin Panel</a>
            </li>
            <li class="nav-item">
                <a class="nav-link" href="/logout"><i class="fas fa-sign-out-alt me-2"></i>Logout</a>
            </li>
        </ul>
    </div>

    <div class="main-content">
        <div class="alert alert-info">
            <h5><i class="fas fa-users-cog me-2"></i>User Management</h5>
            <p class="mb-0">Manage users in the system</p>
        </div>
        
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">User Management</h3>
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-striped">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Username</th>
                                <th>Email</th>
                                <th>Role</th>
                                <th>Created At</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${users.map(user => `
                            <tr>
                                <td>${user.id}</td>
                                <td>${user.username}</td>
                                <td>${user.email}</td>
                                <td>${user.role}</td>
                                <td>${user.created_at}</td>
                                <td>
                                    <button class="btn btn-sm btn-warning me-1" onclick="editUser(${user.id}, encodeURIComponent('${user.username}'), encodeURIComponent('${user.email}'), '${user.role}')">Edit</button>
                                    <button class="btn btn-sm btn-danger" onclick="deleteUser(${user.id})">Delete</button>
                                </td>
                            </tr>`).join('')}
                        </tbody>
                    </table>
                </div>
                
                <div class="mt-4">
                    <h4>${users.length} Users Found</h4>
                </div>
                
                <div class="mt-4" id="editForm" style="display:none;">
                    <h5>Edit User</h5>
                    <form id="editUserForm">
                        <input type="hidden" id="editUserId" name="userId">
                        <div class="mb-3">
                            <label for="editUsername" class="form-label">Username:</label>
                            <input type="text" class="form-control" id="editUsername" name="username" required>
                        </div>
                        <div class="mb-3">
                            <label for="editEmail" class="form-label">Email:</label>
                            <input type="email" class="form-control" id="editEmail" name="email" required>
                        </div>
                        <div class="mb-3">
                            <label for="editRole" class="form-label">Role:</label>
                            <select class="form-control" id="editRole" name="role">
                                <option value="student">student</option>
                                <option value="admin">admin</option>
                            </select>
                        </div>
                        <button type="submit" class="btn btn-primary">Update User</button>
                        <button type="button" class="btn btn-secondary" onclick="cancelEdit()">Cancel</button>
                    </form>
                </div>
            </div>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        let currentUserData = null;
        
        function editUser(id, username, email, role) {
            document.getElementById('editUserId').value = id;
            document.getElementById('editUsername').value = decodeURIComponent(username);
            document.getElementById('editEmail').value = decodeURIComponent(email);
            document.getElementById('editRole').value = role;
            document.getElementById('editForm').style.display = 'block';
            currentUserData = {id, username, email, role};
        }
        
        function cancelEdit() {
            document.getElementById('editForm').style.display = 'none';
            document.getElementById('editUserForm').reset();
            currentUserData = null;
        }
        
        function deleteUser(userId) {
            if (confirm('Are you sure you want to delete this user?')) {
                fetch('/api/users/' + userId, {
                    method: 'DELETE'
                })
                .then(response => {
                    if (response.ok) {
                        location.reload();
                    } else {
                        alert('Error deleting user');
                    }
                });
            }
        }
        
        document.getElementById('editUserForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const formData = new FormData(this);
            const userId = formData.get('userId');
            const userData = {
                username: formData.get('username'),
                email: formData.get('email'),
                role: formData.get('role')
            };
            
            fetch('/api/users/' + userId, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(userData)
            })
            .then(response => {
                if (response.ok) {
                    location.reload();
                } else {
                    alert('Error updating user');
                }
            });
        });
    </script>
</body>
</html>`;
    
    res.send(html);
  });
});

// Get all users - with access control based on config
app.get('/api/admin/users', isLoggedIn, (req, res) => {
  if (config.SECURE_MODE) {
    // In secure mode, check if user is actually an admin
    if (!req.session.user || req.session.user.role !== 'admin') {
      return res.status(403).json({ error: 'Access denied. Admin privileges required.' });
    }
    
    // User is admin, return users
    db.all('SELECT id, username, email, role, created_at FROM users', (err, users) => {
      if (err) {
        // In secure mode, don't expose internal error details
        console.error('Admin users access error:', err);
        return res.status(500).json({ error: 'Internal server error' });
      }
      res.json(users);
    });
  } else {
    // In vulnerable mode, use the original broken access control
    // Vulnerable: only checking if user is logged in, not if they are an admin
    if (!req.session.user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    
    // Broken access control: any logged in user can access this endpoint
    db.all('SELECT id, username, email, role, created_at FROM users', (err, users) => {
      if (err) {
        // Information disclosure: exposing error details
        return res.status(500).json({ error: err.message });
      }
      res.json(users);
    });
  }
});

// Preferences import - with deserialization protection based on config
app.post('/api/preferences/import', isLoggedIn, (req, res) => {
  if (config.SECURE_MODE) {
    try {
      // In secure mode, use safe parsing to prevent prototype pollution
      const preferences = security.safeParse(req.body.preferences);
      
      // Save preferences to database
      db.run(
        'INSERT OR REPLACE INTO user_preferences (user_id, preferences) VALUES (?, ?)',
        [req.session.user.id, JSON.stringify(preferences)],
        (err) => {
          if (err) {
            // In secure mode, don't expose internal error details
            console.error('Preferences import error:', err);
            return res.status(500).json({ error: 'Import failed' });
          }
          res.json({ message: 'Preferences updated successfully' });
        }
      );
    } catch (e) {
      // In secure mode, don't expose internal error details
      res.status(400).json({ error: 'Invalid preferences format' });
    }
  } else {
    try {
      // In vulnerable mode, use the original insecure code
      // Vulnerable: directly parsing user input without sanitization
      const preferences = JSON.parse(req.body.preferences);
      
      // Save preferences to database
      db.run(
        'INSERT OR REPLACE INTO user_preferences (user_id, preferences) VALUES (?, ?)',
        [req.session.user.id, JSON.stringify(preferences)],
        (err) => {
          if (err) {
            // Information disclosure: exposing error details
            return res.status(500).json({ error: err.message });
          }
          res.json({ message: 'Preferences updated successfully' });
        }
      );
    } catch (e) {
      // Information disclosure: exposing error details
      res.status(400).json({ error: e.message });
    }
  }
});

// Delete user - vulnerable to broken access control
app.delete('/api/users/:id', (req, res) => {
  const userId = req.params.id;

  if (!config.SECURE_MODE) {
    // In vulnerable mode: allow deletion without any authentication
    const query = 'DELETE FROM users WHERE id = ?';

    db.run(query, [userId], function(err) {
      if (err) {
        // Information disclosure: exposing error details
        return res.status(500).json({ error: err.message });
      }

      if (this.changes === 0) {
        return res.status(404).json({ error: 'User not found' });
      }

      res.json({ message: 'User deleted successfully', changes: this.changes });
    });
  } else {
    // In secure mode: check if user is admin
    if (req.session && req.session.user && req.session.user.role === 'admin') {
      const query = 'DELETE FROM users WHERE id = ?';
      
      db.run(query, [userId], function(err) {
        if (err) {
          // In secure mode, don't expose internal error details
          console.error('Delete user error:', err);
          return res.status(500).json({ error: 'Internal server error' });
        }
        
        if (this.changes === 0) {
          return res.status(404).json({ error: 'User not found' });
        }
        
        res.json({ message: 'User deleted successfully', changes: this.changes });
      });
    }
  }
});

// Get user preferences
app.get('/api/preferences', isLoggedIn, (req, res) => {
  db.get(
    'SELECT preferences FROM user_preferences WHERE user_id = ?',
    [req.session.user.id],
    (err, row) => {
      if (err) {
        // Information disclosure: exposing error details
        return res.status(500).json({ error: err.message });
      }
      try {
        res.json({ preferences: row ? JSON.parse(row.preferences) : {} });
      } catch (parseErr) {
        // Information disclosure: exposing parsing errors
        if (!config.SECURE_MODE) {
          return res.status(500).json({ error: parseErr.message });
        } else {
          console.error('Preferences parsing error:', parseErr);
          return res.status(500).json({ error: 'Internal server error' });
        }
      }
    }
  );
});

// Import user preferences - vulnerable to prototype pollution and code injection
app.post('/api/preferences/import', isLoggedIn, (req, res) => {
  try {
    // Insecure deserialization: directly parsing user input without sanitization
    if (!config.SECURE_MODE) {
      // Vulnerable code: unsafe parsing of user data
      const preferences = JSON.parse(req.body.preferences);
              
      // Additional vulnerability: unsafe object merging that could lead to prototype pollution
      // In real applications, preferences might be merged with existing objects
      const defaultPrefs = { theme: 'light', lang: 'en' };
      // Unsafe merge that could be exploited
      const mergedPrefs = Object.assign(defaultPrefs, preferences);
              
      // Store the potentially malicious preferences
      db.run(
        'INSERT OR REPLACE INTO user_preferences (user_id, preferences) VALUES (?, ?)',
        [req.session.user.id, JSON.stringify(mergedPrefs)],
        (err) => {
          if (err) {
            // Information disclosure: exposing error details
            return res.status(500).json({ error: err.message });
          }
          res.json({ message: 'Preferences imported successfully' });
        }
      );
    } else {
      // In secure mode, validate and sanitize the input
      const parsed = JSON.parse(req.body.preferences);
      
      // Sanitize the input to prevent prototype pollution
      const sanitized = security.safeParse(parsed);
      
      db.run(
        'INSERT OR REPLACE INTO user_preferences (user_id, preferences) VALUES (?, ?)',
        [req.session.user.id, JSON.stringify(sanitized)],
        (err) => {
          if (err) {
            // In secure mode, don't expose internal error details
            console.error('Preferences import error:', err);
            return res.status(500).json({ error: 'Internal server error' });
          }
          res.json({ message: 'Preferences imported successfully' });
        }
      );
    }
  } catch (error) {
    // Information disclosure: exposing error details in vulnerable mode
    if (!config.SECURE_MODE) {
      return res.status(500).json({ error: error.message });
    } else {
      console.error('Preferences import error:', error);
      return res.status(500).json({ error: 'Invalid preferences format' });
    }
  }
});

// User profile page - IDOR vulnerability
app.get('/user/:userId', isLoggedIn, (req, res) => {
  const userId = req.params.userId;
  
  // In vulnerable mode, allow access to any user's profile
  if (!config.SECURE_MODE) {
    // XSS Vulnerability: Display user comments without sanitization
    const userComments = req.session.userComments || [];
    const commentsHtml = userComments.map(comment => `<div class="comment">${comment}</div>`).join('');
    
    // Read the original HTML file
    let profileHtml = fs.readFileSync(path.join(__dirname, 'public', 'user-profile.html'), 'utf8');
    
    // Inject comments into the profile page - VULNERABLE TO XSS
    profileHtml = profileHtml.replace('<!-- COMMENTS_SECTION -->', `<div class="comments-section"><h3>User Comments</h3>${commentsHtml}<form action="/api/comment" method="POST" class="mt-3"><div class="mb-3"><label for="comment" class="form-label">Add Comment:</label><textarea class="form-control" id="comment" name="comment" rows="3" required></textarea></div><button type="submit" class="btn btn-primary">Submit Comment</button></form></div>`);
    
    res.send(profileHtml);
  } else {
    // In secure mode, check if user has access
    if (!security.validateUserAccess(req, userId)) {
      return res.status(403).send('Access denied');
    }
    // Secure mode: Sanitize comments before displaying
    const userComments = req.session.userComments || [];
    // Basic sanitization to prevent XSS in secure mode
    const sanitizedComments = userComments.map(comment => {
      return comment.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
    });
    const commentsHtml = sanitizedComments.map(comment => `<div class="comment">${comment}</div>`).join('');
    
    // Read the original HTML file
    let profileHtml = fs.readFileSync(path.join(__dirname, 'public', 'user-profile.html'), 'utf8');
    
    // Inject sanitized comments into the profile page
    profileHtml = profileHtml.replace('<!-- COMMENTS_SECTION -->', `<div class="comments-section"><h3>User Comments</h3>${commentsHtml}<form action="/api/comment" method="POST" class="mt-3"><div class="mb-3"><label for="comment" class="form-label">Add Comment:</label><textarea class="form-control" id="comment" name="comment" rows="3" required></textarea></div><button type="submit" class="btn btn-primary">Submit Comment</button></form></div>`);
    
    res.send(profileHtml);
  }
});

// Preferences page
app.get('/preferences', isLoggedIn, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'preferences.html'));
});



// Logout
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

// Route to get all users
app.get('/api/users', (req, res) => {
  // Always return all users without authentication (vulnerable mode)
  db.all('SELECT id, username, email, role, created_at FROM users', (err, users) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(users);
  });
});

// Route to delete a user
app.delete('/api/users/:userId', (req, res) => {
  const userId = req.params.userId;

  // Always allow deletion without authentication (vulnerable mode)
  db.run('DELETE FROM users WHERE id = ?', [userId], function(err) {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json({ message: 'User deleted', changes: this.changes });
  });
});


// Route to update a user (should require authentication but doesn't)
app.put('/api/users/:userId', (req, res) => {
  const userId = req.params.userId;
  const { username, email, role } = req.body;
  
  // Always allow updates without authentication (vulnerable mode)
  // Mass assignment vulnerability - allows updating any user field
  db.run('UPDATE users SET username = ?, email = ?, role = ? WHERE id = ?', [username, email, role, userId], function(err) {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json({ message: 'User updated', changes: this.changes });
  });
});

// XSS Vulnerability - User comments
// Route to submit a comment (vulnerable to XSS)
app.post('/api/comment', isLoggedIn, (req, res) => {
  const { comment } = req.body;
  
  // Vulnerable: storing comment without sanitization
  // In secure mode, this would be sanitized, but in vulnerable mode it's not
  if (!config.SECURE_MODE) {
    // Store comment directly without sanitization - XSS vulnerability
    if (!req.session.userComments) {
      req.session.userComments = [];
    }
    req.session.userComments.push(comment);
    res.redirect('/user/' + req.session.user.id);
  } else {
    // In secure mode, we would sanitize the input
    const sanitizedComment = comment.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
    if (!req.session.userComments) {
      req.session.userComments = [];
    }
    req.session.userComments.push(sanitizedComment);
    res.redirect('/user/' + req.session.user.id);
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});