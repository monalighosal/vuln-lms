const config = require('./config');
const sqlite3 = require('sqlite3').verbose();

// Function to sanitize user input to prevent SQL injection
function sanitizeInput(input) {
  if (typeof input === 'string') {
    // Remove or escape dangerous characters
    return input.replace(/'/g, "''").replace(/;/g, '');
  }
  return input;
}

// Function to validate user access to resources (for IDOR protection)
function validateUserAccess(req, userId) {
  if (config.SECURE_MODE) {
    // In secure mode, check if the requested user ID matches the current user's ID
    // or if the user is an admin
    return req.session.user.id == userId || req.session.user.role === 'admin';
  } else {
    // In vulnerable mode, always return true (no access control)
    return true;
  }
}

// Function to validate course access (for IDOR protection)
function validateCourseAccess(req, courseId, db, callback) {
  if (config.SECURE_MODE) {
    // In secure mode, check if the user is enrolled in the course or is an admin
    const query = `SELECT c.id FROM courses c LEFT JOIN enrollments e ON c.id = e.course_id WHERE c.id = ? AND (e.user_id = ? OR c.instructor_id = ? OR ? = 'admin')`;
    
    db.get(query, [courseId, req.session.user.id, req.session.user.id, req.session.user.role], (err, result) => {
      if (err) {
        console.error('Course access validation error:', err);
        return callback(false);
      }
      callback(!!result);
    });
  } else {
    // In vulnerable mode, always allow access
    callback(true);
  }
}

// Function to validate profile update (for mass assignment protection)
function validateProfileUpdate(req, updates) {
  if (config.SECURE_MODE) {
    // In secure mode, only allow updating specific fields
    const allowedFields = ['username', 'email', 'password', 'created_at'];
    const filteredUpdates = {};
    
    for (const field in updates) {
      if (allowedFields.includes(field)) {
        filteredUpdates[field] = updates[field];
      }
    }
    
    return filteredUpdates;
  } else {
    // In vulnerable mode, return all updates (allowing mass assignment)
    return updates;
  }
}

// Function to validate admin access
function isAdmin(req) {
  if (config.SECURE_MODE) {
    // In secure mode, only allow access if user is actually an admin
    return req.session.user && req.session.user.role === 'admin';
  } else {
    // In vulnerable mode, allow access if user is logged in
    return req.session.user;
  }
}

// Function to prevent insecure deserialization
function safeParse(jsonString) {
  if (config.SECURE_MODE) {
    // In secure mode, use a safe parsing method that prevents prototype pollution
    try {
      // Basic validation to prevent prototype pollution
      if (jsonString.includes('__proto__') || jsonString.includes('constructor')) {
        throw new Error('Invalid input');
      }
      return JSON.parse(jsonString);
    } catch (e) {
      throw e;
    }
  } else {
    // In vulnerable mode, use direct JSON.parse (insecure)
    return JSON.parse(jsonString);
  }
}

module.exports = {
  sanitizeInput,
  validateUserAccess,
  validateCourseAccess,
  validateProfileUpdate,
  isAdmin,
  safeParse
};