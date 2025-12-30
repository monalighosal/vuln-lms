// Configuration file to switch between secure and vulnerable versions
module.exports = {
  // Set to true for secure version, false for vulnerable version
  SECURE_MODE: false,  // Always vulnerable mode
  
  // Other configuration options
  PORT: process.env.PORT || 5000,
  SESSION_SECRET: process.env.SESSION_SECRET || 'vulnerable-secret-key'
};