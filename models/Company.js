const mongoose = require('mongoose');

// Define the schema for the Company model
const companySchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  verificationToken: { type: String },
  status: { type: String, default: 'pending' }
});

// Create and export the Company model
const Company = mongoose.model('Company', companySchema);
module.exports = Company;
