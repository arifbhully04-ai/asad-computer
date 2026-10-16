// Student schema. Passwords are hashed automatically before every save.
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const studentSchema = new mongoose.Schema(
  {
    fullName:  { type: String, required: true, trim: true, maxlength: 80 },
    // unique index = database-level guarantee against duplicate IDs (even in race conditions)
    studentId: { type: String, required: true, unique: true, uppercase: true, trim: true },
    mobile:    { type: String, required: true, trim: true },
    course:    { type: String, required: true, trim: true, maxlength: 80 },
    email:     { type: String, required: true, unique: true, lowercase: true, trim: true },
    // select:false => never returned by queries unless explicitly requested
    password:  { type: String, required: true, select: false }
  },
  { timestamps: true }
);

// Hash only when the password is new or changed
studentSchema.pre('save', async function () {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 12);
  }
});

module.exports = mongoose.model('Student', studentSchema);
