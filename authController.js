// Registration and login logic
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Student = require('../models/Student');

// Compared against when no user is found, so response time doesn't reveal whether an account exists
const DUMMY_HASH = bcrypt.hashSync('timing-equalizer', 12);
const BAD_CREDENTIALS = { message: 'Incorrect ID/email or password.' };

const sign = (payload, expiresIn) =>
  jwt.sign(payload, process.env.JWT_SECRET, { algorithm: 'HS256', expiresIn });

// Auto-generate an ID like ACTC-2026-48213
async function generateStudentId() {
  const year = new Date().getFullYear();
  for (let i = 0; i < 5; i++) {
    const id = `ACTC-${year}-${crypto.randomInt(10000, 100000)}`;
    if (!(await Student.exists({ studentId: id }))) return id;
  }
  throw new Error('Could not generate a unique Student ID');
}

// POST /api/auth/register
exports.register = async (req, res, next) => {
  try {
    const { fullName, mobile, course, email, password } = req.body;
    let studentId = (req.body.studentId || '').trim().toUpperCase();

    if (await Student.exists({ email })) {
      return res.status(409).json({ message: 'This email is already registered.' });
    }
    if (studentId) {
      if (await Student.exists({ studentId })) {
        return res.status(409).json({ message: 'This Student ID is already taken. Choose another or leave it blank.' });
      }
    } else {
      studentId = await generateStudentId();
    }

    // Password is hashed by the model's pre-save hook
    const student = await Student.create({ fullName, studentId, mobile, course, email, password });

    res.status(201).json({
      message: 'Registration successful.',
      student: { studentId: student.studentId, fullName: student.fullName, email: student.email }
    });
  } catch (err) {
    // Duplicate key from a simultaneous request that slipped past the checks above
    if (err.code === 11000) {
      return res.status(409).json({ message: 'Student ID or email is already registered.' });
    }
    next(err);
  }
};

// POST /api/auth/student-login   body: { identifier (Student ID or email), password }
exports.studentLogin = async (req, res, next) => {
  try {
    const { identifier, password } = req.body;
    const query = identifier.includes('@')
      ? { email: identifier.toLowerCase() }
      : { studentId: identifier.toUpperCase() };

    const student = await Student.findOne(query).select('+password');
    const match = await bcrypt.compare(password, student ? student.password : DUMMY_HASH);
    if (!student || !match) return res.status(401).json(BAD_CREDENTIALS);

    const token = sign(
      { sub: student.id, role: 'student', studentId: student.studentId },
      process.env.JWT_EXPIRES_IN || '7d'
    );
    res.json({
      token,
      student: { studentId: student.studentId, fullName: student.fullName, email: student.email, course: student.course }
    });
  } catch (err) { next(err); }
};

// POST /api/auth/admin-login   body: { username, password }
// Admin credentials live in environment variables (bcrypt hash), not in the database.
exports.adminLogin = async (req, res, next) => {
  try {
    const { username, password } = req.body;
    // Always run the hash comparison so timing doesn't reveal whether the username was right
    const passOk = await bcrypt.compare(password, process.env.ADMIN_PASSWORD_HASH);
    const userOk = username === process.env.ADMIN_USERNAME;
    if (!passOk || !userOk) return res.status(401).json({ message: 'Incorrect username or password.' });

    const token = sign({ sub: username, role: 'admin' }, process.env.ADMIN_JWT_EXPIRES_IN || '8h');
    res.json({ token, admin: { username } });
  } catch (err) { next(err); }
};

// GET /api/auth/me   (student token required)
exports.me = async (req, res, next) => {
  try {
    const student = await Student.findById(req.auth.sub);
    if (!student) return res.status(404).json({ message: 'Account not found.' });
    res.json({ student });
  } catch (err) { next(err); }
};
