// /api/auth routes with input validation
const router = require('express').Router();
const { body } = require('express-validator');
const validate = require('../middleware/validate');
const { protect } = require('../middleware/auth');
const c = require('../controllers/authController');

// isString() also blocks NoSQL-injection payloads like {"$ne": ""}
const text = (field, label) =>
  body(field).isString().withMessage(`${label} is required.`).bail().trim().notEmpty().withMessage(`${label} is required.`);

const registerRules = [
  text('fullName', 'Full name').isLength({ min: 3, max: 80 }).withMessage('Full name must be 3 to 80 characters.'),
  body('studentId').optional({ values: 'falsy' }).isString().trim()
    .matches(/^[A-Za-z0-9-]{4,20}$/).withMessage('Student ID must be 4 to 20 letters, numbers or hyphens.'),
  // Bangladesh mobile format: 01XXXXXXXXX
  text('mobile', 'Mobile number').matches(/^01[3-9]\d{8}$/).withMessage('Enter a valid 11-digit mobile number (01XXXXXXXXX).'),
  text('course', 'Course name').isLength({ min: 2, max: 80 }).withMessage('Course name must be 2 to 80 characters.'),
  text('email', 'Email').toLowerCase().isEmail().withMessage('Enter a valid email address.'),
  body('password').isString().withMessage('Password is required.').bail()
    .isLength({ min: 8, max: 72 }).withMessage('Password must be 8 to 72 characters.')
    .matches(/[A-Za-z]/).withMessage('Password must include a letter.')
    .matches(/\d/).withMessage('Password must include a number.')
];

const loginRules = (idField, idLabel) => [
  text(idField, idLabel),
  body('password').isString().notEmpty().withMessage('Password is required.')
];

router.post('/register', registerRules, validate, c.register);
router.post('/student-login', loginRules('identifier', 'Student ID or email'), validate, c.studentLogin);
router.post('/admin-login', loginRules('username', 'Username'), validate, c.adminLogin);
router.get('/me', protect('student'), c.me);

module.exports = router;
