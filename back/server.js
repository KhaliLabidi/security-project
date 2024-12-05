// back/server.js
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const axios = require('axios');

const app = express();
app.use(cors());
app.use(bodyParser.json());

mongoose.connect('mongodb://localhost:27017/mydb')
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('Error connecting to MongoDB:', err));

const userSchema = new mongoose.Schema({
  email: String,
  username: String,
  password: String,
  captcha: String
});

const User = mongoose.model('User', userSchema);

const keyVaultSchema = new mongoose.Schema({
  keyHash: String,
  createdAt: { type: Date, default: Date.now }
});

const KeyVault = mongoose.model('KeyVault', keyVaultSchema);

const crypto = require('crypto');

app.post('/api/store-key', async (req, res) => {
  const { key } = req.body;
  const keyHash = crypto.createHash('sha256').update(key).digest('hex');

  const newKeyVault = new KeyVault({ keyHash });
  await newKeyVault.save();

  res.status(201).send('Key stored successfully');
});

app.post('/api/register', async (req, res) => {
  const { email, username, password, confirmPassword, captcha } = req.body;

  if (password !== confirmPassword) {
    return res.status(400).send('Passwords do not match');
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const newUser = new User({ email, username, password: hashedPassword, captcha });
  await newUser.save();
  res.status(201).send('User registered successfully');
});

app.post('/api/login', async (req, res) => {
  const { email, password, captcha } = req.body;
  console.log('Login Request Data:', req.body); // Add this line

  // Verify reCAPTCHA
  const secretKey = '6LdcjI8qAAAAAGdcaYRETPA0eESwI62kp9vCX6wn';
  const verifyUrl = `https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${captcha}`;

  try {
    const response = await axios.post(verifyUrl);
    console.log('reCAPTCHA Response:', response.data); // Add this line
    if (!response.data.success) {
      return res.status(400).send('reCAPTCHA verification failed');
    }
  } catch (error) {
    console.error('reCAPTCHA Error:', error); // Add this line
    return res.status(500).send('Error verifying reCAPTCHA');
  }

  const user = await User.findOne({ email });
  if (!user) {
    return res.status(400).send('Invalid email or password');
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return res.status(400).send('Invalid email or password');
  }

  let role = 'user';
  if (user._id.toString() === '674ccda89c364e97f5e965df') {
    role = 'admin';
  } else if (['674e2489b7ca46dcfcb80acc', '674e4282b6cd89467793bff5'].includes(user._id.toString())) {
    role = 'privileged';
  }

  console.log(`Assigned role for ${email}: ${role}`); // Add this line
  res.status(200).json({ message: 'Login successful', role });
});

// Endpoint to fetch all users
app.get('/api/users', async (req, res) => {
  const users = await User.find({}, 'username email');
  res.status(200).json(users);
});

// Endpoint to delete a user
app.delete('/api/users/:id', async (req, res) => {
  const { id } = req.params;
  await User.findByIdAndDelete(id);
  res.status(200).send('User deleted successfully');
});

app.listen(5000, () => {
  console.log('Server is running on port 5000');
});