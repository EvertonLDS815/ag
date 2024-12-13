// server.js
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

mongoose.connect(process.env.DB_URI);

// Schemas
const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});

const TaskSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  task: { type: String, required: true },
  completed: { type: Boolean, default: false }
});

const User = mongoose.model('User', UserSchema);
const Task = mongoose.model('Task', TaskSchema);

// Endpoints de autenticação

// Create User
app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }
  const hashedPassword = await bcrypt.hash(password, 10);
  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'Email already registered' });
    }
    const user = new User({ email, password: hashedPassword });
    await user.save();
    res.status(201).json(user);
  } catch (err) {
    res.status(400).json({error: err});
    console.error(err);
  }
});

// Login User
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (user && await bcrypt.compare(password, user.password)) {
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET);
    res.json({ token });
  } else {
    res.status(401).json({error: "Invalid credentials"});
  }
});

// Delete User with your tasks
app.delete('/user/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    await Task.deleteMany({userId});
    await User.findOneAndDelete({ _id: userId });
    return res.sendStatus(204);
  } catch (err) {
    return res.status(500).json(err);
  }
})

// Middleware de autenticação
const auth = (req, res, next) => {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      return res.status(401).json({error: 'Access denied. No token provided.'});
    }
  
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.userId = decoded.userId;
      next();
    } catch (err) {
        return res.status(400).status(err);
    }
};

// Endpoints de tarefas

// Get Tasks
app.get('/tasks', auth, async (req, res) => {
  const tasks = await Task.find({ userId: req.userId });
  return res.json(tasks);
});

// Create Tasks
app.post('/tasks', auth, async (req, res) => {
  const { task } = req.body;
  const newTask = new Task({ userId: req.userId, task });
  await newTask.save();
  return res.status(201).json(newTask);
});

// Update Tasks
app.patch('/tasks/:id', auth, async (req, res) => {
  const { completed } = req.body;
  await Task.findOneAndUpdate(
    { _id: req.params.id, userId: req.userId },
    { completed },
  );
  return res.sendStatus(204);
});

// Delete Tasks
app.delete('/tasks/:id', auth, async (req, res) => {
  await Task.findOneAndDelete({ _id: req.params.id, userId: req.userId });
  return res.sendStatus(204);
});

app.listen(5000, () => {
  console.log('🚀 Server is running on http://localhost:5000');
});
