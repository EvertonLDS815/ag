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
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (user && await bcrypt.compare(password, user.password)) {
      const token = jwt.sign(
        { userId: user._id },
        process.env.JWT_SECRET, 
        {expiresIn: '5d'}
      );
      res.json({ token });
    } else {
      res.status(401).json({error: "Invalid credentials"});
    }
  } catch (err) {
    return res.status(500).json(err);
  }
});

// Delete User with their tasks
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
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      return res.status(401).json({error: 'Access denied. No token provided.'});
    }
  
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.userId = decoded.userId;
      next();
    } catch (err) {
        return res.status(400).json(err);
    }
};

// Exemplo de rota para obter dados do usuário
app.get('/user', auth, async (req, res) => {
  try {
    const {email} = await User.findById(req.userId);
    if (!email) {
      return res.status(404).json({ error: 'User not found' });
    }
    return res.json(email);
  } catch (err) {
    return res.status(500).json({ error: 'Server error' });
  }
});

// Endpoints de tarefas

// Get Tasks
app.get('/tasks', auth, async (req, res) => {
  try {
    const tasks = await Task.find({ userId: req.userId });
    return res.json(tasks);
  } catch (err) {
    return res.status(500).json(err);
  }
});

// Create Tasks
app.post('/tasks', auth, async (req, res) => {
  try {
    const { task } = req.body;
    const newTask = new Task({ userId: req.userId, task });
    await newTask.save();
    return res.status(201).json(newTask);
  } catch (err) {
    return res.status(500).json(err);
  }
});

// Update Tasks
app.patch('/tasks/:id', auth, async (req, res) => {
  try {
    await Task.findOneAndUpdate(
      { _id: req.params.id, userId: req.userId },
      [{ $set: { completed: { $not: "$completed" } } }], // Alterna o valor de "completed"
    );

    return res.sendStatus(204);
  } catch (err) {
    console.error(err);
    return res.status(500).json(err);
  }
});


// Delete Tasks
app.delete('/tasks/:id', auth, async (req, res) => {
  try {
    await Task.findOneAndDelete({ _id: req.params.id, userId: req.userId });
    return res.sendStatus(204);
  } catch (err) {
    return res.status(500).json(err);
  }
});

app.listen(5000, () => {
  console.log('🚀 Server is running on http://localhost:5000');
});
