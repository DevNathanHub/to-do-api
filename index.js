const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('./models/User');
const Todo = require('./models/Todo');
const sanitizeUser = require('./utils/sanitizer');
const cors = require('cors');

dotenv.config();
const app = express();
const port = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;

// Middleware
app.use(express.json());
app.use(express.static('public'));

const corsOptions = {
  origin: 'http://localhost:5173',
};

app.use(cors(corsOptions));

// Connect to MongoDB
mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('db connected'))
.catch(err => console.error(err));

app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

// Signup route
app.post('/api/signup', async (req, res) => {
  const { fullName, email, password } = req.body;

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'Email already in use' });
    }

    const newUser = new User({
      fullName,
      email,
      password,
      todos: []
    });

    await newUser.save();

    res.status(201).json({ message: 'success'});

  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Login route
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });


    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ userId: user._id }, 'secretKey', { expiresIn: '1h' });

    const sanitizedUser = await sanitizeUser(user);

    res.json({ token, sanitizedUser });
    
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Middleware to verify token
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(403).json({ error: 'No token provided' });

  jwt.verify(token, 'secretKey', (err, decoded) => {
    if (err) return res.status(500).json({ error: 'Failed to authenticate token' });

    req.userId = decoded.userId;
    next();
  });
};

// CRUD routes for todos
app.get('/api/todos', verifyToken, async (req, res) => {
  try {
    const todos = await Todo.find({ createdBy: req.userId });
    res.json(todos);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/todos', verifyToken, async (req, res) => {
 const { title, description } = req.body;

  try {
    const newTodo = new Todo({
      title,
      description,
      createdBy: req.body.userId,
    });

    await newTodo.save();
    res.status(201).json(newTodo);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Get all todos
app.get('/api/todos', verifyToken, async (req, res) => {
  try {
    const todos = await Todo.find({ createdBy: req.body.userId });
    res.status(200).json(todos);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


app.put('/api/todos/:id', verifyToken, async (req, res) => {
  const { title, description, completed } = req.body;

  try {
    let updatedTitle = title;
    let updatedDescription = description;

    if (!title) {
      const existingTodo = await Todo.findById(req.params.id);
      if (!existingTodo) {
        return res.status(404).json({ error: 'Todo not found' });
      }
      updatedTitle = existingTodo.title;
    }

    if (!description) {
      const existingTodo = await Todo.findById(req.params.id);
      if (!existingTodo) {
        return res.status(404).json({ error: 'Todo not found' });
      }
      updatedDescription = existingTodo.title;
    }

  
    const updatedTodo = await Todo.findOneAndUpdate(
      { _id: req.params.id, createdBy: req.body.userId },
      { title, description, completed },
      { new: true }
    );

    if (!updatedTodo) {
      return res.status(404).json({ error: 'Todo not found' });
    }

    res.json(updatedTodo);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.delete('/api/todos/:id', verifyToken, async (req, res) => {
 
  try {
    const deletedTodo = await Todo.findOneAndDelete({ _id: req.params.id, createdBy: req.body.userId });

    if (!deletedTodo) {
      return res.status(404).json({ error: 'Todo not found' });
    }

    res.json({ message: 'Todo deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Start server
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
