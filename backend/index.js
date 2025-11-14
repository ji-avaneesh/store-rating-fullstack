
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs'); 
const jwt = require('jsonwebtoken'); 

// JWT secret (key)
const JWT_SECRET = 'mysecretkey12345'; 

const app = express();
const port = 5000;

app.use(cors());
app.use(express.json());

// PostgreSQL connection 
const pool = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: 'rating_app',
  password: 'Awsedrf^0987', // mera password 
  port: 5432,
});

const validatePassword = (password) => {
  if (!password) {
    return 'Password is required';
  }
  if (password.length < 8 || password.length > 16) {
    return 'Password should be between 8 to 16 characters.';
  }
  if (!/[A-Z]/.test(password)) {
    return 'The password must contain at least one uppercase letter.';
  }
  // This regex finds a special character.
  if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
    return 'Password must contain at least one special character (!@#$...).';
  }
  return null; // no error 
};
//  --- helper end here --- 


//  --- Authentication Middleware  --- 
const isAuthenticated = (req, res, next) => {
  try {
    if (!req.headers.authorization) {
      return res.status(401).json({ error: 'Access denied: Token not found' });
    }
    const token = req.headers.authorization.split(' ')[1]; 
    if (!token) {
      return res.status(401).json({ error: 'Access denied: The token format is incorrect' });
    }
    const decodedToken = jwt.verify(token, JWT_SECRET);
    req.user = decodedToken; 
    next(); 
  } catch (err) {
    console.error('Token verification failed:', err.message); 
    res.status(401).json({ error: 'Invalid token' });
  }
};
//  --- isAuthenticated MIddleware end  --- 


//  --- Admin Middleware --- 
const isAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden: Only store owners can do this' });
  }
  next();
};
// --- Admin midleware end  --- 


// --- (Store Owner Middleware) --- 
const isOwner = (req, res, next) => {
  if (req.user.role !== 'owner') {
    return res.status(403).json({ error: 'Forbidden: Only store owners can do this' });
  }
  next();
};
//  --- Store owner middleware end here  --- 



//  (Admin) API Routes


//  --- Admin API : Dashboard status  --- 
app.get('/api/admin/dashboard', [isAuthenticated, isAdmin], async (req, res) => {
  try {
    const userCountPromise = pool.query('SELECT COUNT(*) FROM users');
    const storeCountPromise = pool.query('SELECT COUNT(*) FROM stores');
    const ratingCountPromise = pool.query('SELECT COUNT(*) FROM ratings');
    const [userCount, storeCount, ratingCount] = await Promise.all([
      userCountPromise, storeCountPromise, ratingCountPromise,
    ]);
    res.status(200).json({
      totalUsers: parseInt(userCount.rows[0].count, 10),
      totalStores: parseInt(storeCount.rows[0].count, 10),
      totalRatings: parseInt(ratingCount.rows[0].count, 10),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server Error ' });
  }
});

//  --- Admin API : sabhi users ki list (filter ke sath ) --- 
app.get('/api/admin/users', [isAuthenticated, isAdmin], async (req, res) => {
  try {
    let baseQuery = 'SELECT id, name, email, address, role FROM users';
    const filters = [];
    const values = [];
    const { name, email, address, role } = req.query;
    if (name) { values.push(`%${name}%`); filters.push(`name ILIKE $${values.length}`); }
    if (email) { values.push(`%${email}%`); filters.push(`email ILIKE $${values.length}`); }
    if (address) { values.push(`%${address}%`); filters.push(`address ILIKE $${values.length}`); }
    if (role) { values.push(role); filters.push(`role = $${values.length}`); }
    if (filters.length > 0) { baseQuery += ' WHERE ' + filters.join(' AND '); }
    baseQuery += ' ORDER BY id ASC'; 
    const { rows } = await pool.query(baseQuery, values);
    res.status(200).json(rows); 
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server Error ' });
  }
});

// --- Admin  API: Nya user (Owner) Banana --- 
app.post('/api/admin/users', [isAuthenticated, isAdmin], async (req, res) => {
  try {
    const { name, email, password, address, role } = req.body;
    if (!name || !email || !role) {
      return res.status(400).json({ error: ' Name, email, and role are required' });
    }
    
    //New Password Validation 

    const passwordError = validatePassword(password);
    if (passwordError) {
      return res.status(400).json({ error: passwordError });
    }

    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);
    const newUser = await pool.query(
      "INSERT INTO users (name, email, password_hash, address, role) VALUES ($1, $2, $3, $4, $5) RETURNING id, email, name, role",
      [name, email, passwordHash, address, role]
    );
    res.status(201).json({
      message: `User '${role}' Created successfully!`,
      user: newUser.rows[0],
    });
  } catch (err) {
    console.error(err);
    if (err.code === '23505') { return res.status(400).json({ error: 'This email is already registered' }); }
    res.status(500).json({ error: 'Server error' });
  }
});

//      Admin ke sabhi rating list ke sath 


app.get('/api/admin/stores', [isAuthenticated, isAdmin], async (req, res) => {
  try {
    let baseQuery = `
      SELECT 
        stores.id, stores.name, stores.email, stores.address, stores.owner_id,
        ROUND(COALESCE(AVG(ratings.rating), 0), 1) AS average_rating
      FROM stores
      LEFT JOIN ratings ON stores.id = ratings.store_id
    `;
    const filters = [];
    const values = [];
    const { name, email, address } = req.query; 
    if (name) { values.push(`%${name}%`); filters.push(`stores.name ILIKE $${values.length}`); }
    if (email) { values.push(`%${email}%`); filters.push(`stores.email ILIKE $${values.length}`); }
    if (address) { values.push(`%${address}%`); filters.push(`stores.address ILIKE $${values.length}`); }
    if (filters.length > 0) { baseQuery += ' WHERE ' + filters.join(' AND '); }
    baseQuery += ' GROUP BY stores.id';
    baseQuery += ' ORDER BY stores.id ASC';
    const { rows } = await pool.query(baseQuery, values);
    res.status(200).json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server Error ' });
  }
});

app.post('/api/admin/stores', [isAuthenticated, isAdmin], async (req, res) => {
  try {
    const { name, email, address, owner_id } = req.body;
    if (!name || !email || !owner_id) {
      return res.status(400).json({ error: 'Name, email, and owner_id are required' });
    }
    const newStore = await pool.query(
      "INSERT INTO stores (name, email, address, owner_id) VALUES ($1, $2, $3, $4) RETURNING *",
      [name, email, address, owner_id]
    );
    res.status(201).json({
      message: 'Store created successfully!',
      store: newStore.rows[0],
    });
  } catch (err) {
    console.error(err);
    if (err.code === '23505') { return res.status(400).json({ error: 'This email is already registered' }); }
    if (err.code === '23503') { return res.status(404).json({ error: 'Given owner id does not exists ' }); }
    res.status(500).json({ error: 'Server Error' });
  }
});


app.post('/api/user/ratings', isAuthenticated, async (req, res) => {
  try {
    const { store_id, rating } = req.body;
    const user_id = req.user.userId; 
    if (!store_id || !rating) { return res.status(400).json({ error: 'store_id and rating are required' }); }
    if (rating < 1 || rating > 5) { return res.status(400).json({ error: 'Rating should be between 1 to 5' }); }
    const upsertQuery = `
      INSERT INTO ratings (user_id, store_id, rating) VALUES ($1, $2, $3)
      ON CONFLICT (user_id, store_id) DO UPDATE SET rating = $3, created_at = CURRENT_TIMESTAMP
      RETURNING *
    `;
    const { rows } = await pool.query(upsertQuery, [user_id, store_id, rating]);
    res.status(201).json({ message: 'Rating successfully submitted/updated!', rating: rows[0], });
  } catch (err) {
    console.error(err);
    if (err.code === '23503') { return res.status(404).json({ error: 'store does not exist.' }); }
    res.status(500).json({ error: 'Server Error' });
  }
});

//  --- User API: List of all stores (with user ratings) --- 
app.get('/api/user/stores', isAuthenticated, async (req, res) => {
  try {
    const user_id = req.user.userId; 
    let baseQuery = `
      SELECT 
        s.id, s.name, s.address,
        ROUND(COALESCE(AVG(r_all.rating), 0), 1) AS average_rating,
        r_user.rating AS user_rating
      FROM stores s
      LEFT JOIN ratings r_all ON s.id = r_all.store_id
      LEFT JOIN ratings r_user ON s.id = r_user.store_id AND r_user.user_id = $1
    `;
    const filters = [];
    const values = [user_id]; 
    const { name, address } = req.query; 
    if (name) { values.push(`%${name}%`); filters.push(`s.name ILIKE $${values.length}`); }
    if (address) { values.push(`%${address}%`); filters.push(`s.address ILIKE $${values.length}`); }
    if (filters.length > 0) { baseQuery += ' WHERE ' + filters.join(' AND '); }
    baseQuery += ' GROUP BY s.id, r_user.rating';
    baseQuery += ' ORDER BY s.id ASC';
    const { rows } = await pool.query(baseQuery, values);
    res.status(200).json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server Error ' });
  }
});

//  --- Store owner API: Dashboard Average rating and list  --- 
app.get('/api/owner/dashboard', [isAuthenticated, isOwner], async (req, res) => {
  try {
    const owner_id = req.user.userId; 
    const storeQuery = `
      SELECT 
        s.id, s.name,
        ROUND(COALESCE(AVG(r.rating), 0), 1) AS average_rating
      FROM stores s
      LEFT JOIN ratings r ON s.id = r.store_id
      WHERE s.owner_id = $1
      GROUP BY s.id
    `;
    const storeResult = await pool.query(storeQuery, [owner_id]);

    if (storeResult.rows.length === 0) {
      return res.status(404).json({ error: 'There is no store registered in your name' });
    }
    const storeData = storeResult.rows[0]; 
    const ratersQuery = `
      SELECT u.name AS user_name, u.email AS user_email, r.rating
      FROM ratings r
      JOIN users u ON r.user_id = u.id
      WHERE r.store_id = $1
      ORDER BY r.created_at DESC
    `;
    const ratersResult = await pool.query(ratersQuery, [storeData.id]);
    res.status(200).json({
      storeName: storeData.name,
      averageRating: storeData.average_rating,
      ratingsList: ratersResult.rows 
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server Error ' });
  }
});


// (Shared) API Routes - for all login user 

//  new password update 
app.patch('/api/auth/update-password', isAuthenticated, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;
    const user_id = req.user.userId;

    if (!oldPassword || !newPassword) {
      return res.status(400).json({ error: 'Old and new passwords are required.' });
    }

    const userResult = await pool.query('SELECT password_hash FROM users WHERE id = $1', [user_id]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'user not found' }); 
    }
    const user = userResult.rows[0];

    const isPasswordValid = await bcrypt.compare(oldPassword, user.password_hash);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'wrong old password' });
    }
    
    const passwordError = validatePassword(newPassword);
    if (passwordError) {
      return res.status(400).json({ error: passwordError });
    }

    const salt = await bcrypt.genSalt(10);
    const newPasswordHash = await bcrypt.hash(newPassword, salt);
    
    await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [newPasswordHash, user_id]);
    
    res.status(200).json({ message: 'Password updated successfully!' });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server Error' });
  }
});
//  --- API end --- 


// ===============================================
// 🌐 (Public) API Routes
// ===============================================

//  --- REGISTER API endpoint --- 
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, address } = req.body;
    if (!name || !email) { return res.status(400).json({ error: 'Name and email are required' }); }

    // New password validation
    const passwordError = validatePassword(password);
    if (passwordError) {
      return res.status(400).json({ error: passwordError });
    }

    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);
    const newUser = await pool.query(
      "INSERT INTO users (name, email, password_hash, address, role) VALUES ($1, $2, $3, $4, 'user') RETURNING id, email, name, role",
      [name, email, passwordHash, address]
    );
    res.status(201).json({ message: 'User Regestered Successfully !! ', user: newUser.rows[0], });
  } catch (err) {
    console.error(err);
    if (err.code === '23505') { return res.status(400).json({ error: 'This email allready exist' }); }
    res.status(500).json({ error: '404 Serer Error' });
  }
});

//  --- LOGIN API endpoint  --- 
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) { return res.status(400).json({ error: 'Email and password are required' }); }
    const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userResult.rows.length === 0) { return res.status(401).json({ error: 'Wrong email या password' }); }
    const user = userResult.rows[0];
    const isPasswordValid = await bcrypt.compare(password, user.password_hash);
    if (!isPasswordValid) { return res.status(401).json({ error: 'Wrong email या password' }); }
    const token = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      JWT_SECRET, 
      { expiresIn: '1h' }
    );
    res.status(200).json({
      message: ' Login Successfull !!',
      token: token,
      user: { id: user.id, name: user.name, email: user.email, role: user.role }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server Error' });
  }
});

// --- (Protected) test root--- 
app.get('/api/protected-test', isAuthenticated, (req, res) => {
  res.json({ message: 'now , you can see this protected root ', user: req.user });
});

// DB connection test root 
app.get('/test-db', async (req, res) => {
  try {
    const result = await pool.query('SELECT NOW()');
    res.json({ message: 'Database connected ', time: result.rows[0].now, });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database does not connected' });
  }
});


// (Base Route)
app.get('/', (req, res) => {
  res.send('Server live in backend');
});


app.listen(port, () => {
  console.log(`Server http://localhost:${port} Countinued `);
});