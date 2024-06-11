const express = require('express');
const admin = require('firebase-admin');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// Initialize Express app
const app = express();
const port = process.env.PORT || 3000;

// Initialize Firebase Admin SDK
const serviceAccount = require('./serviceAccountKey.json');
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

// Import the firestore module
const firestore = admin.firestore();

// Middleware to parse JSON bodies
app.use(express.json());

const JWT_SECRET = 'your_jwt_secret'; // Replace with your actual secret

// Function to compare provided password with hashed password
async function comparePasswords(plainPassword, hashedPassword) {
  try {
    return await bcrypt.compare(plainPassword, hashedPassword);
  } catch (error) {
    console.error('Error comparing passwords:', error);
    throw new Error('Error comparing passwords');
  }
}

// Function to generate JWT
function generateToken(user) {
  return jwt.sign({ uid: user.uid, email: user.email }, JWT_SECRET, { expiresIn: '60d' });
}

// Middleware to verify JWT
async function authenticateToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ error: 'Access denied' });

  try {
    // Verify JWT and check if it is still valid with Firebase
    const decodedToken = jwt.verify(token, JWT_SECRET);
    const user = await admin.auth().getUser(decodedToken.uid);
    const validSince = new Date(user.tokensValidAfterTime).getTime() / 1000;

    // Check if the token was issued before the last token revocation
    if (decodedToken.iat < validSince) {
      return res.status(403).json({ error: 'Invalid token' });
    }

    req.user = decodedToken;
    next();
  } catch (error) {
    console.error('Error authenticating token:', error);
    res.status(403).json({ error: 'Invalid token' });
  }
}

// Route to add a new user
app.post('/signup', async (req, res) => {
  try {
    const { email, password, displayName } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);

    const userRecord = await admin.auth().createUser({
      email,
      password,
      displayName
    });

    const userData = {
      email,
      displayName,
      passwordHash: hashedPassword
    };

    await firestore.collection('users').doc(userRecord.uid).set(userData);

    res.status(201).json({ id: userRecord.uid, ...userData });
  } catch (error) {
    console.error('Error adding user:', error);
    res.status(500).json({ error: 'Failed to add user', message: 'The email address is already in use by another account' });
  }
});

// Route to handle user login
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const userSnapshot = await firestore.collection('users').where('email', '==', email).get();

    if (userSnapshot.empty) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const userDoc = userSnapshot.docs[0];
    const userData = userDoc.data();

    const isPasswordValid = await comparePasswords(password, userData.passwordHash);

    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = generateToken({ uid: userDoc.id, email: userData.email });

    res.status(200).json({ message: 'Login successful', token });
  } catch (error) {
    console.error('Error logging in user:', error);
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

// Route to update user
app.put('/user', authenticateToken, async (req, res) => {
  try {
    const { email, displayName } = req.body;
    const userUpdate = {};
    if (email) userUpdate.email = email;
    if (displayName) userUpdate.displayName = displayName;

    await admin.auth().updateUser(req.user.uid, userUpdate);
    await firestore.collection('users').doc(req.user.uid).update(userUpdate);

    res.status(200).json({ message: 'User updated successfully' });
  } catch (error) {
    console.error('Error updating user:', error);
    res.status(500).json({ error: 'Failed to update user' });
  }
});

// Route to handle transactions
app.post('/user/transactions', authenticateToken, async (req, res) => {
  const transaction = {
    amount: req.body.amount,
    type: req.body.type,
    category: req.body.category,
    date: req.body.date
  };

  try {
    const createdTransaction = await firestore.collection('users').doc(req.user.uid).collection('transactions').add(transaction);
    res.status(200).json({ message: 'Transaction performed', id: createdTransaction.id });
  } catch (error) {
    console.error('Error adding transaction:', error);
    res.status(500).json({ error: 'Failed to add transaction' });
  }
});

app.put('/user/transactions', authenticateToken, async (req, res) => {
  try {
    const { amount, type, category, date, id } = req.body;
    const transactionUpdate = { amount, type, category, date };

    await firestore.collection('users').doc(req.user.uid).collection('transactions').doc(id).update(transactionUpdate);

    res.status(200).json({ message: 'Transaction updated successfully' });
  } catch (error) {
    console.error('Error updating transaction:', error);
    res.status(500).json({ error: 'Failed to update transaction' });
  }
});

app.delete('/user/transactions', authenticateToken, async (req, res) => {
  try {
    const { id } = req.body;

    if (!id) {
      return res.status(400).json({ error: 'Transaction ID is required' });
    }

    const transactionRef = firestore.collection('users').doc(req.user.uid).collection('transactions').doc(id);
    const transactionDoc = await transactionRef.get();

    if (!transactionDoc.exists) {
      return res.status(404).json({ error: 'Transaction not found' });
    }

    await transactionRef.delete();

    res.status(200).json({ message: 'Transaction deleted successfully' });
  } catch (error) {
    console.error('Error deleting transaction:', error);
    res.status(500).json({ error: 'Failed to delete transaction' });
  }
});

// Route to handle user logout
app.post('/logout', authenticateToken, async (req, res) => {
  try {
    await admin.auth().revokeRefreshTokens(req.user.uid);
    res.status(200).json({ message: 'Logout successful' });
  } catch (error) {
    console.error('Error logging out user:', error);
    res.status(500).json({ error: 'Failed to logout' });
  }
});

// Route to handle user deletion
app.delete('/user', authenticateToken, async (req, res) => {
  try {
    // Delete the user from Firebase Authentication
    await admin.auth().deleteUser(req.user.uid);
    
    // Delete the user document from Firestore
    await firestore.collection('users').doc(req.user.uid).delete();

    res.status(200).json({ message: 'User deleted successfully' });
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

// Start server
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
