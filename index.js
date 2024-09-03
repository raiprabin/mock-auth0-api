const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const { totp } = require("otplib"); // Use otplib for MFA tokens

const app = express();
const PORT = 3001;

// Secret key for JWT signing (in a real app, store this securely and don't hardcode it)
const JWT_SECRET = "your_secret_key_here";

// Configure CORS to allow requests from http://localhost:5173 and handle credentials
app.use(
  cors({
    origin: "http://localhost:5173", // Replace with your front-end origin
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true, // Allow cookies and other credentials
  })
);

app.use(express.json());

// Mock data
const users = [
  {
    user_id: "auth0|123456",
    email: "prabin.rai@intuji.com",
    name: "Prabin Rai",
    password: "password123", // In a real app, passwords should be hashed
    twoFactorEnabled: true,
    mfaSecret: "YOUR_MFA_SECRET", // Store MFA secret securely
    last_login: "2024-09-02T12:34:56.000Z",
  },
];

const verificationCodes = {}; // Store verification codes for each email
const mfaTokens = {}; // Store MFA tokens for each user
const tokenExpiryStore = {}; // You might want to use a more persistent store in production

// Simulate sending an email (for mock purposes)
const sendVerificationEmail = (email, code) => {
  console.log(`Sending verification code ${code} to ${email}`);
};

// Generate random verification code
const generateVerificationCode = () => {
  return crypto.randomInt(100000, 999999).toString();
};

// Generate MFA token
const generateMfaToken = (secret) => {
  return totp.generate(secret);
};

// Mock API Endpoints

// Login (Passwordless Start)
app.post("/api/v2/login", (req, res) => {
  const { email, password, loggedInStatus } = req.body;
  const user = users.find((u) => u.email === email);

  if (!user) {
    return res.status(400).json({ error: "User not found" });
  }

  // In a real app, validate the password here
  if (user.password !== password) {
    return res.status(401).json({ error: "Invalid password" });
  }
  const tokenExpiry = loggedInStatus ? "30d" : "1h"; // Token expires in 30 days if loginStatus is true, otherwise 1 hour
  console.log("tokenExpiry", tokenExpiry);
  tokenExpiryStore[email] = tokenExpiry;

  if (user.twoFactorEnabled) {
    // 2FA is enabled, send a verification code and MFA token
    const code = generateVerificationCode();
    const mfaToken = generateMfaToken(user.mfaSecret);
    verificationCodes[email] = code;
    mfaTokens[mfaToken] = user.email; // Store MFA token associated with the email
    sendVerificationEmail(email, code);

    return res.json({
      success: true,
      message: "Verification code sent to email.",
      mfaToken, // Send MFA token in the response
    });
  } else {
    // 2FA is not enabled, generate a JWT token directly

    const token = jwt.sign(
      { user_id: user.user_id, email: user.email, name: user.name },
      JWT_SECRET,
      { expiresIn: tokenExpiry } // Token expires in 1 hour
    );

    return res.json({
      success: true,
      message: "2FA not enabled. Token generated successfully.",
      token, // Send token in the response
      redirectTo: "/overview",
    });
  }
});

// API for verifying 2FA code and MFA token
app.post("/api/v2/verify-code", (req, res) => {
  const { verificationCode, mfaToken } = req.body;

  // Find the email associated with the MFA token
  const email = mfaTokens[mfaToken];

  if (!email) {
    return res
      .status(400)
      .json({ success: false, error: "Invalid MFA token." });
  }

  const user = users.find((u) => u.email === email);

  if (!user) {
    return res.status(400).json({ success: false, error: "User not found." });
  }

  // Check if the provided verification code matches the stored code
  if (verificationCodes[email] === verificationCode) {
    // Code matches; verification is successful
    delete verificationCodes[email]; // Clear the code once verified
    delete mfaTokens[mfaToken]; // Clear the MFA token once used
    console.log("tokenExpiryStore", tokenExpiryStore[email]);
    // Generate JWT token
    const token = jwt.sign(
      { user_id: user.user_id, email: user.email, name: user.name },
      JWT_SECRET,
      { expiresIn: tokenExpiryStore[email] } // Token expires in 1 hour
    );

    setTimeout(() => {
      return res.json({
        success: true,
        message: "Code and MFA token verified successfully.",
        token, // Send token in the response
        redirectTo: "/overview",
      });
    }, 3000); // Delay of 3000 milliseconds (3 seconds)
  } else {
    return res
      .status(400)
      .json({ success: false, error: "Invalid verification code." });
  }
});

// API for refreshing token
app.post("/api/v2/refresh-token", (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshTokens[refreshToken]) {
    return res
      .status(403)
      .json({ success: false, error: "Invalid refresh token." });
  }

  const email = refreshTokens[refreshToken];
  const user = users.find((u) => u.email === email);

  if (!user) {
    return res.status(400).json({ success: false, error: "User not found." });
  }

  // Generate new JWT token
  const token = jwt.sign(
    { user_id: user.user_id, email: user.email, name: user.name },
    JWT_SECRET,
    { expiresIn: tokenExpiryStore[email] }
  );

  return res.json({
    success: true,
    token,
  });
});

app.listen(PORT, () => {
  console.log(`Mock Auth0 API running on http://localhost:${PORT}`);
});
