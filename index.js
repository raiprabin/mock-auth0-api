const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const { totp, authenticator } = require("otplib"); // Use otplib for MFA tokens
const bcrypt = require("bcrypt");
const qrcode = require("qrcode");

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
    firstLogin: false,
  },
];

const verificationCodes = {}; // Store verification codes for each email
const mfaTokens = {}; // Store MFA tokens for each user
const tokenExpiryStore = {}; // You might want to use a more persistent store in production
const refreshTokens = {}; // Store refresh tokens for users
// const Company = require('./models/Company');  // Adjust the path based on your folder structure
const companies = []; // In-memory array to store company data

// Simulate sending an email (for mock purposes)
const sendVerificationEmail = (email, code) => {
  console.log(`Sending verification code ${code} to ${email}`);
};

const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  service: "Gmail",
  auth: {
    user: "your-email@gmail.com",
    pass: "your-email-password",
  },
});

const sendRegisterVerificationEmail = async (to, link) => {
  // const mailOptions = {
  //   from: to,
  //   to,
  //   subject: 'Complete Your Registration',
  //   html: `<p>Please complete your registration by clicking the link below:</p>
  //          <a href="${link}">Complete Registration</a>`,
  // };
  console.log(
    `${to} Please complete your registration by clicking the link below: ${link}`
  );

  // await transporter.sendMail(mailOptions);
};

const sendApprovalEmail = async (to) => {
  console.log(`Approval email sent to ${to}`);
};

module.exports = { sendVerificationEmail };

// Generate random verification code
const generateVerificationCode = () => {
  return crypto.randomInt(100000, 999999).toString();
};

// Generate MFA token
const generateMfaToken = (secret) => {
  return totp.generate(secret);
};

// Function to generate the QR code URL
const generateQRCodeURL = async (email, secret) => {
  const otpauthURL = authenticator.keyuri(email, "YourAppName", secret);
  return await qrcode.toDataURL(otpauthURL); // Generate a QR code from the key URI
};

// Login (Passwordless Start)
app.post("/api/v2/login", async (req, res) => {
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
  const code = generateVerificationCode();
  const mfaToken = generateMfaToken(user.mfaSecret);
  // 2FA is enabled, send a verification code and MFA token
  verificationCodes[email] = code;
  mfaTokens[mfaToken] = user.email; // Store MFA token associated with the email
  if (user.twoFactorEnabled && user.firstLogin !== true) {
    sendVerificationEmail(email, code);

    return res.json({
      success: true,
      message: "Verification code sent to email.",
      mfaToken, // Send MFA token in the response
    });
  } else {
    // 2FA is not enabled, generate a JWT token directly
    const mfaToken = generateMfaToken(user.mfaSecret);

    mfaTokens[mfaToken] = user.email; // Store MFA token associated with the email
    // 2FA is not enabled, generate a new TOTP secret and send it to the frontend
    const secret = authenticator.generateSecret(); // Generate a new TOTP secret
    user.mfaSecret = secret; // Save the secret in the user object or database

    // Generate QR code URL for 2FA
    const qrCodeUrl = await generateQRCodeURL(user.email, user.mfaSecret);
    sendVerificationEmail(email, code);

    return res.json({
      success: true,
      message: "2FA not enabled. Token generated successfully.",
      mfaToken, // Send MFA token in the response
      firstLogin: user.firstLogin,
      qrCodeUrl: secret, // Send QR code URL in the response
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

// API endpoint to register the company and send the email
app.post("/api/v2/register", async (req, res) => {
  const { companyName, companyEmail } = req.body;

  try {
    // Check if the email is already registered
    const existingCompany = companies.find(
      (company) => company.email === companyEmail
    );
    if (existingCompany) {
      return res.status(400).json({ message: "Company already registered" });
    }

    // Generate a verification token with JWT
    const token = jwt.sign(
      { companyEmail, companyName },
      JWT_SECRET, // Use your secret key
      { expiresIn: "1d" } // Token expires in 1 day
    );
    // Send verification email
    const verificationLink = `http://localhost:5173/register/complete-registration?token=${token}`;
    await sendRegisterVerificationEmail(companyEmail, verificationLink);
    // Save company registration with a pending status
    const newCompany = {
      name: companyName,
      email: companyEmail,
      verificationToken: token,
      status: "pending",
    };
    companies.push(newCompany);

    res
      .status(200)
      .json({ message: "Verification email sent successfully", success: true });
  } catch (error) {
    console.error("Error during registration:", error);

    if (error.code === "ECONNREFUSED") {
      return res
        .status(500)
        .json({ message: "Failed to connect to email service" });
    }

    res
      .status(500)
      .json({ message: "Error registering company", error: error.message });
  }
});

app.post("/api/v2/get-company-info", (req, res) => {
  const { token } = req.body;

  try {
    // Verify and decode the JWT token
    const decoded = jwt.verify(token, JWT_SECRET);
    const { companyEmail, companyName } = decoded;

    // Return the company information
    return res.status(200).json({
      success: true,
      companyEmail,
      companyName,
    });
  } catch (error) {
    return res
      .status(400)
      .json({ success: false, error: "Invalid or expired token." });
  }
});

// Complete the company registration
app.post("/api/v2/complete-registration", async (req, res) => {
  console.log("req.body", req.body);
  const {
    companyName,
    companyEmail,
    companyWebsite,
    businessRegNo,
    country,
    state,
    city,
    phone,
    accountEmail,
    accountPassword,
  } = req.body;

  try {
    // Validate the presence of required fields
    if (!companyName || !companyEmail || !accountPassword) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    // Find the company by pending status in the in-memory companies array
    // (You may need to adapt this part based on your actual logic to identify the company)
    const company = companies.find(
      (c) => c.email === companyEmail && c.status === "pending"
    );
    if (!company) {
      return res
        .status(400)
        .json({ message: "Company not found or not in pending status" });
    }

    // Hash the password before storing it
    const hashedPassword = await bcrypt.hash(accountPassword, 10);

    // Update company details and mark it as approved
    company.name = companyName;
    company.email = companyEmail;
    company.website = companyWebsite;
    company.businessRegNo = businessRegNo;
    company.country = country;
    company.state = state;
    company.city = city;
    company.phone = phone;
    company.accountEmail = accountEmail;
    company.accountPassword = hashedPassword; // Store the hashed password
    company.status = "approved"; // Mark the company as approved

    // Send approval email (or handle declined status if needed)
    await sendApprovalEmail(companyEmail);

    res
      .status(200)
      .json({ message: "Registration completed successfully", success: true });
  } catch (error) {
    console.error("Error completing registration:", error);
    res
      .status(500)
      .json({ message: "Error completing registration", error: error.message });
  }
});

// API for logging out
app.post("/api/v2/logout", (req, res) => {
  const { token } = req.body;

  if (!token) {
    return res
      .status(400)
      .json({ success: false, error: "No token provided." });
  }

  try {
    // Verify the token
    jwt.verify(token, JWT_SECRET);

    // Invalidate the token by removing it from the store
    // If using refresh tokens, also remove the corresponding refresh token
    // For simplicity, this example does not persist token invalidation
    // In a real app, you might store invalidated tokens in a blacklist

    // Clear any related session or token storage if needed
    // Example: delete refreshTokens[token] if using refresh tokens

    res
      .status(200)
      .json({ success: true, message: "Logged out successfully." });
  } catch (error) {
    res.status(400).json({ success: false, error: "Invalid token." });
  }
});

app.listen(PORT, () => {
  console.log(`Mock Auth0 API running on http://localhost:${PORT}`);
});
