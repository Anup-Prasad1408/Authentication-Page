
require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const cookieParser = require("cookie-parser");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

const OTP_EXPIRY_MS = 10 * 60 * 1000;
const RESEND_WAIT_MS = 60 * 1000;
const COOKIE_NAME = "auth_session";

if (!process.env.MONGODB_URI) {
  console.error("Missing MONGODB_URI in environment.");
  process.exit(1);
}

if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
  console.error("JWT_SECRET must contain at least 32 characters.");
  process.exit(1);
}

app.disable("x-powered-by");
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "20kb" }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: {
    success: false,
    message: "Too many attempts. Please wait and try again."
  }
});

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
      minlength: 2,
      maxlength: 80
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      maxlength: 254
    },
    mobile: {
      type: String,
      default: "",
      maxlength: 25
    },
    passwordHash: {
      type: String,
      required: true
    },
    emailVerified: {
      type: Boolean,
      default: true
    }
  },
  { timestamps: true, versionKey: false }
);

const pendingSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true
    },
    mobile: { type: String, default: "" },
    passwordHash: { type: String, required: true },
    otpHash: { type: String, required: true },
    otpExpiresAt: { type: Date, required: true },
    otpLastSentAt: { type: Date, required: true },
    otpAttempts: { type: Number, default: 0 },
    verifiedAt: { type: Date, default: null }
  },
  { timestamps: true, versionKey: false }
);

const User = mongoose.model("User", userSchema);
const PendingRegistration = mongoose.model(
  "PendingRegistration",
  pendingSchema
);

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) &&
    email.length <= 254;
}

function makeOTP() {
  return String(crypto.randomInt(0, 1000000)).padStart(6, "0");
}

function hash(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function safeUser(user) {
  return {
    id: String(user._id),
    name: user.name,
    email: user.email,
    mobile: user.mobile || "",
    emailVerified: user.emailVerified,
    createdAt: user.createdAt
  };
}

function createMailer() {
  const {
    SMTP_HOST,
    SMTP_PORT,
    SMTP_USER,
    SMTP_PASS,
    SMTP_SECURE
  } = process.env;

  if (!SMTP_HOST || !SMTP_PORT || !SMTP_USER || !SMTP_PASS) {
    throw new Error("Email SMTP settings are missing.");
  }

  return nodemailer.createTransport({
    host: SMTP_HOST,
    port: Number(SMTP_PORT),
    secure: String(SMTP_SECURE).toLowerCase() === "true",
    auth: {
      user: SMTP_USER,
      pass: SMTP_PASS
    }
  });
}

async function sendOTPEmail(email, code) {
  // This mode is for local testing only.
  // Never enable it in production.
  if (
    process.env.DEV_SHOW_OTP === "true" &&
    process.env.NODE_ENV !== "production"
  ) {
    console.log(`[LOCAL TEST ONLY] OTP for ${email}: ${code}`);
    return;
  }

  const transporter = createMailer();

  await transporter.sendMail({
    from: process.env.MAIL_FROM,
    to: email,
    subject: "Your email verification code",
    text:
      `Your verification code is ${code}. ` +
      "It expires in 10 minutes. If you did not request it, ignore this email.",
    html: `
      <div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;padding:28px;color:#15232d">
        <h2 style="color:#129b8e">Verify your email</h2>
        <p>Use this six-digit code to continue creating your account.</p>
        <div style="font-size:32px;letter-spacing:8px;font-weight:bold;padding:20px;background:#e8faf7;text-align:center;border-radius:12px;color:#087e73">
          ${code}
        </div>
        <p>This code expires in 10 minutes.</p>
        <p style="color:#777;font-size:12px">If you did not request this code, you can ignore this email.</p>
      </div>
    `
  });
}

function createSession(res, user) {
  const token = jwt.sign(
    { sub: String(user._id) },
    process.env.JWT_SECRET,
    {
      expiresIn: "2h",
      issuer: "auth-page",
      audience: "auth-page-client"
    }
  );

  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 2 * 60 * 60 * 1000,
    path: "/"
  });
}

async function requireAuth(req, res, next) {
  try {
    const token = req.cookies[COOKIE_NAME];

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Please sign in first."
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET, {
      issuer: "auth-page",
      audience: "auth-page-client"
    });

    const user = await User.findById(decoded.sub);

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Account not found."
      });
    }

    req.user = user;
    next();
  } catch {
    return res.status(401).json({
      success: false,
      message: "Your session expired. Please sign in again."
    });
  }
}

// Health check for deployment monitoring.
app.get("/api/health", (req, res) => {
  const connected = mongoose.connection.readyState === 1;

  res.status(connected ? 200 : 503).json({
    success: connected,
    database: connected ? "connected" : "not_connected"
  });
});

// STEP 1: User requests an OTP.
// The final account is NOT created yet.
app.post("/api/auth/register", limiter, async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const email = normalizeEmail(req.body.email);
    const mobile = String(req.body.mobile || "").trim();
    const password = String(req.body.password || "");

    if (name.length < 2 || name.length > 80) {
      return res.status(400).json({
        success: false,
        message: "Name must contain 2 to 80 characters."
      });
    }

    if (!isValidEmail(email)) {
      return res.status(400).json({
        success: false,
        message: "Enter a valid email address."
      });
    }

    if (mobile.length > 25) {
      return res.status(400).json({
        success: false,
        message: "Mobile number is too long."
      });
    }

    if (password.length < 10 || password.length > 72) {
      return res.status(400).json({
        success: false,
        message: "Password must contain 10 to 72 characters."
      });
    }

    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: "This email already has an account. Please sign in."
      });
    }

    const existingPending = await PendingRegistration.findOne({ email });

    if (
      existingPending &&
      Date.now() - existingPending.otpLastSentAt.getTime() < RESEND_WAIT_MS
    ) {
      return res.status(429).json({
        success: false,
        message: "Please wait 60 seconds before requesting another OTP."
      });
    }

    const code = makeOTP();
    const passwordHash = await bcrypt.hash(password, 12);

    const pendingData = {
      name,
      email,
      mobile,
      passwordHash,
      otpHash: hash(code),
      otpExpiresAt: new Date(Date.now() + OTP_EXPIRY_MS),
      otpLastSentAt: new Date(),
      otpAttempts: 0,
      verifiedAt: null
    };

    let pending;

    if (existingPending) {
      Object.assign(existingPending, pendingData);
      pending = await existingPending.save();
    } else {
      pending = await PendingRegistration.create(pendingData);
    }

    try {
      await sendOTPEmail(email, code);
    } catch (mailError) {
      console.error("OTP email delivery failed:", mailError.message);

      return res.status(503).json({
        success: false,
        message: "Email could not be sent. Check SMTP settings and try again later."
      });
    }

    return res.json({
      success: true,
      message: "OTP sent. Check your inbox and spam folder.",
      email: pending.email
    });
  } catch (error) {
    console.error("Register error:", error.message);

    return res.status(500).json({
      success: false,
      message: "Unable to start registration. Please try again."
    });
  }
});

// STEP 2: Verify the OTP.
// This marks the pending registration as verified;
// it still does not create the final account.
app.post("/api/auth/verify-otp", limiter, async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const code = String(req.body.code || "").trim();

    if (!isValidEmail(email) || !/^\d{6}$/.test(code)) {
      return res.status(400).json({
        success: false,
        message: "Enter a valid email and six-digit OTP."
      });
    }

    const pending = await PendingRegistration.findOne({ email });

    if (!pending) {
      return res.status(400).json({
        success: false,
        message: "Registration not found. Please start again."
      });
    }

    if (pending.verifiedAt) {
      return res.json({
        success: true,
        message: "Email is already verified. You can continue."
      });
    }

    if (Date.now() > pending.otpExpiresAt.getTime()) {
      return res.status(400).json({
        success: false,
        message: "OTP expired. Request a new code."
      });
    }

    if (pending.otpAttempts >= 5) {
      return res.status(429).json({
        success: false,
        message: "Too many incorrect attempts. Request a new OTP."
      });
    }

    if (hash(code) !== pending.otpHash) {
      pending.otpAttempts += 1;
      await pending.save();

      return res.status(400).json({
        success: false,
        message: "Incorrect OTP. Please try again."
      });
    }

    pending.verifiedAt = new Date();
    pending.otpHash = "VERIFIED";
    await pending.save();

    return res.json({
      success: true,
      message: "Email verified successfully. Click Continue to create your account."
    });
  } catch (error) {
    console.error("OTP verification error:", error.message);

    return res.status(500).json({
      success: false,
      message: "Could not verify OTP. Please try again."
    });
  }
});

// Resend a new OTP for a pending registration.
app.post("/api/auth/resend-otp", limiter, async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const pending = await PendingRegistration.findOne({ email });

    if (!pending) {
      return res.status(400).json({
        success: false,
        message: "Registration not found. Please start again."
      });
    }

    if (pending.verifiedAt) {
      return res.status(400).json({
        success: false,
        message: "Email is already verified. You can continue."
      });
    }

    if (
      Date.now() - pending.otpLastSentAt.getTime() < RESEND_WAIT_MS
    ) {
      return res.status(429).json({
        success: false,
        message: "Please wait 60 seconds before resending."
      });
    }

    const code = makeOTP();
    pending.otpHash = hash(code);
    pending.otpExpiresAt = new Date(Date.now() + OTP_EXPIRY_MS);
    pending.otpLastSentAt = new Date();
    pending.otpAttempts = 0;

    await pending.save();

    try {
      await sendOTPEmail(email, code);
    } catch (mailError) {
      console.error("Resend email failed:", mailError.message);

      return res.status(503).json({
        success: false,
        message: "Email could not be sent. Try again later."
      });
    }

    return res.json({
      success: true,
      message: "A new OTP has been sent."
    });
  } catch (error) {
    console.error("Resend error:", error.message);

    return res.status(500).json({
      success: false,
      message: "Unable to resend OTP."
    });
  }
});

// STEP 3: User clicks Continue in the OTP popup.
// Only a verified pending registration can create an account.
app.post("/api/auth/complete-registration", limiter, async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const pending = await PendingRegistration.findOne({ email });

    if (!pending || !pending.verifiedAt) {
      return res.status(403).json({
        success: false,
        message: "Verify your email before creating an account."
      });
    }

    if (Date.now() - pending.verifiedAt.getTime() > 30 * 60 * 1000) {
      await PendingRegistration.deleteOne({ _id: pending._id });

      return res.status(400).json({
        success: false,
        message: "Verification session expired. Please register again."
      });
    }

    const user = await User.create({
      name: pending.name,
      email: pending.email,
      mobile: pending.mobile,
      passwordHash: pending.passwordHash,
      emailVerified: true
    });

    await PendingRegistration.deleteOne({ _id: pending._id });

    createSession(res, user);

    return res.status(201).json({
      success: true,
      message: "Your account has been created successfully!",
      user: safeUser(user)
    });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(409).json({
        success: false,
        message: "This email already has an account. Please sign in."
      });
    }

    console.error("Complete registration error:", error.message);

    return res.status(500).json({
      success: false,
      message: "Could not create your account. Please try again."
    });
  }
});

// Login is allowed only for an account that exists in MongoDB.
app.post("/api/auth/login", limiter, async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");

    const user = await User.findOne({ email });

    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
      return res.status(401).json({
        success: false,
        message: "Email or password is incorrect."
      });
    }

    if (!user.emailVerified) {
      return res.status(403).json({
        success: false,
        message: "Please verify your email before signing in."
      });
    }

    createSession(res, user);

    return res.json({
      success: true,
      message: "Signed in successfully.",
      user: safeUser(user)
    });
  } catch (error) {
    console.error("Login error:", error.message);

    return res.status(500).json({
      success: false,
      message: "Unable to sign in. Please try again."
    });
  }
});

// Return the currently signed-in user.
app.get("/api/auth/me", requireAuth, (req, res) => {
  res.json({
    success: true,
    user: safeUser(req.user)
  });
});

// Logout clears the session cookie.
app.post("/api/auth/logout", (req, res) => {
  res.clearCookie(COOKIE_NAME, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/"
  });

  res.json({
    success: true,
    message: "Signed out successfully."
  });
});

// Serve the frontend for normal page requests.
app.get("*", (req, res) => {
  if (req.path.startsWith("/api/")) {
    return res.status(404).json({
      success: false,
      message: "API route not found."
    });
  }

  res.sendFile(path.join(__dirname, "public", "index.html"));
});

async function startServer() {
  try {
    await mongoose.connect(process.env.MONGODB_URI);
    console.log("MongoDB connected successfully.");

    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  } catch (error) {
    console.error("Could not connect to MongoDB:", error.message);
    process.exit(1);
  }
}

startServer();
