const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/User");

const router = express.Router();

// Register
router.post("/register", async (req, res) => {
  try {
    const { name, phone, age, password, confirmPassword } = req.body;

    if (!name?.trim() || !phone?.trim() || !age || !password) {
      return res.status(400).json({
        message: "Please fill all fields"
      });
    }

    if (!/^\d{10}$/.test(phone.trim())) {
      return res.status(400).json({
        message: "Enter a valid 10-digit phone number"
      });
    }

    if (!Number.isInteger(Number(age)) || Number(age) < 1) {
      return res.status(400).json({
        message: "Enter a valid age"
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        message: "Password must be at least 8 characters"
      });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({
        message: "Passwords do not match"
      });
    }

    const existingUser = await User.findOne({
      phone: phone.trim()
    });

    if (existingUser) {
      return res.status(409).json({
        message: "Phone number already registered"
      });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const user = await User.create({
      name: name.trim(),
      phone: phone.trim(),
      age: Number(age),
      password: hashedPassword
    });

    return res.status(201).json({
      message: "Registration successful",
      user: {
        id: user._id,
        name: user.name,
        phone: user.phone,
        age: user.age
      }
    });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(409).json({
        message: "Phone number already registered"
      });
    }

    console.error(error.message);
    return res.status(500).json({
      message: "Server error"
    });
  }
});

// Login
router.post("/login", async (req, res) => {
  try {
    const { phone, password } = req.body;

    if (!phone?.trim() || !password) {
      return res.status(400).json({
        message: "Phone number and password are required"
      });
    }

    const user = await User.findOne({
      phone: phone.trim()
    });

    if (!user) {
      return res.status(401).json({
        message: "Invalid phone number or password"
      });
    }

    const isMatch = await bcrypt.compare(
      password,
      user.password
    );

    if (!isMatch) {
      return res.status(401).json({
        message: "Invalid phone number or password"
      });
    }

    const token = jwt.sign(
      { userId: user._id.toString() },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    return res.status(200).json({
      message: "Login successful",
      token,
      user: {
        id: user._id,
        name: user.name,
        phone: user.phone,
        age: user.age
      }
    });
  } catch (error) {
    console.error(error.message);
    return res.status(500).json({
      message: "Server error"
    });
  }
});

export default router;