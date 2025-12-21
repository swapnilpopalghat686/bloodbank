import bcrypt from "bcryptjs";
import Donor from "../models/donorModel.js";
import Facility from "../models/facilityModel.js";
import Admin from "../models/adminModel.js";
import jwt from "jsonwebtoken";

/**
 * REGISTER (Unified)
 */
export const register = async (req, res) => {
  try {
    const { role } = req.body;

    if (!role) {
      return res.status(400).json({ message: "Role is required" });
    }

    let user;

    if (role === "donor") {
      user = await Donor.create(req.body);
    } else if (role === "hospital" || role === "blood-lab") {
      user = await Facility.create(req.body);
    } else {
      return res.status(400).json({ message: "Invalid role" });
    }

    const redirect = role === "donor" ? "/donor/dashboard" : "/";

    res.status(201).json({
      success: true,
      message:
        role === "donor"
          ? "Donor registered successfully! Redirecting to dashboard..."
          : "Facility registered successfully! Please wait for admin approval.",
      user: { id: user._id, email: user.email, role: user.role },
      redirect,
    });
  } catch (error) {
    console.error("❌ Registration Error:", error);
    res.status(500).json({ message: "Registration failed" });
  }
};

/**
 * LOGIN
 */
export const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required" });
    }

    const user =
      (await Donor.findOne({ email }).select("+password")) ||
      (await Admin.findOne({ email }).select("+password")) ||
      (await Facility.findOne({ email }).select("+password"));

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    if (user instanceof Facility) {
      if (user.status === "pending" || user.status === "rejected") {
        return res.status(403).json({
          message: "Your account is not approved yet",
        });
      }
    }

    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.status(200).json({
      success: true,
      message: "Login successful",
      token,
      user: {
        id: user._id,
        email: user.email,
        role: user.role,
        status: user.status,
      },
    });
  } catch (error) {
    console.error("🚨 Login Error:", error);
    res.status(500).json({ message: "Login failed" });
  }
};

/**
 * PROFILE
 */
export const getProfile = async (req, res) => {
  try {
    let user;

    if (req.user.role === "donor") {
      user = await Donor.findById(req.user.id).select("-password");
    } else if (req.user.role === "admin") {
      user = await Admin.findById(req.user.id).select("-password");
    } else {
      user = await Facility.findById(req.user.id).select("-password");
    }

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.status(200).json({ user });
  } catch (error) {
    res.status(500).json({ message: "Error fetching profile" });
  }
};
