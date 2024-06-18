import express from "express";
import Joi from "joi";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import gravatar from "gravatar";
import path from "path";
import fs from "fs/promises";
import multer from "multer";
import jimp from "jimp";
import User from "../../models/user.js";
import auth from "../../middlewares/auth.js";
import { sendEmail } from "../../utils/sendEmail.js";
import { v4 as uuidv4 } from "uuid";

const router = express.Router();

const userSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
});

const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
});

router.post("/signup", async (req, res) => {
  try {
    const { error, value } = userSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ message: error.details[0].message });
    }

    const { email, password } = value;
    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res.status(409).json({ message: "Email in use" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const avatarURL = gravatar.url(email, { s: "250", d: "retro" }, true);
    const verificationToken = uuidv4();

    const newUser = await User.create({
      email,
      password: hashedPassword,
      avatarURL,
      verificationToken,
      verify: false,
    });

    const verifyLink = `http://localhost:3000/api/users/verify/${verificationToken}`;
    const html = `<a href="${verifyLink}">Click here to verify your email</a>`;

    await sendEmail(email, "Verify your email", html);

    res.status(201).json({
      user: {
        email: newUser.email,
        subscription: newUser.subscription,
        avatarURL: newUser.avatarURL,
      },
    });
  } catch (error) {
    res.status(500).json({ message: `Server error: ${error.message}` });
  }
});

router.post("/login", async (req, res) => {
  try {
    const { error, value } = loginSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ message: error.details[0].message });
    }

    const { email, password } = value;
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(401).json({ message: "Email or password is wrong" });
    }

    const isPasswordCorrect = await bcrypt.compare(password, user.password);
    if (!isPasswordCorrect) {
      return res.status(401).json({ message: "Email or password is wrong" });
    }

    const token = jwt.sign({ id: user._id }, "secret_key", { expiresIn: "1h" });
    user.token = token;
    await user.save();

    res.status(200).json({
      token,
      user: {
        email: user.email,
        subscription: user.subscription,
        avatarURL: user.avatarURL,
      },
    });
  } catch (error) {
    res.status(500).json({ message: `Server error: ${error.message}` });
  }
});

router.get("/logout", auth, async (req, res) => {
  try {
    req.user.token = null;
    await req.user.save();
    res.status(204).send();
  } catch (error) {
    res.status(500).json({ message: `Server error: ${error.message}` });
  }
});

router.get("/current", auth, (req, res) => {
  const { email, subscription, avatarURL } = req.user;
  res.status(200).json({ email, subscription, avatarURL });
});

const uploadDir = path.join(process.cwd(), "tmp");
const avatarsDir = path.join(process.cwd(), "public", "avatars");

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const [name, ext] = file.originalname.split(".");
    cb(null, `${req.user._id}.${ext}`);
  },
});

const upload = multer({ storage });

router.patch("/avatars", auth, upload.single("avatar"), async (req, res) => {
  try {
    const { path: tempUpload, originalname } = req.file;
    const [name, ext] = originalname.split(".");
    const newFileName = `${req.user._id}.${ext}`;
    const resultUpload = path.join(avatarsDir, newFileName);

    await jimp
      .read(tempUpload)
      .then((image) => {
        return image.resize(250, 250).write(resultUpload);
      })
      .catch((err) => {
        throw err;
      });

    await fs.unlink(tempUpload);

    const avatarURL = `/public/avatars/${newFileName}`;
    req.user.avatarURL = avatarURL;
    await req.user.save();

    res.json({ avatarURL });
  } catch (error) {
    res.status(500).json({ message: `Server error: ${error.message}` });
  }
});

// Endpoint pentru verificare
router.get("/verify/:verificationToken", async (req, res) => {
  try {
    const { verificationToken } = req.params;
    const user = await User.findOne({ verificationToken });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    user.verificationToken = null;
    user.verify = true;
    await user.save();

    res.status(200).json({ message: "Verification successful" });
  } catch (error) {
    res.status(500).json({ message: `Server error: ${error.message}` });
  }
});

router.post("/verify", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ message: "missing required field email" });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (user.verify) {
      return res
        .status(400)
        .json({ message: "Verification has already been passed" });
    }

    const verifyLink = `http://localhost:3000/api/users/verify/${user.verificationToken}`;
    const html = `<a href="${verifyLink}">Click here to verify your email</a>`;

    await sendEmail(email, "Verify your email", html);

    res.status(200).json({ message: "Verification email sent" });
  } catch (error) {
    res.status(500).json({ message: `Server error: ${error.message}` });
  }
});

export default router;
