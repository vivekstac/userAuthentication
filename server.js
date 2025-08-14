const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const sequelize = require("./sequelize");
const User = require("./models/user");
const redis = require("./redis");
require("dotenv").config();

const app = express();
app.use(express.json());

// Middleware
const auth = async (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "No token" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const storedToken = await redis.get(`user:${decoded.id}:token`);
    if (storedToken !== token) {
      return res.status(401).json({ message: "Token invalidated" });
    }

    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ message: "Invalid token" });
  }
};


app.post("/register", async (req, res) => {
  const { email, password } = req.body;
  const hash = await bcrypt.hash(password, 10);
  try {
    const user = await User.create({ email, password: hash });
    res.json({ id: user.id, email: user.email });
  } catch {
    res.status(400).json({ message: "Email already exists" });
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ where: { email } });
  if (!user) return res.status(401).json({ message: "Invalid credentials" });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(401).json({ message: "Invalid credentials" });

  const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: "1h" });

  await redis.set(`user:${user.id}:token`, token);

  res.json({ token });
});

app.post("/logout", auth, async (req, res) => {
  await redis.del(`user:${req.user.id}:token`);
  res.json({ message: "Logged out" });
});

app.get("/me", auth, (req, res) => {
  res.json({ user: req.user });
});

(async () => {
  await sequelize.sync();
  app.listen(process.env.PORT, () => console.log(`Server running on port ${process.env.PORT}`));
})();
