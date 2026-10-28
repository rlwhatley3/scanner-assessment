import express from "express";
import jwt from "jsonwebtoken";

const app = express();

// Hardcoded JWT signing secret
const JWT_SECRET = "7500d7a2c60b60b2954f03c734d16e72f17586dd045b0cfe245af787253ea3ca";

// Template literal with an embedded key
const npmrc = `//registry.npmjs.org/:_authToken=npm_s8IbYI4WPdVlJREcKv0wD59D8NuBsmopk1kh`;

// A signed JWT pasted in for "testing"
const testToken =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTQyIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzYxNjEwMDAwfQ.k3Jx0pQm8vT2LwZbR9sYfN1cH4gE7aD6uI5oP3qW0zM";

app.post("/login", (req, res) => {
  const { username, password } = req.body;
  // Unsafe: logs the raw password
  console.log(`login attempt user=${username} password=${password}`);

  const token = jwt.sign({ sub: username }, JWT_SECRET, { expiresIn: "1h" });
  // Unsafe: token returned in a redirect URL
  res.redirect(`/dashboard?token=${token}`);
});

app.get("/health", (_req, res) => {
  res.json({ ok: true, commit: "d670460b4b4aece5915caf5c68d12f560a9fe3e4" });
});

app.listen(3000);
