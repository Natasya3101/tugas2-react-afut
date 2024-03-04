import express from "express";
import cors from "cors";
import { pool } from "../db.js";
import argon2 from "argon2";
import jwt from "jsonwebtoken"; // Tambahkan import jwt
import cookieParser from "cookie-parser"; // Tambahkan import cookieParser

const app = express();
app.use(express.json());
app.use(
  cors({
    origin: "https://presensi-shalat.vercel.app",
    credentials: true,
  })
);
app.use(cookieParser()); // Gunakan cookieParser untuk mengelola cookie

// Middleware untuk memverifikasi token JWT
const verifyToken = (req, res, next) => {
  // Mengambil token dari cookie
  const token = req.cookies.token;

  // Memeriksa apakah token ada
  if (!token) {
    return res.status(401).send("Token tidak tersedia.");
  }

  try {
    // Verifikasi token
    const decoded = jwt.verify(token, "secret_key"); // Ganti "secret_key" dengan kunci rahasia yang aman
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).send("Token tidak valid.");
  }
};

// Pendaftaran user
app.post("/api/v1/register", async (req, res) => {
  const hash = await argon2.hash(req.body.password);
  const result = await pool.query(
    "INSERT INTO users (username , password) VALUES ($1, $2)",
    [req.body.username, hash]
  );
  res.send("Pendaftaran Berhasil");
});


// Login user
app.post("/api/v1/login", async (req, res) => {
  const result = await pool.query("SELECT * FROM users WHERE username = $1", [
    req.body.username,
  ]);

  if (result.rows.length > 0) {
    if (await argon2.verify(result.rows[0].password, req.body.password)) {
      const token = jwt.sign({ username: req.body.username }, "secret_key", {
        expiresIn: "1h",
      });

      // Set cookie pada respon
      res.cookie("token", token, {
        httpOnly: true,
        secure: true,
        sameSite: "Strict", // Atur SameSite sesuai kebutuhan
      });

      // Kirim token sebagai respon untuk disimpan di frontend
      res.json({ token });

      // atau
      // res.send("Berhasil Login"); // Jika Anda tidak ingin mengirim token ke frontend
    } else {
      res.send("Password salah");
    }
  } else {
    res.send(`User dengan username ${req.body.username} tidak ditemukan`);
  }
});


// Mengamankan rute-rute di bawah dengan middleware verifyToken
app.use((req, res, next) => {
  if (req.path.startsWith("/api/login") || req.path.startsWith("/api/register")) {
    next();
  } else {
    verifyToken(req, res, next);
  }
});

// Rute untuk mendapatkan data mahasiswa dengan token JWT
app.get("/api/v1/students", verifyToken, async (req, res) => {
  try {
    // Mengambil data mahasiswa dari basis data
    const result = await pool.query("SELECT * FROM students");

    // Mengembalikan data mahasiswa sebagai respons
    res.json(result.rows);
  } catch (error) {
    // Menangani kesalahan jika terjadi
    console.error("Gagal mendapatkan data mahasiswa:", error);
    res.status(500).send("Terjadi kesalahan saat mengambil data mahasiswa.");
  }
});


// Rute untuk mendapatkan data mahasiswa dengan token JWT
app.get("/api/v1/students", verifyToken, async (req, res) => {
  try {
    // Mengambil data mahasiswa dari basis data
    const result = await pool.query("SELECT * FROM students");

    // Mengembalikan data mahasiswa sebagai respons
    res.json(result.rows);
  } catch (error) {
    // Menangani kesalahan jika terjadi
    console.error("Gagal mendapatkan data mahasiswa:", error);
    res.status(500).send("Terjadi kesalahan saat mengambil data mahasiswa.");
  }
});



// Get student by ID
app.get("/api/v1/students/:id", async (req, res) => {
  const result = await pool.query("SELECT * FROM students WHERE id = $1", [
    req.params.id,
  ]);
  res.json(result.rows[0]);
});
// Add student
app.post("/api/v1/students", verifyToken, async (req, res) => {
  try {
    const { name, generation } = req.body;
    
    // Memastikan data nama dan generasi tersedia
    if (!name || !generation) {
      return res.status(400).send("Nama dan generasi diperlukan.");
    }

    // Menambahkan data mahasiswa ke basis data
    const result = await pool.query(
      "INSERT INTO students (name, generation) VALUES ($1, $2) RETURNING *",
      [name, generation]
    );

    // Mengembalikan data mahasiswa yang baru ditambahkan sebagai respons
    res.json({
      student: result.rows[0],
      message: "Mahasiswa berhasil ditambahkan.",
    });
  } catch (error) {
    console.error("Gagal menambahkan mahasiswa:", error);
    res.status(500).send("Terjadi kesalahan saat menambahkan mahasiswa.");
  }
});

// Edit student by ID
app.put("/api/v1/students/:id", async (req, res) => {
  await pool.query(
    "UPDATE students SET name = $1, generation = $2 WHERE id = $3",
    [req.body.name, req.body.generation, req.params.id]
  );
  res.send("Mahasiswa berhasil diedit.");
});

// Set present by ID
app.put("/api/v1/students/:id/present", async (req, res) => {
  await pool.query("UPDATE students SET present = $1 WHERE id = $2", [
    req.body.present,
    req.params.id,
  ]);
  res.json(req.body.present);
});

// Delete student by ID
app.delete("/api/v1/students/:id", async (req, res) => {
  await pool.query("DELETE FROM students WHERE id = $1", [req.params.id]);
  res.send("Mahasiswa berhasil dihapus.");
});

app.listen(3000, () => console.log("Server berhasil dijalankan."));
