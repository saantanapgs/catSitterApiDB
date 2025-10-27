const express = require("express");
const cors = require("cors");
const { PrismaClient } = require("@prisma/client");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();
const prisma = new PrismaClient();

app.use(cors());
app.use(express.json());

// ============================
// 🔐 REGISTRO DE USUÁRIO
// ============================
app.post("/register", async (req, res) => {
  const { name, email, phone, birthday, password } = req.body;

  if (!name || !email || !phone || !birthday || !password) {
    return res.status(400).json({
      error: "Por favor, preencha todos os campos obrigatórios.",
    });
  }

  try {
    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      return res.status(400).json({ error: "E-mail já cadastrado." });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await prisma.user.create({
      data: {
        name,
        email,
        phone,
        birthday: new Date(birthday),
        password: hashedPassword,
      },
      select: {
        id: true,
        name: true,
        email: true,
        phone: true,
        birthday: true,
        role: true,
      },
    });

    res.status(201).json(user);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro ao registrar o usuário." });
  }
});

// ============================
// 🔑 LOGIN
// ============================
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(400).json({ error: "Usuário não encontrado." });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: "Senha incorreta." });

    const token = jwt.sign(
      { userId: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro ao fazer login." });
  }
});

// ============================
// 👤 PERFIL DO USUÁRIO
// ============================
app.get("/me", async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "Token ausente." });

  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const user = await prisma.user.findUnique({
      where: { id: decoded.userId },
      select: {
        id: true,
        name: true,
        email: true,
        phone: true,
        birthday: true,
        role: true,
      },
    });

    if (!user) return res.status(404).json({ error: "Usuário não encontrado." });

    res.json(user);
  } catch (err) {
    console.error(err);
    res.status(401).json({ error: "Token inválido ou expirado." });
  }
});

// ============================
// 🧾 CRUD DE SERVIÇOS
// ============================

// Criar um novo serviço (cliente solicita)
app.post("/services", async (req, res) => {
  const { userId, petName, serviceType, date, notes } = req.body;

  try {
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) return res.status(404).json({ error: "Usuário não encontrado." });

    const service = await prisma.service.create({
      data: {
        userId,
        petName,
        serviceType,
        date: new Date(date),
        notes,
      },
    });

    res.status(201).json(service);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro ao criar serviço." });
  }
});

// Listar todos os serviços (admin)
app.get("/services", async (req, res) => {
  try {
    const services = await prisma.service.findMany({
      include: {
        user: {
          select: { id: true, name: true, email: true, phone: true },
        },
      },
      orderBy: { createdAt: "desc" },
    });

    res.json(services);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro ao listar serviços." });
  }
});

// Listar serviços de um usuário específico (cliente)
app.get("/services/:userId", async (req, res) => {
  const { userId } = req.params;

  try {
    const services = await prisma.service.findMany({
      where: { userId: Number(userId) },
      orderBy: { createdAt: "desc" },
    });

    res.json(services);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro ao buscar serviços do usuário." });
  }
});

// ============================
// 🚀 INICIAR SERVIDOR
// ============================
app.listen(3000, () => console.log("✅ API rodando na porta 3000"));
