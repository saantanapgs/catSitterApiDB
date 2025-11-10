const { PrismaClient } = require("@prisma/client")
const bcrypt = require("bcrypt")

const prisma = new PrismaClient()

async function main() {
  const existing = await prisma.user.findUnique({
    where: { email: "admin@email.com" },
  })

  if (existing) {
    console.log("Admin já existe.")
    return
  }

  const hashedPassword = await bcrypt.hash("thayadmin123", 10)

  const user = await prisma.user.create({
    data: {
      name: "Thay",
      email: "petsitterthay@gmail.com",
      phone: "79996405353",
      birthday: new Date("1990-01-01"),
      password: hashedPassword,
      role: "admin",
    },
  })

  console.log("Usuário admin criado:", user)
}

main()
  .then(() => {
    console.log("Finalizado com sucesso.")
    process.exit(0)
  })
  .catch((e) => {
    console.error("Erro ao criar admin:", e)
    process.exit(1)
  })
