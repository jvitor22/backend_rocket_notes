const { hash, compare } = require("bcryptjs")
const AppError = require("../utils/AppError")
const sqliteConnection = require('../database/sqlite')

class UsersController {
  async create (request, response) {
    const { name, email, password } = request.body

    const database = await sqliteConnection()
    const checkUserExists = await database.get("SELECT * FROM users WHERE email = (?)", [email])

    if (checkUserExists) {
      throw new AppError("Este e-mail já está em uso!")  
    }

    const hashedPassword = await hash(password, 8)

    await database.run(
      "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
      [name, email, hashedPassword]
    )

  return response.status(201).json()
  }

  async update (request, response) {
    const { name, email, password, old_password } = request.body
    const user_id = request.user.id

    const database = await sqliteConnection()
   
    const user = await database.get("SELECT * FROM users WHERE id = (?)", [user_id])
    if(!user) {
      throw new AppError("Usuário não encontrado!")
    }

    const userWithUpdatedEmail = await database.get("SELECT * FROM users WHERE email = (?)", [email])
    if (userWithUpdatedEmail && userWithUpdatedEmail.id !== user.id) {
      throw new AppError("Este e-mail já está em uso!")  
    }

    user.name = name ?? user.name
    user.email = email ?? user.email

    if(password && !old_password) {
      throw new AppError("Você precisa informar a senha antiga para definir uma nova senha!")
    }

    if(password && old_password) {
      const checkOldPassword = await compare(old_password, user.password)
      if(!checkOldPassword) {
        throw new AppError("A senha antiga não confere!")
      }

      if(password === old_password) {
        throw new AppError("A nova senha deve ser diferente da senha antiga!")
      }

      user.password = await hash(password, 8)
    }
    

    await database.run(`
    UPDATE users SET
    name = ?,
    email = ?,
    password = ?,
    updated_at = DATETIME('now')
    WHERE id = ?`,
    [user.name, user.email, user.password, user_id]
    )

    return response.json()
  }
}


module.exports = UsersController


/*
Uma classe controller dever ter no máximo 5 métodos (se precisar criar mais que 5 métodos é pq vale a pena criar um controller separado) e pode haver apenas 1 ou mais, mas no máximo 5:
* index - GET para listar vários registros;
* show - GET para exibir um registro específico;
* create - POST para criar um registro;
* update - PUT para atualizar um registro;
* delete - DELETE para remover um registro.
*/ 