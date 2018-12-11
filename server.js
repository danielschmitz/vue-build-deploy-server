const jsonServer = require('json-server')
const jwt = require('jsonwebtoken')
const bodyParser = require('body-parser')

const server = jsonServer.create()
const router = jsonServer.router('northwind.json')

const SECRET_KEY = '123456789'
const expiresIn = '1h'

const options = {
  static: 'dist'
}

const middlewares = jsonServer.defaults(options)
const port = process.env.PORT || 3000

// Create a token from a payload & Secrect key
function createToken (payload) {
  return jwt.sign(payload, SECRET_KEY, { expiresIn })
}

// Verify the token
function verifyToken (token) {
  return jwt.verify(token, SECRET_KEY)
}

// Check if the user exists in database
function isAuthenticated ({ email, password }) {
  return router.db.get('users').find({ 'email': email, 'password': password }).value()
}

/* router post config */
server.use(bodyParser.json())
server.use(bodyParser.urlencoded({
  extended: true
}))

/* Cors */
server.use(function (req, res, next) {
  res.header('Access-Control-Allow-Origin', '*')
  res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,PATCH, OPTIONS')
  res.header('Access-Control-Allow-Headers', 'Origin, authorization, X-Requested-With, Content-Type, Accept')
  res.header('Access-Control-Expose-Headers', 'Refresh')
  next()
})

// Post /auth/login to check users and return token
server.post('/auth/login', (req, res) => {
  const { email, password } = req.body
  if (typeof isAuthenticated({ email, password }) === 'undefined') {
    const status = 401
    const message = 'Incorrect email or password'
    res.status(status).json({ status, message })
    return
  }
  const token = createToken({ email, password })
  res.status(200).json({ token })
})

server.post('/econv/auth', (req, res) => {
  res.status(200).json({
    "data": {
      "ativo": "1",
      "fk_parametros": 1,
      "nome": "James Bond",
      "username": "bond"
    },
    "message": "Token criado.",
    "refresh": "eyJ0eX.....................",
    "resource": "Auth",
    "status": 200,
    "token": "eyJ0eXAiOi.................."
  })
})
server.get('/econv/associados/', (req, res) => {
  res.status(200).json({
    "_meta": {
      "page": req.query.page,
      "per_page": 10,
      "total_items": 18489,
      "total_pages": 1849
    },
    "data": [
      {
        "associado": "ABDENAGO SILVA CASTRO",
        "cpf": "000.000.128-92",
        "dt_nascimento": null,
        "id_associado": 12892,
        "rg": " "
      },
      {
        "associado": "ABEL FERREIRA DA SILVA",
        "cpf": "025.946.078-86",
        "dt_nascimento": "1966-05-16",
        "id_associado": 9828,
        "rg": " "
      },
      {
        "associado": "ABEL FERREIRA DA SILVA",
        "cpf": "279.383.788-10",
        "dt_nascimento": "1979-09-25",
        "id_associado": 2449,
        "rg": " "
      },
      {
        "associado": "ABEL JOSE DA SILVA",
        "cpf": "311.222.498-10",
        "dt_nascimento": "1981-03-05",
        "id_associado": 2246,
        "rg": " "
      },
      {
        "associado": "ABEL MARQUES CARDOSO",
        "cpf": "000.000.133-53",
        "dt_nascimento": null,
        "id_associado": 13353,
        "rg": " "
      },
      {
        "associado": "ABIMAEL FIDELIS FERLETE",
        "cpf": "000.000.130-61",
        "dt_nascimento": null,
        "id_associado": 13061,
        "rg": " "
      },
      {
        "associado": "ABINER ARCO DA SILVA",
        "cpf": "217.288.228-31",
        "dt_nascimento": "1979-11-11",
        "id_associado": 16203,
        "rg": " "
      },
      {
        "associado": "ABNER AUGUSTO FALCO",
        "cpf": "000.000.111-69",
        "dt_nascimento": null,
        "id_associado": 11169,
        "rg": " "
      },
      {
        "associado": "ABNER GINEZ",
        "cpf": "213.312.918-95",
        "dt_nascimento": "1975-06-28",
        "id_associado": 9475,
        "rg": " "
      },
      {
        "associado": "ABRAÃO RAFAEL",
        "cpf": "090.141.678-90",
        "dt_nascimento": "1967-10-14",
        "id_associado": 725,
        "rg": " "
      }
    ],
    "message": "Lista os/as associados paginados(as).",
    "resource": "Asssociados",
    "status": 200
  })
})




// Any route with /api was checked
server.use('/api', (req, res, next) => {
  if (req.method === 'OPTIONS') {
    next()
    return
  }
  if (req.headers.authorization === undefined || req.headers.authorization.split(' ')[0] !== 'Bearer') {
    const status = 401
    const message = 'Bad authorization header'
    res.status(status).json({ status, message })
    return
  }
  try {
    let decode = verifyToken(req.headers.authorization.split(' ')[1])
    if (decode !== undefined) {
      let { email, password } = decode
      const refreshToken = createToken({ email, password })
      res.set("Refresh", [refreshToken])
    }
    next()
  } catch (err) {
    const status = 401
    const message = 'Error: token is not valid'
    res.status(status).json({ status, message })
  }
})

server.use(middlewares)
server.use('/api', router)

server.listen(port, () => {
  console.log('JSON Server is running on ' + port)
})
