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
  return jwt.sign(payload, SECRET_KEY, {expiresIn})
}

// Verify the token
function verifyToken (token) {
  return jwt.verify(token, SECRET_KEY)
}

// Check if the user exists in database
function isAuthenticated ({email, password}) {
  return router.db.get('users').find({'email': email, 'password': password}).value()
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
  next()
})

// Post /auth/login to check users and return token
server.post('/auth/login', (req, res) => {
  const {email, password} = req.body
  if (typeof isAuthenticated({email, password}) === 'undefined') {
    const status = 401
    const message = 'Incorrect email or password'
    res.status(status).json({status, message})
    return
  }
  const token = createToken({email, password})
  res.status(200).json({token})
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
    res.status(status).json({status, message})
    return
  }
  try {
    verifyToken(req.headers.authorization.split(' ')[1])
    next()
  } catch (err) {
    const status = 401
    const message = 'Error: token is not valid'
    res.status(status).json({status, message})
  }
})

server.use(middlewares)
server.use('/api', router)

server.listen(port, () => {
  console.log('JSON Server is running on ' + port)
})
