const express = require('express')
const session = require('express-session')
const passport = require('passport')
const bcrypt = require('bcrypt')
const cors = require('cors')

require('./services/passport')
const { users } = require('./services/database')
const { ensureAuthenticated } = require('./middlewares/auth')

const app = express()

app.use(express.json())
app.use(cors({
    credentials: true,
    origin: 'http://localhost:3001'
}))
app.use(session({
    secret: 'your-session-secret',
    resave: false,
    saveUninitialized: false
}))
app.use(passport.initialize())
app.use(passport.session())

app.post('/register', async (req, res) => {
    const { name, email, password } = req.body

    try {
        if (!name || !email || !password) {
            return res.status(422).json({ error: 'name, email and password are required' })
        }

        if (await users.findOne({ email })) {
            return res.status(409).json({ error: 'email already is use' })
        }

        const hashedPassword = await bcrypt.hash(password, 10)

        const newUser = await users.insert({
            name,
            email,
            password: hashedPassword
        })

        res.status(201).json({ id: newUser._id, name: newUser.name, email: newUser.email })
    } catch (error) {
        res.status(500).json({ error: 'Something went wrong' })
    }
})

app.post('/login', async (req, res) => {
    passport.authenticate('local', (error, user, info) => {
        if (error) {
            return res.status(500).json({ error: 'Something went wrong' })
        }

        if (!user) {
            return res.status(401).json(info)
        }

        req.login(user, (error) => {
            if (error) {
                return res.status(500).json({ error: 'Something went wrong' })
            }

            return res.status(200).json({ id: user._id, name: user.name, email: user.email })
        })
    })(req, res)
})

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }))

app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: false }), (req, res) => {
    res.redirect('http://localhost:3001')
})

app.get('/logout', (req, res) => {
    req.logout((error) => {
        if (error) {
            return res.status(500).json({ error: 'Something went wrong' })
        }

        res.status(204).send()
    })
})

app.get('/me', ensureAuthenticated, (req, res) => {
    res.json({ id: req.user._id, name: req.user.name, email: req.user.email }) 
})

app.listen(3000, () => { console.log('Server started on port 3000') })