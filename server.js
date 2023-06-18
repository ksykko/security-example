const fs = require('fs')
const https = require('https')
const path = require('path')
const express = require('express')
const helmet = require('helmet')
const passport = require('passport')
const { Strategy } = require('passport-google-oauth20')
const cookieSession = require('cookie-session')

require('dotenv').config() // Load environment variables from .env file

const PORT = 3000

const config = {
    CLIENT_ID: process.env.CLIENT_ID,
    CLIENT_SECRET: process.env.CLIENT_SECRET,
    COOKIE_KEY_1: process.env.COOKIE_KEY_1,
    COOKIE_KEY_2: process.env.COOKIE_KEY_2,
}

const AUTH_OPTIONS = {
    callbackURL: '/auth/google/callback', // The URL that Google will call after the user has authenticated with Google
    clientID: config.CLIENT_ID,
    clientSecret: config.CLIENT_SECRET,
}

function verifyCallback(accessToken, refreshToken, profile, done) {
    console.log('Google profile', profile)
    done(null, profile) // Tells Passport that we are done processing the Google strategy and passes the profile to the serializeUser function
}

// Configure the Google strategy for use by Passport.js
passport.use(new Strategy(AUTH_OPTIONS, verifyCallback))

// Save the session to the cookie
passport.serializeUser((user, done) => {
    done(null, user.id)
})

// Extract / Read the session from the cookie
passport.deserializeUser((id, done) => {
    // User.findById(id).then((user) => {
    //     done(null, user)
    // })
    done(null, id)
})

const app = express()

app.use(helmet()) // Use helmet to secure Express with various HTTP headers

app.use(
    cookieSession({
        name: 'session',
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        keys: [config.COOKIE_KEY_1, config.COOKIE_KEY_2],
    })
)

app.use(passport.initialize()) // Use passport middleware to enable OAuth2 login
app.use(passport.session())

// Serialize the user profile into the session
function checkLoggedIn(req, res, next) {
    console.log('Current user is:', req.user)
    const isLoggedIn = req.isAuthenticated() && req.user
    if (!isLoggedIn) {
        return res.status(401).json({
            error: 'You must be logged in!',
        })
    }
    next()
}

app.get(
    '/auth/google',
    passport.authenticate('google', {
        scope: ['email'],
    })
)

app.get(
    '/auth/google/callback',
    passport.authenticate('google', {
        failureRedirect: '/failure',
        successRedirect: '/',
        session: true,
    }),
    (req, res) => {
        console.log('Google called us back!')
    }
)

app.get('/auth/logout', (req, res) => {
    req.logout() // remove the req.user property and clear the login session (if any)
    return res.redirect('/')
})

app.get('/secret', checkLoggedIn, (req, res) => {
    return res.send('Your personal secret value is 42!')
})

app.get('/failure', (req, res) => {
    return res.send('You have failed to login!')
})

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'))
})

https
    .createServer(
        {
            key: fs.readFileSync('key.pem'),
            cert: fs.readFileSync('cert.pem'),
        },
        app
    )
    .listen(PORT, () => {
        console.log(`Server listening on port ${PORT}`)
    })
