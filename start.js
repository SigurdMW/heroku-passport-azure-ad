const isProduction = process.env.NODE_ENV === "production"
if (!isProduction) {
	console.log("=== Running in DEVELOPMENT mode === ")
	require('dotenv').config()
} else {
	console.log("=== Running in PRODUCTION mode ===")
}
const express = require("express")
const session = require("express-session")
const { OIDCStrategy } = require("passport-azure-ad")
const MemoryStore = require("memorystore")(session)
const passport = require("passport")
const bodyParser = require("body-parser")

const app = express()

const { CLIENT_ID, CLIENT_SECRET, REPLY_URL, PORT, METADATA_URL } = process.env

passport.serializeUser((user, done) => { done(null, user) })
passport.deserializeUser((passportSession, done) => { done(null, passportSession) })

passport.use(new OIDCStrategy({
    identityMetadata: METADATA_URL,
    clientID: CLIENT_ID,
	responseType: "code",
    responseMode: "form_post",
    redirectUrl: REPLY_URL,
    allowHttpForRedirectUrl: true,
    clientSecret: CLIENT_SECRET,
	isB2C: true,
    passReqToCallback: true,
    scope: [
		"openid", // Request the identity token
		"offline_access", // Request the refresh token so we can refresh if the access token times out
		"https://dnvglb2cprod.onmicrosoft.com/83054ebf-1d7b-43f5-82ad-b2bde84d7b75/user_impersonation"
	],
    loggingLevel: "info"
  },
  function(req, iss, sub, profile, jwtClaims, accessToken, refreshToken, params, done) {
	console.log("Running onVerify function")

	if (!accessToken || !refreshToken) {
		console.log("onVerify: Missing " + accessToken ? "access" : "refresh" + " token")
		return done(new Error("Missing " + accessToken ? "access" : "refresh" + " token"))
	}

	const user = {
		name: jwtClaims.name,
		id: jwtClaims.oid,
		displayName: profile.displayName,

		tokens: {
			services: {
				access_token: accessToken,
				refresh_token: refreshToken
			}
		}
	}

	done(null, user) // Tell passport that no error occurred (null) and which user object to store with the session.
  }
));

const ensureSignInPolicyQueryParameter = (req, res, next) => {
	req.query.p = req.query.p || "B2C_1A_SignInWithADFSIdp"
	next()
}

app.use(session({
	store: new MemoryStore(),
	secret: "sdasd-as-tsad-as-321-231",
	resave: true,
	saveUninitialized: false
}))

app.use(bodyParser.urlencoded({ extended : true }));

app.use(passport.initialize());
app.use(passport.session());

const htmlTemplate = (content) => (
	`
		<!DOCTYPE html>
		<html lang="en">
		<head>
			<meta charset="UTF-8">
			<meta name="viewport" content="width=device-width, initial-scale=1.0">
			<title>Test auth</title>
		</head>
		<body>
			<a href="/login">Login</a><br>
			<a href="/user">User info</a><br>
			<a href="/logout">Logout</a>
			<hr />
			${content}
		</body>
		</html>
	`
)

app.get("/", (req, res) => {
	res.send(htmlTemplate(""))
})

app.get("/login", ensureSignInPolicyQueryParameter, (req, res, next) => {
	passport.authenticate('azuread-openidconnect', { 
		response: res,
		failureRedirect: '/' 
	})(req, res, next)
},
function(req, res) {
    console.log('Login was called in the Sample');
	res.redirect('/');
})

app.post("/auth/return", function(req, res, next) {
    passport.authenticate('azuread-openidconnect', 
      { 
        response: res,                      // required
        failureRedirect: '/'  
      }
    )(req, res, next);
  },
function(req, res) {
    console.log('We received a return from AzureAD.');
    res.redirect('/user');
});

const isAuthenticated = (req, res, next) => {
	if (req.isAuthenticated()) {
		return next()
	}
	res.status(401).send(htmlTemplate(`<h1>Unauthorized</h1>`))
}

app.get("/user", isAuthenticated, (req, res) => {
	res.send(htmlTemplate(JSON.stringify(req.user)))
})

app.get("/logout", (req, res) => {
	req.logout()
	res.redirect("https://www.veracity.com/auth/logout")
})

app.use(function (err, req, res, next) {
	console.error(err.stack)
	res.status(500).send(htmlTemplate(JSON.stringify(err.stack)))
})

const actualPort = PORT || 3000

app.listen(actualPort, () => {
	console.log(`Example app listening on http://localhost:${actualPort}/`)
})
