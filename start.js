const logger = (msg) => console.log(msg)

const isProduction = process.env.NODE_ENV === "production"
if (!isProduction) {
	logger("=== Running in DEVELOPMENT mode === ")
	require('dotenv').config()
} else {
	logger("=== Running in PRODUCTION mode ===")
}

const axios = require("axios")
const express = require("express")
const FormData = require("form-data")
const session = require("express-session")
const { OIDCStrategy } = require("passport-azure-ad")
const MemoryStore = require("memorystore")(session)
const passport = require("passport")
const bodyParser = require("body-parser")

const app = express()

const { CLIENT_ID, CLIENT_SECRET, REPLY_URL, PORT, METADATA_URL, POLICY = "B2C_1A_SignInWithADFSIdp" } = process.env

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
	logger("Running onVerify function")

	if (!accessToken || !refreshToken) {
		logger("onVerify: Missing " + accessToken ? "access" : "refresh" + " token")
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
	req.query.p = req.query.p || POLICY
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
			<a href="/refresh">Refresh token</a><br>
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
    logger('Login was called in the Sample');
	res.redirect('/');
})

app.post("/auth/return", function(req, res, next) {
    passport.authenticate('azuread-openidconnect', 
      { 
        response: res,
        failureRedirect: "/auth/retry"
      }
    )(req, res, next);
  },
function(req, res) {
    logger('We received a return from AzureAD.');
    res.redirect('/user');
});

app.get("/auth/retry", (req, res, next) => {
	logger("Did hit the auth recovery process")
	logger("Step 1: Reload session")
	req.session.reload((error) => {
		if (error) {
			logger("Reload session data failed")
		} else {
			logger("Successfully reloaded session")
		}
		const attemptNumber = req.session.loginRetryCount
		if (attemptNumber && attemptNumber > 2) {
			logger("Too many login attempts, aborting login process")
			delete req.session.loginRetryCount
			res.redirect("/")
			return
		}
		return next()
	})
}, (req, res, next) => {
	const returnTo = req.session.returnTo
	const retryCount = req.session.loginRetryCount
	logger("Step 2: Trying to regenerate the session...")
	req.session.regenerate((err) => {
		if (err) {
			logger("Did not manage to regenerate session", err)
			return next(err)
		}
		logger("Success regenerating session.")
		req.session.returnTo = returnTo
		req.session.loginRetryCount = retryCount
		return next()
	})
},
(req, res) => {
	logger("Step 3: Redirect to login")
	const retryBefore = req.session.loginRetryCount
	req.session.loginRetryCount = (req.session.loginRetryCount || 0) + 1
	logger("Login retry count before is: " + retryBefore + " and after is: " + req.session.loginRetryCount)
	res.redirect("/auth/login")
})


const isAuthenticated = (req, res, next) => {
	if (req.isAuthenticated()) {
		return next()
	}
	res.status(401).send(htmlTemplate(`<h1>Unauthorized</h1>`))
}

app.get("/user", isAuthenticated, (req, res) => {
	res.send(htmlTemplate(JSON.stringify(req.user)))
})

const resolveRefreshToken = (req) => {
	try {
		return req.user.tokens.services.refresh_token
	} catch (e) {
		logger("Unable to resolve refresh token from the request. Missing user, user.tokens or user.tokens.")
		throw e
	}
}

const refreshTokenMiddleware = async (req, res, next) => {
	try {
		const refreshToken = resolveRefreshToken(req)
		if (!refreshToken) {
			return next(new Error("No refresh token received"))
		}
		logger("Got refresh token")

		const metadataResponse = await axios.get(METADATA_URL)
		const tokenEndpointUrl = new URL(metadataResponse.data.token_endpoint)
		tokenEndpointUrl.searchParams.append("p", POLICY)
		const form = new FormData()
		form.append("client_id", CLIENT_ID)
		form.append("client_secret", CLIENT_SECRET)
		form.append("grant_type", "refresh_token")
		form.append("scope", "offline_access https://dnvglb2cprod.onmicrosoft.com/83054ebf-1d7b-43f5-82ad-b2bde84d7b75/user_impersonation")
		form.append("refresh_token", refreshToken)

		const { data } = await axios.post(tokenEndpointUrl.toString(), form, { headers: form.getHeaders() })
		logger("Successful request to get new access token from refresh_token")

		if (data.access_token && data.refresh_token) {
			const { refresh_token, access_token, expires_in, expires_on } = data
			const additionalInfo = {}
			if (expires_in) additionalInfo.accessTokenExpires =  Number(expires_in)
			if (expires_on) additionalInfo.accessTokenLifetime = Number(expires_on)
			req.user.tokens.services = {
				access_token,
				refresh_token,
				...additionalInfo
			}
			logger("Success updating tokens to user session")
		} else {
			logger("No access_token or refresh_token found when trying to refresh in refreshTokenMiddleware")
			throw new Error("No access_token or refresh_token found when trying to refresh in refreshTokenMiddleware")
		}
		return next()
	} catch (error) {
		if (error.statusCode && error.statusCode > 299) {
			// tslint:disable-next-line: max-line-length
			logger("Fetch to get new access token failed with status code " + error.statusCode + " and message " + error.message)
		} else {
			logger("Error in createRefreshTokenMiddleware: '" + error.message + "'")
		}
		return next(error)
	}
}

app.get("/refresh", isAuthenticated, refreshTokenMiddleware, (req, res) => {
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
	logger(`Example app listening on http://localhost:${actualPort}/`)
})
