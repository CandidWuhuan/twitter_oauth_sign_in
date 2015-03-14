var express = require('express');
var session = require('express-session');

var oauth = require('./oauth.js');

var app = express();

app.use(session({
	'resave': false,
	'saveUninitialized': true,
	'secret': 'password1234'
}));

app.use(function(req, res, next) {
	var session = req.session;
	if (!session) {
		return;
	}

	// twitter's oauth endpoints
	var oauthRequestTokenURL = 'https://api.twitter.com/oauth/request_token';
	var oauthAccessTokenURL  = 'https://api.twitter.com/oauth/access_token';
	var oauthAuthenticateURL = 'https://api.twitter.com/oauth/authenticate';

	var callbackURL = 'http://localhost:3000/auth/twitter';

	var SESSION_PREFIX = 'TWITTER_OAUTH.'; // Prevent session key collision

	var signMethod = 'HMAC-SHA1'; // OAuth signature method
	var consumerKey = '/* YOUR CONSUMER KEY HERE */';
	var consumerSecret = '/* YOUR CONSUMER SECRET HERE */';

	if (session[SESSION_PREFIX + 'authenticated']) {
		next();
	} else if (req.query['oauth_token'] && '/auth/twitter' === req['path']) { // twitter calls back
		oauth.getAccessToken(oauthAccessTokenURL, req.query['oauth_token'], req.query['oauth_verifier'], signMethod, consumerKey, consumerSecret, function(oauthToken, oauthTokenSecret) {
			if (req.query['oauth_token'] !== session[SESSION_PREFIX + 'oauth_token']) {
				res.writeHead(500);
				res.end('error 500');
				return;
			}

			session[SESSION_PREFIX + 'authenticated'] = true;

			// token and secret are no longer needed unless we need to access twitter api
			delete session[SESSION_PREFIX + 'oauth_token'];
			delete session[SESSION_PREFIX + 'oauth_token_secret'];
			
			// redirect to the URL of the original request
			var originalUrl = session[SESSION_PREFIX + 'original_url'];
			delete session[SESSION_PREFIX + 'original_url'];
			res.redirect('http://localhost:3000' + originalUrl);
		});
	} else {
		console.log('user attempts to access %s but user is not authenticated yet', req['path']);
		// save down url for redirect after authentication
		session[SESSION_PREFIX + 'original_url'] = req['originalUrl'];
		oauth.getRequestToken(oauthRequestTokenURL, callbackURL, signMethod, consumerKey, consumerSecret, function(oauthToken, oauthTokenSecret, oauthCallbackConfirmed) {
			if (oauthCallbackConfirmed) {
				session[SESSION_PREFIX + 'oauth_token'] = oauthToken;
				session[SESSION_PREFIX + 'oauth_token_secret'] = oauthTokenSecret;
				res.redirect(oauthAuthenticateURL + '?oauth_token=' + oauthToken);
			} else {
				console.log('oauth callback is not confirmed');
				res.writeHead(500);
				res.end('error 500 oauth callback is not confirmed');
			}
		});
	}
});

// Protected resources
app.get('/', function(req, res) {
	res.send('hello world');
	res.end();
});

var server = app.listen(3000, function() {
	console.log('server is started at 127.0.0.1:3000');
});

