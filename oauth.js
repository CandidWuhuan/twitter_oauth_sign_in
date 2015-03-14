var https   = require('https');
var querystring = require('querystring');
var url = require('url');

var utils = require('./utils.js');

module.exports = {
	getRequestToken: getRequestToken,
	getAccessToken: getAccessToken
}

function getRequestToken(requestTokenURL, callbackURL, signMethod, consumerKey, consumerSecret, callback) {
	var reqMethod = 'POST';
	var nonce = utils.generateNonce(32);	
	var timestamp = '' + utils.getTimestampInSeconds();
	var version = '1.0';

	var signature = generateRequestTokenSignature(
		reqMethod, 
		requestTokenURL, 
		nonce, 
		callbackURL, 
		signMethod, 
		timestamp,
		version,
		consumerKey,
		consumerSecret);

	var authHeader = 'OAuth' +
		' oauth_nonce="' + nonce + '",' +
		' oauth_callback="' + encodeURIComponent(callbackURL) + '",' +
		' oauth_consumer_key="' + consumerKey + '",' +
		' oauth_signature_method="' + signMethod + '",' +
		' oauth_signature="' + utils.percentEncode(signature) + '",' +
		' oauth_timestamp="' + timestamp + '",' +
		' oauth_version="' + version + '"';

	var options = generateHttpRequestOptions(requestTokenURL, reqMethod, null, authHeader);

	var req = https.request(options, function(res) {
		res.setEncoding('utf8');
		var raw = '';
		res.on('data', function(chunk) {
			raw += chunk;
		});
		res.on('end', function() {
			var data = querystring.parse(raw);
			callback(data['oauth_token'], data['oauth_token_secret'], data['oauth_callback_confirmed']);
		});
	});

	req.on('error', function(e) {
		console.log('problem with request: ' + e.message);
	});

	req.end();
}

function getAccessToken(accessTokenURL, oauthToken, oauthVerifier, signMethod, consumerKey, consumerSecret, callback) {
	var reqMethod = 'POST';
	var nonce = utils.generateNonce(32);
	var timestamp = '' + utils.getTimestampInSeconds();
	var version = '1.0';

	var signature = generateAccessTokenSignature(
		reqMethod, 
		accessTokenURL, 
		nonce, 
		signMethod, 
		timestamp,
		version,
		oauthToken,
		oauthVerifier,
		consumerKey,
		consumerSecret);

	var authHeader = 'OAuth' +
		' oauth_nonce="' + nonce + '",' +
		' oauth_consumer_key="' + consumerKey + '",' +
		' oauth_token="' + oauthToken + '",' +
		' oauth_signature_method="' + signMethod + '",' +
		' oauth_signature="' + utils.percentEncode(signature) + '",' +
		' oauth_timestamp="' + timestamp + '",' +
		' oauth_version="' + version + '"';

	var payload = 'oauth_verifier=' + oauthVerifier;

	var options = generateHttpRequestOptions(accessTokenURL, reqMethod, payload, authHeader);

	var req = https.request(options, function(res) {
		res.setEncoding('utf8');
		var raw = '';
		res.on('data', function(chunk) {
			raw += chunk;
		});
		res.on('end', function() {
			var data = querystring.parse(raw);
			callback(data['oauth_token'], data['oauth_token_secret']);
		});
	});

	req.on('error', function(e) {
		console.log('problem with request: ' + e.message);
	});

	req.write(payload, 'utf-8', function() {
		req.end();
	});
}

function generateRequestTokenSignature(reqMethod, requestTokenURL, nonce, callbackURL, signMethod, timestamp, version, consumerKey, consumerSecret) {
	var params = [];
	params['oauth_nonce'] = nonce;
	params['oauth_callback'] = callbackURL;
	params['oauth_signature_method'] = signMethod;
	params['oauth_timestamp'] = timestamp;
	params['oauth_consumer_key'] = consumerKey;
	params['oauth_version'] = version;

	return utils.generateSignature(signMethod, reqMethod, requestTokenURL, params, consumerSecret, null);
}

function generateAccessTokenSignature(reqMethod, accessTokenURL, nonce, signMethod, timestamp, version, oauthToken, oauthVerifier, consumerKey, consumerSecret) {
	var params = [];
	params['oauth_nonce'] = nonce;
	params['oauth_signature_method'] = signMethod;
	params['oauth_timestamp'] = timestamp;
	params['oauth_token'] = oauthToken;
	params['oauth_verifier'] = oauthVerifier;
	params['oauth_consumer_key'] = consumerKey;
	params['oauth_version'] = version;

	return utils.generateSignature(signMethod, reqMethod, accessTokenURL, params, consumerSecret, null);
}

function generateHttpRequestOptions(requestURL, reqMethod, payload, authHeader) {
	var reqUrl = url.parse(requestURL);

	return {
		hostname: reqUrl['host'],
		port: 'https:' === reqUrl['protocol'] ? 443 : 80, // assume either https or http
		path: reqUrl['path'],
		method: reqMethod,
		headers: {
			'Content-Type': 'application/x-www-form-urlencoded',
			'Content-Length': payload ? payload.length : "0",
			'Authorization': authHeader
		}
	};
}