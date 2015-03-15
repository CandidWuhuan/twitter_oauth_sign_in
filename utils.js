var crypto = require('crypto');

module.exports = {
	percentEncode: percentEncode,
	getTimestampInSeconds: getTimestampInSeconds,
	generateNonce: generateNonce,
	generateSignature: generateSignature
}

function percentEncode(raw) {
	if (raw) {
		var encoded = encodeURIComponent(raw);
		return encoded
			.replace(/!/g, '%21')
			.replace(/'/g, '%27')
			.replace(/\(/g, '%28')
			.replace(/\)/g, '%29')
			.replace(/\*/g, '%2A');
	} else {
		return '';
	}
}

function getTimestampInSeconds() {
	return Math.floor((new Date()).getTime() / 1000);
}

function generateNonce(size) {
	var characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	var nonce = '';
	var index;
	for (var i=0; i<size; ++i) {
		index = Math.floor(Math.random() * characters.length);
		nonce += characters[index];
	}
	return nonce;
}

 function generateSignature(signMethod, reqMethod, url, params, consumerSecret, oauthTokenSecret) {
 	if ('HMAC-SHA1' !== signMethod && 'PLAINTEXT' !== signMethod ) {
 		throw 'Invalid signature method type [TYPE:' + signMethod + ']';
 	}

	var tokenSecret = oauthTokenSecret || '';
	var signingKey = consumerSecret + '&' + tokenSecret;

	 if ('PLAINTEXT' === signMethod) {
	 	return signingKey;
	 }

	var paramString = generateParameterString(params);
	var signatureBase = generateSignatureBase(reqMethod, url, paramString);

	var signature = null;
	switch (signMethod) {
		case 'HMAC-SHA1':
			(function() {
				var hmac = crypto.createHmac('sha1', signingKey);
				hmac.update(signatureBase);
				signature = hmac.digest('base64');
			})();
			break;
	}

	return signature;
}

function generateParameterString(params) {
	var encodedParams = [];
	var encodedKeys = [];

	for (var key in params) {
		if (params.hasOwnProperty(key)) {
			var encodedKey = percentEncode(key);
			var encodedValue = percentEncode(params[key]);
			encodedKeys.push(encodedKey);
			encodedParams[encodedKey] = encodedValue;
		}
	}

	encodedKeys.sort();

	var output = '';
	for (var i=0; i<encodedKeys.length; ++i) {
        var encodedKey = encodedKeys[i];
		output += encodedKey + '=' + encodedParams[encodedKey];
		if (i != encodedKeys.length - 1) {
			output += '&';
		}
	}
	return output;
}

function generateSignatureBase(reqMethod, url, paramString) {
	return reqMethod.toUpperCase() + '&' + percentEncode(url) + '&' + percentEncode(paramString);
}