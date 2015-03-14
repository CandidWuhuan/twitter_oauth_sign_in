var CryptoJS = require('crypto-js');

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
 		// TODO: throw exception
 		return null;
 	}

	var tokenSecret = oauthTokenSecret || '';
	var signingKey = consumerSecret + '&' + tokenSecret;

	 if ('PLAINTEXT' === signMethod) {
	 	return signingKey;
	 }

	var paramString = generateParameterString(params);
	var signatureBase = generateSignatureBase(reqMethod, url, paramString);

	var hash = null;
	switch (signMethod) {
		case 'HMAC-SHA1':
			hash = CryptoJS.HmacSHA1(signatureBase, signingKey);
			break;
	}

	var signature = CryptoJS.enc.Base64.stringify(hash);
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