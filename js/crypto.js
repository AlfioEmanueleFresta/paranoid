/**
 * crypto.js
 *
 * Generate cryptographic keys, and operate with keys. 
 */
define(['./libs/base64js.min.js'], function(base64) {

	var ALGORITHM_ASYMMETRIC_SIGNATURE = {"name": "RSASSA-PKCS1-v1_5",
							    		  "modulusLength": 4096,
							    		  "publicExponent": new Uint8Array([1, 0, 1]), // 65537
										  "hash": {"name": "SHA-256"}};
	var ALGORITHM_ASYMMETRIC_ENCRYPTION = {"name": "RSA-OAEP",
							    		   "modulusLength": 2048,
							    		   "publicExponent": new Uint8Array([1, 0, 1]), // 65537
										   "hash": {"name": "SHA-256"}};
    var ALGORITHM_SYMMETRIC  = {"name": "AES-CBC",
								"length": 256} 

	self = {};


	var exportNativeKey = async function(nativeKey) {
		let jwk = await crypto.subtle.exportKey("jwk", nativeKey)
		return jwk;
	};

	/**
	 * Returns a promise to load a native private CryptoKey from the
	 * Javascript Object representing the JWK key.
	 */
	var loadSignaturePrivateKey = async function(jwk) {
		console.debug("crypto:loadSignaturePrivateKey", jwk);
		let nativeKey = await crypto.subtle.importKey(
			"jwk", jwk, ALGORITHM_ASYMMETRIC_SIGNATURE, true, ["sign"]
		);
		console.debug("crypto:loadSignaturePrivateKey", jwk);
		return nativeKey;
	};

	/**
	 * Returns a promise to load a native private CryptoKey from the
	 * Javascript Object representing the JWK key.
	 */
	var loadSignaturePublicKey = async function(jwk) {
		console.debug("crypto:loadSignaturePublicKey", jwk);
		let nativeKey = await crypto.subtle.importKey(
			"jwk", jwk, ALGORITHM_ASYMMETRIC_SIGNATURE, true, ["verify"]
		);
		console.debug("crypto:loadSignaturePublicKey", "Success");
		return nativeKey;
	};

	var loadEncryptionPrivateKey = async function(jwk) {
		console.debug("crypto:loadEncryptionPrivateKey", jwk);
		let nativeKey = await crypto.subtle.importKey(
			"jwk", jwk, ALGORITHM_ASYMMETRIC_ENCRYPTION, true, ["decrypt"]
		);
		console.debug("crypto:loadEncryptionPrivateKey", "Success");
		return nativeKey;
	};

	var loadEncryptionPublicKey = async function(jwk) {
		console.debug("crypto:loadEncryptionPublicKey", jwk);
		let nativeKey = await crypto.subtle.importKey(
			"jwk", jwk, ALGORITHM_ASYMMETRIC_ENCRYPTION, true, ["encrypt"]
		);
		console.debug("crypto:loadEncryptionPublicKey", "Success");
		return nativeKey;
	};

	var loadSymmetricKey = async function (jwk) {
		console.debug("crypto:loadSymmetricKey", jwk);
		let nativeKey = await crypto.subtle.importKey(
			"jwk", jwk, ALGORITHM_SYMMETRIC, true, ["encrypt", "decrypt"]
		);
		console.debug("crypto:loadSymmetricKey", "Success");
		return nativeKey;
	};

	var generateAsymmetricKeyPair = async function(algorithm, usages) {
		let keypair;
		try {
			keypair = await crypto.subtle.generateKey(algorithm, true, usages);

		} catch (error) {
			console.error("crypto:generateAsymmetricKeyPair", error);
			throw error;
		}

		console.debug("crypto:generateAsymmetricKeyPair");
		let nativePublic = keypair.publicKey;
		let nativePrivate = keypair.privateKey;
		let exportPublicPromise = exportNativeKey(nativePublic);
		let exportPrivatePromise = exportNativeKey(nativePrivate);

		let keys = await Promise.all([exportPublicPromise, exportPrivatePromise]);
		let publicKey = keys[0];
		let privateKey = keys[1];
		return {"public": publicKey, "private": privateKey};
	}

	var generateSymmetricKey = async function() {
		let usages = ["encrypt", "decrypt"];
		let key;
		try {
			key = await crypto.subtle.generateKey(
				ALGORITHM_SYMMETRIC, true, usages
			);

		} catch (error) {
			console.error("crypto:generateSymmetricKey", error);
		}
		let exportedKey = await exportNativeKey(key);
		console.debug("crypto:generateSymmetricKey", exportedKey);
		return exportedKey;
	};

	self.generateSymmetricKey = generateSymmetricKey;

	/**
	 * Returns a promise for a keypair.
	 *
	 * @return {Object({private: Object, public: Object})}	Key pair
	 */
	self.generateSignatureKeyPair = function() {
		return generateAsymmetricKeyPair(ALGORITHM_ASYMMETRIC_SIGNATURE, ["sign", "verify"]);
	};

	self.generateEncryptionKeyPair = function() {
		return generateAsymmetricKeyPair(ALGORITHM_ASYMMETRIC_ENCRYPTION, ["encrypt", "decrypt"]);
	};

	/**
	 * Return a promise to sign some binary. Returns base64 encoded data.
	 */
 	self.signData = async function(privateKey, base64data) {
 		let binaryData = base64.toByteArray(base64data);
 		let nativeKey = await loadSignaturePrivateKey(privateKey);
 		let signature = await crypto.subtle.sign(
 			ALGORITHM_ASYMMETRIC_SIGNATURE, nativeKey, binaryData
		);
		let base64signature = base64.fromByteArray(new Uint8Array(signature));
 		return base64signature;
 	};

 	/**
 	 * Return a promise to verify a signature using a key.
 	 */
 	self.verifySignature = async function(publicKey, base64data, base64signature) {
 		let binaryData = base64.toByteArray(base64data);
 		let binarySignature = base64.toByteArray(base64signature);
 		let nativeKey = await loadSignaturePublicKey(publicKey);
 		let result = await crypto.subtle.verify(
 			ALGORITHM_ASYMMETRIC_SIGNATURE, nativeKey, 
 			binarySignature, binaryData
		);
 		return result;
 	};

 	/** 
 	 * Generate a random initialisation vector for
 	 * AES-CBC symmetric crypto.
 	 */
 	var generateIV = async function() {
 		let length = 16;
 		let array = new Uint8Array(length);
 		crypto.getRandomValues(array);
 		return array;
 	};

 	var serialiseIV = function(iv) {
 		return base64.fromByteArray(iv);
 	};

 	var deserialiseIV = function(serialisedIV) {
 		let buffer = base64.toByteArray(serialisedIV);
 		let array = new Uint8Array(buffer);
 		return array;
 	};

 	var isSymmetricKey = function(key) {
 		return (key.alg == "A256CBC");
 	}

 	/**
 	 * Return a promise to encrypt some data using a key.
 	 */
 	var encryptData = async function(key, binaryData) {
 		if (isSymmetricKey(key)) {
 			// Symmetric crypto
 			let nativeKey = await loadSymmetricKey(key);
 			let iv = await generateIV();
 			let algorithm = ALGORITHM_SYMMETRIC;
 				algorithm.iv = iv;
 			let data = await crypto.subtle.encrypt(
 				algorithm, nativeKey, binaryData
 			);
 			let base64data = base64.fromByteArray(new Uint8Array(data));
 			let serialisedIV = serialiseIV(iv);
 			return {"iv": serialisedIV, "data": base64data};

 		} else {
 			// Asymmetric crypto
 			let nativeKey = await loadEncryptionPublicKey(key);
 			let data = await crypto.subtle.encrypt(
 				ALGORITHM_ASYMMETRIC_ENCRYPTION, nativeKey, binaryData
 			);
 			let base64data = base64.fromByteArray(new Uint8Array(data));
 			return base64data;

 		}
 	};

 	self.encryptData = encryptData;


 	var encryptText = async function(key, text) {
 		let encoder = new TextEncoder();
 		let data = encoder.encode(text);
 		return encryptData(key, data);
 	};

 	self.encryptText = encryptText;


 	var encryptObject = async function(key, obj) {
 		let text = JSON.stringify(obj);
 		return encryptText(key, text);
 	};

 	self.encryptObject = encryptObject;

 	/**
 	 * Decrypt some encrypted data.
 	 *
 	 * If the data was encrypted with an asymmetric key (RSA-OAP), the data must
 	 * be base64-encoded text, and IV should not be provided.
 	 *
 	 * If the data was encrypted with a symmetric key (AES-CBC), the data must
 	 * be an object {"data": base64data, "iv": iv}.
 	 * 
 	 * @param {Object} key 	A cryptographic key.
 	 * @param {Object({data, iv})|string} data  The data to decrypt.
 	 * @return string 	Base64-encoded data.
 	 */ 	
 	var decryptData = async function(key, data) {

 		let binaryData;
 		let algorithm;
 		let nativeKey;
 		if (isSymmetricKey(key)) {
 			// Symmetric crypto
 			let iv = deserialiseIV(data.iv);
 			binaryData = base64.toByteArray(data.data);
 			algorithm = ALGORITHM_SYMMETRIC;
 			algorithm.iv = iv;
 			nativeKey = await loadSymmetricKey(key);

 		} else {
 			// Asymmetric crypto
	 		binaryData = base64.toByteArray(data);
	 		algorithm = ALGORITHM_ASYMMETRIC_ENCRYPTION;
	 		nativeKey = await loadEncryptionPrivateKey(key);

 		}

 		let result = await crypto.subtle.decrypt(
 			algorithm, nativeKey, binaryData
 		);
 		return result;
 	};

 	self.decryptData = decryptData;


 	var decryptText = async function(key, base64data) {
 		let data = await decryptData(key, base64data);
 		let decoder = new TextDecoder();
 		let text = decoder.decode(data);
 		return text;
 	};

 	self.decryptText = decryptText;


 	var decryptObject = async function(key, base64data) {
 		let text = await decryptText(key, base64data);
 		let obj = JSON.parse(text);
 		return obj;
 	};

 	self.decryptObject = decryptObject;


	self.init = function() {
		console.debug("crypto:init");
	};

	self.init();
	return self;

});