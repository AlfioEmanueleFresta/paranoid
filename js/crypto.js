/**
 * crypto.js
 *
 * Generate cryptographic keys, and operate with keys. 
 */
define(function() {

	var ALGORITHM_ASYMMETRIC_SIGNATURE = {"name": "RSASSA-PKCS1-v1_5",
							    		  "modulusLength": 4096,
							    		  "publicExponent": new Uint8Array([1, 0, 1]), // 65537
										  "hash": {"name": "SHA-256"}};
	var ALGORITHM_ASYMMETRIC_ENCRYPTION = {"name": "RSA-OAEP",
							    		   "modulusLength": 2048,
							    		   "publicExponent": new Uint8Array([1, 0, 1]), // 65537
										   "hash": {"name": "SHA-256"}};
    var ALGORITHM_SYMMETRIC  = {"name": "AES-CBC",
								"length": 512} 

	self = {};


	var exportNativeKey = function(nativeKey) {
		return new Promise(function(resolve, reject) {
			crypto.subtle.exportKey("jwk", nativeKey)
			.then(function(jwk) {
				resolve(jwk);

			}).catch(function(error) {
				console.error("crypto:exportNativeKey", error);
				reject(error);

			});
		});
	};

	/**
	 * Returns a promise to load a native private CryptoKey from the
	 * Javascript Object representing the JWK key.
	 */
	var loadSignaturePrivateKey = function(jwk) {
		return new Promise(function(resolve, reject) {
			crypto.subtle.importKey("jwk", jwk, ALGORITHM_ASYMMETRIC_SIGNATURE,
									true, ["sign"])
			.then(function(nativeKey) {
				resolve(nativeKey);

			}).catch(function(error) {
				console.error("crypto:loadSignaturePrivateKey", error);
				reject(error);

			})
		});
	};

	/**
	 * Returns a promise to load a native private CryptoKey from the
	 * Javascript Object representing the JWK key.
	 */
	var loadSignaturePublicKey = function(keyObject) {
		let jwk = JSON.stringify(keyObject);
		return new Promise(function(resolve, reject) {
			crypto.subtle.importKey("jwk", jwk, ALGORITHM_ASYMMETRIC_SIGNATURE,
									true, ["verify"])
			.then(function(nativeKey) {
				resolve(nativeKey);

			}).catch(function(error) {
				console.error("crypto:loadSignaturePublicKey", error);
				reject(error);

			})
		});
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
	 * Return a promise to sign some binary.
	 */
 	self.signBinaryData = function(privateKey, data) {
 		return new Promise(function(resolve, reject) {
 			loadSignaturePrivateKey(privateKey)
 			.then(function(nativeKey) {
 				crypto.subtle.sign(ALGORITHM_ASYMMETRIC_SIGNATURE, nativeKey, data)
 				.then(function(signature) {
 					resolve(signature);

 				})
 				.catch(function(error) {
 					console.error("crypto:signBinaryData", error);
 					reject(error);

 				})
 			});
 		});
 	};

 	/**
 	 * Return a promise to verify a signature using a key.
 	 */
 	self.verifySignatureBinary = function(publicKey, data, signature) {
 		return new Promise(function(resolve, reject) {
 			loadSignaturePublicKey(publicKey)
 			.then(function(nativeKey) {
 				crypto.subtle.verify(ALGORITHM_ASYMMETRIC_SIGNATURE, nativeKey,
 									 signature, data)
 				.then(function(result) {
 					resolve(result);

 				}).catch(function(error) {
 					console.error("crypto:verifySignatureBinary", error);

 				});
 			});
 		});
 	};


	self.init = function() {
		console.debug("crypto:init");
	};

	self.init();
	return self;

});