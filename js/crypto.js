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


	var exportNativeKey = async function(nativeKey) {
		let jwk = await crypto.subtle.exportKey("jwk", nativeKey)
		return jwk;
	};

	/**
	 * Returns a promise to load a native private CryptoKey from the
	 * Javascript Object representing the JWK key.
	 */
	var loadSignaturePrivateKey = async function(jwk) {
		let nativeKey = await crypto.subtle.importKey(
			"jwk", jwk, ALGORITHM_ASYMMETRIC_SIGNATURE, true, ["sign"]
		);
		return nativeKey;
	};

	/**
	 * Returns a promise to load a native private CryptoKey from the
	 * Javascript Object representing the JWK key.
	 */
	var loadSignaturePublicKey = async function(keyObject) {
		let jwk = JSON.stringify(keyObject);
		let nativeKey = await crypto.subtle.importKey(
			"jwk", jwk, ALGORITHM_ASYMMETRIC_SIGNATURE, true, ["verify"]
		);
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
 	self.signBinaryData = async function(privateKey, data) {
 		let nativeKey = await loadSignaturePrivateKey(privateKey);
 		let signature = await crypto.subtle.sign(
 			ALGORITHM_ASYMMETRIC_SIGNATURE, nativeKey, data
		);
 		return signature;
 	};

 	/**
 	 * Return a promise to verify a signature using a key.
 	 */
 	self.verifySignatureBinary = async function(publicKey, data, signature) {
 		let nativeKey = await loadSignaturePublicKey(publicKey);
 		let result = await crypto.subtle.verify(
 			ALGORITHM_ASYMMETRIC_SIGNATURE, nativeKey, signature, data
		);
 		return result;
 	};


	self.init = function() {
		console.debug("crypto:init");
	};

	self.init();
	return self;

});