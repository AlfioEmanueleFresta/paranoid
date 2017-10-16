/**
 * certificates.js
 *
 * Methods to generate and verify peer certificates.
 */
define(['./crypto'], function(crypto) {

	self = {};

	/** 
	 * Generate a certificate pair.
	 */
	self.generateCertificates = async function() {
		console.log("before");
		let signatureKeyPair  = await crypto.generateSignatureKeyPair();
		let encryptionKeyPair = await crypto.generateEncryptionKeyPair();
		console.log("after", signatureKeyPair, encryptionKeyPair);

		return {
			"public": {
				"signature":  signatureKeyPair.public,
				"encryption": encryptionKeyPair.public
			},
			"private": {
				"signature":  signatureKeyPair.private,
				"encryption": encryptionKeyPair.private
			}
		};
	};

	self.init = function() {
		console.debug("certificates:init");
	};


	// TODO change certificates to contain both signing and encryption keys
	// public: {encryption:, signature:}
	// private: {encryption:, signature:}
	
	self.init();
	return self;

});