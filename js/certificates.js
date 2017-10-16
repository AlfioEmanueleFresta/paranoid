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
	self.generateCertificates = function() {
		return new Promise(function(resolve, reject) {
			crypto.generateSignatureKeyPair()
			.then(function(keyPair) {
				resolve({"public": keyPair.public},
						{"private": keyPair.private})

			}).catch(function(error) {
				console.error("certificates:generateCertificate", error);
				reject(error);

			});
		});
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