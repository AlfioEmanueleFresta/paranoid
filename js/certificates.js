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
	var generateCertificates = async function() {
		console.debug("certificates:generateCertificates", "Please wait...");
		let signatureKeyPair  = await crypto.generateSignatureKeyPair();
		let encryptionKeyPair = await crypto.generateEncryptionKeyPair();

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

	self.generateCertificates = generateCertificates;


	self.init = function() {
		console.debug("certificates:init");
	};

	/**
	 * Compare two certificates for equality.
	 *
	 * @param {Object} a  The first certificate.
	 * @param {Object} b  The second certificate.
	 * @return {boolean} True if the certificates are equal, false otherwise.
	 */
	var compareCertificates = function(a, b) {
		let encryptionN = a.encryption.n == b.encryption.n;
		let encrpytionE = a.encryption.e == b.encryption.e;
		let signatureN  = a.signature.n  == b.signature.n;
		let signatureE  = a.signature.e  == b.signature.e;
		return encryptionN && encrpytionE && signatureN && signatureE;
	};

	self.compareCertificates = compareCertificates;


	// TODO change certificates to contain both signing and encryption keys
	// public: {encryption:, signature:}
	// private: {encryption:, signature:}
	
	self.init();
	return self;

});