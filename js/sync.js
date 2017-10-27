/**
 * sync.js
 *
 * Synchronisation utility.
 */
define(['./preferences', './certificates', './stores/certificates'], 
	function(preferences, certificates, certStore) {

	var PREFERENCES_CHECK_EVERY_MS = 5000;

	self = {
		"enabled": false
	};

	self.connections = {};

	/**
	 * Enable synchronisation. Start all connections.
	 */
	self.enable = async function() {
		// Connect to server.
		if (!self.connect()) {
			console.error("sync:enable", "Unable to connect to server.");
			return;
		}

		self.enabled = true;
	};

	self.connect = async function() {
		
		// Get PeerJS preferences
		let host = preferences.get("sync:host");
		let port = preferences.get("sync:port");
		let secure = preferences.get("sync:secure");

		let options = {"host": host, "port": port, "secure": secure};
		let peerId = self.getId();
		let certificates = await self.getCertificates();

		self.peer = new Peer(peerId, options);
		self.peer.on("open", function(id) {
			console.debug("sync:connect:open", id);
			peerId = id;
		});
		self.peer.on("error", function(error) {
			console.debug("sync:onerror", error);
		});

		self.peer.on("connection", function(conn) {
			console.debug("sync:connection", conn.peer);
			self.registerConnection(conn, false);
		});

		return true;
	};

	self.connectToPeer = function(peerId) {
		console.debug("sync:connectToPeer", peerId);
		let newConnection;
		try {
			newConnection = self.peer.connect(peerId);
		} catch (error) {
			console.error("sync:connectToPeer", error);
		}
		self.registerConnection(newConnection, true);
	};

	self.disconnectPeer = function(peerId) {
		console.debug("sync:disconnectPeer", peerId);
		let connection = self.connections[peerId];
		if ( connection ) {
			connection.close();
			delete self.connections[peerId];
		}
	};

	self.registerConnection = async function(newConnection, outbound) {
		console.debug("sync:registerConnection", newConnection);
		let peerId = newConnection.peer;

		if (!outbound) {
			let shouldRegister = confirm("Do you want to accept a connection from " + peerId + "?");
			if (!shouldRegister) {
				console.debug("sync:registerConnection", "ignored incoming connection from" + peerId);
				return;
			}
		}

		self.connections[peerId] = newConnection;
		console.debug("sync:registerConnection", peerId);

		// Add connection handlers
		newConnection.on('open', function() {
			console.debug("sync:registerConnection:open", peerId);

			newConnection.on('data', function(data) {
				self.dispatch(peerId, data);
			});

			newConnection.on('close', function() {
				self.disconnectPeer(peerId);
			});

			self.sendHandshake(peerId);
		});


	};

	self.sendHandshake = async function(peerId) {
		let publicCertificate = await self.getCertificates();
		let handhakeData = {
			"certificate": publicCertificate.public
			// TODO version information
		};
		self.sendPlaintextMessage(peerId, "handshake", handhakeData);
	};

	var unencryptedHandler = function(handler) {
		let modifiedHandler = async function(peerId, message) {
			if (message.encrypted) {
				console.error("sync:unencryptedHandler", "Unencrypted message is actually encrypted.",
							  message);
				return;
			}

			return handler(peerId, message);
		};
		return modifiedHandler;
	};

	var encryptedHandler = function(handler) {
		let modifiedHandler = async function(peerId, message) {
			if (!message.encrypted) {
				console.error("sync:encryptedHandler", "Encrypted message is not actually encrypted.",
							  message);
				return;
			}

			let decrypted = self.decryptMessage(peerId, message);
			if (!decrypted) {
				return;
			}

			return hander(peerId, decrypted);
		}
		return modifiedHandler;
	};

	var PEER_CERTIFICATES = {};

	var HANDLERS = {};

	/**
	 * Handle an handshake message.
	 */
	var handleHandshake = async function(peerId, message) {
		let knownCertificate = await certStore.getPeerCertificate(peerId);
		let presentedCertificate = message.certificate;
		
		console.debug("sync:handleHandshake", peerId, {"known": knownCertificate,
													   "presented": presentedCertificate});

		if (!knownCertificate) {
			// This is the first time we connect with this peer.

			let shouldContinue = confirm(peerId + " presented certificate " + presentedCertificate + ", accept?");
			if (!shouldContinue) {
				console.warn("sync:handleHandshake", "Certificate presented by peer", peerId, "was refused by user", presentedCertificate)
				self.dropConnection(peerId);
				return;
			}

			// User accepted certificate
			certStore.setPeerCertificate(peerId, presentedCertificate);
			knownCertificate = presentedCertificate;
			console.debug("sync:handleHandshake", "Certificate presented by peer", peerId, "was accepted.");

		} else if (!certificates.compareCertificates(knownCertificate, presentedCertificate)) {
			// Something is wrong!!1!
			console.warn("sync:handleHandshake", "Peer presented different certificate. Refusing connection.");
			self.dropConnection(peerId);

			// Notify user
			// TODO improve
			alert("Peer " + peerId + " presented a different certificate. Connection dropped.");
			// TODO allow change of certificate?
		}

		console.debug("sync:handleHandshake", peerId, "Handshake successful.");

		// Send an hello message.
		self.sendEncryptedMessage(peerId, {"hello": "Hey!"});

	};

	var handleHello = async function(peerId, message) {
		console.log("sync:handleHello", peerId, "says hello!", message);
	};

	// Set protocol handlers
	HANDLERS["handshake"] = unencryptedHandler	(handleHandshake);
	HANDLERS["hello"]	  = encryptedHandler	(handleHello);

	/**
	 * Handle data received from a peer.
	 */
	self.dispatch = function(peerId, message) {
		console.debug("sync:dispatch", peerId, message);

		if (message.encrypted) {
			message = self.decryptMessage(peerId, message);
		}

		let handler = HANDLERS[message.type];
		if (!handler) {
			console.warn("sync:dispatch", peerId, "Unknown request type", message);
			return;
		}

		// Handle message
		handler(peerId, message.data);
	};

	/**
	 * Decrypt a message received from a known peer.
	 */
	self.decryptMessage = function(peerId, message) {
		// TODO get peer's public key
		//		verify signature {"signature"} using known public key
		// 		if valid, decrypt symmetric key {"encryptedKey"}
		//		use decrypted key to decrypt JSON data {"encryptedData"}
		//		add decrypted data to message 

		return message;
	};

	/**
	 * Close a connection with a peer.
	 */
	self.dropConnection = function(peerId) {
		console.debug("sync:dropConnection", peerId);
		let connection = self.connections[peerId];
		if (!connection) {
			return;
		}
		connection.close();
		delete self.connections[peerId];
	}

	/**
	 * Send a message to a peer.
	 */
	self.sendRaw = function(peerId, rawMessage) {
		let connection = self.connections[peerId];
		if (!connection) {
			console.warn("sync:send", "Unable to find connection to peer", peerId);
			return;
		}
		console.debug("sync:sendRaw", peerId, rawMessage);
		connection.send(rawMessage);
	};

	self.sendPlaintextMessage = function(peerId, type, data) {
		self.sendRaw(peerId, {"type": type, "encrypted": false, "data": data});
	};

	self.sendEncryptedMessage = function(peerId, type, data) {
		// TODO generate symmetric key
		// 		encrypt symmetric key with peer's public key
		// 		add key to message {"encryptedKey"}
		//		serialise data to JSON
		// 		encrypt data with symmetric key
		//		add encrypted data to message {"encryptedData"}
		//		generate signature with my private key
		// 		add signature to message {"signature"}
		let rawMessage = {"type": type, "encrypted": true,
						  "encryptedKey": null, "encryptedData": null,
						  "signature": null};
		self.sendRaw(peerId, rawMessage);
	};

	self.generateId = function() {
		let alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
		let desiredLength = 8;
		let id = "";
		for (let i = 0; i < desiredLength; i++) {
			id += alphabet.charAt(Math.floor(Math.random() * alphabet.length));
		}
		return id;
	};

	self.getId = function() {
		let currentId = preferences.get("sync:id");
		if (!currentId) {
			currentId = self.generateId();
			preferences.set("sync:id", currentId);
		}
		return currentId;
	};

	self.generateCertificates = async function() {
		let keypair = await certificates.generateCertificates();
		return keypair;
	};

	self.getCertificates = async function() {
		let publicSignatureCertificate   = preferences.get("sync:certificate:public:signature");
		let publicEncryptionCertificate  = preferences.get("sync:certificate:public:encryption");
		let privateSignatureCertificate  = preferences.get("sync:certificate:private:signature");
		let privateEncryptionCertificate = preferences.get("sync:certificate:private:encryption");

		if (!publicSignatureCertificate) {
			let newCertificates = await self.generateCertificates();

			publicSignatureCertificate = newCertificates.public.signature;
			publicEncryptionCertificate = newCertificates.public.encryption;
			privateSignatureCertificate = newCertificates.private.signature;
			privateEncryptionCertificate = newCertificates.private.encryption;

			preferences.set("sync:certificate:public:signature",   publicSignatureCertificate);
			preferences.set("sync:certificate:public:encryption",  publicEncryptionCertificate);
			preferences.set("sync:certificate:private:signature",  privateSignatureCertificate);
			preferences.set("sync:certificate:private:encryption", privateEncryptionCertificate);
		}

		let certificates = {
			"public": {
				"signature": publicSignatureCertificate,
				"encryption": publicEncryptionCertificate
			},
			"private": {
				"signature": privateSignatureCertificate,
				"encryption": privateEncryptionCertificate
			}
		}

		console.debug("sync:getCertificates", certificates);

		return certificates;
	};

	/**
	 * Disable synchronisation. Stop all connections.
	 */
	self.disable = function() {
		self.enabled = false;

	};

	/**
	 * Check the current preferences. Enable/disable synchronisation
	 * according to the current preferences.
	 */
	self.checkPreferences = function() {
		let shouldBeEnabled = preferences.get("sync:enabled");

		if ( shouldBeEnabled && !self.enabled ) {
			// Should enable.
			self.enable();

		} else if ( !shouldBeEnabled && self.enabled ) {
			// Should disable
			self.disable();

		}
	};

	self.init = function() {
		console.debug("sync:init");

		// Check the preferences now and then.
		self.checkPreferences();
		setInterval(self.checkPreferences, PREFERENCES_CHECK_EVERY_MS);
	};

	self.init();

	return self;

});