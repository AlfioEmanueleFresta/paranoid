/**
 * sync.js
 *
 * Synchronisation utility.
 */
define(['./preferences', './certificates', './stores/certificates', 
		'./crypto', './database'], 
	function(preferences, certificates, certStore, crypto, db) {

	var PREFERENCES_CHECK_EVERY_MS = 5000;
	var AUTO_CONNECT_DELAY = 3000;

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

	var connectToKnownPeers = async function() {
		let knownPeers = await getKnownPeers();
		console.debug("sync:connectToKnownPeers", knownPeers);
		for (let i in knownPeers) {
			let peer = knownPeers[i];
			let peerId = peer.id;
			self.connectToPeer(peerId);
		}
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

			// Connected. Search for known peers.
			setTimeout(connectToKnownPeers, AUTO_CONNECT_DELAY);
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

	self.connectToPeer = function(peerId, failSilently) {
		console.debug("sync:connectToPeer", peerId);

		// Check if a connection was already there
		if (self.connections[peerId]) {
			let isAlive = self.connections[peerId].alive;
			if (!isAlive) {
				console.debug("sync:connectToPeer", peerId,
							  "The connection had been established, but was not " +
							  "alive. Reconnecting...");
				self.disconnectPeer(peerId);
			} else {
				console.warn("sync:connectToPeer", peerId,
						     "Connection already established, and peer alive.");
				return;

			}
		}

		let newConnection;
		try {
			newConnection = self.peer.connect(peerId);
		} catch (error) {
			!failSilently && console.error("sync:connectToPeer", error);
		}
		self.registerConnection(newConnection, true);
	};

	var getKnownPeers = async function() {
		return certStore.getAllPeers();
	};

	self.getKnownPeers = getKnownPeers;

	self.getAlivePeers = function() {
		let peers = [];
		for (let peerId in self.connections) {
			if ( self.connections[peerId].alive ) {
				peers.push(peerId);
			}
		}
		return peers;
	};

	self.disconnectPeer = function(peerId) {
		let connection = self.connections[peerId];
		if (connection) {
			delete self.connections[peerId];
			connection.close();
			console.info("sync:disconnectPeer", peerId, "Disconnected from peer.");
		}
	};

	self.registerConnection = async function(newConnection, outbound) {
		console.debug("sync:registerConnection", newConnection);
		let peerId = newConnection.peer;

		if (!outbound) {
			let isKnownPeer = !!(await certStore.getPeerCertificate(peerId));
			console.debug("sync:registerConnection", "isKnownPeer", isKnownPeer);
			let shouldRegister = isKnownPeer || confirm("Do you want to accept a connection from " + peerId + "?");
			if (!shouldRegister) {
				console.debug("sync:registerConnection", "ignored incoming connection from" + peerId);
				return;
			}
		}

		self.connections[peerId] = newConnection;
		console.debug("sync:registerConnection", peerId);

		// Add connection handlers
		newConnection.on('open', function() {
			console.debug("sync:registerConnection:open", peerId,
						  (outbound) ? "(outbound)" : "(inbound)");

			newConnection.on('data', function(data) {
				self.dispatch(peerId, data);
			});

			newConnection.on('close', function() {
				self.disconnectPeer(peerId);
			});

			if (outbound) {
				console.debug("sync:registerConnection",
							  "Outbound connection. Sending handshake request.");
				sendHandshake(peerId, outbound);
			}
		});


	};

	var sendHandshake = async function(peerId, outbound) {
		let publicCertificate = await self.getCertificates();
		let handhakeData = {
			"certificate": 	publicCertificate.public,
			"outbound": 	!!outbound
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

			return handler(peerId, message.data);
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

			let decrypted = await self.decryptMessage(peerId, message);
			if (!decrypted) {
				return;
			}

			return handler(peerId, decrypted.data);
		}
		return modifiedHandler;
	};

	var PEER_CERTIFICATES = {};

	var HANDLERS = {};

	var sendHeartbeat = function(peerId) {
		self.sendEncryptedMessage(peerId, "heartbeat", {"alive": true});
	};

	var sendReplication = async function(peerId) {
		let stream = await db.getReplicationStream();
		self.sendEncryptedMessage(peerId, "replication", stream);
	};

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
			console.debug("sync:handleHandshake", peerId, "No known certificate for the peer.");

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


		if (message.outbound) {
			// I received an outbound handshake, I need to shake back.
			console.debug("sync:handleHandshake", peerId, "Shaking back, and waiting for first heartbeat.");
			sendHandshake(peerId, false);
		
		} else {
			// I received a shake back. Send my first heartbeat. Secure connection OK.
			console.debug("sync:handleHandshake", peerId, "Handshake completed. Sending heartbeat.");
			sendHeartbeat(peerId);
			peerIsAlive(peerId);

		}


	};

	/**
	 * Mark the peer as alive, i.e. the connection was established.
	 */
	var peerIsAlive = function(peerId) {
		if (self.connections[peerId].alive) {
			// Connection was already alive.
			return;
		}

		console.info("sync:peerIsAlive", peerId, 
				     "Connected securely to peer.");
	    self.connections[peerId].alive = true;
	};

	var handleHeartbeat = async function(peerId, message) {
		console.debug("sync:handleHeartbeat", peerId, 
					 "Beat received.", message);
		peerIsAlive(peerId);
		sendReplication(peerId);
	};

	var handleReplication = async function(peerId, message) {
		console.debug("sync:handleReplication", peerId,
					  "Peer wants to ensure replication.", message);
		await db.applyReplicationStream(message);
	};

	// Replicate local changes to a peer
	var replicateChangeToPeer = async function(peerId, change) {
		console.debug("sync:replicateChangeToPeer", peerId);
		// TODO this should use change only, but currently initiates full synchronisation
		sendReplication(peerId);
	};

	var replicateChangeToAllPeers = async function(change) {
		let peerIds = self.getAlivePeers();
		for (let i in peerIds) {
			let peerId = peerIds[i];
			replicateChangeToPeer(peerId, change);
		};
	};

	var listenForChanges = function() {
		let changesCallback = function(change) {
			console.debug("sync:changesCallback", change);

			if (self.enabled) {
				replicateChangeToAllPeers(change);

				// TODO if it's a new peer, connect to it
				connectToKnownPeers();
			}
		};
		db.onChange(changesCallback);
	};

	// Set protocol handlers
	HANDLERS["handshake"] = 	unencryptedHandler	(handleHandshake);
	HANDLERS["heartbeat"] = 	encryptedHandler	(handleHeartbeat);
	HANDLERS["replication"] = 	encryptedHandler  	(handleReplication);

	/**
	 * Handle data received from a peer.
	 */
	self.dispatch = async function(peerId, message) {

		console.debug(
			"sync:dispatch", peerId, 
			message.encrypted ? "(encrypted)" : "(unencrypted)",
			message
		);

		let handler = HANDLERS[message.type];
		if (!handler) {
			console.warn("sync:dispatch", peerId, "Unknown request type", message);
			return;
		}

		// Handle message
		handler(peerId, message);
	};

	/**
	 * Decrypt a message received from a known peer.
	 */
	self.decryptMessage = async function(peerId, message) {
		let peerPublicKey = await certStore.getPeerCertificate(peerId);
			peerPublicKey = peerPublicKey.signature;
		let privateKey = await getCertificates();
			privateKey = privateKey.private.encryption;

		// First, verify the signature
		let validSignature = await crypto.verifySignature(
			peerPublicKey, message.encryptedData.data, message.signature
		);
		if (!validSignature) {
			console.error("sync:decryptMessage", peerId, "Invalid signature", message);
			return;
		}

		// Decrypt the symmetric key
		let symmetricKey = await crypto.decryptObject(privateKey, message.encryptedKey);

		// Decrypt the message and append the clear text
		let decryptedData = await crypto.decryptObject(symmetricKey, message.encryptedData);
		message.data = decryptedData;
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

	var sendEncryptedMessage = async function(peerId, type, data) {
		let privateSignatureCertificate = await getCertificates();
			privateSignatureCertificate = privateSignatureCertificate.private.signature;
		let publicKey = await certStore.getPeerCertificate(peerId);
		    publicKey = publicKey.encryption;
		let symmetricKey = await crypto.generateSymmetricKey();
		let encryptedSymmetricKey = await crypto.encryptObject(publicKey, symmetricKey);
		let encryptedData = await crypto.encryptObject(symmetricKey, data);
		let signature = await crypto.signData(privateSignatureCertificate, encryptedData.data);
		let rawMessage = {"type": type, 
						  "encrypted": true,
						  "encryptedKey": encryptedSymmetricKey,
						  "encryptedData": encryptedData,
						  "signature": signature};
		self.sendRaw(peerId, rawMessage);
	};

	self.sendEncryptedMessage = sendEncryptedMessage;


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

	var getCertificates = async function() {
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

	self.getCertificates = getCertificates;

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
		listenForChanges();
		setInterval(self.checkPreferences, PREFERENCES_CHECK_EVERY_MS);
	};

	self.init();

	return self;

});