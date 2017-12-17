var PEER_INITIALISING = -1;
var PEER_CONNECTING = 0;
var PEER_AUTHENTICATING = 1;
var PEER_SECURING = 2;
var PEER_CONNECTED = 3;
var PEER_DISCONNECTED = 4;

var DIRECTION_INBOUND = 0;
var DIRECTION_OUTBOUND = 1;

var ENCRYPTION_DISABLED = 0;
var ENCRYPTION_ENABLED = 1;

var MESSAGE_AUTHENTICATION_REQUEST      = "auth_request";
var MESSAGE_AUTHENTICATION_RESPONSE     = "auth_response";
var MESSAGE_SECURE_REQUEST              = "secure_request";
var MESSAGE_SECURE_RESPONSE             = "secure_response";
var MESSAGE_HEARTBEAT_REQUEST           = "heartbeat_request";
var MESSAGE_HEARTBEAT_RESPONSE          = "heartbeat_response";

import Identity from "./Identity.js";

class PeerConnection {

    /**
     * Initialises a peer connection, given the connections manager and
     * the peer ID or the peer connection.
     *
     * If an expected identity is provided for the peer,
     * the connection is only established if the peer can prove its
     * identity.
     *
     * If no expected identity is provided (this is the first time we
     * connect to this peer), this event will generate an authentication
     * events sequence. 
     *
     * @param {ConnectionsManager}      The connections manager.
     * @param {string|Object}           The peer identifier, or the peer connection.
     * @param {Object}                  Optional. The expected identity.
     */
    constructor(connectionsManager, peerIdOrConnection, expectedIdentity) {
        this.status = PEER_INTIALISING;
        this.connectionsManager = connectionsManager;
        this.expectedIdentity = expectedIdentity;
        this.encryption = ENCRYPTION_DISABLED;

        if (typeof peerIdOrConnection == "string") {
            // Outbound connection.
            this.peerId = peerIdOrConnection;
            this.direction = DIRECTION_OUTBOUND;
            this.connect();
            // TODO set interval to re-secure channel every now and then

        } else {
            // Inbound connection.
            this.connection = peerIdOrConnection;
            this.direction = DIRECTION_INBOUND;
            this._registerEventHandlers();
            this._registerMessageHandlers();
        }

    }

    /**
     * Connect to the peer.
     */
    connect() {
        console.debug("PeerConnection:connect", this);
        this.status = PEER_CONNECTING;
        this.connection = this.connectionsManager.connect(this.peerId);
        _registerEventHandlers();
        _registerMessageHandlers();
    }

    _disconnect() {
        console.debug("PeerConnection:_disconnect", this);
        this.connection.disconnect();
        this.status = PEER_DISCONNECTED;
    }

    _registerEventHandlers() {
        this.connection.on('open', this._connectionOpen);
        this.connection.on('data', this._connectionData);
        this.connection.on('disconnected', this._connectionDisconnected);
        this.connection.on('error', this._connectionError);
    }

    _registerMessageHandlers() {
        this.messageHandlers = {};
        this.messageHandlers[MESSAGE_AUTHENTICATION_REQUEST] = this._handleAuthenticationRequest;
        this.messageHandlers[MESSAGE_AUTHENTICATION_RESPONSE] = this._handleAuthenticationResponse;
        this.messageHandlers[MESSAGE_SECURE_REQUEST] = this._handleSecureRequest;
        this.messageHandlers[MESSAGE_SECURE_RESPONSE] = this._handleSecureResponse;
        // TODO add handlers
    }

    _connectionOpen(peerId) {
        console.debug("PeerConnection:_connectionOpen", this, peerId);
        this.state = PEER_AUTHENTICATING;

        // If this is an outbound connection, authenticate.
        // Otherwise, wait for an authentication request.
        if (this.direction == DIRECTION_OUTBOUND) {
            this._sendAuthenticationRequest();
        }
    }

    _getOwnPublicIdentity() {
        return this.connectionsManager.identity.public;
    }

    _setPeerPublicIdentity(publicIdentity) {
        console.debug("PeerConnection:_setPeerPublicIdentity", this, publicIdentity);
        let peerIdentity = new Identity({"public": payload.identity});
        this.peerIdentity = peerIdentity;
    }

    _sendAuthenticationRequest() {
        console.debug("PeerConnection:_sendAuthenticationRequest", this);
        console.assert(this.direction   == DIRECTION_OUTBOUND);
        console.assert(this.status      == PEER_AUTHENTICATING);
        console.assert(this.encryption  == ENCRYPTION_DISABLED);

        let ownPublicIdentity = _getOwnPublicIdentity();
        this._sendPlainMessage(MESSAGE_AUTHENTICATION_REQUEST,
                               {"identity": ownPublicIdentity});
    }

    _handleAuthenticationRequest(payload) {
        console.debug("PeerConnection:_handleAuthenticationRequest", this);
        console.assert(this.direction   == DIRECTION_INBOUND);
        console.assert(this.status      == PEER_AUTHENTICATING);
        console.assert(this.encryption  == ENCRYPTION_DISABLED);

        console.assert(payload.identity !== undefined);

        this._setPeerPublicIdentity(payload.identity);

        let shouldAccept = await _shouldAcceptAuthenticationRequest(this.peerIdentity);
        if (!shouldAccept) {
            // Connection refused.
            _disconnect();
            return;
        }

        // Connection can continue.
        this._sendAuthenticationResponse();
    }

    async _shouldAcceptAuthenticationRequest(peerIdentity) {
        if (this.expectedIdentity) {

            if (!this.expectedIdentity.equals(peerIdentity)) {
                throw "Unexpected identity.";
            } 

        } else {

            let thumbprint = await peerIdentity.getThumbprint();
            return prompt("Do you want to connect to " + thumbprint + "?");

        }

        return true;
    }

    async _sendAuthenticationResponse() {
        console.debug("PeerConnection:_sendAuthenticationResponse", this);
        console.assert(this.direction   == DIRECTION_INBOUND);
        console.assert(this.status      == PEER_AUTHENTICATING);
        console.assert(this.encryption  == ENCRYPTION_DISABLED);

        let ownPublicIdentity = _getOwnPublicIdentity();
        this._sendPlainMessage(MESSAGE_AUTHENTICATION_RESPONSE,
                               {"identity": ownPublicIdentity});

        // Now, expect a secure request.
        this.state == PEER_SECURING;
    }

    _handleAuthenticationResponse(payload) {
        console.debug("PeerConnection:_handleAuthenticationResponse", this);
        console.assert(this.direction   == DIRECTION_OUTBOUND);
        console.assert(this.status      == PEER_AUTHENTICATING);
        console.assert(this.encryption  == ENCRYPTION_DISABLED);

        console.assert(payload.identity !== undefined);

        this._setPeerPublicIdentity(payload.identity);

        let shouldAccept = await _shouldAcceptAuthenticationRequest(this.peerIdentity);
        if (!shouldAccept) {
            // Connection refused.
            _disconnect();
            return;
        }

        // Connection can continue.
        // The channel is now authenticated. We need
        // to add encryption.
        this.state = PEER_SECURING;
        this._sendSecureRequest();
    }

    async _sendSecureRequest() {
        console.debug("PeerConnection:_sendSecureRequest", this);
        console.assert(this.status      >= PEER_SECURING);

        _generateOwnSessionKey();
        let ownPublicSessionKey = this.ownSessionKey.public;
        let jwk = await crypto.subtle.exportKey("jwk", ownPublicSessionKey);

        let sendFunction = this.encryption == ENCRYPTION_ENABLED ? 
                           this._sendEncryptedMessage : this._sendPlainMessage;
        sendFunction(MESSAGE_SECURE_REQUEST,
                     {"publicKey": jwk});
    }

    /**
     * Generate this peer's asymmetric session encryption key and stores
     * it as the 'ownSessionKey' attribute.
     */
    async _generateOwnSessionKey() {
        console.debug("PeerConnection:_generateOwnSessionKey", this);
        let algorithm = {"name": "RSA-OAEP",
                         "hash": {"name": "SHA-256"},
                         "modulusLength": 2048,
                         "publicExponent": new Uint8Array([0x01, 0x00, 0x01])};
        let keyUsages = ["encrypt", "decrypt"];
        let sessionKey = await crypto.subtle.generateKey(algorithm, true, keyUsages);
        this.ownSessionKey = sessionKey;
        return this.ownSessionKey;
    }

    _setPeerPublicSessionKey(jwk) {
        console.debug("PeerConnection:_setPeerPublicSessionKey", this, jwk);
        let peerPublicSessionKey = await crypto.subtle.importKey("jwk", payload.publicKey);
        this.peerPublicSessionKey = peerPublicSessionKey;
    }

    async _handleSecureRequest(payload) {
        console.debug("PeerConnection:_handleSecureRequest", this, payload);
        console.assert(this.status          >= PEER_SECURING);
        console.assert(payload.publicKey    !== undefined);

        this._setPeerPublicSessionKey(payload.publicKey);
        this.encryption = ENCRYPTION_ENABLED;

        // TODO: is it wise to respond always?

        this._sendSecureResponse();
    }

    async _sendSecureResponse() {
        console.debug("PeerConnection:_sendSecureResponse", this);
        console.assert(this.status      >= PEER_SECURING);

        _generateOwnSessionKey();
        let ownPublicSessionKey = this.ownSessionKey.public;
        let jwk = await crypto.subtle.exportKey("jwk", ownPublicSessionKey);

        this._sendEncryptedMessage(MESSAGE_SECURE_RESPONSE,
                                   {"publicKey": jwk});

        // Connection authenticated and secured.
        this._handshakeFinished();
    }

    _handleSecureResponse(payload) {
        console.debug("PeerConnection:_handleSecureResponse", this, payload);
        console.assert(this.status          >= PEER_SECURING);
        console.assert(this.encryption      == ENCRYPTION_ENABLED);
        console.assert(payload.publicKey    !== undefined);

        this._setPeerPublicSessionKey(payload.publicKey);
        this.status = PEER_CONNECTED;

        // Connection authenticated and secured.
        this._handshakeFinished();
    }

    _handshakeFinished() {
        console.debug("PeerConnection:_hadshakeFinished", this);
        // Notify connections manager of finished handshake.

        this.connectionsManager._peerHandshakeFinished(this);
    }

    async _sendPlainMessage(type, payload) {
        console.debug("PeerConnection:_sendPlainMessage", this, type, payload);
        console.assert(this.encryption  == ENCRYPTION_DISABLED);

        let message = {"type": type, "payload": payload};
        this.connection.send(message);
    }

    async _sendEncryptedMessage(type, payload) {
        console.debug("PeerConnection:_sendEncryptedMessage", this, type, payload);
        console.assert(this.encryption  == ENCRYPTION_ENABLED);

        let message = {"type": type, "payload": payload};
        let encryptedMessage = await this._encryptMessage(message);
        this.connection.send(encryptedMessage);
    }

    _handleMessage(message) {
        console.debug("PeerConnection:_handleMessage", this, message);
        console.assert(message.type     !== undefined);
        console.assert(message.payload  !== undefined);

        // TODO
    }

    /**
     * Encode an object to binary representation.
     */
    async __encode(text) {
        let serialised = JSON.stringify(text);
        let textEncoder = new TextEncoder("UTF-8");
        serialised = textEncoder.encode(text);
        return serialised;
    }

    /**
     * Decode an object from binary representation.
     */
    async __decode(data) {
        let textDecoder = new TextDecoder("UTF-8");
        let decoded = textDecoder.decode(data);
        let deserialised = JSON.parse(decoded);
        return deserialised;
    }

    async _generateMessageKey() {
        console.debug("PeerConnection:_generateMessageKey", this);
        let algorithm = {"name": "AES-CBC", "length": 256};
        let keyUsages = ["encrypt", "decrypt"];
        let key = crypto.subtle.generateKey(algorithm, true, keyUsages);
        return key;
    }

    async _generateMessageIV() {
        return crypto.getRandomValues(new Uint8Array(16));
    }

    async _encryptMessage(message) {
        console.debug("PeerConnection:_encryptMessage", this, message);
        console.assert(message.type     !== undefined);
        console.assert(message.payload  !== undefined);

        let serialisedMessage = await this.__encode(message);
        let peerPublicSessionKey = this.peerPublicSessionKey;
        let encryptedMessage = {};

        // First, generate symmetric message key (AES-256)
        let messageSymmetricKey = await this._generateMessageKey();
        let messageIV = await this._generateMessageIV();

        // Encrypt the message
        let symmetricAlgorithm = {"name": "AES-CBC", "length": 256};
        symmetricAlgorithm.iv = messageIV;
        let encryptedData = await crypto.subtle.encrypt(symmetricAlgorithm, messageSymmetricKey,
                                                        serialisedMessage);

        // Add encrypted message and IV
        encryptedMessage.encryptedData = encryptedData;
        encryptedMessage.encryptionIV = encryptionIV;

        // Sign the encrypted message
        let signature = await this._getOwnPublicIdentity().sign(encryptedData);

        // Add signature
        encryptedMessage.signature = signature;

        // Encrypt message key with session key of peer
        let asymmetricAlgorithm = {"name": "RSA-OAEP", "hash": {name: "SHA-256"}};
        let serialisedEncryptionKey = await crypto.subtle.exportKey("jwk", messageSymmetricKey);
            serialisedEncryptionKey = await this.__encode(serialisedEncryptionKey);
        let encryptedKey = await crypto.subtle.encrypt(asymmetricAlgorithm, peerPublicSessionKey,
                                                       serialisedEncryptionKey);

        // Add encrypted message key
        encryptedMessage.encryptedKey = encryptedKey;

        return encryptedMessage;
    }

    async _decryptMessage(message) {
        console.debug("PeerConnection:_decryptMessage", this, message);
        console.assert(message.encryptedData    !== undefined);
        console.assert(message.signature        !== undefined);
        console.assert(message.encryptionKey    !== undefined);
        console.assert(message.encryptionIV     !== undefined);

        // Verify signature of encryptedData
        let peerPublicIdentity = this.peerIdentity;
        if (!peerPublicIdentity.verify(message.encryptedData, message.signature)) {
            throw "Invalid signature.";
        }

        // Decrypt AES message key using session key
        let asymmetricAlgorithm = {"name": "RSA-OAEP", "hash": {name: "SHA-256"}};
        let ownPrivateSessionKey = this.ownSessionKey.private;
        let decryptedMessageKey = await crypto.subtle.decrypt(asymmetricAlgorithm, ownPrivateSessionKey,
                                                              message.encryptionKey);
        decryptedMessageKey = await this.__decode(decryptedMessageKey);
        decryptedMessageKey = await crypto.subtle.importKey("jwk", decryptedMessageKey);

        // Use message key and IV to decrypt data
        let symmetricAlgorithm = {"name": "AES-CBC", "length": 256};
        symmetricAlgorithm.iv = message.encryptionIV;
        let decryptedData = await crypto.subtle.decrypt(symmetricAlgorithm, decryptedMessageKey,
                                                        message.encryptedData);
            decryptedData = await this.__decode(decryptedData);

        // Return decrypted message
        if (!this._isPlainMessage(decryptedData)) {
            throw "Invalid message.";
        }

        return decryptedData;
    }

    _connectionError(error) {
        console.debug("PeerConnection:_connectionError", this, error);
        console.error(error);
        this.connectionsManager._peerError(this, error);
    }

    async _connectionData(data) {
        console.debug("PeerConnection:_connectionData", this, data);

        // First, ensure this is a message.
        if (!_isPlainMessage && !_isEncryptedMessage) {
            throw "Unknown data.";

        } else if (_isPlainMessage(data)) {
            if (this.encryption == ENCRYPTION_ENABLED) {
                throw "Unexpected plain-text message in encrypted channel.";
            }

            this.handleMessage(message);

        } else if (_isEncryptedMessage(data)) {
            let decryptedMessage = await _decryptMessage(data);
            this.handleMessage(decryptedMessage);

        }
    }

    _isPlainMessage(data) {
        let hasType = data.type !== undefined;
        let hasPayload = data.payload !== undefined;
        return hasType && hasPayload;
    }

    _isEncryptedMessage(data) {
        let hasEncryptedData = data.encryptedData !== undefined;
        let hasSignature = data.signature !== undefined;
        let hasEncryptionKey = data.encryptionKey !== undefined;
        let hasEncryptionIV = data.encryptionIV !== undefined;
        return      hasEncryptedData && hasSignature
                &&  hasEncryptionKey && hasEncryptionIV;
    }

    _connectionDisconnected() {
        console.debug("PeerConnection:_connectionDisconnected", this);

        if (this.state == PEER_AUTHENTICATING || this.state == PEER_SECURING) {
            console.warn("PeerConnection:_connectionDisconnected", "Peer refused authentication.");
            // Failed authentication

        } else {
            console.debug("PeerConnection:_connectionDisconnected", "Peer dropped connection.");
            // Connection dropped at any other time -- assume they simply disconnected.

        }

        this.state = PEER_DISCONNECTED;

        // Notify manager
        this.connectionsManager._peerDisconnected(this);
    }



}