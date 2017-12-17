import PeerConnection from "./PeerConnection.js";


/**
 * A connections manager.
 *
 * Manages a number of peer connections.
 */
class ConnectionsManager {

    /**
     * Initialises a connections manager, given a list of
     * known peers and their identities.
     *
     * @param Object                    A connection to a PeerJS server.
     * @param Object                    This peer's identity.
     * @param Object({String: Object})  An object of known peer IDs and their public identity.
     * @param boolean                   Whether to attempt to connect to the known peers automatically.
     */
    constructor(serverConnection, identity, knownPeers, connectAutomatically) {
        this.server = serverConnection;
        this._registerServerEvents();
        this.identity = identity;
        this.connections = {};
        this.knownPeers = knownPeers;
        if ( this.connectAutomatically ) {
            this.connect();
        }
    }

    /**
     * This peer's identity.
     *
     * @return {Object(public, private)}
     */
    get identity() {
        return this.identity;
    }

    /**
     * Attempt to connect to all known peers.
     */
    connect() {
        console.debug("ConnectionsManager:connect", this);
        for ( let peerId in this.knownPeers ) {
            this.connectToKnownPeer(peerId);
        }
    }

    /**
     * Connect to a known peer by its id.
     *
     * @param String    The peer identifier.
     */
    connectToKnownPeer(peerId) {
        console.debug("ConnectionsManager:connectToKnownPeer", this, peerId);
        let expectedIdentity = this.knownPeers[peerId];
        let connection = new PeerConnection(this, peerId, expectedIdentity);
        this.connections[peerId] = connection;
        return connection;
    }

    /**
     * Register the event handlers for the server connection
     */
    _registerServerEvents() {
        console.debug("ConnectionsManager:_registerServerEvents", this);
        this.server.on('disconnected',  this._serverDisconnected);
        this.server.on('error',         this._serverError);
        this.server.on('connection',    this._serverNewConnection);
    }

    /**
     * This method is called when the server is disconnected.
     */
    _serverDisconnected() {
        console.debug("ConnectionsManager:_serverDisconnected", this);

    }

    /**
     * This method is called when the server connection throws an error.
     *
     * See http://peerjs.com/docs/#peeron-error for a list of possible
     * error identifiers.
     *
     * @param String    The error identifier.
     */
    _serverError(error) {
        console.debug("ConnectionsManager:_serverError", this, error);

    }

    /**
     * This method is called when the server notifies us of a new incoming
     * connection.
     */
    _serverNewConnection(newDataConnection) {
        console.debug("ConnectionsManager:_serverNewConnection", this, newDataConnection);

        // Create the PeerConnection instance and wait for it to finish
        // the handshake and trigger the handshakeFinished event.
        let peerConnection = new PeerConnection(this, newDataConnection);
    }

    // Peer events TODO
    async _getPeerId(peerConnection) {
        // If we opened the connection, we have it as the key for
        // the connections object.
        for (let peerId in this.connections) {
            if (peerConnection == this.connections[peerId]) {
                return peerConnection;
            }
        }

        // Otherwise we received this connection, so we need
        // to rely on the identity received, if any.
        let peerIdentity = peerConnection.peerIdentity;
        let shortThumbprint = await awaitpeerIdentity.getShortThumbprint();
        if (!shortThumbprint) {
            throw "Unable to determine peer ID.";
        }

        return shortThumbprint;
    } 

    _addKnownPeer(peerId, identity) {
        console.debug("ConnectionsManager:_addKnownPeer", this, peerId, identity);
        this.knownPeers[peerId] = identity;
    }

    async _peerHandshakeFinished  (peerConnection) {
        console.debug("ConnectionsManager:_peerHandshakeFinished", this, peerConnection);
        // Add this peer as a known peer
        let peerId = await this._getPeerId(peerConnection);
        this._addKnownPeer(peerId, peerConnection.peerIdentity);
    }

    async _peerDisconnected       (peerConnection) {
        console.debug("ConnectionsManager:_peerDisconnected", this, peerConnection);
        // Remove this from the list of current connections
        let peerId = await this._getPeerId(peerConnection);
        delete this.connections[peerId];
    }

    _peerError              (peerConnection, error) {
        console.warn("ConnectionsManager:_peerError", this, peerConnection, error);
    }

    /**
     * Gets the list of known peers, including all 
     * accepted peers. This list will contain all
     * known peers passed to the constructor, unless
     * there's been a problem with any peers.
     */ 
    getKnownPeers() {
        return this.knownPeers;
    }

}