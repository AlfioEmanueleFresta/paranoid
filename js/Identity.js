/**
 * Represents an identity.
 *
 * An identity always has a public key, and
 * may also have a private key.
 */
class Identity {

    constructor(JSONdata) {
        if ( JSONdata === undefined ) {
            _generate();
        } else {
            _load(JSONdata);
        }
    }

    /**
     * Generates a new identity.
     */
    async _generate() {
        console.debug("Identity:_generate", this);
        let algorithm = {"name": "RSASSA-PKCS1-v1_5",
                         "hash": {"name": "SHA-256"},
                         "modulusLength": 2048,
                         "publicExponent": new Uint8Array([0x01, 0x00, 0x01])};
        let keyUsages = ["sign", "verify"];
        let keypair = await crypto.subtle.generateKey(algorithm, true, keyUsages);
        let jwk = await crypto.subtle.exportKey("jwk", keypair);
        this.publicJWK = jwk.public;
        this.privateJWK = jwk.private;
    }

    /**
     * Load an identity from JSON data
     */
    _load(JSONdata) {
        console.debug("Identity:_load", this, JSONdata);
        let publicKey = JSONdata.public;
        if (!publicKey) {
            throw "Invalid identity."
        }
        this.publicJWK = publicKey;
        let privateKey = JSONdata.private;
        if (privateKey) {
            this.privateJWK = privateKey;
        }
    }

    /**
     * Check if this identity corresponds to another
     * Identity object. Return true if they both have
     * the same public key.
     */
    equals(other) {
        return this.publicJWK == other.publicJWK;
    }

    async getPublicHash(algorithm) {
        let orderedJWK = {};
        orderedJWK["e"] = this.publicJWK["e"];
        orderedJWK["kty"] = this.publicJWK["kty"];
        orderedJWK["n"] = this.publicJWK["n"];
        let jsonJWK = JSON.stringify(orderedJWK);
        let textEncoder = new TextEncoder("UTF-8");
        let encoded = textEncoder.encode(jsonJWK);
        let hash = await crypto.subtle.digest(algorithm, encoded);
        return hash;
    }

    /**
     * JSON Web Key (JWK) Thumbprint
     * draft-ietf-jose-jwk-thumbprint-08
     */
    async getThumbprint() {
        let hash = await this.getPublicHash("SHA-256");
        return btoa(hash); // TODO base64url
    }

    /**
     * Get a very short, easy-to-type, key thumbprint.
     */
    async getShortThumbprint() {
        let hash = await this.getPublicHash("SHA-1");
        return btoa(hash);
    }

    /**
     * Get a CryptoKey object for the public part of the identity.
     *
     * @return {CryptoKey}  The public key.
     */
    async getPublicKey() {
        console.debug("Identity:getPublicKey", this);
        let publicKey = await crypto.subtle.importKey("jwk", this.publicJWK);
        return publicKey;
    }

    /**
     * Get a CryptoKey object for the private part of the identity.
     *
     * @return {CryptoKey}  The private key.
     */
    async getPrivateKey() {
        console.debug("Identity:getPrivateKey", this);
        if (!this.hasPrivateKey) {
            throw "This identity doesn't have a private key.";
        }
        let privateKey = await crypto.subtle.importKey("jwk", this.privateJWK);
        return privateKey;
    }

    /**
     * Verify a signature for this identity.
     *
     * @param {Uint8Array}  data
     * @param {Uint8Array}  signature
     * @return boolean
     */
    async verify(data, signature) {
        console.debug("Identity:verify", this, data, signature);
        let publicKey = await this.getPublicKey();
        let algorithm = {"name": "RSASSA-PKCS1-v1_5",
                         "hash": {"name": "SHA-256"},
                         "modulusLength": 2048,
                         "publicExponent": new Uint8Array([0x01, 0x00, 0x01])};
        let result = await crypto.subtle.verify(algorithm, publicKey, 
                                                signature, data);
        return result;
    }

    /** 
     * Generate a signature with this identity.
     *
     * @param {Uint8Array}  data
     * @return {Uint8Array} Signature.
     */
    async sign(data) {
        console.debug("Identity:sign", this, data);
        let privateKey = await this.getPrivateKey();
        let algorithm = {"name": "RSASSA-PKCS1-v1_5",
                         "hash": {"name": "SHA-256"},
                         "modulusLength": 2048,
                         "publicExponent": new Uint8Array([0x01, 0x00, 0x01])};
        let signature = await crypto.subtle.sign(algorithm, privateKey, data);
        return signature;
    }

    get hasPrivateKey() {
        return (this.privateKey !== undefined);
    }

    get JSON() {
        let object = {};
        object["public"] = this.publicKey;
        if (this.hasPrivateKey) {
            object["private"] = this.privateKey;
        }
        return object;
    }

}