/* 
 * stores/certificates.js
 * 
 * Certificate store.
 */
define(['../database.js'], function(db) {

    self = {};

    var DB_NAME = "peers";

    self.init = function() {
        console.debug("stores/certificates:init");
    }

    var getAllPeers = async function() {
        let peers = await db.all(DB_NAME);
        console.debug("stores/certificates:getAllPeers", peers);
        return peers;
    };

    self.getAllPeers = getAllPeers;

    var getPeerCertificate = async function(peerId) {
        try {
            let certificate = await db.get(DB_NAME, peerId);
            console.debug("stores/certificates:getPeerCertificate", peerId, certificate);
            return certificate;
        } catch (e) {
            // Certificate not available.
            console.debug("stores/certificates:getPeerCertificate", peerId, "Unavailable.");
            return null;
        }
    };

    self.getPeerCertificate = getPeerCertificate;


    var setPeerCertificate = function(peerId, certificate) {
        console.debug("stores/certificates:setPeerCertificate", peerId, certificate);
        certificate._id = peerId;
        let result = db.put(DB_NAME, certificate);
        result.then(function(r) {
            console.log(r);
            return r.ok;
        });
    };

    self.setPeerCertificate = setPeerCertificate;


    self.init();
    return self;

});