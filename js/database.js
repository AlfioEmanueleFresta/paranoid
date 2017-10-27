/*
 * database.js
 *
 * The PouchDB database to store keys, and peer certificates.
 */
define(['./libs/pouchdb.min.js'], function(PouchDB) {

    self = {};

    var DATABASE_SHORT_NAMES = ["peers", "wallets"];
    var DATABASE_PREFIX = "paranoid-";

    /* Will be populated on init. */
    var DATABASES = {};

    var getDatabaseLongName = function(shortName) {
        return DATABASE_PREFIX + shortName;
    }

    var getDatabase = function(shortName) {
        if (DATABASE_SHORT_NAMES.indexOf(shortName) == -1) {
            console.error("database:getDatabase", shortName, "not a valid database name.");
            throw "database:getDatabase";
        }
        return DATABASES[shortName];
    };

    var initialiseDatabases = function() {
        console.debug("database:initialiseDatabases", DATABASE_SHORT_NAMES);
        for (let i in DATABASE_SHORT_NAMES) {
            let shortName = DATABASE_SHORT_NAMES[i]
            let longName = getDatabaseLongName(shortName);
            let options = {"adapter": "idb"};
            let newDb = new PouchDB(longName, options);
            DATABASES[shortName] = newDb;
        }
    };

    var put = function(databaseShortName, doc) {
        console.debug("database:put", databaseShortName, doc);
        let database = getDatabase(databaseShortName);
        return database.put(doc);
    };

    self.put = put;


    var post = function(databaseShortName, doc) {
        console.debug("database:post", databaseShortName, doc);
        let database = getDatabase(databaseShortName);
        return database.post(doc);
    };

    self.post = post;


    var get = function(databaseShortName, docId) {
        console.debug("database:get", databaseShortName, docId);
        let database = getDatabase(databaseShortName);
        return database.get(docId);
    };

    self.get = get;


    var remove = function(databaseShortName, docId) {
        console.debug("database:remove", databaseShortName, docId);
        let database = getDatabase(databaseShortName);
        return database.get(docId, docRev);
    };

    self.remove = remove;


    var find = function(databaseShortName, request) {
        console.debug("database:find", request);
        let database = getDatabase(databaseShortName);
        return database.find(request);
    }

    self.find = find;


    self.init = function() {
        console.debug("database:init");
        initialiseDatabases();
    };

    self.init();
    return self;

});