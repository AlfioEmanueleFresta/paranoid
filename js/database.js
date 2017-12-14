/*
 * database.js
 *
 * The PouchDB database to store keys, and peer certificates.
 */
define(['./libs/pouchdb.min.js',
        './libs/pouchdb.replication-stream.js',
        './libs/pouchdb.load.js',
        './libs/memorystream.min.js'], 
    function(PouchDB, ReplicationStream, PouchDBLoad, MemoryStream) {

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
        PouchDB.plugin(ReplicationStream.plugin);
        PouchDB.plugin(PouchDBLoad);
        PouchDB.adapter('writableStream', ReplicationStream.adapters.writableStream);
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
        console.debug("database:find", databaseShortName, request);
        let database = getDatabase(databaseShortName);
        return database.find(request);
    }

    self.find = find;

    var all = async function(databaseShortName, request) {
        console.debug("database:all", databaseShortName, request);
        let database = getDatabase(databaseShortName);
        let docs = await database.allDocs();
        return docs.rows;
    };

    self.all = all;

    var getReplicationStreamForDatabase = async function(shortName) {
        let database = getDatabase(shortName);
        let output = "";
        let stream = new MemoryStream();
        stream.on('data', function(chunk) {
            output += chunk.toString();
        });
        let ok = await database.dump(stream);
        return output;
    };

    var getReplicationStream = async function() {
        let streams = {};
        for (let i in DATABASE_SHORT_NAMES) {
            let shortName = DATABASE_SHORT_NAMES[i];
            streams[shortName] = await getReplicationStreamForDatabase(shortName);
        }
        return streams;
    };

    self.getReplicationStream = getReplicationStream;


    var applyReplicationStreamToDatabase = async function(shortName, streamString) {
        let database = getDatabase(shortName);
        let ok = await database.load(streamString);
        console.debug("database:applyReplicationStreamToDatabase", shortName);
        return true;
    };

    var applyReplicationStream = async function(stream) {
        let results = {};
        for (let i in DATABASE_SHORT_NAMES) {
            let shortName = DATABASE_SHORT_NAMES[i];
            results[shortName] = await applyReplicationStreamToDatabase(
                shortName, stream[shortName]
            );
        }
        return results;
    };

    self.applyReplicationStream = applyReplicationStream;

    /**
     * Add a callback that is called on change.
     */
    var onDatabaseChange = function(databaseShortName, callback) {
        console.debug("database:onDatabaseChange", databaseShortName, callback);
        let database = getDatabase(databaseShortName);
        database.changes({
            "since": "now",
            "live": true,
            "include_docs": true
        }).on('change', callback);
    };

    var onChange = function(callback) {
        for (let i in DATABASE_SHORT_NAMES) {
            let shortName = DATABASE_SHORT_NAMES[i];
            onDatabaseChange(shortName, callback);
        }
    };

    self.onChange = onChange;

    self.init = function() {
        console.debug("database:init");
        initialiseDatabases();
    };

    self.init();
    return self;

});