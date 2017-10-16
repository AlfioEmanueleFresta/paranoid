/**
 * preferences.js
 *
 * Simple preferences storage module.
 */
define(function() {

	self = {};

	/**
	 * Default preference values.
	 */
	var DEFAULTS = {

		/* Synchronisation */
		"sync:id": 			undefined,		// The PeerID of this machine
		"sync:enabled": 	true,			// Whether the wallets sharing feature is enabled
		"sync:host": 		"127.0.0.1",
		"sync:port": 		9000,
		"sync:secure": 		false

	};

	/**
	 * Storage backend.
	 */
	var getStorage = function() {
		return window.localStorage;
	};


	/**
	 * Get preference by key.
	 *
	 * @param {string} key			Preference name.
	 * @return 	The preference value.
	 */
	self.get = function(key) {
		let storedJSON = getStorage().getItem(key);

		if (storedJSON === null) {
			// Key not stored.
			// Get the default, or undefined.
			let defaultValue = DEFAULTS[key];
			console.debug("preferences:get", key, "defaultValue", defaultValue);
			return defaultValue;
		}

		// Return the native object.
		let storedValue = JSON.parse(storedJSON);
		console.debug("preferences:get", key, "storedValue", storedValue);
		return storedValue;
	}

	/**
	 * Set a preference item by key.
	 *
	 * @param {string} key 			Preference name.
	 * @param {string} value 		Preference value.
	 * @return {boolean}	Whether the operation was successful.
	 */
	self.set = function(key, value) {
		if (value === undefined) {
			console.warn("storage:put", "undefined is not allowed for key", key);
			return false;
		}

		let JSONvalue = JSON.stringify(value);
		getStorage().setItem(key, JSONvalue);
		console.debug("preferences:set", key, value);
		return true;
	}

	/**
	 * Initialise the module.
	 */
	self.init = function() {
		console.debug("storage:init");
	};

	return self;

});
