
require(['../js/sync', '../js/preferences'], function(sync, preferences) {

	console.log("webrtc:load");

});

var servers;
var connection;

var receiveChannel;
var sendChannel;

var peer;
var peerId;

var connections = {};

$(document).ready(function() {



	$("#registerButton").click(function() {
		peer = new Peer({"host": "127.0.0.1", "port": 9000, "path": "/",
					 	 "debug": 3});
		peer.on('open', function(id) {
			console.debug("peer:open", id);
			peerId = id;
			$("#registrationToken").val(id);
		});

		peer.on('connection', function(conn) {
			console.debug("connection", conn);
			registerConnection(conn);
		});

	});

	function registerConnection(connection) {
		let otherId = connection.peer;
		connections[otherId] = connection;
		connection.on('open', function() {
			console.debug("connection opened", connection);

			connection.on('data', function(data) {
				console.debug("received", data, connection);
			});

			connection.send("Hello!");
		});
	}

	$("#connectButton").click(function() {
		let other = $("#otherId").val();
		console.debug("connecting to", other);

		let connection = peer.connect(other);
		registerConnection(connection);
	});

});
