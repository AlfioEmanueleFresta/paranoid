
require(['../js/sync', '../js/preferences', '../js/database.js'], function(sync, preferences, db) {

	console.log("webrtc:load");

	setInterval(function() {
		$("#peerId").text(sync.getId());
	}, 1500);

	$("#connectButton").click(function() {
		let otherId = $("#otherId").val();
		sync.connectToPeer(otherId);
	});

	$("#disconnectButton").click(function() {
		let otherId = $("#otherId").val();
		sync.disconnectPeer(otherId);
	});

	$("#debugPeers").click(function() {
		let peers = db.all("peers", {});
		peers.then(function(results) {
			console.debug("debugPeers", results);
		});
		let refreshList = async function() {
			let peers = await sync.getKnownPeers();
			let connected = await sync.getAlivePeers();

			let list = $("#peersList");
			let string = "";
			for (let i in peers) {
				let peer = peers[i];
				let peerId = peer.id;
				console.debug(peerId, peers, connected);
				let isAlive = connected.indexOf(peerId) != -1;
				string += "<li>" + peerId;

				if ( isAlive ) {
					string += " (connected)";
				} else {
					string += " (not connected)";
				}

				string += "</li>\n";
			}
			list.html(string);
		};
		refreshList();
	});



});
