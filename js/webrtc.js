
require(['../js/sync', '../js/preferences'], function(sync, preferences) {

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

});
