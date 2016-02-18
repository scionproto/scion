/*
 *  Node.js UDP echo server
 *
 *  This demonstration shows a basic echo server that has randomly drops responses.
 *  The drop factor is `threshold` 0.99 = 99% chance of success, 1% dropped packets
 * 
 *  Additionally each response is delayed by 2-3 seconds.
 * 
 *  Listens on port 7777 by default. Pass in a desired port as cmdline argument.
 */

var dgram = require('dgram');
var server = dgram.createSocket('udp4');

var threshold = 0.99;

server.on("listening", function() {
	var address = server.address();
	console.log("Listening on " + address.address);
});

server.on("message", function(message, rinfo) {
	var delay = 2000 + Math.random() * 1000;
	// Echo the message back to the client.
	var dropped = Math.random();
	if (dropped > threshold) {
		console.log("Recieved message from: " + rinfo.address + ", DROPPED");
		return;
	}
	console.log("Recieved message from: " + rinfo.address + "," + message + ","
			+ message.length);
	var jLen = message.readUInt32BE(0);
	var jData = message.toString("utf-8", 4);

	// TODO: lengths not equal over 256 length son on js server
	// test?

	// check length
	if (jLen != jData.length) {
		console.log("Lengths not equal: " + jLen + "," + jData.length);
		return;
	}

	// parse the json
	var rc = JSON.parse(jData);
	var jData = null;

	// add dummy parameters before echoing back
	if (rc.command == 'LOOKUP') {
		var u = {};
		u.sent_packets = getRandomIntArray(0, 100, 12);
		u.received_packets = getRandomIntArray(0, 100, 12);
		u.acked_packets = getRandomIntArray(0, 100, 12);
		u.rtts = getRandomIntArray(0, 100, 12);
		u.loss_rates = getRandomDoubleArray(12);
		u.if_lists = [];
		u.if_counts = [];
		for (c = 0; c < 12; c++) {
			u.if_counts.push(getRandomInt(10, 16));
			var col = [];
			for (r = 0; r < u.if_counts[c]; r++) {
				var n = {};
				n.IFID = getRandomInt(0, 100);
				n.ISD = getRandomInt(0, 100);
				n.AD = getRandomInt(0, 100);
				col.push(n);
			}
			u.if_lists.push(col);
		}
		jData = JSON.stringify(u);

		// jData = '{"if_lists": [[{"IFID": 1, "ISD": 1, "AD": 19}, {"IFID": 3,
		// "ISD": 1, "AD": 16}, {"IFID": 1, "ISD": 1, "AD": 16}, {"IFID": 3,
		// "ISD": 1, "AD": 13}, {"IFID": 2, "ISD": 1, "AD": 13}, {"IFID": 2,
		// "ISD": 1, "AD": 12}, {"IFID": 3, "ISD": 1, "AD": 12}, {"IFID": 1,
		// "ISD": 2, "AD": 22}, {"IFID": 3, "ISD": 2, "AD": 22}, {"IFID": 1,
		// "ISD": 2, "AD": 24}, {"IFID": 3, "ISD": 2, "AD": 24}, {"IFID": 2,
		// "ISD": 2, "AD": 26}], [{"IFID": 1, "ISD": 1, "AD": 19}, {"IFID": 3,
		// "ISD": 1, "AD": 16}, {"IFID": 1, "ISD": 1, "AD": 16}, {"IFID": 3,
		// "ISD": 1, "AD": 13}, {"IFID": 1, "ISD": 1, "AD": 13}, {"IFID": 2,
		// "ISD": 1, "AD": 11}, {"IFID": 1, "ISD": 1, "AD": 11}, {"IFID": 1,
		// "ISD": 1, "AD": 12}, {"IFID": 3, "ISD": 1, "AD": 12}, {"IFID": 1,
		// "ISD": 2, "AD": 22}, {"IFID": 3, "ISD": 2, "AD": 22}, {"IFID": 1,
		// "ISD": 2, "AD": 24}, {"IFID": 3, "ISD": 2, "AD": 24}, {"IFID": 2,
		// "ISD": 2, "AD": 26}], [{"IFID": 1, "ISD": 1, "AD": 19}, {"IFID": 3,
		// "ISD": 1, "AD": 16}, {"IFID": 1, "ISD": 1, "AD": 16}, {"IFID": 3,
		// "ISD": 1, "AD": 13}, {"IFID": 1, "ISD": 1, "AD": 13}, {"IFID": 2,
		// "ISD": 1, "AD": 11}, {"IFID": 3, "ISD": 1, "AD": 11}, {"IFID": 1,
		// "ISD": 2, "AD": 21}, {"IFID": 2, "ISD": 2, "AD": 21}, {"IFID": 2,
		// "ISD": 2, "AD": 22}, {"IFID": 3, "ISD": 2, "AD": 22}, {"IFID": 1,
		// "ISD": 2, "AD": 24}, {"IFID": 3, "ISD": 2, "AD": 24}, {"IFID": 2,
		// "ISD": 2, "AD": 26}], [{"IFID": 1, "ISD": 1, "AD": 19}, {"IFID": 3,
		// "ISD": 1, "AD": 16}, {"IFID": 1, "ISD": 1, "AD": 16}, {"IFID": 3,
		// "ISD": 1, "AD": 13}, {"IFID": 2, "ISD": 1, "AD": 13}, {"IFID": 2,
		// "ISD": 1, "AD": 12}, {"IFID": 1, "ISD": 1, "AD": 12}, {"IFID": 1,
		// "ISD": 1, "AD": 11}, {"IFID": 3, "ISD": 1, "AD": 11}, {"IFID": 1,
		// "ISD": 2, "AD": 21}, {"IFID": 2, "ISD": 2, "AD": 21}, {"IFID": 2,
		// "ISD": 2, "AD": 22}, {"IFID": 3, "ISD": 2, "AD": 22}, {"IFID": 1,
		// "ISD": 2, "AD": 24}, {"IFID": 3, "ISD": 2, "AD": 24}, {"IFID": 2,
		// "ISD": 2, "AD": 26}], [{"IFID": 1, "ISD": 1, "AD": 19}, {"IFID": 3,
		// "ISD": 1, "AD": 16}, {"IFID": 1, "ISD": 1, "AD": 16}, {"IFID": 3,
		// "ISD": 1, "AD": 13}, {"IFID": 1, "ISD": 1, "AD": 13}, {"IFID": 2,
		// "ISD": 1, "AD": 11}, {"IFID": 3, "ISD": 1, "AD": 11}, {"IFID": 1,
		// "ISD": 2, "AD": 21}, {"IFID": 3, "ISD": 2, "AD": 21}, {"IFID": 2,
		// "ISD": 2, "AD": 23}, {"IFID": 5, "ISD": 2, "AD": 23}, {"IFID": 1,
		// "ISD": 2, "AD": 26}], [{"IFID": 1, "ISD": 1, "AD": 19}, {"IFID": 3,
		// "ISD": 1, "AD": 16}, {"IFID": 1, "ISD": 1, "AD": 16}, {"IFID": 3,
		// "ISD": 1, "AD": 13}, {"IFID": 2, "ISD": 1, "AD": 13}, {"IFID": 2,
		// "ISD": 1, "AD": 12}, {"IFID": 1, "ISD": 1, "AD": 12}, {"IFID": 1,
		// "ISD": 1, "AD": 11}, {"IFID": 3, "ISD": 1, "AD": 11}, {"IFID": 1,
		// "ISD": 2, "AD": 21}, {"IFID": 3, "ISD": 2, "AD": 21}, {"IFID": 2,
		// "ISD": 2, "AD": 23}, {"IFID": 5, "ISD": 2, "AD": 23}, {"IFID": 1,
		// "ISD": 2, "AD": 26}], [{"IFID": 1, "ISD": 1, "AD": 19}, {"IFID": 3,
		// "ISD": 1, "AD": 16}, {"IFID": 1, "ISD": 1, "AD": 16}, {"IFID": 3,
		// "ISD": 1, "AD": 13}, {"IFID": 2, "ISD": 1, "AD": 13}, {"IFID": 2,
		// "ISD": 1, "AD": 12}, {"IFID": 3, "ISD": 1, "AD": 12}, {"IFID": 1,
		// "ISD": 2, "AD": 22}, {"IFID": 2, "ISD": 2, "AD": 22}, {"IFID": 2,
		// "ISD": 2, "AD": 21}, {"IFID": 3, "ISD": 2, "AD": 21}, {"IFID": 2,
		// "ISD": 2, "AD": 23}, {"IFID": 5, "ISD": 2, "AD": 23}, {"IFID": 1,
		// "ISD": 2, "AD": 26}], [{"IFID": 1, "ISD": 1, "AD": 19}, {"IFID": 3,
		// "ISD": 1, "AD": 16}, {"IFID": 1, "ISD": 1, "AD": 16}, {"IFID": 3,
		// "ISD": 1, "AD": 13}, {"IFID": 1, "ISD": 1, "AD": 13}, {"IFID": 2,
		// "ISD": 1, "AD": 11}, {"IFID": 1, "ISD": 1, "AD": 11}, {"IFID": 1,
		// "ISD": 1, "AD": 12}, {"IFID": 3, "ISD": 1, "AD": 12}, {"IFID": 1,
		// "ISD": 2, "AD": 22}, {"IFID": 2, "ISD": 2, "AD": 22}, {"IFID": 2,
		// "ISD": 2, "AD": 21}, {"IFID": 3, "ISD": 2, "AD": 21}, {"IFID": 2,
		// "ISD": 2, "AD": 23}, {"IFID": 5, "ISD": 2, "AD": 23}, {"IFID": 1,
		// "ISD": 2, "AD": 26}], [{"IFID": 1, "ISD": 1, "AD": 19}, {"IFID": 3,
		// "ISD": 1, "AD": 16}, {"IFID": 1, "ISD": 1, "AD": 16}, {"IFID": 3,
		// "ISD": 1, "AD": 13}, {"IFID": 1, "ISD": 1, "AD": 13}, {"IFID": 2,
		// "ISD": 1, "AD": 11}, {"IFID": 3, "ISD": 1, "AD": 11}, {"IFID": 1,
		// "ISD": 2, "AD": 21}, {"IFID": 3, "ISD": 2, "AD": 21}, {"IFID": 2,
		// "ISD": 2, "AD": 23}, {"IFID": 5, "ISD": 2, "AD": 23}, {"IFID": 1,
		// "ISD": 2, "AD": 26}], [{"IFID": 1, "ISD": 1, "AD": 19}, {"IFID": 3,
		// "ISD": 1, "AD": 16}, {"IFID": 1, "ISD": 1, "AD": 16}, {"IFID": 3,
		// "ISD": 1, "AD": 13}, {"IFID": 2, "ISD": 1, "AD": 13}, {"IFID": 2,
		// "ISD": 1, "AD": 12}, {"IFID": 1, "ISD": 1, "AD": 12}, {"IFID": 1,
		// "ISD": 1, "AD": 11}, {"IFID": 3, "ISD": 1, "AD": 11}, {"IFID": 1,
		// "ISD": 2, "AD": 21}, {"IFID": 3, "ISD": 2, "AD": 21}, {"IFID": 2,
		// "ISD": 2, "AD": 23}, {"IFID": 5, "ISD": 2, "AD": 23}, {"IFID": 1,
		// "ISD": 2, "AD": 26}], [{"IFID": 1, "ISD": 1, "AD": 19}, {"IFID": 3,
		// "ISD": 1, "AD": 16}, {"IFID": 1, "ISD": 1, "AD": 16}, {"IFID": 3,
		// "ISD": 1, "AD": 13}, {"IFID": 2, "ISD": 1, "AD": 13}, {"IFID": 2,
		// "ISD": 1, "AD": 12}, {"IFID": 3, "ISD": 1, "AD": 12}, {"IFID": 1,
		// "ISD": 2, "AD": 22}, {"IFID": 2, "ISD": 2, "AD": 22}, {"IFID": 2,
		// "ISD": 2, "AD": 21}, {"IFID": 3, "ISD": 2, "AD": 21}, {"IFID": 2,
		// "ISD": 2, "AD": 23}, {"IFID": 5, "ISD": 2, "AD": 23}, {"IFID": 1,
		// "ISD": 2, "AD": 26}], [{"IFID": 1, "ISD": 1, "AD": 19}, {"IFID": 3,
		// "ISD": 1, "AD": 16}, {"IFID": 1, "ISD": 1, "AD": 16}, {"IFID": 3,
		// "ISD": 1, "AD": 13}, {"IFID": 1, "ISD": 1, "AD": 13}, {"IFID": 2,
		// "ISD": 1, "AD": 11}, {"IFID": 1, "ISD": 1, "AD": 11}, {"IFID": 1,
		// "ISD": 1, "AD": 12}, {"IFID": 3, "ISD": 1, "AD": 12}, {"IFID": 1,
		// "ISD": 2, "AD": 22}, {"IFID": 2, "ISD": 2, "AD": 22}, {"IFID": 2,
		// "ISD": 2, "AD": 21}, {"IFID": 3, "ISD": 2, "AD": 21}, {"IFID": 2,
		// "ISD": 2, "AD": 23}, {"IFID": 5, "ISD": 2, "AD": 23}, {"IFID": 1,
		// "ISD": 2, "AD": 26}]], "sent_packets": [8, 3, 1, 1, 1, 1, 1, 1, 1, 1,
		// 1, 1], "acked_packets": [8, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1], "rtts":
		// [14665, 28524, 37004, 37003, 37004, 37004, 37004, 37004, 37004,
		// 37004, 37002, 37002], "loss_rates": [0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
		// 0.0, 0.0, 0.0, 0.0, 0.0, 0.0], "received_packets": [1, 1, 1, 1, 2, 2,
		// 2, 2, 7, 1, 0, 0], "if_counts": [12, 14, 14, 16, 12, 14, 14, 16, 12,
		// 14, 14, 16]}';

	} else if (rc.command == 'LIST') {
		var lu = [];
		lu.push([ "GET", "http://www.cnn.com" ]);
		lu.push([ "POST", "http://www.google.com" ]);
		lu.push([ "CONNECT", "http://www.yahoo.com" ]);
		jData = JSON.stringify(lu);

		// jData = '[["CONNECT", "self-repair.mozilla.org:443"], ["CONNECT",
		// "collector.githubapp.com:443"], ["CONNECT",
		// "www.google-analytics.com:443"], ["POST",
		// "http://clients1.google.com/ocsp"], ["CONNECT",
		// "api.github.com:443"], ["CONNECT", "geo.mozilla.org:443"],
		// ["CONNECT", "avatars2.githubusercontent.com:443"], ["CONNECT",
		// "live.github.com:443"], ["POST", "http://ocsp.digicert.com/"],
		// ["CONNECT", "avatars0.githubusercontent.com:443"], ["CONNECT",
		// "github.com:443"]]';
	}

	var buf = new Buffer(4);
	buf.writeUInt32BE(jData.length, 0);

	var resp = Buffer.concat([ buf, new Buffer(jData) ]);

	setTimeout(function() {
		server.send(resp, 0, resp.length, rinfo.port, rinfo.address, function(
				err, bytes) {
			console.log(err, bytes);
		});
	}, delay);
});

server.on("close", function() {
	console.log("Socket closed");
});

var port = process.argv[2];
server.bind(port ? parseInt(port) : 7777);

function getRandomInt(min, max) {
	return Math.floor(Math.random() * (max - min)) + min;
}

function getRandomIntArray(min, max, total) {
	var arr = [ total ];
	for (var i = 0; i < total; i++) {
		arr[i] = getRandomInt(max, min);
	}
	return arr;
}

function getRandomDoubleArray(total) {
	var arr = [ total ];
	for (var i = 0; i < total; i++) {
		arr[i] = Math.random().toFixed(2);
	}
	return arr;
}

function getRandomULong(min, max) {
	return Math.floor(Math.random() * (max - min)) + min;
}
