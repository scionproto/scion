// Copyright 2016 SCION

var C_HEAD = '9080FF'; // supplied by jQuery
var C_STAT = '99CCFF';
var MS_LIST_INTERVAL = 5000;
var MS_LOOKUP_INTERVAL = 1000;

window.onload = function() {

	// listen for messages from ext after window opened
	chrome.runtime.onMessageExternal.addListener(function(request, sender,
			sendResponse) {

		if (request.urls) {
			console.log("Recieved message 'urls': " + request.urls);
			var u = JSON.parse(request.urls);
			addUrlToAccordion(u);
			sortAccordion();
		}
	});
}

// D3 simple table...

// TODO: show topology, links widening, perhaps as num, pct, width, cut node.

var j = function(name, arr) {

	return {
		name : name,
		path0 : arr[0],
		path1 : arr[1],
		path2 : arr[2],
		path3 : arr[3],
		path4 : arr[4],
		path5 : arr[5],
		path6 : arr[6],
		path7 : arr[7],
		path8 : arr[8],
		path9 : arr[9],
		path10 : arr[10],
		path11 : arr[11]
	};
};

var kBaseIndex = 0;
var kBaseIndexSel = 0;
var kBaseUrlSel = null;
var nullStats = [
		j('', [ 'P0', 'P1', 'P2', 'P3', 'P4', 'P5', 'P6', 'P7', 'P8', 'P9',
				'P10', 'P11' ]),
		j('sent pkts', [ '-', '-', '-', '-', '-', '-', '-', '-', '-', '-' ]),
		j('recv pkts', [ '-', '-', '-', '-', '-', '-', '-', '-', '-', '-' ]),
		j('ack pkts', [ '-', '-', '-', '-', '-', '-', '-', '-', '-', '-' ]),
		j('rtts', [ '-', '-', '-', '-', '-', '-', '-', '-', '-', '-' ]),
		j('loss rates', [ '-', '-', '-', '-', '-', '-', '-', '-', '-', '-' ]),
		j('IF counts', [ '-', '-', '-', '-', '-', '-', '-', '-', '-', '-' ]),
		j('IF lists', [ '-', '-', '-', '-', '-', '-', '-', '-', '-', '-' ]) ]

var backgroundJobs = nullStats;

function renderStats(index) {

	var tbody = d3.select(".urlStatsWidget").select('[id="' + index + '"]')
			.select('tbody');

	var rows = tbody.selectAll("tr").data(backgroundJobs, function(d) {
		return d.name;
	});
	rows.enter().append("tr");
	rows.order();
	var cells = rows.selectAll("td").data(function(row) {
		return [ {
			column : 'Name',
			value : row.name
		}, {
			column : 'P0',
			value : row.path0
		}, {
			column : 'P1',
			value : row.path1
		}, {
			column : 'P2',
			value : row.path2
		}, {
			column : 'P3',
			value : row.path3
		}, {
			column : 'P4',
			value : row.path4
		}, {
			column : 'P5',
			value : row.path5
		}, {
			column : 'P6',
			value : row.path6
		}, {
			column : 'P7',
			value : row.path7
		}, {
			column : 'P8',
			value : row.path8
		}, {
			column : 'P9',
			value : row.path9
		}, {
			column : 'P10',
			value : row.path10
		}, {
			column : 'P11',
			value : row.path11
		} ];
	});
	cells.enter().append("td");
	cells.text(function(d) {
		return d.value;
	});
	cells.exit().remove();
	rows.exit().remove();
}

// UDP sockets...

console.debug = function() {
};

var echoClient = null;

window.addEventListener("load", function() {
	var connect = document.getElementById("connect");
	var address = document.getElementById("address");

	echoClient = newEchoClient(address.value);
	connect.onclick = function(ev) {
		echoClient.disconnect();
		echoClient = newEchoClient(address.value);
	};
	address.onkeydown = function(ev) {
		if (ev.which == 13) {
			echoClient.disconnect();
			echoClient = newEchoClient(address.value);
		}
	};
});

var newEchoClient = function(address) {
	var ec = new chromeNetworking.clients.echoClient();
	ec.sender = attachSend(ec);
	var hostnamePort = address.split(":");
	var hostname = hostnamePort[0];
	var port = (hostnamePort[1] || 7) | 0;
	ec.connect(hostname, port, function() {
		console.log("Connected");

		// prepare list method after connection
		clearInterval(self.listIntervalId);
		requestListUpdate();
		self.listIntervalId = setInterval(function() {
			requestListUpdate();
		}, MS_LIST_INTERVAL);
	});
	return ec;

	// TODO: serialize all UDP requests, probably in networking.js
	// TODO: make client request serial, mutex
};

var attachSend = function(client) {
	return function(e) {
		var c = kBaseUrlSel.split(" ");
		var u = {};
		u.version = '0.1';
		u.command = 'LOOKUP';
		u.req_type = c[0];
		u.res_name = c[1];

		var jSend = JSON.stringify(u);
		var jLen = jSend.length;

		var dataLookup = str2ab(ab2str(toBytesInt32(jLen)) + jSend);

		client.echo(dataLookup, function() {
		});
	};
};

// TODO: Add button to pull data from server, rather than timeout

function requestListUpdate() {
	var u = {};
	u.version = '0.1';
	u.command = 'LIST';

	var jSend = JSON.stringify(u);
	var jLen = jSend.length;

	var dataList = str2ab(ab2str(toBytesInt32(jLen)) + jSend);

	// TODO: use list method to report to user when knowledge base is offline
	// TODO: warn if knowledge base unavailable

	echoClient.echo(dataList, function() {
	});
}

function updateUiUdpSent(text) {
	console.log('send', "'" + text + "'");
}

function updateUiUdpRecv(text) {
	console.log('receive', "'" + text + "' ");

	var jLen = fromBytesInt32(str2ab(text.substring(0, 4)));
	var jData = text.substring(4);
	// check length
	if (jLen != jData.length) {
		console.log("Lengths not equal: " + jLen + "," + jData.length);
	}

	try {
		var u = JSON.parse(jData);
		if (Array.isArray(u)) {
			// list
			u.forEach(function(entry) {
				addUrlToAccordion(entry);
			});
			sortAccordion();

		} else {
			// lookup
			var arrPcts = [
					j('', [ 'P0', 'P1', 'P2', 'P3', 'P4', 'P5', 'P6', 'P7',
							'P8', 'P9', 'P10', 'P11' ]),
					j('sent pkts', (u.sent_packets ? u.sent_packets : '-')),
					j('recv pkts', (u.received_packets ? u.received_packets
							: '-')),
					j('ack pkts', (u.acked_packets ? u.acked_packets : '-')),
					j('rtts', (u.rtts ? u.rtts : '-')),
					j('loss rates', (u.loss_rates ? u.loss_rates : '-')),
					j('IF counts', (u.if_counts ? u.if_counts : '-')) ];
			backgroundJobs = arrPcts.concat(getInterfaceListRows(u));
			renderStats(kBaseIndexSel);
		}
	} catch (e) {
		if (e instanceof SyntaxError) {
			console.log("JSON parse error: %s", e);
		} else {
			throw e;
		}
	}
}

function getInterfaceListRows(u) {
	var rows = [];
	var r = 0;
	var found = true;
	var max_count = Math.max.apply(null, u.if_counts);
	do {
		var row = [];
		for (c = 0; c < u.if_lists.length; c++) {
			if (r < u.if_counts[c]) {
				var n = u.if_lists[c][r];
				row.push(n.IFID + '-' + n.ISD + '-' + n.AD);
			} else {
				row.push('-');
			}
		}
		rows.push(j('IF' + r, (row ? row : '-')));
		r++;
	} while (r < max_count);
	return rows;
}

function sortAccordion() {
	// Get an array of jQuery objects containing each h3 and the div
	// that follows it
	var entries = $.map($(".urlStatsWidget").children("h3").get(), function(
			entry) {
		var $entry = $(entry);
		return $entry.add($entry.next());
	});

	// Sort the array by the h3's text
	entries.sort(function(a, b) {
		return a.filter("h3").text().localeCompare(b.filter("h3").text());
	});

	// Put them in the right order in the container
	$.each(entries, function() {
		this.detach().appendTo($(".urlStatsWidget"));
	});
}

function addUrlToAccordion(url) {
	var header = url[0] + " " + url[1];
	$(function() {
		// determine which elements are new
		var foundin = $('body:contains("' + header + '")');
		if (!foundin.length) {
			// add urls to widget
			var newDiv = "<h3>" + url[0] + " " + url[1] + "</h3><div id='"
					+ kBaseIndex + "' style='background-color:#" + C_STAT
					+ ";'><table><tbody></tbody></table></div>";
			$(".urlStatsWidget").append(newDiv)
			$(".urlStatsWidget").accordion("refresh");
			kBaseIndex++;
		}
	});
}

function removeUrlFromAccordion(a) {
	// first remove the div, then the header
	$(a).parent().next().remove();
	$(a).parent().remove();
	$(".urlStatsWidget").accordion("refresh");
	return false;
}

function str2ab(str) {
	var encoder = new TextEncoder('utf-8');
	return encoder.encode(str).buffer;
}

function ab2str(ab) {
	var dataView = new DataView(ab);
	var decoder = new TextDecoder('utf-8');
	return decoder.decode(dataView);
}

function toBytesInt32(num) {
	arr = new ArrayBuffer(4);
	view = new DataView(arr);
	view.setUint32(0, num, false);
	return arr;
}

function fromBytesInt32(arr) {
	view = new DataView(arr);
	return view.getUint32(0, false);
}

// JQuery...

// initialize accordion widget
$(function() {
	$(".urlStatsWidget").accordion({
		collapsible : true,
		active : false,
		heightStyle : "content",
		activate : function(event, ui) {
		}
	}).sortable({
		axis : "y",
		handle : "h3",
		sorting : true,
		stop : function() {
			stop = true;
		}
	});
	$(".urlStatsWidget").on("accordionactivate", function(event, ui) {
		if (ui.newHeader.length && ui.newPanel.length) {
			// accordion is expanding, start udp lookups
			kBaseUrlSel = ui.newHeader[0].innerText;
			kBaseIndexSel = ui.newPanel.attr('id');
			console.log("activate init event: " + kBaseIndexSel);
			if (echoClient != null) {
				self.lookupIntervalId = setInterval(function() {
					echoClient.sender();
				}, MS_LOOKUP_INTERVAL);
			}
		} else {
			// accordion collapsing, stop udp lookups
			clearInterval(self.lookupIntervalId);

			// TODO: this can get out of sync, need to add push/pop array of
			// interval ids
		}
	});
});
