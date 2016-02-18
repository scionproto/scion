// Copyright 2016 SCION

// Test logging of IP addresses
chrome.webRequest.onSendHeaders.addListener(function(info) {
//	console.log("onSendHeaders: " + info.method + " / " + info.url);
//	var urls = [];
//	urls.push(info.method);// 0
//	urls.push(info.url);// 1
//
//	// send urls to app
//	chrome.runtime.sendMessage("bogdaeienjhpdgpnmhenbgkjkglcbdok", {
//		launch : true,
//		urls : (JSON.stringify(urls))
//	});
//}, {
//	urls : [ "<all_urls>" ]
});

// Initializes the background page by loading a ProxyErrorHandler, and resetting
// proxy settings if required.
document.addEventListener("DOMContentLoaded", function() {
	var errorHandler = new ProxyErrorHandler();

	// If this extension has already set the proxy settings, then reset it
	// once as the background page initializes. This is essential, as
	// incognito settings are wiped on restart.
	var persistedSettings = ProxyFormController.getPersistedSettings();
	if (persistedSettings !== null) {
		chrome.proxy.settings.set({
			'value' : persistedSettings.regular
		});
	}
});
