// Copyright 2016 SCION

// open the window on launch
chrome.app.runtime.onLaunched.addListener(function() {
	chrome.app.window.create('main.html', {
		'outerBounds' : {
			'width' : 600,
			'height' : 800
		}
	});
});
