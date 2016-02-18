// Copyright 2016 SCION

// A generic onclick callback function.
function genericOnClick(info, tab) {
	console.log("item " + info.menuItemId + " was clicked");
	console.log("info: " + JSON.stringify(info));
	console.log("tab: " + JSON.stringify(tab));

	chrome.tabs.getAllInWindow(null, function(tabs) {
		var urls = [];

		// // collect all open tabs
		// tabs.forEach(function(tab) {
		// console.log(tab.url);
		// urls.push(tab.url);
		// });

		// collect the current url selection
		urls.push(info.linkUrl ? info.linkUrl : info.pageUrl);

		// send urls to app
		chrome.runtime.sendMessage("bogdaeienjhpdgpnmhenbgkjkglcbdok", {
			launch : true,
			urls : (JSON.stringify(urls))
		});
	});

}

// Create one test item for each context type.
var contexts = [ "page", "selection", "link", "editable", "image", "video",
		"audio" ];
for (var i = 0; i < contexts.length; i++) {
	var context = contexts[i];
	var title = "Query '" + context + "' url";
	var id = chrome.contextMenus.create({
		"title" : title,
		"contexts" : [ context ],
		"onclick" : genericOnClick
	});
	console.log("'" + context + "' item:" + id);
}

// Create a parent item and two children.
var parent = chrome.contextMenus.create({
	"title" : "Test parent item"
});
var child1 = chrome.contextMenus.create({
	"title" : "Child 1",
	"parentId" : parent,
	"onclick" : genericOnClick
});
var child2 = chrome.contextMenus.create({
	"title" : "Child 2",
	"parentId" : parent,
	"onclick" : genericOnClick
});
console.log("parent:" + parent + " child1:" + child1 + " child2:" + child2);
