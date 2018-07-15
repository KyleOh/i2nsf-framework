var express = require('express');
var router = express.Router();
var yang_parser = require('../module/yang-parser.js');
var restconf_function_list = require('../module/restconf-function-list.js');

var read_leaf_list = function(obj, route) {
	leaf = obj["leaf"];
	list = obj["list"];

	if (leaf != undefined && leaf != null) {
		var key = obj["key"];
		for (var l in leaf) {
			/* key fields will be automatically filled */
			if(l == key) continue;

			var tmpRoute = route + "/:" + l;
			
			if(restconf_function_list[tmpRoute]) {
				router.get(tmpRoute, restconf_function_list[tmpRoute]);
				console.log(tmpRoute, "Listener registered!");
			} else {
				console.log(tmpRoute, "No proper listener...");
			}
		}
	}

	
	if (list != undefined && list != null) {
		var tmpRoute = route;
		for (var l in list) {
			tmpRoute += ("/" + l + "/:" + l + "_" + list[l]['key']);
			read_leaf_list(list[l], tmpRoute);
		}	
	}
}

yang_parser.load_system_yang(function(err, data) {
	for (var module in data["module"]) {
		var target_module = data["module"][module];

		read_leaf_list(target_module, "/config/" + target_module["prefix"]);
	}
});

module.exports = router;
