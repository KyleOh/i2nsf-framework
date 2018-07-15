var config = require('../config.js');
var yjs = require('yang-js');
var fs = require('fs');

exports.load_system_yang = function(callback) {
	fs.readFile(config.system_yang_path, "utf-8", function(err, data){
		if(err) {
			console.log(err);
			callback(err);
		}
		system_yang = yjs.parse(data);

		console.log("Loading system YANG is completed.");
		callback(null, system_yang.toJSON());
	});
};
