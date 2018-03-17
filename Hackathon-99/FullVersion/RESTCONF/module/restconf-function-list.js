http = require('http')

var options = {
	host: 'localhost',
	port: '9000',
	path: '/sc/ipc/config/',
	method: 'GET',
	headers: {
		accept: 'text/json'
	}
};

module.exports = {
	"/config/sc/nsf/:nsf_name/policy/:policy_name/:rule": function(req, res, next) {
		nsf_name = req.params["nsf_name"];
		policy_name = req.params["policy_name"];
		rule = req.params["rule"];
		console.log(nsf_name, policy_name, rule);

		var options = {
			host: 'localhost',
			port: '9000',
			path: '/sc/ipc/config/',
			method: 'GET',
			headers: {
				accept: 'text/json'
			}
		};

		options.path += '?nsf_name=' + nsf_name;
		options.path += '&policy_name=' + policy_name;
		options.path += '&rule=' + rule;

		http.get(options, function(result) {
			console.log("Send data to sc python components");

			result.on('data', function(data) {
				data = JSON.parse(data.toString('utf-8'));
				console.log(data);
				res.json(data);
			});
		});
	}
};
