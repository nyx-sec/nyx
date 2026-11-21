var http = require('http');
var url = require('url');
var fs = require('fs');

http.createServer(function(req, res) {
    var query = url.parse(req.url, true).query;
    fs.readFile("/srv/files/" + query, function(err, data) {
        res.end(data);
    });
}).listen(8080);
