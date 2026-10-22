const http = require('http');
const url = require('url');
const fs = require('fs');

http.createServer((req, res) => {
    const pathname = url.parse(req.url).pathname;
    fs.readFile(__dirname + pathname, (err, data) => res.end(data));
}).listen(8080);
