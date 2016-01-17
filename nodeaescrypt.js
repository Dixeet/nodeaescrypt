var fs = require('fs');
var crypto = require('crypto');
var nodeaes = require('./nodeaes.js');
var filePath = 'LICENSE';
var pwd = 'test';
var toto = new Buffer();
var fIn = fs.createReadStream(filePath);
nodeaes.decrypt(fIn, pwd, function (err, data) {
    if (err) {
        console.log(err);
    } else {
        console.log(data.toString());
    }
});

