var fs = require('fs');
var crypto = require('crypto');
var nodeaes = require('./nodeaes.js');
var filePath = '';
var pwd = '';
var fIn = fs.createReadStream(filePath);
nodeaes.decrypt(fIn,pwd,function(err, data){
   console.log(data.toString());
});

