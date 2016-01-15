const crypto = require('crypto');

const aesCrypt = exports;
aesCrypt.decrypt = function(fileIn, password, callback){
    if (typeof callback == 'function')
        HandleWithCallback(fileIn, password, callback);
};
const defaultError = 'Error: file is corrupted or not an AES Crypt (or pyAesCrypt) file.';


function HandleWithCallback(f, pwd, cb){
    f.on('readable', function () {
        //First 3 bytes should be 'AES'
        var data = f.read(3);
        if (data.toString('ascii') != 'AES') {
            Terminate(defaultError);
        }

        //Check version, for now only v2
        data = f.read(1);
        if (data[0] != 2) {
            Terminate(defaultError);
        } else {
            var dataBuf = VersionV2(f, pwd);
            cb(undefined, dataBuf);
        }

    });
}

function VersionV2(f, pwd) {
    //skip reserved byte
    f.read(1);

    //skip extension
    while (true) {
        var data = f.read(2);
        if (data.equals(new Buffer([0, 0]))) {
            break;
        }
        f.read(ConvertBufferToInt(data));
    }

    //read the external iv
    var ivExt = f.read(16);

    //get the hashed key+password
    var key = HashIVPwd(ivExt, pwd);

    //read encrypted main iv and key
    var encIvAndKey = f.read(48);

    //read HMAC-SHA256 of the encrypted iv and key
    var hmac1 = f.read(32);

    //Build Hmac with the previous hashed key+password
    var hmac1Comp = crypto.createHmac('sha256', key);
    hmac1Comp.update(encIvAndKey);
    var hmac1CompDig = hmac1Comp.digest();

    //Compare if the both Hmac are the same
    if (!hmac1.equals(hmac1CompDig)) {
        Terminate('Error: wrong password (or file is corrupted).');
    }

    var decipher1 = crypto.createDecipheriv('aes-256-cbc', key, ivExt);
    decipher1.setAutoPadding(false);
    var iv_key = Buffer.concat([decipher1.update(encIvAndKey),decipher1.final()]);

    var realIv = iv_key.slice(0, 16);
    var realKey = iv_key.slice(16);

    var decipher = crypto.createDecipheriv('aes-256-cbc', realKey, realIv);
    decipher.setAutoPadding(false);
    var hmac = crypto.createHmac('sha256', realKey);

    var cText, textBuf;
    while (f._readableState.length - 32 - 1 - 16) {
        cText = f.read(16);
        hmac.update(cText);
        textBuf = Buffer.concat([decipher.update(cText),decipher.final()]);
    }

    cText = f.read(16);
    hmac.update(cText);

    var fileSize = f.read(1);

    if (textBuf != undefined){
        textBuf = Buffer.concat([textBuf, decipher.update(cText),decipher.final()])
    } else {
        textBuf = Buffer.concat([decipher.update(cText),decipher.final()]);
    }
    var byteToRemove = (16 - ConvertBufferToInt(fileSize)) % 16;
    return textBuf.slice(0, -byteToRemove);
}

function HashIVPwd(iv, password) {
    var nullByteBuffer = new Buffer(16).fill(0);
    var digest = Buffer.concat([iv, nullByteBuffer]);
    for (var i = 0; i < 8192; i++) {
        var pwdhash = crypto.createHash('sha256');
        pwdhash.update(digest);
        pwdhash.update(password, 'utf16le');
        digest = pwdhash.digest();
    }
    return digest;
}

function ConvertBufferToInt(data) {
    //data.
    return parseInt(data.toString('hex'), 16);
}

function Terminate(reason) {
    console.log(reason);
    process.exit();
}
