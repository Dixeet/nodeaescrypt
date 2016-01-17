"use strict";
const crypto = require('crypto');
const CustomBuffer = require('./customBuffer.js');

class DecrypterAesFileFormatV2FromBuffer {
    constructor(fileBuffer, password) {
        if (!(fileBuffer instanceof Buffer)) throw new Error('fileBuffer should be a Buffer');
        if (!password) throw new Error('password should be a String');
        this._fileCustomBuffer = new CustomBuffer(fileBuffer);
        this.password = password;
    }

    setPassword(password) {
        this.password = password;
    }

    setFileBuffer(fileBuffer) {
        this._fileCustomBuffer = new CustomBuffer(fileBuffer);
    }

    _skipHeadersAndReservedByte() {
        this._fileCustomBuffer.read(5);
    }

    _skipExtensions() {
        while (true) {
            let data = this._fileCustomBuffer.read(2);
            if (data.equals(new Buffer([0, 0]))) {
                break;
            }
            this._fileCustomBuffer.read(CustomBuffer.bufferToInt(data));
        }
    }

    _setPublicIv() {
        this._publicIv = this._fileCustomBuffer.read(16);
    }

    _setEncryptedIvAndKey() {
        this._encryptedIvAndKey = this._fileCustomBuffer.read(48);
    }

    _setHmacIvAndKey() {
        this._hmacIvAndKey = this._fileCustomBuffer.read(32);
    }

    _setDataSize() {
        this._dataSize = this._fileCustomBuffer.read(1);
    }

    _setHmacEncryptedData() {
        this._hmacEncryptedData = this._fileCustomBuffer.read(32);
    }

    _generatePublicKey() {
        let nullByte = new Buffer(16).fill(0);
        let digest = Buffer.concat([this._publicIv, nullByte]);
        for (var i = 0; i < 8192; i++) {
            let pwdhash = crypto.createHash('sha256');
            pwdhash.update(digest);
            pwdhash.update(this.password, 'utf16le');
            digest = pwdhash.digest();
        }
        this._publicKey = digest;
    }

    _computeHmacIvAndKey() {
        let hmac = crypto.createHmac('sha256', this._publicKey);
        hmac.update(this._encryptedIvAndKey);
        this._hmacComputedIvAndKey = hmac.digest();
    }

    _compareHmacIvKeyAndComputedHmac() {
        if (!this._hmacComputedIvAndKey.equals(this._hmacIvAndKey)) throw new Error('Wrong password');
    }
    
    _decryptIvKey(){
        let decipher = crypto.createDecipheriv('aes-256-cbc', this._publicKey, this._publicIv);
        decipher.setAutoPadding(false);
        let iv_key = Buffer.concat([decipher.update(this._encryptedIvAndKey), decipher.final()]);
        this.privateIv = iv_key.slice(0, 16);
        this.privateKey = iv_key.slice(16);
    }

    _decryptData(){
        let decipher = crypto.createDecipheriv('aes-256-cbc', this.privateKey, this.privateIv);
        decipher.setAutoPadding(false);
        let hmac = crypto.createHmac('sha256', this.privateKey);
        let encryptedText, decryptedText;
        while (this._fileCustomBuffer.buffer.length - this._fileCustomBuffer.byteRead - 32 - 1 - 16) {
            encryptedText = this._fileCustomBuffer.read(16);
            hmac.update(cText);
            decryptedText = Buffer.concat([decipher.update(encryptedText), decipher.final()]);
        }
        encryptedText = this._fileCustomBuffer.read(16);
        hmac.update(encryptedText);
        this._setDataSize();
        if (decryptedText != undefined) {
            decryptedText = Buffer.concat([decryptedText, decipher.update(encryptedText), decipher.final()])
        } else {
            decryptedText = Buffer.concat([decipher.update(encryptedText), decipher.final()]);
        }
        let byteToRemove = (16 - CustomBuffer.bufferToInt(this._dataSize)) % 16;
        this._decryptedData = decryptedText.slice(0, -byteToRemove);
        this._hmacData = hmac.digest();
    }

    _compareHmacDataAndEncryptedHmacData(){
        if (!this._hmacData.equals(this._hmacEncryptedData)) throw new Error('Data decrypted is corrupted');
    }

    decrypt() {
        this._fileCustomBuffer.resetByteRead();
        this._skipHeadersAndReservedByte();
        this._skipExtensions();
        this._setPublicIv();
        this._generatePublicKey();
        this._setEncryptedIvAndKey();
        this._setHmacIvAndKey();
        this._computeHmacIvAndKey();
        this._compareHmacIvKeyAndComputedHmac();
        this._decryptIvKey();
        this._decryptData();
        this._setHmacEncryptedData();
        this._compareHmacDataAndEncryptedHmacData();
        return this._decryptedData;
    }
}

class DecrypterAesFileFormatFromBuffer {
    constructor(fileBuffer, password) {
        if (!(fileBuffer instanceof Buffer)) throw new Error('fileBuffer should be a Buffer');
        if (!(password instanceof String)) throw new Error('password should be a String');
        this.fileBuffer = fileBuffer;
        this.password = password;
    }

    _checkAesFile() {

    }

    _checkVersion() {

    }
}

module.exports = DecrypterAesFileFormatV2FromBuffer;