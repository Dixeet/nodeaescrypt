'use strict';
class CustomBuffer {
    constructor(buffer) {
        if (!(buffer instanceof Buffer)) throw new Error('A buffer should be given');
        this.buffer = buffer;
        this.resetByteRead();
    }

    resetByteRead() {
        this.byteRead = 0;
    }

    read(n) {
        let byteRead = this.byteRead;
        this.byteRead += n;
        return this.buffer.slice(byteRead, byteRead + n);
    }

    toInt() {
        return CustomBuffer.bufferToInt(this.buffer);
    }

    static bufferToInt(buf) {
        return parseInt(buf.toString('hex'), 16);
    }
}
module.exports = CustomBuffer;