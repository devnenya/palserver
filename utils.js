// utils.js

/**
 * Returns the current timestamp in 'YYYY-MM-DD HH:MM:SS' format.
 */
function now_at() {
    const now = new Date();
    const pad = (num) => String(num).padStart(2, '0');

    return `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())} ` +
           `${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
}

/**
 * Formats a string with a 4-byte length prefix.
 * @param {string} theString - The string to format.
 */
function FBL(theString) {
    const lengthBuffer = Buffer.from(fourByteLength(theString.length));
    const stringBuffer = Buffer.from(theString, 'ascii');

    return Buffer.concat([lengthBuffer, stringBuffer]);
}

/**
 * Formats a string with a 2-byte length prefix.
 * @param {string} input - The string to format.
 */
function TBL(input) {
    if (!input) return Buffer.from([0, 0]); // Return empty buffer for null/undefined input
    const buffer = Buffer.from(input, 'ascii');
    return Buffer.concat([Buffer.from([buffer.length >> 8, buffer.length & 0xff]), buffer]);
}

/**
 * Converts a byte array to an ASCII string separated by spaces.
 * @param {Uint8Array|Array} byteArray - The byte array to convert.
 */
function AsciiString(byteArray) {
    if (!Array.isArray(byteArray) && !(byteArray instanceof Uint8Array)) {
        console.error(`${now_at()} Input must be a ByteArray or Uint8Array.`);
        return "";
    }

    return Array.from(byteArray).join(' ');
}

/**
 * Extracts a 4-byte unsigned integer from a buffer.
 * @param {Buffer} buffer - The buffer to extract from.
 */
function UFBL(buffer) {
    if (buffer.length !== 4) {
        console.error(`${now_at()} UFBL expects a 4-byte buffer.`);
        return;
    }

    let a = buffer[0] * (256 ** 3);
    let b = buffer[1] * (256 ** 2);
    let c = buffer[2] * 256;
    let d = buffer[3];
    return a + b + c + d;
}

/**
 * Extracts a 2-byte unsigned integer from a buffer.
 * @param {Buffer} buffer - The buffer to extract from.
 */
function UTBL(buffer) {
    if (buffer.length !== 2) {
        console.error(`${now_at()} UTBL expects a 2-byte buffer.`);
        return;
    }

    const a = buffer[0] * 256;
    const b = buffer[1];
    return a + b;
}

/**
 * Converts a number to a 4-byte array in big-endian order.
 * @param {number} uintPacketSize - The number to convert.
 */
function fourByteLength(uintPacketSize) {
    let chrPacketHeader = new Uint8Array(4);

    chrPacketHeader[0] = (uintPacketSize >> 24) & 0xFF; // Highest byte
    chrPacketHeader[1] = (uintPacketSize >> 16) & 0xFF; // Second highest byte
    chrPacketHeader[2] = (uintPacketSize >> 8) & 0xFF;  // Second lowest byte
    chrPacketHeader[3] = uintPacketSize & 0xFF;         // Lowest byte

    return chrPacketHeader;
}

/**
 * Converts a number to a 2-byte array in big-endian order.
 * @param {number} uintPacketSize - The number to convert.
 */
function twoByteLength(uintPacketSize) {
    if (uintPacketSize > 65535) {
        throw new RangeError(`${now_at()} Packet length cannot exceed 65,535 bytes.`);
    }

    let chrPacketHeader = new Uint8Array(2);

    chrPacketHeader[0] = (uintPacketSize >> 8) & 0xFF; // High byte
    chrPacketHeader[1] = uintPacketSize & 0xFF;        // Low byte

    return chrPacketHeader;
}

module.exports = {
    now_at,
    TBL,
    FBL,
    AsciiString,
    UFBL,
    UTBL,
    fourByteLength,
    twoByteLength
};