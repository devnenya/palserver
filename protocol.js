// protocol.js
const { FBL, AsciiString, now_at } = require('./utils');

/**
 * Sends data to a user.
 * @param {User} user - The user to send data to.
 * @param {Buffer} data - The data to send.
 */
function sendOut(user, data) {
    if (!user.connection) {
        console.error(`${now_at()} ${user.username} is not connected`);
        return;
    }

    // Prepare the packet
    const packet = Buffer.concat([Buffer.from([user.sByte]), FBL(data)]);
    const canWrite = user.connection.write(packet);

    // Cycle `sByte` between 129 and 255
    user.sByte = user.sByte === 255 ? 129 : user.sByte + 1;

    console.log(`${now_at()} ${user.username} DEBUG OUT ${AsciiString(packet)}`);

    // Handle backpressure if the write buffer is full
    if (!canWrite) {
        console.warn(`${now_at()} ${user.username} Backpressure detected, waiting for drain event`);
        user.connection.once('drain', () => {
            console.log(`${now_at()} ${user.username} Drain event triggered, resuming writes`);
        });
    }
}

module.exports = { sendOut };
