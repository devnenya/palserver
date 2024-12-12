// handlers/roomHandler.js
const { sendOut, now_at, TBL, AsciiString } = require('../utils');
const { PAL_BOT_ID } = require('../constants');

/**
 * Handles Room-related packets.
 * @param {Buffer} clientPacket - The raw packet data from the client.
 * @param {User} user - The user interacting with the room.
 * @param {Map<string, Room>} rooms - Map of roomURL to Room instances.
 * @param {Function} sendOutFunc - Function to send data to a user.
 * @param {Array<User>} users - Array of all connected users.
 * @param {Function} findUserByID - Function to find a user index by their ID.
 */
function handleRoom(clientPacket, user, rooms, sendOutFunc, users, findUserByID) {
    switch (clientPacket[10]) {
        case 21:
            let tIDRequest = AsciiString(clientPacket.slice(5, 9)); // Extract tID from the packet
            const findBuddyRoom = findUserByID(tIDRequest); // Find user by tID

            console.log(`${now_at()} ${user.username} Avatar-REQUEST-> ${findBuddyRoom >= 0 ? users[findBuddyRoom].username : 'Unknown'}`);

            if (findBuddyRoom >= 0) {  // Ensure buddy is found (index >= 0)
                const responseRoom = Buffer.concat([
                    Buffer.from([0, 15, 0, 0, 1]),  // Fixed header
                    clientPacket.slice(5, 9),
                    Buffer.from([0, 21, 1, 1]),     // Packet flags or additional data
                    Buffer.from(users[findBuddyRoom].avatarData)
                ]);

                sendOutFunc(user, responseRoom); // Send the response to the user
                console.log(`${now_at()} ${user.username} Avatar-SENT-> ${users[findBuddyRoom].username}`);
            }
            break;

        case 22:
            let avdata = clientPacket.slice(13);
            console.log(`${now_at()} ${user.username} Avatar-UPDATE-> ${avdata.length}`);
            user.avatarData = Buffer.from(avdata);
            break;

        default:
            console.log(`${now_at()} ${user.username} Unknown Room packet type: ${clientPacket[10]}`);
            break;
    }
}

module.exports = { handleRoom };
