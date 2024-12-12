// handlers/dmHandler.js
const { now_at, TBL, AsciiString, UTBL, UFBL } = require('../utils');
const { sendOut } = require('../protocol');

/**
 * Handles Direct Message (DM) packets.
 * @param {Buffer} clientPacket - The raw packet data from the client.
 * @param {User} user - The user sending the DM.
 * @param {Array<User>} users - Array of all connected users.
 * @param {Function} findUserByID - Function to find a user index by their ID.
 */
function handleDM(clientPacket, user, users) {
    const key = clientPacket.slice(12, 14).join(',');

    switch (key) {
        case '2,2':
            console.log(`${AsciiString(clientPacket.slice(clientPacket.length - 4))}`);
            // Outbound More Info Req.
            const findBuddy2 = users.findIndex(u => AsciiString(u.getServerIDBytes()) === AsciiString(clientPacket.slice(clientPacket.length - 4)));
            if (findBuddy2 >= 0) {
                const response2 = Buffer.concat([
                    Buffer.from([0, 5, 0]),
                    users[findBuddy2].getServerIDBytes(),
                    Buffer.from([0, 0, 0, 0, 0, 2, 2, 0]),
                    user.getServerIDBytes(),
                    Buffer.from([
                        1, 0,
                        ...TBL(user.username),
                        2, 0, 0, 0, 0, 0, 0
                    ])
                ]);

                sendOut(users[findBuddy2], response2);
            }
            break;

        case '6,3':
            const findBuddy6 = users.findIndex(u => AsciiString(u.getServerIDBytes()) === AsciiString(clientPacket.slice(clientPacket.length - 4)));
            if (findBuddy6 >= 0) {
                const response6 = Buffer.concat([
                    Buffer.from([0, 5, 0]),
                    users[findBuddy6].getServerIDBytes(),
                    clientPacket.slice(7, clientPacket.length - 4),
                    user.getServerIDBytes(),
                    Buffer.from([
                        1, 0,
                        ...TBL(user.username),
                        2, 0, 0, 0, 0, 0, 0
                    ])
                ]);

                sendOut(users[findBuddy6], response6);
            }
            break;

        default:
            // Handle standard DM
            let messagesize = UTBL(clientPacket.slice(7, 9)); // Extract message size
            let messagetext = clientPacket.slice(9, 9 + messagesize); // Extract message text

            let attachmentsizeStart = 9 + messagesize;
            let attachmentsize = UFBL(clientPacket.slice(attachmentsizeStart, attachmentsizeStart + 4)); // Extract attachment size    

            let hasGesture = attachmentsize !== 0;

            let gesturetext = "";
            let sIDStart;

            if (hasGesture) {
                let gesturesizeStart = attachmentsizeStart + 5; // Gesture TBL starts after the flag
                let gesturesize = UTBL(clientPacket.slice(gesturesizeStart, gesturesizeStart + 2));
                gesturetext = clientPacket.slice(gesturesizeStart + 2, gesturesizeStart + 2 + gesturesize);
                sIDStart = gesturesizeStart + 2 + gesturesize; // sID starts after gesture data
            } else {
                // No gesture
                sIDStart = attachmentsizeStart + 4;
            }

            let tID = AsciiString(clientPacket.slice(clientPacket.length - 4));
            console.log(`${now_at()} ${user.username} DM->${tID} ${messagesize}`);

            let findBuddy = users.findIndex(u => AsciiString(u.getServerIDBytes()) === tID);
            if (findBuddy >= 0) { 
                const response = Buffer.concat([
                    Buffer.from([0, 5, 0]),       // Fixed header
                    users[findBuddy].getServerIDBytes(),
                    TBL(messagetext),
                    clientPacket.slice(attachmentsizeStart, sIDStart),
                    user.getServerIDBytes(),
                    Buffer.from([1, 0]),
                    TBL(user.username),
                    Buffer.from([2, 255, 255, 255, 255, 0, 0])
                ]);
                sendOut(users[findBuddy], response); 
            }
            break;
    }
}

module.exports = { handleDM };