// handlers/buddyHandler.js
const { now_at, TBL, UTBL, FBL, UFBL, twoByteLength, fourByteLength, AsciiString } = require('../utils');
const { PAL_BOT_ID, VPUSERSERVICE_BOT_ID, PAL_STATUS_ONLINE } = require('../constants');
const { sendOut } = require('../protocol');

/**
 * Handles Buddy-related packets.
 * @param {Buffer} clientPacket - The raw packet data from the client.
 * @param {User} user - The user performing the buddy action.
 * @param {Array<User>} users - Array of all connected users.
 * @param {Function} findUserByName - Function to find a user index by their name.
 */
function handleBuddy(clientPacket, user, users, findUserByName) {
    // Defer the require to prevent circular dependency issues
    const { broadcast_status } = require('../palserver'); // Adjust the path if necessary

    switch (clientPacket[12]) {
        case 65: // PAL_TYPE_ADD
            let buddyNameText = clientPacket.slice(21, clientPacket.length - 4).toString('utf-8');
            console.log(`${now_at()} Buddylist->ADD ${buddyNameText.length} ${buddyNameText}`);
            let buddyIndex = findUserByName(buddyNameText);
            if ((buddyIndex >= 0) && (users[buddyIndex].status.equals(PAL_STATUS_ONLINE))) { 
                let buddyID = users[buddyIndex].getServerIDBytes();
                console.log(`${now_at()} User Online: ${AsciiString(buddyID)} ${buddyNameText}`);

                user.addBuddy(users[buddyIndex].username);

                if (users[buddyIndex].status.equals(PAL_STATUS_ONLINE)) { // Corrected comparison
                    const response = Buffer.concat([
                        Buffer.from([0, 29, 0]),       // Fixed header
                        user.getServerIDBytes(),        // User ID (Buffer)
                        Buffer.from([0, 0, 10, 114, 48, 111, 0, 0, 0, 0]),
                        Buffer.concat([
                            TBL(Buffer.concat([
                                users[buddyIndex].status, // Already a Buffer
                                TBL(users[buddyIndex].username),
                                buddyID
                            ]))
                        ]),
                        PAL_BOT_ID
                    ]);
                    sendOut(user, response); 
                }
            }
            break;

        case 82: // PAL_TYPE_REMOVE
            let buddyNameToRemove = clientPacket.slice(21, clientPacket.length - 4).toString('utf-8');
            user.removeBuddy(buddyNameToRemove);
            console.log(`${now_at()} ${user.username} Buddylist->REMOVE ${buddyNameToRemove.length} ${buddyNameToRemove}`);
            break;

        case 83: // PAL_TYPE_LIST
            const friendCount = UTBL(clientPacket.slice(24, 26));
            console.log(`${now_at()} ${user.username} Buddylist: ${friendCount} friends`);
            let buddyBegin = 26;
            let tempPacket = Buffer.alloc(0);
            let onlineCount = 0;

            for (let i = 0; i < friendCount; i++) {
                const tempBuddyNameSize = UTBL(clientPacket.slice(buddyBegin, buddyBegin + 2));
                buddyBegin += 2;

                const tempBuddyName = clientPacket.slice(buddyBegin, buddyBegin + tempBuddyNameSize).toString('utf-8');
                buddyBegin += tempBuddyNameSize;

                user.addBuddy(tempBuddyName);
                console.log(`${now_at()} ${user.username} Buddylist->INIT ${tempBuddyName}`);

                let findBuddyList = findUserByName(tempBuddyName);
                if (findBuddyList >= 0) { 
                    let buddyIDList = users[findBuddyList].getServerIDBytes();
                    console.log(`${now_at()} Sending User Online for ${AsciiString(buddyIDList)} ${tempBuddyName} to ${AsciiString(user.getServerIDBytes())} ${user.username}`);

                    if (users[findBuddyList].status.equals(PAL_STATUS_ONLINE)) { // Corrected comparison
                        tempPacket = Buffer.concat([tempPacket, TBL(users[findBuddyList].username), buddyIDList]);
                        onlineCount++;
                    }
                }
            }
            const response = Buffer.concat([
                Buffer.from([0, 29, 0]),       // Fixed header
                user.getServerIDBytes(),        // User ID (Buffer)
                VPUSERSERVICE_BOT_ID,
                Buffer.from([48, 117, 0, 0]),
                FBL(Buffer.concat([
                    twoByteLength(onlineCount), // Online count as a 2-byte buffer
                    tempPacket,
                    Buffer.from([0, 0]),
                ])),
                PAL_BOT_ID
            ]);
            sendOut(user, response); 
            break;

        case 86:
            switch (clientPacket[19]) {
                case 1:
                    user.status = Buffer.from([1]); // PAL_STATUS_ONLINE
                    break;
                case 0:
                    user.status = Buffer.from([0]); // PAL_STATUS_OFFLINE
                    break;
                case 2:
                    user.status = Buffer.from([2]); // PAL_STATUS_AWAY
                    break;
                default:
                    console.log(`${now_at()} ${user.username} Unknown type: ${clientPacket[19]}`)
                    break;
            }
            broadcast_status(user, users);
            break;

        default:
            console.log(`${now_at()} ${user.username} Unknown type: ${clientPacket[12]}`);
            break;
    }
}

module.exports = { handleBuddy };
