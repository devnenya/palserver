// handlers/locateHandler.js
const { now_at, TBL, twoByteLength, FBL, UTBL, AsciiString } = require('../utils');
const { FAKE_USER_IP, ROOM_TYPE_LOBBY, PAL_USER_TYPE } = require('../constants');
const { sendOut } = require('../protocol');

/**
 * Handles Locate packets.
 * @param {Buffer} clientPacket - The raw packet data from the client.
 * @param {User} user - The user initiating the locate.
 * @param {Array<User>} users - Array of all connected users.
 */
function handleLocate(clientPacket, user, users) {
    let searchTextSize = UTBL(clientPacket.slice(15, 17));
    let searchTextData = Buffer.from(clientPacket.slice(17, 17 + searchTextSize), 'ascii');
    let locate_results = users.filter(u => u.username.toLowerCase().includes(searchTextData.toString().toLowerCase()));
    let returnsize = twoByteLength(locate_results.length);

    let results = Buffer.alloc(0);

    for (const result of locate_results) {
        // Debugging: Check each component before concatenation
        const serverIDBytes = result.getServerIDBytes();
        const usernameBuffer = TBL(result.username);
        const idNameBuffer = TBL(result.idName || '');
        const idLocationBuffer = TBL(result.idLocation || '');
        const idEmailBuffer = TBL(result.idEmail || '');
        const roomURL = TBL("vpbuddy://palenhanced");
        const roomName = TBL("Community Lobby");

        console.log(`${now_at()} Processing user: ${result.username}`);
        console.log(`serverIDBytes: ${AsciiString(serverIDBytes)}`);
        console.log(`usernameBuffer: ${usernameBuffer}`);
        console.log(`idNameBuffer: ${AsciiString(idNameBuffer)}`);
        console.log(`idLocationBuffer: ${AsciiString(idLocationBuffer)}`);
        console.log(`idEmailBuffer: ${AsciiString(idEmailBuffer)}`);
        console.log(`FAKE_USER_IP: ${AsciiString(FAKE_USER_IP)}`);
        console.log(`ROOM_TYPE_LOBBY: ${AsciiString(ROOM_TYPE_LOBBY)}`);
        console.log(`roomURL: ${AsciiString(roomURL)}`);
        console.log(`roomName: ${AsciiString(roomName)}`);

        console.log(`serverIDBytes: ${serverIDBytes.toString('hex')}, type=${typeof serverIDBytes}, length=${serverIDBytes.length}`);
console.log(`usernameBuffer: ${usernameBuffer.toString('hex')}, type=${typeof usernameBuffer}, length=${usernameBuffer.length}`);
console.log(`idNameBuffer: ${idNameBuffer.toString('hex')}, type=${typeof idNameBuffer}, length=${idNameBuffer.length}`);
console.log(`idLocationBuffer: ${idLocationBuffer.toString('hex')}, type=${typeof idLocationBuffer}, length=${idLocationBuffer.length}`);
console.log(`idEmailBuffer: ${idEmailBuffer.toString('hex')}, type=${typeof idEmailBuffer}, length=${idEmailBuffer.length}`);


        // Check for undefined
        if (!serverIDBytes || !usernameBuffer || !idNameBuffer || !idLocationBuffer || !idEmailBuffer) {
            console.error(`${now_at()} Error: Missing data for user ${result.username}. Skipping.`);
            continue; // Skip this user
        }

        // Proceed with concatenation
        results = Buffer.concat([
            results,
            serverIDBytes,
            Buffer.from([1, 0, 1]),
            usernameBuffer,
            PAL_USER_TYPE,
            idNameBuffer,
            idLocationBuffer,
            idEmailBuffer,
            FAKE_USER_IP,
            roomURL,
            roomName,
            ROOM_TYPE_LOBBY,
            Buffer.from([0, 0, 0, 0, 0, 0, 4, 1, 1, 0, 0])
        ]);
    }

    const response = Buffer.concat([
        Buffer.from([0, 10, 0]),
        user.getServerIDBytes(),
        Buffer.from([0, 0, 0, 1]),
        TBL(searchTextData),
        Buffer.from([0, 0]),
        returnsize,
        results
    ]);

    sendOut(user, response);            
}

module.exports = { handleLocate };