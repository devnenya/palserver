// main.js
// PAL Server
const VERSION = '0.8.0';
// December 12, 2024
// catielovexo@gmail.com

console.log(`Welcome to PAL Server ${VERSION}`);
console.log('');

const path = require('path');
const fs = require('fs');
const net = require('net');
const http = require('http');
const Room = require('./room');
const User = require('./user');
const { sendOut } = require('./protocol');
const { now_at, AsciiString, FBL, TBL, UFBL, UTBL, twoByteLength, fourByteLength } = require('./utils');
const { assignServerID } = require('./idGenerator');
const { 
    PAL_BOT_ID, 
    VPUSERSERVICE_BOT_ID, 
    PAL_STATUS_ONLINE, 
    PAL_STATUS_OFFLINE, 
    PAL_STATUS_AWAY, 
    FAKE_USER_IP, 
    ROOM_TYPE_LOBBY,
    SERVER_BOT_ID,
    SERVER_BOT_TYPE
} = require('./constants');

// Import handler modules
const dmHandler = require('./handlers/dmHandler');
const locateHandler = require('./handlers/locateHandler');
const buddyHandler = require('./handlers/buddyHandler');
const roomHandler = require('./handlers/roomHandler');

const rooms = new Map(); // Key: roomURL, Value: Room instance
const dbPath = path.join(process.cwd(), 'database.json');

// Initialize or load the database
let db = { users: [] };

if (fs.existsSync(dbPath)) {
    try {
        const rawData = fs.readFileSync(dbPath, 'utf8');
        db = JSON.parse(rawData);
        console.log(`${now_at()} Database loaded successfully.`);
    } catch (err) {
        console.error(`${now_at()} Error reading database:`, err.message);
    }
} else {
    console.log(`${now_at()} Database file not found. Creating a new one.`);
    fs.writeFileSync(dbPath, JSON.stringify(db, null, 2), 'utf8');
}

// Function to save the database to file
function saveDatabase() {
    try {
        fs.writeFileSync(dbPath, JSON.stringify(db, null, 2), 'utf8');
    } catch (err) {
        console.error(`${now_at()} Error saving database:`, err.message);
    }
}

// Function to register a user
function registerUser(username, password) {
    if (db.users.find((user) => user.username === username)) {
        console.error(`${now_at()} User ${username} already exists.`);
        return false;
    }

    const newUser = {
        id: db.users.length > 0 ? db.users[db.users.length - 1].id + 1 : 1,
        username,
        password,
    };

    db.users.push(newUser);
    saveDatabase();
    console.log(`${now_at()} User ${username} registered successfully.`);
    return true;
}

// Function to validate a user
function validateUser(username, password) {
    const user = db.users.find((user) => user.username === username);

    if (!user) {
        console.log(`${now_at()} User ${username} not found. Registering.`);
        registerUser(username, password);
        return true;
    }

    if (user.password !== password) {
        console.error(`${now_at()} Password mismatch for user ${username}.`);
        return false;
    }

    console.log(`${now_at()} User ${username} validated successfully.`);
    return true;
}

const users = [];
const serverStartTime = Date.now();

// HTTP API Gateway
const httpServer = http.createServer((req, res) => {
    if (req.method === 'GET' && req.url === '/stats') {
        const onlineUsers = users.length;
        const currentTime = Date.now();
        const uptimeMillis = currentTime - serverStartTime;

        // Convert uptime to a readable format (hours, minutes, seconds)
        const uptimeSeconds = Math.floor(uptimeMillis / 1000);
        const hours = Math.floor(uptimeSeconds / 3600);
        const minutes = Math.floor((uptimeSeconds % 3600) / 60);
        const seconds = uptimeSeconds % 60;

        const response = {
            timestamp: new Date().toISOString(),
            onlineUsers: onlineUsers,
            uptime: `${hours}h ${minutes}m ${seconds}s`
        };

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(response));
    } else {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not Found');
    }
});

httpServer.listen(8080, () => {
    console.log(`${now_at()} HTTP API Gateway listening on port 8080`);
});

// Protocol Constants (moved to constants.js)
const SERVER_PARAM_COUNT = Buffer.from([0, 3]); // 3 Params required for minimum PAL Compatibility
const SERVER_PARAM = Buffer.from([3, 251]);
const SERVER_TITLE = TBL('palserver');
const SERVER_TITLE_PARAM = Buffer.from([3, 232]);
const REGISTRATION_PAGE = TBL('http://pal.nenya.dev:81/');
const REGISTRATION_PAGE_PARAM = Buffer.from([3, 233]);

const NEW_LOGIN_RESPONSE = Buffer.from([223]);
const INVALID_LOGIN_RESPONSE = Buffer.from([235]);

const PAL_USER_TYPE = Buffer.from([2]);

const PACKET_MAIN_DM = 5;
const PACKET_MAIN_LOCATE = 10;
const PACKET_MAIN_BUDDY = 28;
const PACKET_MAIN_ROOM = 15;
const PAL_TYPE_ADD = 65;
const PAL_TYPE_REMOVE = 82;
const PAL_TYPE_LIST = 83;

const SERVER_BOT_COUNT = Buffer.from([0, 3]); // 3 Bots required for minimum PAL Compatibility
const VPUSERSERVICE_BOT_TYPE = Buffer.from([1, 33]);
const PAL_BOT_TYPE = Buffer.from([1, 71]);

// Function to add a user to the users array
const addUser = (user) => users.push(user);

// Function to remove a user from the users array and all rooms
const removeUser = (user) => {
    user.connection.destroy();
    const index = users.findIndex(u => u.serverID === user.serverID);
    if (index >= 0) {
        users.splice(index, 1);
        console.log(`${now_at()} ${user.serverID} User removed.`);
    }

    // Remove user from all rooms
    user.rooms.forEach(room => {
        room.removeUser(user);
        // Optionally, delete the room if it's empty
        if (room.currentSize === 0) {
            rooms.delete(room.roomURL);
            console.log(`${now_at()} Deleted empty room: ${room.roomTitle}`);
        }
    });
};

// Function to find users with a specific buddy
function findUsersWithBuddy(buddy) {
    const usersWithBuddy = [];

    // Loop through all users in the users array
    users.forEach(user => {
        // Check if the buddyName is in the user's buddyList
        if (user.buddyList.includes(buddy.username)) {
            usersWithBuddy.push(user);
        }
    });

    return usersWithBuddy;
}

// Function to find user index by name
function findUserByName(username) {
    return users.findIndex(u => u.username.toLowerCase() === username.toString().toLowerCase());
}

// Function to find users by search string
function findUsersByString(searchString) {
    if (!searchString) return []; // Return an empty array for invalid input
    return users.filter(u =>
        u.username.toLowerCase().includes(searchString.toString().toLowerCase())
    );
}

// Function to find user index by ID
function findUserByID(ID) {
    return users.findIndex(u => AsciiString(u.getServerIDBytes()) === ID);
}

// Function to convert IP to bytes
const ipToBytes = (ip) => {
    console.log("Input IP:", ip);

    // Check if it's an IPv4-mapped IPv6 address
    if (ip.startsWith("::ffff:")) {
        ip = ip.slice(7); // Extract the IPv4 part after "::ffff:"
    }

    const parts = ip.split('.').map(Number);

    // Validate the IP format and range
    if (parts.length !== 4 || parts.some(part => part < 0 || part > 255)) {
        throw new Error('Invalid IPv4 address');
    }

    return Buffer.from(parts);
};

// Function to join a room
function joinRoom(user, roomURL, roomTitle, maxSize = 100) {
    let room;
    if (rooms.has(roomURL)) {
        room = rooms.get(roomURL);
        if (!room.addUser(user)) {
            console.log(`${now_at()} ${user.username} could not join room ${room.roomTitle} as it is full.`);
            return false;
        }
    } else {
        room = new Room(roomURL, roomTitle, maxSize);
        room.addUser(user);
        rooms.set(roomURL, room);
        console.log(`${now_at()} Created and joined new room: ${room.roomTitle} with URL: ${roomURL}`);
    }
    user.rooms.add(room);
    return true;
}

// Function to leave a room
function leaveRoom(user, roomURL) {
    if (rooms.has(roomURL)) {
        const room = rooms.get(roomURL);
        room.removeUser(user);
        user.rooms.delete(room);
        if (room.currentSize === 0) {
            rooms.delete(roomURL);
            console.log(`${now_at()} Deleted empty room: ${room.roomTitle}`);
        }
    } else {
        console.log(`${now_at()} ${user.username} tried to leave non-existent room with URL: ${roomURL}`);
    }
}

// Function to broadcast data to a specific room
function broadcastToRoom(roomURL, data) {
    const room = rooms.get(roomURL);
    if (room) {
        room.broadcast(data);
        console.log(`${now_at()} Broadcasted data to room ${room.roomTitle}.`);
    } else {
        console.log(`${now_at()} Room with URL ${roomURL} does not exist.`);
    }
}

// Function to get all users in a specific room
function getUsersInRoom(roomURL) {
    const room = rooms.get(roomURL);
    if (room) {
        return room.getUserList();
    }
    return [];
}

const startServer = async () => {
    try {
        console.log(`${now_at()} Server started on port 1533`);

        const server = net.createServer(handleConnection);
        server.listen(1533);
    } catch (err) {
        console.error(`${now_at()} Error starting server:`, err);
    }
};

const handleConnection = (socket) => {
    const remoteAddr = socket.remoteAddress;
    const ipBytes = ipToBytes(remoteAddr);
    const user = new User(socket, ipBytes);
    addUser(user);

    console.log(`${now_at()} ${user.serverID} New user connected`);
    sendOut(user, Buffer.from(ipBytes, 'ascii'));

    socket.on('data', (data) => {
        try {
            // Append received data to the user's buffer
            appendBuffer(user, data);
        } catch (error) {
            console.error(`${now_at()} ${user.serverID} Error while processing data from client: ${error.message}`);
            user.connection.destroy();
            removeUser(user);
        }
    });

    socket.on('close', () => {
        console.log(`${now_at()} ${user.serverID} User disconnected`);
        user.status = PAL_STATUS_OFFLINE;
        broadcast_status(user);
        removeUser(user);
    });

    socket.on('error', (err) => console.error(`${now_at()} ${user.serverID} CONN-Error-> `, err));
};

function appendBuffer(user, data) {
    try {
        user.buffer = Buffer.concat([user.buffer, data]); // Append new data
        handleData(user); // Process any complete packets
    } catch (error) {
        console.error(`${now_at()} ${user.username} Error in appendBuffer-> ${error}`);
    }
}

function handleData(user) {
    try {
        // Check for any control signals or immediate responses
        if (user.buffer.length > 0 && user.buffer[0] === 128) {
            console.log(`${now_at()} ${user.username} HEARTBEAT received`);
            user.buffer = user.buffer.slice(1); // Remove processed control byte
        }

        // Process complete packets
        while (user.buffer.length >= 5) { // Minimum header size
            // Extract packet length from the buffer
            const packetLength = UFBL(user.buffer.slice(1, 5)); // Your length extraction logic
            if (isNaN(packetLength) || packetLength < 0) {
                throw new Error(`${now_at()} ${user.username} Invalid packet length: ${packetLength}`);
            }

            // Check if the full packet is available in the buffer
            if (user.buffer.length < packetLength + 5) {
                console.log(`${now_at()} ${user.username} Incomplete packet, waiting for more data, expected ${packetLength} received: ${user.buffer.length}`);
                console.log(`${now_at()} ${user.username} DEBUG ${AsciiString(user.buffer)}`);
                break; // Wait for the next chunk of data
            }

            // Extract and process the complete packet
            const packetData = user.buffer.slice(5, 5 + packetLength);
            processPacket(user.buffer[0], packetData, user, users, findUserByID, sendOut); // Pass necessary functions and data

            // Remove processed packet from the buffer
            user.buffer = user.buffer.slice(5 + packetLength);
        }
    } catch (error) {
        console.error(`${now_at()} ${user.serverID} Error in handleData:`, error);
        user.connection.destroy(); // Optionally terminate connection for critical errors
    }
}

function broadcast_status(user) {
    const usersWithBuddy = findUsersWithBuddy(user);
    console.log(`${now_at()} Looking for ${user.username} buddylist users.`);
    const buddyID = user.getServerIDBytes();

    usersWithBuddy.forEach(tempuser => {
        console.log(`Sending update for ${user.username} to ${tempuser.username}`);

        const tempUserID = tempuser.getServerIDBytes();
        const response = Buffer.concat([
            Buffer.from([0, 29, 0]),       // Fixed header
            tempUserID,                    // User ID (Buffer)
            Buffer.from([0, 0, 10, 114, 48, 111, 0, 0, 0, 0]),
            TBL(Buffer.concat([
                user.status, 
                TBL(user.username),
                buddyID
            ])),
            PAL_BOT_ID
        ]);
        sendOut(tempuser, response); 
    });
}


function processPacket(sByte, clientPacket, user, users, findUserByID, sendOutFunc) {
    let response = Buffer.alloc(0);
    const userID = user.getServerIDBytes();

    console.log(`${now_at()} ${user.username} DEBUG IN ${sByte}: ${AsciiString(clientPacket)}`);
    if (!user.logged) {
        switch (sByte) {
            case 129:
                response = Buffer.concat([
                    Buffer.from([0, 0, 0, 0, 3, 0, 1]),
                    SERVER_BOT_COUNT,
                    SERVER_BOT_ID,
                    SERVER_BOT_TYPE,
                    Buffer.from([0, 0, 0, 7]),
                    FAKE_USER_IP,
                    VPUSERSERVICE_BOT_ID,
                    VPUSERSERVICE_BOT_TYPE,
                    Buffer.from([0, 0, 0, 1]),
                    FAKE_USER_IP,
                    PAL_BOT_ID,
                    PAL_BOT_TYPE,
                    Buffer.from([0, 0, 0, 0]),
                    FAKE_USER_IP,
                    SERVER_PARAM_COUNT,
                    Buffer.from([5]),
                    SERVER_PARAM,
                    Buffer.from([0, 0]),
                    SERVER_TITLE_PARAM,
                    SERVER_TITLE,
                    Buffer.from([0]),
                    REGISTRATION_PAGE_PARAM,
                    REGISTRATION_PAGE,
                    Buffer.from([0, 0, 0, 0]),
                ]);
                sendOutFunc(user, response);
                break;

            case 130:
                if (clientPacket.length < 5) {
                    console.log("Error: Packet too short to contain valid data.");
                    return;
                }

                const usernameLength = UTBL(clientPacket.slice(5, 7));
                if (clientPacket.length < 7 + usernameLength) {
                    console.log(`${now_at()} ${user.serverID} Error: Packet too short to contain username.`);
                    return;
                }
                const username = clientPacket.slice(7, 7 + usernameLength).toString('utf-8');
                console.log(`${now_at()} ${user.serverID} Username-> ${username}`); // For debugging

                const passwordLength = UTBL(clientPacket.slice(14 + usernameLength, 16 + usernameLength));
                if (clientPacket.length < 10 + usernameLength + passwordLength) {
                    console.log("Error: Packet too short to contain password.");
                    return;
                }
                const password = clientPacket.slice(16 + usernameLength, 18 + usernameLength + passwordLength).toString('utf-8');
                console.log(`${now_at()} ${username} Password-> ${passwordLength}`); // For debugging

                if (validateUser(username, password) === false) {
                    response = Buffer.concat([
                        Buffer.from([0, 14]),
                        user.getServerIDBytes(),
                        Buffer.from([0, 0, 0, 0]),
                        INVALID_LOGIN_RESPONSE
                    ]);

                    sendOutFunc(user, response);
                    removeUser(user);
                    return;
                }

                const checkExistingLogin = findUserByName(username);
                if (checkExistingLogin >= 0) { 
                    // Disconnect existing user.
                    response = Buffer.concat([
                        Buffer.from([0, 14]),
                        user.getServerIDBytes(),
                        Buffer.from([0, 0, 0, 0]),
                        NEW_LOGIN_RESPONSE
                    ]);

                    sendOutFunc(users[checkExistingLogin], response);
                    removeUser(users[checkExistingLogin]);
                }

                user.username = username;
                user.password = password;

                const part1 = Buffer.from([0, 12, 0, 0, 0]);
                const part2 = userID;
                const part3 = TBL(user.username);
                const part4 = Buffer.from([1, 2, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, 2, 0, 0, 0, 0, 0]);

                // Combine all parts into a single packet
                response = Buffer.concat([part1, part2, part3, part4]);
                sendOutFunc(user, response);
                break;

            case 132:
                const urlLength = UTBL(clientPacket.slice(13, 15));
                const urlBytes = clientPacket.slice(15, 15 + urlLength);
                const roomURL = urlBytes.toString();
                const roomTitle = `Room for ${roomURL}`; // Customize as needed

                console.log(`${now_at()} ${user.username} NAVIGATE ${urlLength} ${roomURL}`);

                let room;
                if (rooms.has(roomURL)) {
                    room = rooms.get(roomURL);
                    // Check if room is full
                    if (!room.addUser(user)) {
                        // Optionally, send a response to the user that the room is full
                        console.log(`${now_at()} ${user.username} could not join room ${room.roomTitle} as it is full.`);
                        // You might want to disconnect the user or send an error packet
                        return;
                    }
                } else {
                    // Create a new room
                    room = new Room(roomURL, roomTitle, 100); // Set desired max size
                    room.addUser(user);
                    rooms.set(roomURL, room);
                    console.log(`${now_at()} Created and joined new room: ${room.roomTitle} with URL: ${roomURL}`);
                }

                user.rooms.add(room);

                // Construct the first response packet
                response = Buffer.concat([
                    Buffer.from([0, 15, 0, 0, 1]), // Fixed header
                    userID,                        // User ID (Buffer)
                    Buffer.from([0, 3, 0, 0, 0, 38, 8, 128]), // Fixed part
                    TBL(urlBytes),                 // URL bytes with length
                    Buffer.from([
                        1, 1, 0, 0, 0, 40, 0, 0, 0, 39, 0, 0, 0, 0, 0, 0, 0, 0, 0, 50, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    ]),
                ]);
                sendOutFunc(user, response);

                // Construct the second response packet
                response = Buffer.concat([
                    Buffer.from([0, 29, 0]),       // Fixed header
                    userID,                        // User ID (Buffer)
                    Buffer.from([0, 0, 10, 114, 0, 104, 0, 0, 0, 0, 0, 0]),
                    PAL_BOT_ID
                ]);
                sendOutFunc(user, response);

                user.logged = true;
                user.status = PAL_STATUS_ONLINE;

                broadcast_status(user);
                break;                
        }
    } else {
        switch(clientPacket[1]) {
            case PACKET_MAIN_DM: // Handle DMs
                dmHandler.handleDM(clientPacket, user, users, findUserByID, sendOut);
                break;

            case PACKET_MAIN_LOCATE:
                locateHandler.handleLocate(clientPacket, user, users);
                break;

            case PACKET_MAIN_BUDDY:
                buddyHandler.handleBuddy(clientPacket, user, users, findUserByName, sendOut);
                break;

            case PACKET_MAIN_ROOM:
                roomHandler.handleRoom(clientPacket, user, rooms, sendOut, users, findUserByID);
                break;

            default:
                console.log(`${now_at()} Unknown packet type: ${clientPacket[1]}`);
                break;
        }
    }
}

startServer();

module.exports.broadcast_status = broadcast_status;