// room.js
const { assignServerID } = require('./idGenerator');
const { now_at, AsciiString } = require('./utils');
const { sendOut } = require('./protocol');

class Room {
    constructor(roomURL, roomTitle, maxSize) {
        this.roomURL = roomURL;
        this.roomTitle = roomTitle;
        this.roomID_Corridor = assignServerID();
        this.roomID_Observe = assignServerID();
        this.roomID_Room = assignServerID();
        this.maxSize = maxSize;
        this.currentSize = 0;
        this.users = new Set(); // Using a Set to prevent duplicate users
    }

    addUser(user) {
        if (this.currentSize >= this.maxSize) {
            console.log(`${now_at()} Room ${this.roomTitle} is full.`);
            return false;
        }
        this.users.add(user);
        this.currentSize++;
        console.log(`${now_at()} User ${user.username} joined room ${this.roomTitle}.`);
        return true;
    }

    removeUser(user) {
        if (this.users.has(user)) {
            this.users.delete(user);
            this.currentSize--;
            console.log(`${now_at()} User ${user.username} left room ${this.roomTitle}.`);
        }
    }

    broadcast(data) {
        this.users.forEach(user => {
            sendOut(user, data);
        });
    }

    getUserList() {
        return Array.from(this.users);
    }
}

module.exports = Room;
