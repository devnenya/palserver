// user.js
const { assignServerID } = require('./idGenerator');
const { now_at, TBL, AsciiString } = require('./utils');

const PAL_STATUS_ONLINE = Buffer.from([1]);
const PAL_STATUS_OFFLINE = Buffer.from([0]);
const PAL_STATUS_AWAY = Buffer.from([2]);

class User {
    constructor(connection, ip) {
        this.serverID = assignServerID();
        this.logged = false;
        this.username = '';
        this.password = '';
        this.avatarData = Buffer.alloc(0);
        this.idName = '';
        this.idLocation = '';
        this.idEmail = '';
        this.rooms = new Set();
        this.status = PAL_STATUS_OFFLINE;
        this.buddyList = [];
        this.connection = connection;
        this.sByte = 129;
        this.ip = ip;
        this.buffer = Buffer.alloc(0);
    }

    // Add a buddy to the buddy list
    addBuddy(buddy) {
        if (!this.buddyList.includes(buddy)) {
            this.buddyList.push(buddy);
        } else {
            console.log(`${now_at()} ${this.username} Buddy ${buddy} is already listed.`);
        }
    }

    // Remove a buddy from the buddy list
    removeBuddy(buddy) {
        const index = this.buddyList.indexOf(buddy);
        if (index !== -1) {
            this.buddyList.splice(index, 1);
        } else {
            console.log(`${now_at()} ${this.username} Buddy ${buddy} not found in the list.`);
        }
    }

    getServerIDBytes() {
        const buffer = Buffer.alloc(4);
        buffer.writeUInt32BE(this.serverID);
        return buffer;
    }
}

module.exports = User;
