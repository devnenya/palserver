// constants.js
const PAL_BOT_ID = Buffer.from([0, 0, 0, 2]);
const VPUSERSERVICE_BOT_ID = Buffer.from([0, 0, 0, 1]);
const PAL_STATUS_ONLINE = Buffer.from([1]);
const PAL_STATUS_OFFLINE = Buffer.from([0]);
const PAL_STATUS_AWAY = Buffer.from([2]);
const PAL_USER_TYPE = Buffer.from([2]);


const SERVER_BOT_ID = new Uint8Array([0, 0, 0, 0]);
const SERVER_BOT_TYPE = new Uint8Array([1, 32]);

const FAKE_USER_IP = Buffer.from([255, 255, 255, 255]);


const ROOM_TYPE_PRIVATE = Buffer.from([8, 32]);
const ROOM_TYPE_REGULAR = Buffer.from([8, 64]);
const ROOM_TYPE_PICKER = Buffer.from([8, 128]);
const ROOM_TYPE_LOBBY = Buffer.from([8, 129]);
const ROOM_TYPE_AUDITORIUM = Buffer.from([8, 130]);

module.exports = {
    PAL_BOT_ID,
    VPUSERSERVICE_BOT_ID,
    PAL_STATUS_ONLINE,
    PAL_STATUS_OFFLINE,
    PAL_STATUS_AWAY,
    PAL_USER_TYPE,
    FAKE_USER_IP,
    ROOM_TYPE_PRIVATE,
    ROOM_TYPE_REGULAR,
    ROOM_TYPE_PICKER,
    ROOM_TYPE_LOBBY,
    ROOM_TYPE_AUDITORIUM,
    SERVER_BOT_ID,
    SERVER_BOT_TYPE
};
