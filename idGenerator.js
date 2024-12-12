// idGenerator.js
let nextID = 5; // Start with ServerID 0x00000005

function assignServerID() {
    return nextID++;
}

module.exports = { assignServerID };
