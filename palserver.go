package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

type Buddy struct {
	Name     string // Buddy's name
	ServerID uint32 // Buddy's server ID
	sID      []byte
	Status   string // Buddy's current status
}

type User struct {
	ServerID   uint32
	sID        []byte
	Logged     bool
	Username   string
	Password   string
	AvatarData []byte // Binary data of the avatar image
	IDName     string
	IDLocation string
	IDEmail    string
	Status     string
	BuddyList  []Buddy
	Connection net.Conn // The user’s active connection
	SByte      byte     // User-specific starting byte
	IP         string
}

const (
	HeartbeatByte = 128
)

var (
	AllUsers       = make(map[string]*User)     // Concurrent-safe map needed
	allUsersLock   sync.Mutex                   // Protects access to AllUsers
	users          []User                       // Tracks currently active users
	usersLock      sync.Mutex                   // Protects access to users slice
	nextID         uint32                   = 1 // Start with ServerID 0x00000001
	serverIPBytes  []byte
	serverIPString string
)

func getPublicIP() (string, error) {
	resp, err := http.Get("https://api.ipify.org?format=text") // You can use other APIs here
	if err != nil {
		return "", fmt.Errorf("failed to get public IP: %w", err)
	}
	defer resp.Body.Close()

	// Read the response body
	ip, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	return string(ip), nil
}

// Main function to start the TCP server
func main() {
	// Listen on TCP port 1533
	listener, err := net.Listen("tcp", ":1533")
	if err != nil {
		log.Fatal("Error starting server: ", err)
	}
	defer listener.Close()

	// Get the public IP
	publicIP, err := getPublicIP()
	if err != nil {
		log.Fatalf("Error fetching public IP: %v", err)
	}

	// Convert the public IP to bytes
	serverIPBytes, err = ipToBytes(net.ParseIP(publicIP))
	if err != nil {
		log.Fatalf("Error converting public IP to bytes: %v", err)
	}

	// Convert the public IP to string for logging and further use
	serverIPString = net.IP(serverIPBytes).String()

	log.Printf("Server started on IP: %s, port 1533", serverIPString)

	// Accept incoming connections
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Error accepting connection: ", err)
			continue
		}

		// Handle the connection in a new goroutine
		go handleConnection(conn)
	}
}

func (u *User) GetServerIDBytes() []byte {
	// Check the ServerID value
	fmt.Printf("ServerID: %d\n", u.ServerID)

	// Create a byte slice to hold the 4 bytes
	serverIDBytes := make([]byte, 4)

	// Convert the ServerID to a 4-byte slice in Big Endian format
	binary.BigEndian.PutUint32(serverIDBytes, u.ServerID)

	// Print the bytes to verify the conversion
	fmt.Printf("ServerID Bytes: %v\n", serverIDBytes)

	// Return the bytes as a string, each byte represented by chr(<byte>)
	result := ""
	for _, b := range serverIDBytes {
		result += fmt.Sprintf("chr(%d) ", b)
	}
	return serverIDBytes
}

func ipToBytes(ip net.IP) ([]byte, error) {
	if ip = ip.To4(); ip == nil {
		return nil, fmt.Errorf("invalid IPv4 address")
	}
	return ip, nil
}

func assignServerID() uint32 {
	usersLock.Lock()
	defer usersLock.Unlock()

	id := nextID
	nextID++
	return id
}

func RegisterUser(user *User) {
	allUsersLock.Lock()
	defer allUsersLock.Unlock()

	AllUsers[user.Username] = user
	fmt.Printf("User '%s' registered in AllUsers.\n", user.Username)
}

func UnregisterUser(username string) {
	allUsersLock.Lock()
	defer allUsersLock.Unlock()

	if _, exists := AllUsers[username]; exists {
		delete(AllUsers, username)
		fmt.Printf("User '%s' removed from AllUsers.\n", username)
	} else {
		fmt.Printf("User '%s' not found in AllUsers.\n", username)
	}
}

func addUser(user User) {
	RegisterUser(&user)

	usersLock.Lock()
	defer usersLock.Unlock()

	users = append(users, user)
	fmt.Printf("User '%s' added to active users. Total users: %d\n", user.Username, len(users))
}

func removeUser(user User) {
	// Unregister globally by username
	UnregisterUser(user.Username)

	// Remove from the session-specific users slice
	usersLock.Lock()
	defer usersLock.Unlock()

	for i, u := range users {
		if u.ServerID == user.ServerID {
			users = append(users[:i], users[i+1:]...)
			fmt.Printf("User '%s' removed from active users.\n", user.Username)
			return
		}
	}
	fmt.Printf("User '%s' not found in active users.\n", user.Username)
}

func UpdateStatus(buddyName, newStatus string) {
	allUsersLock.Lock()
	defer allUsersLock.Unlock()
	for _, user := range AllUsers {
		for i, buddy := range user.BuddyList {
			if buddy.Name == buddyName {
				user.BuddyList[i].Status = newStatus
			}
		}
	}
}

func UpdateServerID(buddyName string, newServerID uint32) {
	allUsersLock.Lock()
	defer allUsersLock.Unlock()
	for _, user := range AllUsers {
		for i, buddy := range user.BuddyList {
			if buddy.Name == buddyName {
				user.BuddyList[i].ServerID = newServerID
			}
		}
	}
}

func (u *User) AddBuddy(buddy Buddy) {
	for _, b := range u.BuddyList {
		if b.Name == buddy.Name {
			return // Buddy already exists
		}
	}
	u.BuddyList = append(u.BuddyList, buddy)
}

func (u *User) RemoveBuddy(buddyName string) {
	for i, b := range u.BuddyList {
		if b.Name == buddyName {
			u.BuddyList = append(u.BuddyList[:i], u.BuddyList[i+1:]...)
			return
		}
	}
}

func (u *User) GetBuddyDataByName(username string) (*User, bool) {
	for i := range users {
		fmt.Println(users[i].Logged)
		if users[i].Username == username {
			return &users[i], true // Return a pointer to avoid copying the struct
		}
	}
	return nil, false // Return nil if not found
}

// Handle each connection
func handleConnection(conn net.Conn) {
	defer func() {
		conn.Close()
	}()

	// Get the IP address of the user (the remote address of the connection)
	remoteAddr := conn.RemoteAddr().String()

	// Extract the IP address from the string (remoteAddr is in the format "ip:port")
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		log.Println("Error extracting IP address: ", err)
		return
	}

	ipBytes, err := ipToBytes(net.ParseIP(ip))
	if err != nil {
		log.Printf("Failed to convert IP: %v\n", err)
		return
	}

	ipString := string(ipBytes)

	// Create a new user and add it to the users array
	user := User{
		ServerID:   assignServerID(),
		Logged:     false,
		Connection: conn,
		IP:         ipString,
		SByte:      129,
	}

	// Add the user to the slice
	addUser(user)

	user.sID = user.GetServerIDBytes()

	log.Printf("New user connected: ServerID %08x\n", user.ServerID)

	sendOut(&user, ipBytes)

	// Buffer to hold incoming data
	buffer := make([]byte, 1024)

	for {
		// Read data from the connection
		n, err := conn.Read(buffer)
		if err != nil {
			log.Printf("User %08x disconnected: %v\n", user.ServerID, err)
			removeUser(user)
			return
		}

		// Process the received data
		handleData(&user, buffer[:n])
	}
}

// Handle the incoming data based on the logic from your JavaScript example
func handleData(user *User, buffer []byte) {
	// Check for heartbeat byte (128)
	if buffer[0] == 128 {
		// Send Heartbeat ACK
		user.Connection.Write([]byte{128})
		if len(buffer) == 1 {
			return
		}
		// Remove the processed byte and continue handling the rest
		buffer = buffer[1:]
	}

	// Check if the length is sufficient to process a packet
	if len(buffer) < 5 {
		return
	}

	// Extract the packet length
	packetLength := UFBL(buffer[1:5])

	// Ensure the buffer contains the complete packet
	if len(buffer) < packetLength+5 {
		return
	}

	// Extract the packet data
	packetData := buffer[5 : packetLength+5]
	fmt.Println("Received:", AsciiString(append([]byte{buffer[0]}, packetData...)))

	// Process the packet (your custom logic)
	processPacket(buffer[0], packetData, user)

	// Handle remaining data in the buffer
	remainingBuffer := buffer[packetLength+5:]
	if len(remainingBuffer) > 0 {
		handleData(user, remainingBuffer) // Continue processing any leftover data
	}
}

func processPacket(sByteIn byte, packetData []byte, user *User) {
	if !user.Logged {
		switch sByteIn {
		case 129:
			//Server Parameters
			part1 := []byte{0, 0, 0, 0, 3, 0, 1, 0, 3}
			part2 := []byte{0, 0, 0, 0, 1, 32, 0, 0, 0, 7, 0, 0, 0, 0}            //Fake Bot 1, VP_SERVER_CORE = 32
			part3 := []byte{0, 0, 0, 4, 1, 33, 0, 0, 0, 1, 255, 255, 255, 255}    //Fake Bot 2, VP_USERS_SERVICE = 33
			part4 := []byte{0, 0, 10, 112, 1, 71, 0, 0, 0, 0, 255, 255, 255, 255} //Fake Bot 3, VP_BUDDY_LIST = 71
			part5 := []byte{0, 3, 5, 3, 251, 0}
			part6 := []byte{0, 3, 232, 0, 7, 79, 112, 101, 110, 80, 65, 76}  //Server Name, OpenPAL
			part7 := []byte{0, 3, 233, 0, 7, 104, 116, 116, 112, 58, 47, 47} //Login URL, there is none, http://
			part8 := []byte{0, 0, 0, 0}

			packet := append(part1, part2...)
			packet = append(packet, part3...)
			packet = append(packet, part4...)
			packet = append(packet, part5...)
			packet = append(packet, part6...)
			packet = append(packet, part7...)
			packet = append(packet, part8...)

			// We just got the version packet
			sendOut(user, packet)
			break
		case 130:
			if len(packetData) < 5 {
				log.Println("Error: Packet too short to contain valid data.")
				return
			}

			// Skipping the fixed part (0 11 0 0 0)
			fixedPart := packetData[:5]
			fmt.Println("Fixed part:", fixedPart) // For debugging

			usernameLength := UTBL(packetData[5:7]) // Extract the username length from the next 2 bytes
			if len(packetData) < 7+usernameLength {
				log.Println("Error: Packet too short to contain username.")
				return
			}
			username := string(packetData[7 : 7+usernameLength])
			user.Username = username

			fmt.Println("Username:", user.Username) // For debugging

			// Extract the password (after the username)
			passwordLength := UTBL(packetData[9+usernameLength : 11+usernameLength]) // Extract the password length

			password := string(packetData[11+usernameLength : 13+usernameLength+passwordLength])
			fmt.Println("Password:", password) // For debugging

			user.Password = password

			part1 := []byte{0, 12, 0, 0, 0}
			part2 := user.GetServerIDBytes()
			part3 := TBL(user.Username)
			part4 := []byte{1, 2, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, 2, 0, 0, 0, 0, 0}

			packet := append(part1, part2...)
			packet = append(packet, part3...)
			packet = append(packet, part4...)
			sendOut(user, packet)
			break
		case 132:
			//User Navigated to Community Lobby
			urlLength := UTBL(packetData[13:15])
			urlBytes := packetData[15 : 15+urlLength]

			fmt.Println("URL:", string(urlBytes)) // For debugging

			part1 := []byte{0, 15, 0, 0, 1} // 0, 1 represent RoomsBeen, the number of times the user navigates, as we do this only once this doesn't need to be saved and iterated
			part2 := user.sID
			part3 := []byte{0, 3, 0, 0, 0, 38, 8, 128} //Room Header Data
			part4 := TBL(string(urlBytes))
			part5 := []byte{1, 1, 0, 0, 0, 40, 0, 0, 0, 39, 0, 0, 0, 0, 0, 0, 0, 0, 0, 50, 0, 0, 0, 0, 0, 0, 0, 0, 0} //Empty Room Data

			// Create the packet by appending each part
			packet := append(part1, part2...) // Directly append the bytes from part2 (ServerID bytes)
			packet = append(packet, part3...)
			packet = append(packet, part4...) // part4 is already a byte slice
			packet = append(packet, part5...)

			// Debug the final packet to ensure ServerID is included
			fmt.Printf("Final Packet: %v\n", packet)

			// Send the packet (directly passing the byte slice)
			sendOut(user, packet)

			newpart1 := []byte{0, 29, 0}
			newpart2 := user.sID
			newpart3 := []byte{0, 0, 10, 114, 0, 104, 0, 0, 0, 0, 0, 0, 0, 0, 10, 112}

			packet2 := append(newpart1, newpart2...)
			packet2 = append(packet2, newpart3...)

			sendOut(user, packet2)
			user.Status = "Online"
			user.Logged = true
			break

		}
	}
	switch packetData[1] {
	case 28:
		//Add Buddy
		//0 28 0 0 0 4 174 0 0 0 0 0 65 0 0 0 0 0 7 0 5 116 105 109 109 121 0 0 10 112

		//Remove Buddy
		//0 28 0 0 0 4 174 0 0 0 0 0 82 0 0 0 0 0 7 0 5 116 105 109 109 121 0 0 10 112

		switch packetData[12] {
		case 65: // Add Budy
			buddyNameText := packetData[20 : len(packetData)-4]
			fmt.Println("User Added:", string(buddyNameText))
			buddy, found := user.GetBuddyDataByName(string(buddyNameText))
			if found {
				fmt.Println("FOUND:", string(buddyNameText))

				user.AddBuddy(Buddy{
					Name:     string(buddyNameText), // Correct field: Name
					ServerID: buddy.ServerID,        // Correct field: ServerID
					sID:      buddy.sID,
					Status:   buddy.Status, // Correct field: Status
				})
				if buddy.Status == "Online" {
					// Byte slices for fixed parts
					part1 := []byte{0, 29, 0}
					part3 := []byte{0, 0, 10, 114, 48, 111, 0, 0, 0, 0, 0, 12, 1}
					part4 := TBL(string(buddyNameText)) // Assuming TBL returns []byte
					part6 := []byte{0, 0, 10, 112}

					// Directly append user.sID and buddy.sID since they are already []byte
					part2 := user.sID
					part5 := buddy.sID

					// Combine all parts into the final packet
					packet := append(part1, part2...)
					packet = append(packet, part3...)
					packet = append(packet, part4...)
					packet = append(packet, part5...)
					packet = append(packet, part6...)

					// Send the packet
					sendOut(user, packet)
				}

			}
			break

		case 82: // Remove Buddy
			buddyNameText := packetData[20 : len(packetData)-4]
			fmt.Printf("User Removed:", buddyNameText)
			break

		case 83: // Buddylist
			break

		}

		fmt.Println("Got it!")
		break
	}
}

// Function to send data to a user (equivalent to SendOut in JavaScript)
func sendOut(user *User, data []byte) {
	if user.Connection == nil {
		log.Println("User is not connected, unable to send data.")
		return
	}

	// Convert the data into the proper format (FBL equivalent)
	dataBuffer := FBL(data) // FBL should accept a byte slice, not a string

	// Combine the user-specific sByte with the data
	sByteBuffer := []byte{user.SByte}
	packet := append(sByteBuffer, dataBuffer...)

	// Try to send the data to the user
	err := sendPacket(user.Connection, packet)
	if err != nil {
		log.Printf("Error during SendOut for user %s: %v", user.Username, err)
	}

	// Increment and reset sByte logic
	if user.SByte == 255 {
		user.SByte = 129
	} else {
		user.SByte = (user.SByte + 1)
	}
}

// Helper function to send packet and handle backpressure (equivalent to the JavaScript version)
func sendPacket(conn net.Conn, packet []byte) error {
	canWrite := make(chan bool)

	// Try to write the packet
	go func() {
		_, err := conn.Write(packet)
		if err != nil {
			log.Println("Error writing packet:", err)
		}
		canWrite <- err == nil
	}()

	// Wait for the result of the write operation
	if success := <-canWrite; !success {
		log.Println("Backpressure detected, waiting for socket to drain...")

		// Wait for the socket to drain and then retry
		conn.(*net.TCPConn).SetWriteDeadline(time.Now().Add(time.Second))
		<-canWrite
		log.Println("Socket drained, resuming sending...")
	}

	log.Printf("Data sent to %s: %s\n", conn.RemoteAddr(), AsciiString(packet))
	return nil
}

// Convert a 4-byte buffer to an integer (similar to JS's UFBL)
func UFBL(buffer []byte) int {
	if len(buffer) != 4 {
		fmt.Println("UFBL expects a 4-byte buffer.")
		return 0
	}
	return int(buffer[0])<<(3*8) | int(buffer[1])<<(2*8) | int(buffer[2])<<8 | int(buffer[3])
}

func UTBL(buffer []byte) int {
	if len(buffer) != 2 {
		fmt.Println("UTBL expects a 2-byte buffer.")
		return 0
	}
	return int(buffer[0])<<8 | int(buffer[1])
}

func FBL(theBytes []byte) []byte {
	lengthBuffer := fourByteLength(len(theBytes)) // Get length of byte array
	return append(lengthBuffer, theBytes...)      // Append the byte array to the length buffer
}

func fourByteLength(uintPacketSize int) []byte {
	return []byte{
		byte(uintPacketSize >> 24), // highest byte
		byte(uintPacketSize >> 16), // second highest byte
		byte(uintPacketSize >> 8),  // second lowest byte
		byte(uintPacketSize),       // lowest byte
	}
}

func TBL(data string) []byte {
	// Get the length of the username
	packetLength := len(data)
	// Get the length buffer (2-byte)
	lengthBuffer := twoByteLength(packetLength)

	// Convert the username string to a byte slice (ASCII encoding by default)
	stringBuffer := []byte(data)

	// Debugging: print the lengthBuffer and stringBuffer
	fmt.Printf("Length Buffer: %v\n", lengthBuffer)
	fmt.Printf("String Buffer: %v\n", stringBuffer)

	// Return the length buffer followed by the string buffer
	return append(lengthBuffer, stringBuffer...)
}

func twoByteLength(uintPacketSize int) []byte {
	if uintPacketSize > 65535 {
		panic("Packet length cannot exceed 65,535 bytes.")
	}
	return []byte{
		byte(uintPacketSize >> 8), // high byte
		byte(uintPacketSize),      // low byte
	}
}

// Convert a byte array to a space-separated ASCII string (similar to JS's AsciiString)
func AsciiString(byteArray []byte) string {
	str := ""
	for _, b := range byteArray {
		str += fmt.Sprintf("%d ", b)
	}
	return str[:len(str)-1] // Trim the last space
}
