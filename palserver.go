package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type User struct {
	ServerID   uint32
	Logged     bool
	Username   string
	Password   string
	AvatarData []byte // Binary data of the avatar image
	IDName     string
	IDLocation string
	IDEmail    string
	Status     string
	BuddyList  []string // Array of buddylist names
	Connection net.Conn // The user’s active connection
	SByte      byte     // User-specific starting byte
	IP         string
}

const (
	HeartbeatByte = 128
)

var (
	users          []User
	nextID         uint32     = 1 // Start with ServerID 0x00000001
	usersLock      sync.Mutex     // Protect access to the `users` slice and `nextID`
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

func addUser(user User) {
	usersLock.Lock()
	defer usersLock.Unlock()

	users = append(users, user)
}

func removeUser(user User) {
	usersLock.Lock()
	defer usersLock.Unlock()

	for i, u := range users {
		if u.ServerID == user.ServerID {
			users = append(users[:i], users[i+1:]...)
			log.Printf("User %08x removed\n", user.ServerID)
			return
		}
	}
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

	// Assign a unique ServerID
	serverID := assignServerID()

	// Create a new user and add it to the users array
	user := User{
		ServerID:   serverID,
		Logged:     false,
		Connection: conn,
		IP:         ipString,
		SByte:      129,
	}

	// Add the user to the slice
	addUser(user)

	log.Printf("New user connected: ServerID %08x\n", user.ServerID)

	sendOut(&user, ipString)

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
		user.Connection.Write([]byte("Heartbeat ACK"))
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
			// We just got the version packet
			sendOut(user, string(VpString("0 0 0"))) // Convert byte slice to string
			break
		case 130:
			//SERVER: 131 0 0 0 44 0 12 0 0 0 0 0 120 158 0 14 112 114 105 110 99 101 115 115 64 98 117 100 100 121 1 2 0 0 0 1 0 0 0 3 0 0 0 2 0 0 0 0 0
			if len(packetData) < 5 {
				log.Println("Error: Packet too short to contain valid data.")
				return
			}

			// Skipping the fixed part (0 11 0 0 0)
			fixedPart := packetData[:5]
			fmt.Println("Fixed part:", fixedPart) // For debugging

			// Extract the username (after the fixed part)
			// The length of the username is encoded using TBL format
			usernameLength := UTBL(packetData[5:7]) // Extract the username length from the next 2 bytes
			if len(packetData) < 7+usernameLength {
				log.Println("Error: Packet too short to contain username.")
				return
			}
			username := string(packetData[7 : 7+usernameLength])
			fmt.Println("Username:", username) // For debugging

			// Extract the password (after the username)
			passwordLength := UTBL(packetData[9+usernameLength : 11+usernameLength]) // Extract the password length

			password := string(packetData[11+usernameLength : 13+usernameLength+passwordLength])
			fmt.Println("Password:", password) // For debugging

			// Now, set the user’s credentials
			user.Username = username
			user.Password = password

			part1 := VpString("0 12 0 0 0")
			part2 := string(user.ServerID)
			part3 := TBL(user.Username)
			part4 := VpString("1 2 0 0 0 1 0 0 0 3 0 0 0 2 0 0 0 0 0")

			packet := append(part1, part2...)
			packet = append(packet, part3...)
			packet = append(packet, part4...)
			sendOut(user, string(packet))
			break
		case 132:
			//0 15 0 0 0 0 0 113 68 0 0 0 1 0 17 118 112 98 117 100 100 121 58 47 47 104 97 108 115 111 102 116 0 1 0 0 0
			//0 15 0 0 1 0 0 113 68 0 3 0 0 0 38 8 128 0 17 118 112 98 117 100 100 121 58 47 47 104 97 108 115 111 102 116 1 1 0 0 0 40 0 0 0 39 0 0 0 0 0 0 0 0 0 50 0 0 0 0 0 0 0 0 0
			fmt.Println("Processing 131")
			urlLength := UTBL(packetData[13:15])
			urlBytes := packetData[15 : 15+urlLength]

			fmt.Println("URL:", string(urlBytes)) // For debugging

			part1 := VpString("0 15 0 0 1")
			part2 := string(user.ServerID)
			part3 := VpString("0 3 0 0 0 38 8 128")
			part4 := string(urlBytes)
			part5 := VpString("1 1 0 0 0 40 0 0 0 39 0 0 0 0 0 0 0 0 0 50 0 0 0 0 0 0 0 0 0")

			packet := append(part1, part2...)
			packet = append(packet, part3...)
			packet = append(packet, part4...)
			packet = append(packet, part5...)

			sendOut(user, string(packet))
			user.Logged = true
			break

		}
	}
	switch packetData[1] {
	case 28:
		fmt.Println("Got it!")
		break
	}
}

// Function to send data to a user (equivalent to SendOut in JavaScript)
func sendOut(user *User, data string) {
	if user.Connection == nil {
		log.Println("User is not connected, unable to send data.")
		return
	}

	// Convert the data into the proper format (FBL equivalent)
	dataBuffer := FBL(data) // FBL returns a buffer for the data

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

// Convert a 2-byte buffer to an integer (similar to JS's UTBL)
func UTBL(buffer []byte) int {
	if len(buffer) != 2 {
		fmt.Println("UTBL expects a 2-byte buffer.")
		return 0
	}
	return int(buffer[0])<<8 | int(buffer[1])
}

// Convert a string to a 4-byte length + string buffer (similar to JS's FBL)
func FBL(theString string) []byte {
	lengthBuffer := fourByteLength(len(theString))
	stringBuffer := []byte(theString) // ASCII encoding by default in Go
	return append(lengthBuffer, stringBuffer...)
}

// Convert a string to a 2-byte length + string buffer (similar to JS's TBL)
func TBL(theString string) []byte {
	lengthBuffer := twoByteLength(len(theString))
	stringBuffer := []byte(theString) // ASCII encoding by default in Go
	return append(lengthBuffer, stringBuffer...)
}

// Convert a uint packet size to a 4-byte array (similar to JS's fourByteLength)
func fourByteLength(uintPacketSize int) []byte {
	return []byte{
		byte(uintPacketSize >> 24), // highest byte
		byte(uintPacketSize >> 16), // second highest byte
		byte(uintPacketSize >> 8),  // second lowest byte
		byte(uintPacketSize),       // lowest byte
	}
}

// Convert a uint packet size to a 2-byte array (similar to JS's twoByteLength)
func twoByteLength(uintPacketSize int) []byte {
	if uintPacketSize > 65535 {
		panic("Packet length cannot exceed 65,535 bytes.")
	}
	return []byte{
		byte(uintPacketSize >> 8), // high byte
		byte(uintPacketSize),      // low byte
	}
}

// Split a space-separated string into an array of integers and convert it to a byte slice (similar to JS's VpString)
func VpString(theString string) []byte {
	parts := strings.Split(theString, " ")
	byteArray := make([]byte, len(parts))
	for i, part := range parts {
		num, err := strconv.Atoi(part)
		if err != nil {
			fmt.Println("Error converting string to integer:", err)
			return nil
		}
		byteArray[i] = byte(num)
	}
	return byteArray
}

// Convert a byte array to a space-separated ASCII string (similar to JS's AsciiString)
func AsciiString(byteArray []byte) string {
	str := ""
	for _, b := range byteArray {
		str += fmt.Sprintf("%d ", b)
	}
	return str[:len(str)-1] // Trim the last space
}
