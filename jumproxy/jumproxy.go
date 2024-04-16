package main

import (
	"crypto/aes" // GO ibrary for AES --symmetric key encryption
	"crypto/cipher"
	"crypto/rand"   // Import rand to generate secure random numbers
	"crypto/sha256" // Import SHA-256 for hashing
	"flag"          // popular go library for flag implements command-line flag parsing
	"fmt"           // popular go library for formatted I/O operations
	"io"            // popular go library for io for basic input/output operations
	"io/ioutil"     // popular go library forfor simple I/O utility functions
	"log"           // popular go library for for logging messages in a standardized format
	"net"           // popular go library forfor a portable interface for network I/O, including TCP/IP, UDP, domain name resolution, and Unix domain sockets
	"os"            // popular go library for a platform-independent interface to operating system functionality
	"time" 			// popular go library for time operations

	"golang.org/x/crypto/pbkdf2" // Import pbkdf2 for key derivation
)

// Constants for encryption settings
const (
	salt                 = "thiswastoughtofinishandtest" // I used a random string
	keyLength            = 32             // it is the standard key length for AES-256
	iterations           = 4096           // Number of iterations for key derivation function
	expandableBufferSize = 65536          // to cater to maximum 64kb of data that flows through ssh connection
)

var (
	// AppLogger (named logger) is the application's logger instance
	logger *log.Logger
)

func setLog(f *os.File) {
	// Initialize the AppLogger

	logger = log.New(f, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	logger.SetPrefix("JP::")
	logger.Println("This is a test log entry")
}

// Global variables to parse command line arguments
var (
	listenPort  = flag.String("l", "", "Port to listen on. If not specified, run in client mode.")
	pwdFile     = flag.String("k", "", "File containing the ASCII passphrase.")
	destination = flag.String("d", "", "Destination host:port")
)

// main initializes the application, parses flags, and decides the mode of operation (server or client).
func main() {
	flag.Parse() // Parse command-line flags
	// Check if mandatory flags are missing
	if *pwdFile == "" || *destination == "" {
		fmt.Println("Jumproxy Usage: jumproxy -k pwdfile [-l listenport] destination:port")
		os.Exit(1)
	}
	logFileName := "log-" + time.Now().Format("2006-01-02_15-04-05")
	f, err := os.OpenFile(logFileName, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()
	setLog(f)
	logger.Println(*pwdFile)

	// Read the passphraseFromFile from the file specified in the flag
	passphraseFromFile, err := ioutil.ReadFile(*pwdFile)
	if err != nil {
		logger.Fatalf("Failed to read passphrase file: %v", err)
	}

	// here we get the cryptographic key using PBKDF2 with SHA-256
	key := deriveKey(passphraseFromFile, []byte(salt), iterations, keyLength)

	// the programs runs in Server mode if a listen port is specified
	if *listenPort != "" {
		listener, err := net.Listen("tcp", ":"+*listenPort)
		if err != nil {
			logger.Fatalf("Failed to listen on port %s: %v", *listenPort, err)
		}
		defer listener.Close()
		logger.Printf("Jumproxy server running on port %s", *listenPort)

		// As a servr it accept connections in an infinite loop
		for {
			conn, err := listener.Accept()
			if err != nil {
				logger.Printf("Failed to accept connection: %v", err)
				continue
			}

			go acceptServerConnections(conn, *destination, key)
		}
	} else {
		// In Client mode: we either connect to the destination which is (jumproxy server)
		//	and handle I/O on stdin and stdout
		handleClientConnections(*destination, os.Stdin, os.Stdout, key)
	}
}

func deriveKey(password, salt []byte, iterations, keyLength int) []byte {
	return pbkdf2.Key(password, salt, iterations, keyLength, sha256.New)
}

// Here we Handle each connection in a new goroutine
// acceptServerConnections manages the setup of secure encrypted tunnels between the client and the destination.
func acceptServerConnections(conn net.Conn, dest string, key []byte) {
	defer conn.Close() // To ensure that the connection is closed on function exit. This is done to prevent connection leakages in go.

	// Dial the destination servicein our case it is SSH service
	destConn, err := net.Dial("tcp", dest)
	if err != nil {
		logger.Printf("Failed to connect to destination %s: %v", dest, err)
		return
	}
	defer destConn.Close()

	// In this the jumproxy server decrypts the data and forwards it to the localhost ssh server
	go modifyConnectionData(conn, destConn, key, false) // This is the request case which handles  decryption:

	// In this the jumproxy server receivers the data from localhost ssh server and forwards it to the jumproxy client
	modifyConnectionData(destConn, conn, key, true) // This is the request case which handles  encryption:
}

// modifyConnectionData handles the encryption or decryption of data streams between the source and destination endpoints.
// We simply pass the connection writer of both connections after analysing which way we need to pass the traffic.
func modifyConnectionData(sourceConnectionWriter io.Reader, dstConnectionWriter io.Writer, pbkdKey []byte, toEncrypt bool) {

	// Step 1: a new cipher block from the key
	block, err := aes.NewCipher(pbkdKey)
	if err != nil {
		logger.Fatalf("Failed to create cipher: %v", err)
	}

	// Step 2:  a Galois Counter Mode (GCM) cipher mode of operation
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		logger.Fatalf("Failed to create GCM: %v", err)
	}

	// step 3:  here we create a nonce with a size dependent on the GCM cipher mode
	nonce := make([]byte, gcm.NonceSize())

	// Step 4: CHOOSE TO ENCRYPT OR DECRYPT
	/* Encryption case**/
	if toEncrypt {

		// rand.read generate a random nonce basedon default Reader and is based on io.util
		if _, err := rand.Read(nonce); err != nil {
			logger.Fatalf("Failed to generate nonce: %v", err)
		}
		// A major trick we are using is sending the nonce immediately after gereating  which is why we write the nonce to the destination
		// This is used for decryption
		if _, err := dstConnectionWriter.Write(nonce); err != nil {
			logger.Fatalf("Failed to write nonce: %v", err)
		}
	} else {
		/* Decryption case**/
		// Here we read the nonce from the source connection ( based on the use case it will vary
		//e.g for client it will be from jumproxy server and from server it will be from client) before decryption

		if _, err := io.ReadFull(sourceConnectionWriter, nonce); err != nil {
			logger.Fatalf("Failed to read nonce: %v", err)
			return
		}
	}

	// Main dataBuffer for reading data
	dataBuffer := make([]byte, expandableBufferSize)
	for {
		actualDataLength, err := sourceConnectionWriter.Read(dataBuffer)
		if err != nil {
			if err != io.EOF {
				logger.Printf("Read error: %v", err)
			}
			break
		}

		var datatoSend []byte
		/* Encryption case**/
		if toEncrypt {
			// Encrypt the data with the GCM mode, using the nonce
			datatoSend = gcm.Seal(nil, nonce, dataBuffer[:actualDataLength], nil)
		} else {
			/* Decryption case**/
			// Decrypt the data with the GCM mode, using the nonce
			datatoSend, err = gcm.Open(nil, nonce, dataBuffer[:actualDataLength], nil)
			if err != nil {
				logger.Printf("Decryption error: %v", err)
				continue
			}
		}

		// Write the (encrypted or decrypted) data
		if _, err := dstConnectionWriter.Write(datatoSend); err != nil {
			logger.Printf("Write error: %v", err)
			break
		}
	}
}

// handleClientConnections establishes a connection to the destination and sets up data transfer paths for secure communication.
func handleClientConnections(destinationString string, inputReader io.Reader, outputWriter io.Writer, pbkdKey []byte) {
	// Connect to the destination
	clientConnection, err := net.Dial("tcp", destinationString)
	if err != nil {
		logger.Fatalf("Failed to connect to %s: %v", destinationString, err)
	}
	defer clientConnection.Close()

	// Set up proxying of data: encrypting data sent to the destination, decrypting received data
	// for the client theporcessing is slightly different as it  need to forward data to the jumproxy server and sshclient

	// In this case we forward data from jumproxy server connection and receive it ,decrypt ity and forward it to ssh client for stdout
	go modifyConnectionData(clientConnection, outputWriter, pbkdKey, false)

	// In this case we forward data from  stdin from ssh client ,encrypt it and forward it to to jumproxy server connection
	modifyConnectionData(inputReader, clientConnection, pbkdKey, true)
}
