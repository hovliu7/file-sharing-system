package client

// CS 161 Project 2

// Only the following imports are allowed! ANY additional imports
// may break the autograder!
// - bytes
// - encoding/hex
// - encoding/json
// - errors
// - fmt
// - github.com/cs161-staff/project2-userlib
// - github.com/google/uuid
// - strconv
// - strings

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
	Username  string
	Password  string
	RsaDecKey userlib.PKEDecKey // private RSA key for decryption
	SignKey   userlib.DSSignKey // private RSA key for signing
	SymKey    []byte            // symmetric key to encrypt/decrypt fileAccess structs
}

// Gives us access to FileData
// UUID: Generate using filename and receiver's username
// Encryption: Use receiver's symmetric key
// Note: this struct is needed because it's inefficient for a receiver to keep accessing an invitation struct. They would need to store the sender's UUID to access public signing key.
// For a receiver, this struct is stored in Datastore
type FileAccess struct {
	FileDataUUID  userlib.UUID // UUID of FileData
	FileDataKey   []byte       // Key to decrypt FileData
	OwnerUsername string       // File owner's username
}

// contains the linked list of FileNodes
type FileNodeContainer struct {
	HeadUUID userlib.UUID // UUID of head FileNode
	HeadKey  []byte       // Key to decrypt head FileNode
	TailUUID userlib.UUID // UUID of tail FileNode
	TailKey  []byte       // Key to decrypt tail FileNode
}

// Gives us access to FileNodes
type FileData struct {
	Filename              string
	FileNodeContainerUUID userlib.UUID // UUID of corresponding FileNodeContainer struct
	FileNodeContainerKey  []byte       // Key of correspondingFileNodeContainer struct
	SharedUserMapUUID     userlib.UUID // UUID of corresponding SharedUserFileMap
	SharedUserMapKey      []byte       // Key of corresponding SharedUserFileMap 
}

// A Map of Owners for a given file 
type SharedUserFileMap struct {
	OwnerMap map[string]Invitation // Map of (RecipientUsername:Invitation), empty if not Owner, used for revocation

}

// Stores file contents
type FileNode struct {
	Contents []byte
	PrevUUID userlib.UUID // UUID of previous FileNode
	PrevKey  []byte       // Key to decrypt previous FileNode
}

// For an owner, this struct is stored in FileData's map
// When sending invitations, Invitation structs are created (and stored in the FileData's map, so not in Datastore), Invitation structs are created and contain FileAccess data
// When accepting invitations, receiver takes data from the Invitation struct, and generates their own FileAccess struct
// Encrypt invitations using receiver's public key, decrypt using receiver's private key
// Sign invitations using sender's private key, verify using sender's public key
type Invitation struct {
	FileDataUUID  userlib.UUID // UUID of FileData
	FileDataKey   []byte       // Key to decrypt FileData
	OwnerUsername string       // File owner's username
}

// Given username, return UUID of user
func GetUserUUID(username string) (UUID userlib.UUID) {
	hashedUsername := userlib.Hash([]byte(username))   // convert username to bytes, then hash
	userUUID, _ := uuid.FromBytes(hashedUsername[:16]) // get UUID from hashedUsername
	return userUUID
}

// Encrypts data using symmetric encryption, then appends an HMAC tag, returns a slice
func SymEncryptThenMac(sourceKey []byte, data []byte) (encryptedData []byte) {
	encKey, _ := userlib.HashKDF(sourceKey, []byte("encryption")) // generate symmetric encryption key for user struct
	encKey = encKey[:16]                                          // sym encryption only takes 16 bytes
	macKey, _ := userlib.HashKDF(sourceKey, []byte("mac"))        // generate mac key for user struct
	macKey = macKey[:16]                                          // sym encryption only takes 16 bytes
	encIV := userlib.RandomBytes(16)
	encryptedStruct := userlib.SymEnc(encKey, encIV, data) // variable len, encrypt serialized user struct using encKey and random IV
	tag, _ := userlib.HMACEval(macKey, encryptedStruct)    // 64 bytes, generates HMAC tag given macKey and encrypted struct

	encryptThenMac := append(encryptedStruct[:], tag[:]...) // convert arrays to slices, then append
	return encryptThenMac
}

// Decrypts data using symmetric decryption, checks if tag is valid, returns the serialized struct
func SymDecryptThenDemac(sourceKey []byte, encryptedData []byte) (decryptedStruct []byte, ok bool) {
	decKey, _ := userlib.HashKDF(sourceKey, []byte("encryption")) // generate symmetric encryption key for user struct
	decKey = decKey[:16]                                          // sym encryption only takes 16 bytes
	macKey, _ := userlib.HashKDF(sourceKey, []byte("mac"))        // generate mac key for user struct
	macKey = macKey[:16]                                          // sym encryption only takes 16 bytes

	encryptedStruct := encryptedData[:len(encryptedData)-64]
	tag := encryptedData[len(encryptedData)-64:]

	referenceTag, _ := userlib.HMACEval(macKey, encryptedStruct)

	if !userlib.HMACEqual(tag, referenceTag) {
		return nil, false
	}

	decryptedStruct = userlib.SymDec(decKey, encryptedStruct)
	return decryptedStruct, true
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	userdata := User{}

	// check if username is empty
	if username == "" {
		return nil, errors.New("empty username")
	}

	userdata.Username = username
	userdata.Password = password

	var RsaEncKey userlib.PKEEncKey
	RsaEncKey, userdata.RsaDecKey, _ = userlib.PKEKeyGen() // get public/private keypair for RSA encryption/decryption
	userlib.KeystoreSet(username+"RsaEncKey", RsaEncKey)   // store public RSA key in Keystore

	var VerifyKey userlib.DSVerifyKey
	userdata.SignKey, VerifyKey, _ = userlib.DSKeyGen()  // get private/public keypair for RSA signatures
	userlib.KeystoreSet(username+"VerifyKey", VerifyKey) // store public verify key in Keystore

	userdata.SymKey = userlib.RandomBytes(16) // get random 16-byte symmetric key

	userUUID := GetUserUUID(username) // get the user's UUID

	// check if user already exists
	_, exists := userlib.DatastoreGet(userUUID)
	if exists {
		return nil, errors.New("username already exists")
	}

	serializedUserData, _ := json.Marshal(userdata) // serialize user struct
	hashedUsername := userlib.Hash([]byte(username))
	sourceKey := userlib.Argon2Key([]byte(password), hashedUsername, 16) // create symmetric key, password as password, hashedUsername as salt

	encryptedData := SymEncryptThenMac(sourceKey, serializedUserData) // encrypted struct (includes tag)

	userlib.DatastoreSet(userUUID, encryptedData) // add (UUID: encrypted struct) to Datastore

	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	userdata := User{}
	userdataptr = &userdata

	userUUID := GetUserUUID(username)                       // get the user's UUID
	encryptedData, exists := userlib.DatastoreGet(userUUID) // get the encrypted user struct from Datastore

	// check if the user exists
	if !exists {
		return nil, errors.New("user does not exist, must initialize first")
	}

	hashedUsername := userlib.Hash([]byte(username))
	sourceKey := userlib.Argon2Key([]byte(password), hashedUsername, 16)       // create symmetric key, password as password, hashedUsername as salt
	decryptedStruct, validTag := SymDecryptThenDemac(sourceKey, encryptedData) // get the serialized user struct

	// validTag is false if the data has been tampered with or if the credentials are wrong
	if !validTag {
		return nil, errors.New("user credentials are invalid, or integrity of user struct has been compromised")
	}

	err = json.Unmarshal(decryptedStruct, userdataptr) // deserialize to get the user struct

	// do we need to check for this?
	if err != nil {
		return nil, errors.New("deserialization unsuccessful")
	}

	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	fileAccessUUID, _ := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	encryptedFileAccess, exists := userlib.DatastoreGet(fileAccessUUID)

	// Initialize head FileNode, store in Datastore
	headNode := FileNode{
		Contents: content,
	}
	headUUID := uuid.New()             // randomly assign UUID
	headKey := userlib.RandomBytes(16) // randomly assign key
	serializedHeadNode, _ := json.Marshal(headNode)
	encryptedHeadNode := SymEncryptThenMac(headKey, serializedHeadNode)
	userlib.DatastoreSet(headUUID, encryptedHeadNode)

	// Initialize tail FileNode, store in Datastore
	tailNode := FileNode{
		PrevUUID: headUUID,
		PrevKey:  headKey,
	}
	tailUUID := uuid.New()             // randomly assign UUID
	tailKey := userlib.RandomBytes(16) // randomly assign key
	serializedTailNode, _ := json.Marshal(tailNode)
	encryptedTailNode := SymEncryptThenMac(tailKey, serializedTailNode)
	userlib.DatastoreSet(tailUUID, encryptedTailNode)

	if exists { // if file already exists, replace its contents
		serializedFileAccess, ok := SymDecryptThenDemac(userdata.SymKey, encryptedFileAccess)
		if !ok {
			return errors.New("integrity of fileaccess struct has been compromised")
		}
		var fileAccess FileAccess
		err = json.Unmarshal(serializedFileAccess, &fileAccess)
		if err != nil {
			return err
		}

		encryptedFileData, exists := userlib.DatastoreGet(fileAccess.FileDataUUID)
		if !exists {
			return errors.New("fileData struct does not exist in Datastore")
		}
		serializedFileData, ok := SymDecryptThenDemac(fileAccess.FileDataKey, encryptedFileData)
		if !ok {
			return errors.New("integrity of filedata struct has been compromised")
		}

		// get current FileData
		fileData := FileData{}
		err = json.Unmarshal(serializedFileData, &fileData)
		if err != nil {
			return err
		}

		// get current FileNodeContainer
		encryptedFileNodeContainer, ok := userlib.DatastoreGet(fileData.FileNodeContainerUUID)
		if !ok {
			return errors.New("fileNodeContainer struct does not exist in Datastore")
		}
		serializedFileNodeContainer, ok := SymDecryptThenDemac(fileData.FileNodeContainerKey, encryptedFileNodeContainer)
		if !ok {
			return errors.New("integrity of fileNodeContainer struct has been compromised")
		}
		fileNodeContainer := FileNodeContainer{}
		err = json.Unmarshal(serializedFileNodeContainer, &fileNodeContainer)
		if err != nil {
			return err
		}

		// replace FileNodeContainer contents with new nodes
		fileNodeContainer.HeadUUID = headUUID
		fileNodeContainer.HeadKey = headKey
		fileNodeContainer.TailUUID = tailUUID
		fileNodeContainer.TailKey = tailKey

		// store updated fileNodeContainer back in Datastore
		serializedFileNodeContainer, err = json.Marshal(fileNodeContainer)
		if err != nil {
			return err
		}
		encryptedFileNodeContainer = SymEncryptThenMac(fileData.FileNodeContainerKey, serializedFileNodeContainer)
		userlib.DatastoreSet(fileData.FileNodeContainerUUID, encryptedFileNodeContainer)

	} else { // if file doesn't exist, create a new file

		// initialize the new SharedUserFileMap
		sharedUserMapUUID := uuid.New()
		sharedUserMapKey := userlib.RandomBytes(16)
		sharedUserFileMap := SharedUserFileMap{
			OwnerMap: map[string]Invitation{},
		}
		serializedSharedUserFileMap, err := json.Marshal(sharedUserFileMap)
		if err != nil {
			return err
		}
		encryptedSharedUserFileMap := SymEncryptThenMac(sharedUserMapKey, serializedSharedUserFileMap)
		userlib.DatastoreSet(sharedUserMapUUID, encryptedSharedUserFileMap)

		// initialize the new FileNodeContainer struct
		fileNodeContainerUUID := uuid.New()
		fileNodeContainerKey := userlib.RandomBytes(16)
		fileNodeContainer := FileNodeContainer{
			HeadUUID: headUUID,
			HeadKey:  headKey,
			TailUUID: tailUUID,
			TailKey:  tailKey,
		}
		serializedFileNodeContainer, err := json.Marshal(fileNodeContainer)
		if err != nil {
			return err
		}
		encryptedFileNodeContainer := SymEncryptThenMac(fileNodeContainerKey, serializedFileNodeContainer)
		userlib.DatastoreSet(fileNodeContainerUUID, encryptedFileNodeContainer)

		// Initialize FileData, store in Datastore
		fileData := FileData{
			Filename:              filename,
			FileNodeContainerUUID: fileNodeContainerUUID,
			FileNodeContainerKey:  fileNodeContainerKey,
			SharedUserMapUUID:     sharedUserMapUUID,
			SharedUserMapKey:      sharedUserMapKey,
		}
		fileDataUUID := uuid.New()             // randomly assign UUID
		fileDataKey := userlib.RandomBytes(16) // randomly assign key
		serializedFileData, err := json.Marshal(fileData)
		if err != nil {
			return err
		}
		encryptedFileData := SymEncryptThenMac(fileDataKey, serializedFileData)
		userlib.DatastoreSet(fileDataUUID, encryptedFileData)

		// Initialize FileAccess, store in Datastore, key is user's symmetric key
		fileAccess := FileAccess{
			FileDataUUID:  fileDataUUID,
			FileDataKey:   fileDataKey,
			OwnerUsername: userdata.Username,
		}
		serializedFileAccess, _ := json.Marshal(fileAccess)
		encryptedFileAccess := SymEncryptThenMac(userdata.SymKey, serializedFileAccess)
		userlib.DatastoreSet(fileAccessUUID, encryptedFileAccess)
	}

	return
}

// Helper function that basically loads a function by retrieving the fileacess and then using it to decrypt the filedata
func (fileData *FileData) RetrieveFileData(userdata *User, filename string) (fileAccess *FileAccess, err error) {
	fileAccessUUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16]) // Load FileAcess struct UUID
	if err != nil {
		return nil, err
	}

	encryptedFileAcess, exists := userlib.DatastoreGet(fileAccessUUID)
	if !exists {
		return nil, errors.New(strings.ToTitle("fileAccess struct does not exist in Datastore"))
	}

	decryptedFileAccess, ok := SymDecryptThenDemac(userdata.SymKey, encryptedFileAcess) // Marshelled FileAccess struct
	if !ok {
		return nil, errors.New("integrity of FileAccess struct has been compromised")
	}

	err = json.Unmarshal(decryptedFileAccess, &fileAccess) // contentAddress should point to the struct now
	if !exists {
		return nil, err
	}

	fileKey := fileAccess.FileDataKey   // Gets file key from fileAccess
	fileUUID := fileAccess.FileDataUUID // Gets file uuid from fileAccess

	encryptedFileData, ok := userlib.DatastoreGet(fileUUID) // Pulls the encrypted fileData struct
	if !ok {
		return nil, errors.New(strings.ToTitle("fileData struct not found in Datastore"))
	}

	decryptedFileData, ok := SymDecryptThenDemac(fileKey, encryptedFileData) // Marshelled FileAccess struct
	if !ok {
		return nil, errors.New("integrity of FileData struct has been compromised")
	}

	err = json.Unmarshal(decryptedFileData, &fileData) // FileData struct now stored in fileData var
	if err != nil {
		return nil, err
	}

	return fileAccess, nil
}

// Appends content to the file in filename
func (userdata *User) AppendToFile(filename string, content []byte) (err error) {
	var fileData FileData

	_, err = fileData.RetrieveFileData(userdata, filename)
	if err != nil {
		return err
	}

	// get current FileNodeContainer
	encryptedFileNodeContainer, ok := userlib.DatastoreGet(fileData.FileNodeContainerUUID)
	if !ok {
		return errors.New("fileNodeContainer struct does not exist in Datastore")
	}
	serializedFileNodeContainer, ok := SymDecryptThenDemac(fileData.FileNodeContainerKey, encryptedFileNodeContainer)
	if !ok {
		return errors.New("integrity of fileNodeContainer struct has been compromised")
	}
	fileNodeContainer := FileNodeContainer{}
	err = json.Unmarshal(serializedFileNodeContainer, &fileNodeContainer)
	if err != nil {
		return err
	}

	// Retrieve and decrypt tailNode
	var tailNode FileNode
	encryptedFileNode, ok := userlib.DatastoreGet(fileNodeContainer.TailUUID) // Pulls the encrypted fileData struct
	if !ok {
		return errors.New(strings.ToTitle("tailNode does not exist in Datastore"))
	}

	decryptedFileNode, ok := SymDecryptThenDemac(fileNodeContainer.TailKey, encryptedFileNode) // Marshelled FileAccess struct
	if !ok {
		return errors.New("integrity of FileNode struct has been compromised")
	}

	err = json.Unmarshal(decryptedFileNode, &tailNode) // FileNode struct now stored in tailNode var
	if err != nil {
		return err
	}

	// Update the contents of the current tailnode with the append
	tailNode.Contents = content // Assign contents to the current tail node.
	serializedTailNode, err := json.Marshal(tailNode)
	if err != nil {
		return err
	}
	encryptedTailNode := SymEncryptThenMac(fileNodeContainer.TailKey, serializedTailNode)
	userlib.DatastoreSet(fileNodeContainer.TailUUID, encryptedTailNode) // Updates the tailNode with the new contents

	// New Empty Tail creation
	newTailNode := FileNode{
		PrevUUID: fileNodeContainer.TailUUID,
		PrevKey:  fileNodeContainer.TailKey,
	}
	fileNodeContainer.TailUUID = uuid.New()             // randomly assign new tail UUID
	fileNodeContainer.TailKey = userlib.RandomBytes(16) // randomly assign new tail key
	newSerializedTailNode, err := json.Marshal(newTailNode)
	if err != nil {
		return err
	}
	newEncryptedTailNode := SymEncryptThenMac(fileNodeContainer.TailKey, newSerializedTailNode)
	userlib.DatastoreSet(fileNodeContainer.TailUUID, newEncryptedTailNode) // Push new tail into the datastore

	// store updated fileNodeContainer back in Datastore
	serializedFileNodeContainer, err = json.Marshal(fileNodeContainer)
	if err != nil {
		return err
	}
	encryptedFileNodeContainer = SymEncryptThenMac(fileData.FileNodeContainerKey, serializedFileNodeContainer)
	userlib.DatastoreSet(fileData.FileNodeContainerUUID, encryptedFileNodeContainer)

	return nil
}

// Helper function to collapse all appends when called given a decrypted tail node
func (fileData *FileData) CollapseAppends() (content []byte, err error) {
	// get the FileNodeContainer
	encryptedFileNodeContainer, exists := userlib.DatastoreGet(fileData.FileNodeContainerUUID)
	if !exists {
		return nil, errors.New("fileNodeContainer struct does not exist in Datastore")
	}
	decryptedFileNodeContainer, ok := SymDecryptThenDemac(fileData.FileNodeContainerKey, encryptedFileNodeContainer)
	if !ok {
		return nil, errors.New("integrity of fileNodeContainer struct has been compromised")
	}
	fileNodeContainer := FileNodeContainer{}
	err = json.Unmarshal(decryptedFileNodeContainer, &fileNodeContainer)
	if err != nil {
		return nil, err
	}

	// retrieve the tail node from the FileNodeContainer
	tailNode := &FileNode{}
	encryptedTailNode, exists := userlib.DatastoreGet(fileNodeContainer.TailUUID)
	if !exists {
		return nil, errors.New("tail node does not exist in Datastore")
	}
	decryptedTailNode, ok := SymDecryptThenDemac(fileNodeContainer.TailKey, encryptedTailNode)
	if !ok {
		return nil, errors.New("integrity of tail node struct has been compromised")
	}
	err = json.Unmarshal(decryptedTailNode, tailNode)
	if err != nil {
		return nil, err
	}

	// If there is more than one tailnode
	for fileNodeContainer.TailUUID != fileNodeContainer.HeadUUID { // while tail is not the head
		// get the prev node
		var prevTailNode *FileNode
		encryptedPrevTailNode, ok := userlib.DatastoreGet(tailNode.PrevUUID)
		if !ok {
			return nil, errors.New(strings.ToTitle("previous node does not exist in Datastore"))
		}
		decryptedPrevTailNode, ok := SymDecryptThenDemac(tailNode.PrevKey, encryptedPrevTailNode) // Marshelled FileNode struct
		if !ok {
			return nil, errors.New("integrity of FileAccess struct has been compromised")
		}
		err = json.Unmarshal(decryptedPrevTailNode, &prevTailNode) // newTailNode now points to the new tailNode
		if err != nil {
			return nil, err
		}

		prevTailNode.Contents = append(prevTailNode.Contents, tailNode.Contents...) // Collapse contents

		userlib.DatastoreDelete(fileNodeContainer.TailUUID) // delete old tail node from Datastore

		// fileNodeContainer's tail node is now prev node
		fileNodeContainer.TailUUID = tailNode.PrevUUID
		fileNodeContainer.TailKey = tailNode.PrevKey

		tailNode = prevTailNode // Updates tailNode		
	}
	// NOTE: In order to prevent any information from leaking, we need to create a copy of the headnode with a fresh uuid and key
	updatedHeadNode := FileNode{
		Contents: tailNode.Contents,
	}
	userlib.DatastoreDelete(fileNodeContainer.HeadUUID) // Reset the headNode
	fileNodeContainer.HeadUUID = uuid.New()
	fileNodeContainer.HeadKey = userlib.RandomBytes(16)

	// store updated tailNode (now technically the Head Node)
	serializedUpdatedHeadNode, err := json.Marshal(updatedHeadNode)
	if err != nil {
		return nil, err
	}
	encryptedUpdatedHeadNode := SymEncryptThenMac(fileNodeContainer.HeadKey, serializedUpdatedHeadNode)
	userlib.DatastoreSet(fileNodeContainer.HeadUUID, encryptedUpdatedHeadNode)

	// Creates new empty tailNode
	// NOTE: at this point, container's headNode == tailNode, so we need to create a new empty tailnode
	newTailNode := FileNode{
		PrevUUID: fileNodeContainer.HeadUUID,
		PrevKey:  fileNodeContainer.HeadKey,
	}
	tailUUID := uuid.New() // randomly assign UUID
	if err != nil {
		return nil, err
	}
	tailKey := userlib.RandomBytes(16) // randomly assign key
	serializedTailNode, err := json.Marshal(newTailNode)
	if err != nil {
		return nil, err
	}
	encryptedTailNode = SymEncryptThenMac(tailKey, serializedTailNode)
	userlib.DatastoreSet(tailUUID, encryptedTailNode) // Adds new tailNode to

	// assign fileNodeContainer's new empty tail
	fileNodeContainer.TailUUID = tailUUID
	fileNodeContainer.TailKey = tailKey

	// store updated fileNodeContainer back in Datastore
	decryptedFileNodeContainer, err = json.Marshal(fileNodeContainer)
	if err != nil {
		return nil, err
	}
	encryptedFileNodeContainer = SymEncryptThenMac(fileData.FileNodeContainerKey, decryptedFileNodeContainer)
	userlib.DatastoreSet(fileData.FileNodeContainerUUID, encryptedFileNodeContainer)

	return tailNode.Contents, nil // tailNode.Contents should be the headNode.Contents
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	var fileData FileData
	_, err = fileData.RetrieveFileData(userdata, filename) // Gets file data for the filename given a user
	if err != nil {
		return nil, err
	}

	content, err = fileData.CollapseAppends() // fileData should now be collapsed and also returns content
	if err != nil {
		return nil, err
	}
	
	return content, nil
}

// give owner's FileData struct, return the SharedUserFileMap
func GetSharedUserFileMap(fileData *FileData) (sharedUserFileMap *SharedUserFileMap, err error) {
	sharedUserMapUUID := fileData.SharedUserMapUUID
	sharedUserMapKey := fileData.SharedUserMapKey
	encryptedSharedUserFileMap, ok := userlib.DatastoreGet(sharedUserMapUUID)
	if !ok {
		return nil, errors.New("sharedUserFileMap does not exist in Datastore")
	}

	serializedSharedUserFileMap, ok := SymDecryptThenDemac(sharedUserMapKey, encryptedSharedUserFileMap)
	if !ok {
		return nil, errors.New("integrity of sharedUserFileMap has been compromised")
	}

	sharedUserFileMap = &SharedUserFileMap{} // Initialize the struct before unmarshalling into it
	err = json.Unmarshal(serializedSharedUserFileMap, sharedUserFileMap)
	if err != nil {
		return nil, err
	}

	return sharedUserFileMap, nil
}

// SetSharedUserFileMap updates the shared user file map in the datastore
func SetSharedUserFileMap(fileData *FileData, sharedUserFileMap *SharedUserFileMap) error {
    // Serialize the sharedUserFileMap struct
    serializedSharedUserFileMap, err := json.Marshal(sharedUserFileMap)
    if err != nil {
        return err
    }

    // Encrypt the serialized data
    encryptedSharedUserFileMap := SymEncryptThenMac(fileData.SharedUserMapKey, serializedSharedUserFileMap)

    // Store the encrypted data in the Datastore
    userlib.DatastoreSet(fileData.SharedUserMapUUID, encryptedSharedUserFileMap)

    return nil
}

// encrypt symmetric key with RSA
// public keys are length 2048
// ciphertexts from RSA encryption are 256 bytes long
func HybridEncrypt(publicEncKey userlib.PKEEncKey, data []byte) (encryptedKey []byte, encryptedData []byte, err error) {

	symmetricKey := userlib.RandomBytes(16)
	encryptedData = SymEncryptThenMac(symmetricKey, data)

	encryptedKey, err = userlib.PKEEnc(publicEncKey, symmetricKey)
	if err != nil {
		return nil, nil, err
	}

	return encryptedKey, encryptedData, nil
}

// decrypt with RSA private key, get symmetric keys, decrypt the struct
func HybridDecrypt(privateDecKey userlib.PKEDecKey, encryptedKey []byte, encryptedData []byte) (decryptedData []byte, ok bool) {
	symmetricKey, err := userlib.PKEDec(privateDecKey, encryptedKey)
	if err != nil {
		return nil, false
	}

	return SymDecryptThenDemac(symmetricKey, encryptedData)
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {

	// generate new FileData struct
	// generate new invitation struct
	// add invitation struct to sharedUserFileMap

	// get sender's FileData and FileAccess struct
	var senderFileData FileData
	senderFileAccess, err := senderFileData.RetrieveFileData(userdata, filename)
	if err != nil {
		return uuid.Nil, err
	}

	var invitation Invitation

	if senderFileAccess.OwnerUsername == userdata.Username { // sender is file owner, will require making a new FileData struct

		// initialize the recipient's new FileData struct
		recipientFileData := FileData{
			Filename:              senderFileData.Filename,
			FileNodeContainerUUID: senderFileData.FileNodeContainerUUID,
			FileNodeContainerKey:  senderFileData.FileNodeContainerKey,
		}

		// encrypt and store the recipient's new FileData struct
		serializedFileData, err := json.Marshal(recipientFileData)
		if err != nil {
			return uuid.Nil, err
		}
		recipientFileDataKey := userlib.RandomBytes(16)
		encryptedRecipientFileData := SymEncryptThenMac(recipientFileDataKey, serializedFileData)
		recipientFileDataUUID := uuid.New()
		userlib.DatastoreSet(recipientFileDataUUID, encryptedRecipientFileData)

		// initialize invitation struct, which will give access to the FileData struct
		invitation = Invitation{
			FileDataUUID:  recipientFileDataUUID,
			FileDataKey:   recipientFileDataKey,
			OwnerUsername: userdata.Username,
		}

		// add invitation struct to sharedUserFileMap
		ownerSharedUserFileMap, err := GetSharedUserFileMap(&senderFileData)
		if err != nil {
			return uuid.Nil, err
		}
		ownerSharedUserFileMap.OwnerMap[recipientUsername] = invitation
		err = SetSharedUserFileMap(&senderFileData, ownerSharedUserFileMap)
		if err != nil {
			return uuid.Nil, err
		}
	} else { // sender is not the file owner, just share with them your FileData struct

		// recipient's FileData struct will be the same as sender's
		// initialize invitation struct, which will give access to the FileData struct
		invitation = Invitation{
			FileDataUUID:  senderFileAccess.FileDataUUID,
			FileDataKey:   senderFileAccess.FileDataKey,
			OwnerUsername: senderFileAccess.OwnerUsername,
		}
	}
	serializedInvitation, err := json.Marshal(invitation)
	if err != nil {
		return uuid.Nil, err
	}

	// get recipient's encryption key
	publicEncKey, ok := userlib.KeystoreGet(recipientUsername + "RsaEncKey")
	if !ok {
		return uuid.Nil, errors.New("recipient's public encryption key does not exist")
	}

	// hybrid encrypt the invitation struct
	invitationUUID := uuid.New()

	encryptedKey, encryptedData, err := HybridEncrypt(publicEncKey, serializedInvitation)
	if err != nil {
		return uuid.Nil, err
	}

	signature, err := userlib.DSSign(userdata.SignKey, append(encryptedKey, encryptedData...))
	if err != nil {
		return uuid.Nil, err
	}

	// append 256-byte signature, 256-byte encryptedKey, and encryptedData
	fullyEncryptedInvitation := append(append(signature, encryptedKey...), encryptedData...)
	userlib.DatastoreSet(invitationUUID, fullyEncryptedInvitation)

	return invitationUUID, nil
}

// When accepting invitation, the entire idea is that the recipient creates a new FileAccess struct
// Recipient's new FileAccess struct still points to whatever FileData struct the owner created for you
func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	// decrypt the Invitation struct
	// create a new FileAccess struct, copy contents from Invitation struct

	// get encrypted Invitation from Datastore
	fullyEncryptedInvitation, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("invitation does not exist in Datastore")
	}

	// verify the signature
	signature := fullyEncryptedInvitation[:256]                              // get the signature from the first 256 bytes of the cipher text
	keyAndData := fullyEncryptedInvitation[256:]                             // get the encrypted key and encrypted data
	verificationKey, ok := userlib.KeystoreGet(senderUsername + "VerifyKey") // get the public verification key of the sender
	if !ok {
		return errors.New("sender's verification key does not exist in Keystore")
	}
	err := userlib.DSVerify(verificationKey, keyAndData, signature)
	if err != nil {
		return err
	}

	// decrypt Invitation struct
	encryptedKey := keyAndData[:256] // get the encrypted key from the first 256 bytes of keyAndData
	encryptedData := keyAndData[256:]
	serializedInvitation, ok := HybridDecrypt(userdata.RsaDecKey, encryptedKey, encryptedData)
	if !ok {
		return errors.New("invitation has been compromised")
	}
	invitation := &Invitation{}
	err = json.Unmarshal(serializedInvitation, &invitation)
	if err != nil {
		return err
	}

	// create a new FileAccess struct for recipient
	fileAccess := FileAccess{
		FileDataUUID:  invitation.FileDataUUID,
		FileDataKey:   invitation.FileDataKey,
		OwnerUsername: invitation.OwnerUsername,
	}

	// encrypt the new FileAccess struct
	serializedFileAccess, err := json.Marshal(fileAccess)
	if err != nil {
		return err
	}
	encryptedFileAccess := SymEncryptThenMac(userdata.SymKey, serializedFileAccess)

	// store the FileAccess in DataStore
	// UUID generated with filename and receiver's username
	fileAccessUUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return err
	}
	userlib.DatastoreSet(fileAccessUUID, encryptedFileAccess)
	userlib.DatastoreDelete(invitationPtr)
	return nil
}

// Takes a UUID, Key and a pointer of where to store the struct
func DecryptAndUnmarshal[T any](UUID userlib.UUID, sourceKey []byte, result *T) error {
	encryptedData , ok := userlib.DatastoreGet(UUID) 
	if !ok {
		return errors.New("value at UUID does not exist")
	}

	decryptedData, ok := SymDecryptThenDemac(sourceKey, encryptedData)
	if !ok {
		return errors.New("decryption and validation/verification failed")
	}
    
    // Unmarshal the decrypted data into the provided result struct
    return json.Unmarshal(decryptedData, result) // Returns an error if it exists
}

//TODO: implement
func EncryptMarshalAndSet[T any](UUID userlib.UUID, sourceKey []byte, input *T) error {
	serializedData, err := json.Marshal(input)
	if err != nil {
		return err
	}
	encryptedData := SymEncryptThenMac(sourceKey, serializedData)
	userlib.DatastoreSet(UUID, encryptedData)
	return nil
}

// Takes in fileData of what we want to delete and its UUID to delete FileData and the SharedUserFileMap from Datastore
func (fileData *FileData) RecursiveRevoke (fileDataUUID userlib.UUID) error {
	userlib.DatastoreDelete(fileDataUUID) // Deletes fileData

	var sharedUserFileMapTemp SharedUserFileMap
	err := DecryptAndUnmarshal(fileData.SharedUserMapUUID, fileData.SharedUserMapKey, &sharedUserFileMapTemp)
	if err != nil {
		return err
	}

	userlib.DatastoreDelete(fileData.SharedUserMapUUID) // Deletes SharedUserFileMap

	// Goes through all other users in OwnerMap and does the same
	for _, invitation := range sharedUserFileMapTemp.OwnerMap {
		var fileDataTemp FileData
		DecryptAndUnmarshal(invitation.FileDataUUID, invitation.FileDataKey, &fileDataTemp)
		err := fileDataTemp.RecursiveRevoke(invitation.FileDataUUID)
		if err != nil {
			return err
		}
	}
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	
	var userFileData FileData
	userFileAccess , err := userFileData.RetrieveFileData(userdata, filename)
	if err != nil {
		return err
	}

	// Get SharedUserFileMap
	var userMap SharedUserFileMap
	err = DecryptAndUnmarshal(userFileData.SharedUserMapUUID, userFileData.SharedUserMapKey, &userMap)
	if err != nil {
		return err
	}

	
	// Check if recipientUsername exists and loads invitation struct
	invitation, ok := userMap.OwnerMap[recipientUsername] 
	if !ok {
		return errors.New("target to revoke does not exist")
	} 
	
	// 1: Delete the FileData struct

	userlib.DatastoreDelete(invitation.FileDataUUID)
	delete(userMap.OwnerMap, recipientUsername)

	// Updates SharedUserMap
	err = EncryptMarshalAndSet(userFileData.SharedUserMapUUID, userFileData.SharedUserMapKey, &userMap) 
	if err != nil {
		return err
	}


	// 2: Reencrypt all the nodes and the container

	_, err = userdata.LoadFile(filename) // Just to collapse appends and set new keys for fileNodes
	if err != nil {
		return err
	}

	// Fetch the fileNodeContainer
	encryptedFileNodeContainer, ok := userlib.DatastoreGet(userFileData.FileNodeContainerUUID)
	if !ok {
		return errors.New("error retreiving fileNodeContainer")
	}

	decryptedFileNodeContainer, ok := SymDecryptThenDemac(userFileData.FileNodeContainerKey, encryptedFileNodeContainer)
	if !ok {
		return errors.New("could not validate or verify fileNodeContainer")
	}

	// Generates new information for the fileNodeContainer
	userlib.DatastoreDelete(userFileData.FileNodeContainerUUID) // Gets rid of old container first
	userFileData.FileNodeContainerUUID = uuid.New()
	userFileData.FileNodeContainerKey = userlib.RandomBytes(16)

	
	// Update container on datastore
	encryptedData := SymEncryptThenMac(userFileData.FileNodeContainerKey, decryptedFileNodeContainer)
	userlib.DatastoreSet(userFileData.FileNodeContainerUUID, encryptedData)

	// Update FileData on datastore
	err = EncryptMarshalAndSet(userFileAccess.FileDataUUID, userFileAccess.FileDataKey, &userFileData)
	if err != nil {
		return err
	}

	// 3: Update FileNodeContainer UUID and key for everyone else

	for _, invitationStruct := range userMap.OwnerMap {
		var fileDataTemp FileData
		err := DecryptAndUnmarshal(invitationStruct.FileDataUUID, invitationStruct.FileDataKey, &fileDataTemp)
		if err != nil {
			return err
		}

		// Update fileNodeContainer info
		fileDataTemp.FileNodeContainerUUID = userFileData.FileNodeContainerUUID
		fileDataTemp.FileNodeContainerKey = userFileAccess.FileDataKey

		// Update datastore with updated fileData
		EncryptMarshalAndSet(invitationStruct.FileDataUUID, invitationStruct.FileDataKey, &fileDataTemp)
	}

	return nil
}
