# Encrypted File Sharing System
#### Author: Hovan Liu

This document outlines the design and implementation details for an end-to-end encrypted file sharing system, focusing on user authentication, file operations, and secure data storage using cryptographic techniques.

## User and User Authentication
```
type User struct {
    Username string
    Password string
    RsaDecKey userlib.PKEDecKey // private RSA key for decryption
    SignKey userlib.DSSignKey   // private RSA key for signing
    SymKey []byte               // symmetric key to encrypt/decrypt fileAccess structs
}
```

### Initializing Users
When initializing a new user, given a username and password, we will generate a new `User` struct. The `User` struct will contain the given username and password, a private RSA decryption key, a private RSA signing key, and a symmetric key. When storing `User` structs, they will first be serialized using `json.Marshal()`. The serialized bytes will then by encrypted then MAC’d with a unique symmetric key `k`. This key `k` will be generated with `Argon2Key`, with the user’s password as the `password` and a hash of their username as the `salt`. For Encrypt-then-Mac, we need two unique keys, `k1` for encryption and `k2` for MAC. To generate `k1` and `k2` from `k`, we use `HashKDF` with `k` as the source key and `"encryption"` and `"mac"` as the purposes. After encrypting and appending the MAC tag, the ciphertext is stored in Datastore at a unique UUID. This UUID must be unique for every user, so it is generated by hashing the username, slicing the first 16 bytes, and calling `uuid.FromBytes()` on these 16 bytes. 

### Getting Users
When getting a user, follow the same steps above to get the user's UUID and key. If the UUID does not exist, return an error. If the UUID does exist but decryption fails, return an error. We know that the username and password are valid if and only if the decryption is successful. 

## File Operations
```
type FileAccess struct {
	FileDataUUID  userlib.UUID // UUID of FileData
	FileDataKey   []byte       // Key to decrypt FileData
	OwnerUsername string       // File owner's username
}

type FileData struct {
	Filename              string
	FileNodeContainerUUID userlib.UUID // UUID of FileNodeContainer struct
	FileNodeContainerKey  []byte       // Key of decrypt FileNodeContainer struct
	SharedUserMapUUID     userlib.UUID // UUID of SharedUserFileMap
	SharedUserMapKey      []byte       // Key of decrypt SharedUserFileMap
}

type FileNodeContainer struct {
	HeadUUID userlib.UUID // UUID of head FileNode
	HeadKey  []byte       // Key to decrypt head FileNode
	TailUUID userlib.UUID // UUID of tail FileNode
	TailKey  []byte       // Key to decrypt tail FileNode
}

type FileNode struct {
	Contents []byte
	PrevUUID userlib.UUID // UUID of previous FileNode
	PrevKey  []byte       // Key to decrypt previous FileNode
}
```

### Storing Files
At a high level, `FileAccess` structs give access to `FileData` structs, which give access to `FileNodeContainer` structs, which give access to `FileNode` structs.

#### Case 1: File Does Not Exist
If the file does not exist yet, we must create a new file. We begin by creating a head `FileNode` struct and a tail `FileNode` struct. The head `FileNode` struct will contain the file contents, while the tail `FileNode` struct contains empty contents and points to the head `FileNode` struct. The `FileNode` structure is a linked list where the tail will be updated with following appends, and every node points to the previous node. `FileNode` UUIDs and symmetric keys are randomly generated and stored in the `FileNodeContainer` struct. `FileNode` structs are serialized, encrypted, MAC'd and stored in Datastore.

Next, we create a new `FileNodeContainer` struct. The `FileNodeContainer` struct gives access to the head `FileNode` and the tail `FileNode`. `FileNodeContainer` UUIDs and keys are randomly generated and stored in the `FileData` struct. This struct is necessary to ensure file contents will always be up to date for every shared user. Because the `FileNodeContainer` UUID and key never change, the `FileData` struct will always give access to the corresponding `FileNodeContainer` UUID. When making updates (such as appends), we can update the contents of `FileNodeContainer`. 

Next, we create a new `FileData` struct. The `FileData` struct contains the name of the file, gives access to the corresponding `FileNodeContainer` struct, and gives access to the corresponding `SharedUserFileMap` struct. The `SharedUserFileMap` is used for sharing and revocation. `FileData` UUIDs and keys are randomly generated and stored in the `FileAccess` struct. 

Lastly, we create a new FileAccess struct. The `FileAccess` struct contains the name of the file owner and gives access to the corresponding `FileData` struct. This `FileAccess` struct's UUID is deterministically generated by appending the filename and username strings, hashing the bytes, slicing the first 16 bytes of the hash, and generating a UUID using `uuid.FromBytes()`. `FileAccess` structs are then serialized using `json.Marshal()`, encrypted and MAC'd using the user's `SymKey`, and stored in Datastore. 

#### Case 2: File Already Exists
If the file already exists, we only have to replace the current file contents with the new `content`. Get the corresponding `FileAccess`, `FileData`, and `FileNodeContainer` structs using the method detailed previously. Create a new head `FileNode` struct and a new tail `FileNode` struct. The head `FileNode` struct will contain the new file contents, while the tail `FileNode` struct contains empty contents and points to the head `FileNode` struct. Again, randomly generate UUIDs and keys for these `FileNode` structs, serialize them, encrypt them, MAC them, and store the result in Datastore.

### Loading Files
Obtain the UUID of the `FileAccess` struct using the method detailed previously. If the file does not exist in Datastore, return an error. If the file does exist in Datastore, obtain the `FileAccess`, `FileData`, `FileNodeContainer`, and tail `FileNode` structs using the methods detailed previously. "Collapse" the appends of the file by iterating through the linked list of `FileNode` structs and appending their contents, starting with the tail. After we are left with two `FileNode` structs in the linked lists, the empty tail and the head with the complete file contents, return the complete file contents.

### Appending to Files
Obtain the UUID of the 'FileAccess' struct using the method detailed previously. If the file does not exist in Datastore, return an error. If the file does exist in Datastore, obtain the `FileAccess`, `FileData`, `FileNodeContainer`, and tail `FileNode` structs using the methods detailed previously. Create a new `FileNode` struct that contains the appended contents, this node will be our new tail node. Ensure that this new tail `FileNode` struct points to our old tail `FileNode` struct. Serialize, encrypt, MAC, and store our new tail `FileNode` struct in Datastore. In our `FileNodeContainer` struct, update the tail pointer to give access to our new tail `FileNode`. Then, reserialize, reencrypt, reMAC, and store the `FileNodeContainer` struct in Datastore.

Note that we do not "collapse" appends during the `AppendToFile()` function call, but rather in the `LoadFile` function call. This is done to meet the bandwidth requirements for appending to files. 

## Sharing and Revocation

```
type SharedUserFileMap struct {
	OwnerMap map[string]Invitation // Map of [RecipientUsername:Invitation], empty if not Owner, used for revocation

}

type Invitation struct {
	FileDataUUID  userlib.UUID // UUID of FileData
	FileDataKey   []byte       // Key to decrypt FileData
	OwnerUsername string       // File owner's username
}
```

### Understanding the Shared User Design
The idea behind sharing files between users involves the `FileAccess` and `Invitation` structs. When a sender wants to send an invitation to a recipient, the sender generates an `Invitation` struct that gives access to a `FileData` struct. The sender will encrypt this `Invitation` struct with RSA encryption using the recipient's public key. Then, the recipient will decrypt the `Invitation` struct using their own private key, and generate their own `FileAccess` struct, which gives access to the `FileData` struct. 

Every shared user of a given file will have their own `FileAccess` struct. Every shared user of a given file will reference the same `FileNode` structs and `FileNodeContainer` structs. Every shared user of a given file within a "shared group" will share the same `FileData` struct. For example, suppose user A (the owner) shares a file with user B and user C. User B then shares the file with user D, who shares the file with user E. User C then shares the file with user F, who shares the file with user G. User B, D, and E are within a "shared group", so they share a `FileData` struct. User C, F, and G are within a different "shared group", so they share a different `FileData` struct. The owner of a given file will have their own `FileData` struct. Note that even though these three `FileData` structs are different, they all give access to the same `FileContainer` and `FileNode` structs.

### Sending Invitations
#### Case 1: Sender is the owner
If the sender is the owner, the sender creates a new `FileData` struct for the recipient. This `FileData` struct contains the same data has the sender's `FileData` struct for this file, except it does not contain access to the `SharedUserFileMap`. Generate a random UUID and symmetric key for this `FileData` struct, then serialize, encrypt, MAC, and store in Datastore. Next, the owner creates a new `Invitation` struct for the recipient. This `Invitation` struct will contain the UUID and key of the recipient's `FileData` struct, as well as the sender/owner's username. A copy of this `Invitation` struct is stored in the owner's `SharedUserFileMap` in the owner's `FileData` struct. We will also store the `Invitation` struct in Datastore using hybrid encryption. First generate a random UUID and symmetric key for the `Invitation` struct, then serialize, encrypt, and MAC the `Invitation` struct. After, encrypt the symmetric key with the recipient's private key using RSA encryption, and append the encrypted key to the encrypted `Invitation` struct. Lastly, sign the appended ciphertext with the sender's private signing key, append the signature to the entire ciphertext, and store the entire ciphertext in Datastore given the previously mentioned UUID. 

#### Case 2: Sender is not the owner
If the sender is not the owner, the sender does not need to create a new `FileData` struct. Instead, they create a new `Invitation` struct that contains the same data as their `FileAccess` struct for this corresponding file. Note that this `Invitation` struct gives them access to the same `FileData` struct as the sender's (who is not an owner). Follow the previously mentioned steps to serialize, hybrid encrypt, and store the `Invitation` struct. 

### Accepting Invitations
The recipient must verify and decrypt the `Invitation` struct using the sender's public verification key and their own private decryption key. Then, the recipient creates their own `FileAccess` struct containing the same data as the `Invitation` struct. Again, this `FileAccess` struct's UUID is deterministically generated by appending the filename and recipient's username strings, hashing the bytes, slicing the first 16 bytes of the hash, and generating a UUID using `uuid.FromBytes()`. Then, serialize, encrypt, MAC, and store the `Invitation` struct using the recipient's private symmetric key. 

### Revoking Users
Revocation involves using the owner's `SharedFileUserMap` in the corresponding `FileData` struct. First, find the `Invitation` struct corresponding to the given recipient, and delete the corresponding `FileData` struct from Datastore using the `FileDataUUID`. Now, the revoked user (and any other children under that shared branch) will no longer have access to their `FileData` struct. However, we must account for the case that they wrote down the UUID and symmetric key values for the `FileNodeContainer` and `FileNode` structs, which contain the file contents themselves. To account for this case, we call `LoadFile`, which calls `CollapseAppends` to collapse all `FileNode` structs and reencrypt the head and tail `FileNode` structs with new UUIDs and new symmetric keys. Then, we also reencrypt `FileNodeContainer` structs with new UUIDs and new symmetric keys. Note that this reencryption must be done and updated for `FileData` structs of all shared users, other than the revoked user. This will ensure that the revoked user will never have access to any file contents.
