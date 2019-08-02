package assn1

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.
//
import (

	// You neet to add with
	// go get github.com/fenilfadadu/CS628-assn1/userlib

	"github.com/fenilfadadu/CS628-assn1/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...

	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"

	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys
	"strings"

	// Want to import errors
	"errors"
)

// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// test
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var key *userlib.PrivateKey
	key, _ = userlib.GenerateRSAKey()
	userlib.DebugMsg("Key is %v", key)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

//User : User structure used to store the user information
type User struct {
	Username              string
	Salt                  string
	PasswordHash          string
	FileDetails           map[string][]string
	UserDataLocation      string //Location at which user data is stored
	UserDataEncryptionKey string //Key to encrypt user data loaction
	UserPrivateKey        userlib.PrivateKey
	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

//GetBytes : convert User struct to bytes
func (userdata User) GetBytes() (bytes []byte, err error) {
	jsonData, err := json.Marshal(userdata)
	if err != nil {
		ErrorWrapper("Error Occured while Marshalling the User Data Structure, It might be corruped or modified", &err)
	}
	return jsonData, err
}

//SetUserData : set User's username, salt and passwordhash
func (userdata *User) SetUserData(username, password, userDataLocation string) {
	userdata.Username = username
	userdata.Salt = hex.EncodeToString(userlib.RandomBytes(16))
	userdata.PasswordHash = GenerateSha256Hash([]byte(password + userdata.Salt))
	userdata.UserDataLocation = userDataLocation
	return
}

//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.
// AppendFile : Function to append the file
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	userdata.ReloadUserDS(&err)
	fileMeta, exist := userdata.FileDetails[filename]
	if exist && len(fileMeta) == 2 {

		fileStructureLocation, encryptedKey1Bytes := GetFileStructureLocation(fileMeta, &err)
		if err == nil {
			InitiateAppend(fileStructureLocation, data, encryptedKey1Bytes, &err)
		} else {
			ErrorWrapper("File structure invalid or may be modified", &err)
		}

	} else {
		ErrorWrapper("File does not exist or File meta data is not matching", &err)
	}
	return err
}

// LoadFile :This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
// LoadFile : Function used to the file
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	// fmt.Print(userlib.DatastoreGet(userdata.UserDataLocation))
	userdata.ReloadUserDS(&err)
	if err != nil {
		ErrorWrapper("Error in Loading User data", &err)
		return
	}
	fileMeta, exist := userdata.FileDetails[filename]
	if !exist {
		return nil, nil
	}
	if exist && len(fileMeta) == 2 {

		fileStructureLocation, encryptedKey1Bytes := GetFileStructureLocation(fileMeta, &err)
		if err == nil {
			file, encryptedKey2Bytes, isValid := GetFileStructure(fileStructureLocation, encryptedKey1Bytes, &err)
			if isValid && err == nil {
				data, err = file.GetFileContent(encryptedKey2Bytes)
			} else {
				ErrorWrapper("File structure not found or may be modified", &err)
			}
		} else {
			ErrorWrapper("File structure not found or may be modified", &err)
		}

	} else {
		ErrorWrapper("File meta data is not matching", &err)
	}
	return
}

// ShareFile : Function used to the share file with other user
func (userdata *User) ShareFile(filename string, recipient string) (msgid string, err error) {

	//Get metaLoc and encryption Key
	fileDetails := userdata.FileDetails[filename]
	encryptionKey1 := fileDetails[0]
	fileMetaLocation := fileDetails[1]
	randomValue := userlib.RandomBytes(16)
	randomLocation := GenerateSha256Hash(randomValue) //to store the sharing message at, in the datastore

	receiverPubKey, pubKeyExists := userlib.KeystoreGet(recipient)
	if !pubKeyExists {
		ErrorWrapper("Receiver Public Key not found in Keystore", &err)
		return
	}
	var sharingMessage = sharingRecord{FileMetaLoc: fileMetaLocation, Key: encryptionKey1}
	sharingMessageBytes, err := sharingMessage.GetBytes() //check
	if err != nil {
		return
	}

	//RSA Encryption and signature
	label := []byte(randomLocation) //to use as tag in RSAEncrypt
	encryptedSharing, err := userlib.RSAEncrypt(&receiverPubKey, sharingMessageBytes, label)
	if err != nil {
		ErrorWrapper("RSA Encryption Error", &err)
	}
	privKey := userdata.UserPrivateKey
	sign, err := userlib.RSASign(&privKey, encryptedSharing)
	if err != nil {
		ErrorWrapper("RSA Signing Error", &err)
	}

	//convert to sharingMesg : { message, signature}
	sharing := sharingMesg{Message: hex.EncodeToString(encryptedSharing), Signature: hex.EncodeToString(sign)}
	sharingBytes, err := sharing.GetBytes()
	if err != nil {
		ErrorWrapper("Error in sharing", &err)
		return
	}
	userlib.DatastoreSet(randomLocation, sharingBytes)

	msgid = randomLocation
	return msgid, err

}

// ReceiveFile:Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
// ReceiveFile : function used to receive the file details from the sender
func (userdata *User) ReceiveFile(filename string, sender string, msgid string) error {

	var err error
	userdata.ReloadUserDS(&err)
	if err != nil {
		ErrorWrapper("Error while reloading user data in ReceiveFile", &err)
		return err
	}
	data, sharingExists := userlib.DatastoreGet(msgid)
	if !sharingExists {
		ErrorWrapper("Sharing Message not found in Data Store", &err)
		return err
	}

	var encryptedSharing sharingMesg
	unmarshalError := json.Unmarshal(data, &encryptedSharing)
	if unmarshalError != nil {
		ErrorWrapper("Unmarshalling error in ReceiveFile", &err)
		return err
	}

	privKey := userdata.UserPrivateKey
	senderPubKey, ok := userlib.KeystoreGet(sender)
	if !ok {
		ErrorWrapper("Sender public key not found", &err)
		return err
	}

	//RSA Decryption and signature Verification
	messageBytes, decodeError1 := hex.DecodeString(encryptedSharing.Message)
	signatureBytes, decodeError2 := hex.DecodeString(encryptedSharing.Signature)
	if !(decodeError1 == nil && decodeError2 == nil) {
		ErrorWrapper("String Decoding Error", &err)
		return err
	}
	verificationError := userlib.RSAVerify(&senderPubKey, messageBytes, signatureBytes)
	if verificationError != nil {
		ErrorWrapper("RSA Signature Verification Unsuccessful", &err)
		return err
	}
	label := []byte(msgid)
	sharingMessageBytes, err := userlib.RSADecrypt(&privKey, messageBytes, label)
	if err != nil {
		ErrorWrapper("RSA Decryption Error", &err)
		return err
	}

	//Get File meta and key, update user Data Structure
	var sharingMessage sharingRecord
	unmarshalError = json.Unmarshal(sharingMessageBytes, &sharingMessage)
	if unmarshalError != nil {
		ErrorWrapper("Unmarshalling Error in ReceiveFile", &err)
		return err
	}
	_, fileExist := userdata.FileDetails[filename]
	if fileExist {
		ErrorWrapper("Filename already exists.", &err)
		return err
	}

	userdata.FileDetails[filename] = []string{sharingMessage.Key, sharingMessage.FileMetaLoc}
	_, isFileMetaExist := userlib.DatastoreGet(sharingMessage.FileMetaLoc)
	if !isFileMetaExist {
		ErrorWrapper("File Meta Location X not found", &err)
		return err
	}

	//Update userdata Structure in Data Store.
	UpdateUserData(userdata)
	return err
}

// RevokeFile : function used revoke the shared file access
func (userdata *User) RevokeFile(filename string) (err error) {
	userdata.ReloadUserDS(&err)
	if err != nil {
		ErrorWrapper("Error while reloading user data structure in RevokeFile", &err)
	}
	fileMeta, exist := userdata.FileDetails[filename]
	if !(exist && len(fileMeta) == 2) {
		ErrorWrapper("File Meta Location not found in user data Structure", &err)
		return
	}

	//Generate new Ek1, X, Ek2
	newRandomString2 := userlib.RandomBytes(16)
	newFileStructureLocation := GenerateSha256Hash(newRandomString2) //New X
	newFileStructureLocationBytes, decodeError1 := hex.DecodeString(newFileStructureLocation)
	passwordBytes := []byte(userdata.PasswordHash)
	newEncryptionKey1Bytes := userlib.Argon2Key(newRandomString2, passwordBytes, uint32(userlib.AESKeySize)) //New Ek1
	newEncryptionKey2Bytes := userlib.Argon2Key(newFileStructureLocationBytes, newEncryptionKey1Bytes, uint32(userlib.AESKeySize))
	newEncryptionKey1 := hex.EncodeToString(newEncryptionKey1Bytes)

	if decodeError1 != nil {
		ErrorWrapper("String Decoding Error in RevokeFile", &err)
	}
	//Get old Ek1, X, Ek2
	oldFileStructureLocation, oldEncryptedKey1Bytes := GetFileStructureLocation(fileMeta, &err)
	oldFileStructureLocationBytes, decodeError2 := hex.DecodeString(oldFileStructureLocation)
	oldEncryptionKey2Bytes := userlib.Argon2Key(oldFileStructureLocationBytes, oldEncryptedKey1Bytes, uint32(userlib.AESKeySize))
	encryptedFileStructureBytes, isFileStrucExist := userlib.DatastoreGet(oldFileStructureLocation)
	if !isFileStrucExist {
		ErrorWrapper("FileStructure Content not found in Datastore", &err)
		return
	}
	if decodeError2 != nil {
		ErrorWrapper("Decoding String error in revoke file", &err)
		return
	}
	//Decrypt structure, Verify HMAC, Encrypt using new Key
	var file File
	if len(encryptedFileStructureBytes) < userlib.BlockSize {
		ErrorWrapper("Error in Decryption", &err)
		return
	}
	_, fileStructureBytes := Decryption(encryptedFileStructureBytes, oldEncryptionKey2Bytes)
	unmarshalError := json.Unmarshal(fileStructureBytes, &file)

	if unmarshalError != nil {
		ErrorWrapper("Unmarshalling error in file structure", &err)
		return
	}
	if !file.VerifyHMAC(oldEncryptionKey2Bytes, &err) {
		return
	}

	//Place new encrypted content and file structure in Datastore
	EncryptAgain(&file, oldEncryptionKey2Bytes, newEncryptionKey2Bytes,
		newEncryptionKey1Bytes, newFileStructureLocation, &err)
	if err != nil {
		return
	}
	userdata.FileDetails[filename][0] = newEncryptionKey1

	//Make the change in fileMetaLoc : NewX + HMAC(NewX)
	var message Message
	message.AddMessage(newFileStructureLocation, newEncryptionKey1)
	messageBytes, err := message.GetBytes()
	if err != nil {
		ErrorWrapper("Error Occured in Message Marshaling", &err)
	}
	_, fileMetaDataBytes := Encryption(messageBytes, newEncryptionKey1Bytes)
	fileMetaLocation := fileMeta[1]
	userlib.DatastoreSet(fileMetaLocation, fileMetaDataBytes)

	UpdateUserData(userdata)
	userlib.DatastoreDelete(oldFileStructureLocation)

	return
}

//StoreFile : This stores a file in the datastore.
//
// StoreFile : function used to create a  file
func (userdata *User) StoreFile(filename string, data []byte) {
	var fileMetaLocation string
	var err error
	userdata.ReloadUserDS(&err)
	if err != nil {
		panic("User Data structure is been modified or corrupted")
	}

	fileMeta, exist := userdata.FileDetails[filename]
	if exist && len(fileMeta) == 2 {
		fileMetaLocation = fileMeta[1]
	} else {
		randomString1 := userlib.RandomBytes(16)
		fileMetaLocation = GenerateSha256Hash(randomString1)
	}
	randomString2 := userlib.RandomBytes(16)
	fileStructureLocation := GenerateSha256Hash(randomString2)
	fileStructureLocationBytes, err1 := hex.DecodeString(fileStructureLocation)
	if err1 != nil {
		panic("Decode Error : File Structure location might be modifed or data might be modified")
	}

	//KeyGeneration
	passwordBytes := []byte(userdata.PasswordHash)
	encryptionKey1Bytes := userlib.Argon2Key(randomString2, passwordBytes, 16)
	encryptionKey2Bytes := userlib.Argon2Key(fileStructureLocationBytes, encryptionKey1Bytes, 16)
	encryptionKey1 := hex.EncodeToString(encryptionKey1Bytes)
	var file File
	var storeError error
	file.Append(data, encryptionKey2Bytes)                                  //add new contentLocation to FileStructure, place content
	file.StoreFile(fileStructureLocation, encryptionKey2Bytes, &storeError) //encrypt Filestructure and place in DS
	if storeError != nil {
		panic("Error Occured while storing the file or data might be modified")
	}
	//Storing the  Locations
	var message Message
	message.AddMessage(fileStructureLocation, encryptionKey1)
	messageBytes, err := message.GetBytes()
	if err != nil {
		panic("Error Occured marshalling the file structure location or data might be modified")
	}

	_, fileMetaDataBytes := Encryption(messageBytes, encryptionKey1Bytes)
	//X-> fileStructurelocation
	userlib.DatastoreSet(fileMetaLocation, fileMetaDataBytes)

	userdata.FileDetails[filename] = []string{encryptionKey1, fileMetaLocation}

	// Make this change in User Data structure in Datastore.
	UpdateUserData(userdata)

}

//ReloadUserDS : Reloads userdata from datastore into userdata pointer
func (userdata *User) ReloadUserDS(err *error) {
	dataLocation := userdata.UserDataLocation
	userDSkey, decodeError := hex.DecodeString(userdata.UserDataEncryptionKey)
	if decodeError != nil {
		ErrorWrapper("Error while decoding string in ReloadUser 1", err)
		return
	}
	userdataBytes, userExists := userlib.DatastoreGet(dataLocation)
	if !userExists {
		ErrorWrapper("User Data Location is corrupted or User data not found", err)
		return
	}
	var newUserData User
	var msg Message
	if len(userdataBytes) < userlib.BlockSize {
		ErrorWrapper("Error in Decryption", err)
		return
	}
	_, decryptedUserDataBytes := Decryption(userdataBytes, userDSkey)
	unmarshalError := json.Unmarshal(decryptedUserDataBytes, &msg)
	if unmarshalError != nil {
		ErrorWrapper("Unmarshalling error in reloaduserDS", err)
		return
	}
	//Verify HMAC
	informationBytes, decodeerror := hex.DecodeString(msg.Information)
	if decodeerror != nil {
		ErrorWrapper("Error while decoding string in ReloadUser 2", err)
		return
	}
	msgHMAC := GenerateHMAC(informationBytes, userDSkey)
	if msgHMAC != msg.Hash {
		ErrorWrapper("HMAC Unequal. Integrity failed. Data has been changed", err)
		return
	}
	unmarshalError = json.Unmarshal(informationBytes, &newUserData)
	if unmarshalError != nil {
		ErrorWrapper("Unmarshalling error in reloaduser ds", err)
		return
	}

	userdata.FileDetails = newUserData.FileDetails
	userdata.Username = newUserData.Username
	userdata.Salt = newUserData.Salt
	userdata.PasswordHash = newUserData.PasswordHash
	userdata.UserPrivateKey = newUserData.UserPrivateKey

}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.
// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
type sharingRecord struct {
	FileMetaLoc string
	Key         string
}

//Converts sharingRecord struct to bytes
func (sharingData sharingRecord) GetBytes() (bytes []byte, err error) {
	jsonData, err := json.Marshal(sharingData)
	if err != nil {
		ErrorWrapper("Marshalling Error in sharing Record", &err)
	}
	return jsonData, err
}

//Has encrypted sharing message and RSA Signature
type sharingMesg struct {
	Message   string
	Signature string
}

//Converts sharingMesg to bytes
func (sharingMsg sharingMesg) GetBytes() (bytes []byte, err error) {
	jsonData, err := json.Marshal(sharingMsg)
	if err != nil {
		ErrorWrapper("Marshalling Error", &err)
	}
	return jsonData, err
}

// Message : sturcture used to store information with hash in the data store
type Message struct {
	Information string
	Hash        string
}

// GetBytes : function used to convert the struct to bytes
func (message Message) GetBytes() (bytes []byte, err error) {
	jsonData, err := json.Marshal(message)
	if err != nil {
		ErrorWrapper("Error Occured while Marshalling the Message, It might be corruped or modified", &err)
	}
	return jsonData, err
}

//GetMessage : function used to get the message structure and will check the hash
func (message *Message) GetMessage(bytes []byte, key string) bool {
	err := json.Unmarshal(bytes, message)
	if err != nil {
		return false
	}
	keyBytes := []byte(key)
	messageBytes := []byte(message.Information)
	hash := GenerateHMAC(messageBytes, keyBytes)
	return hash == message.Hash
}

//AddMessage : function used to add the message  in to the message structure ,hash
func (message *Message) AddMessage(information, key string) {
	message.Information = information
	keyBytes := []byte(key)
	messageBytes := []byte(information)
	message.Hash = GenerateHMAC(messageBytes, keyBytes)
}

//File : File structure used to store the file content details and hash
type File struct {
	ContentLocations []Message
	Hash             string
	AppendCount      int
}

//GetBytes : function used to convert the struct to bytes
func (file File) GetBytes() (bytes []byte, err error) {
	fileBytes, err := json.Marshal(file)
	if err != nil {
		ErrorWrapper("Error Occured while Marshalling the fileBytes, It might be corruped or modified", &err)
	}
	return fileBytes, err
}

//VerifyHMAC : function verifies signature
func (file *File) VerifyHMAC(encryptionKey []byte, err *error) bool {

	contentDataBytes, er := json.Marshal(file.ContentLocations)
	if er != nil {
		ErrorWrapper("HMAC Verification Failed.", err)
		return false
	}
	hmacString := GenerateHMAC(contentDataBytes, encryptionKey)
	if hmacString != file.Hash {
		ErrorWrapper("HMAC Verification Failed.", err)
		return false
	}
	return true
}

//Append : function used to encrypt and append content to file structure
func (file *File) Append(message, encryptedKey2 []byte) {

	contentLocation := GenerateSha256Hash(userlib.RandomBytes(16))

	hashOfContent := GenerateHMAC(message, encryptedKey2)

	var content = Message{Information: contentLocation, Hash: hashOfContent}

	file.ContentLocations = append(file.ContentLocations, content)
	file.AppendCount++

	_, cipherTextBytes := Encryption(message, encryptedKey2)
	userlib.DatastoreSet(contentLocation, cipherTextBytes)
}

//GetFileContent : function used to decrypt and get the content of the file
func (file File) GetFileContent(encryptedKey2 []byte) (data []byte, err error) {
	var fileContent strings.Builder
	for _, contentLocation := range file.ContentLocations {
		cipheredContentBytes, exist := userlib.DatastoreGet(contentLocation.Information)
		if exist {
			if len(cipheredContentBytes) < userlib.BlockSize {
				ErrorWrapper("Error in Decryption", &err)
				return nil, err
			}
			_, contentBytes := Decryption(cipheredContentBytes, encryptedKey2)
			contentHash := GenerateHMAC(contentBytes, encryptedKey2)
			if contentHash == contentLocation.Hash {
				fileContent.Write(contentBytes)
			} else {
				ErrorWrapper("Hash of the file content is not matching, It might have modified", &err)
				break
			}
		} else {
			ErrorWrapper("Content Location Not found or It might have modified", &err)
			break
		}
	}
	if fileContent.Len() > 0 {
		data = []byte(fileContent.String())
	}

	return data, err
}

//StoreFile : function used to encrypt and store  the content into the file structure
func (file *File) StoreFile(fileStructureLocation string, encryptedKey2 []byte, err *error) {
	if file.AppendCount > 0 {
		fileBytes, err1 := json.Marshal(file.ContentLocations)
		if err1 == nil {
			file.Hash = GenerateHMAC(fileBytes, encryptedKey2)
			fileBytes, err2 := file.GetBytes()
			if err2 == nil {
				_, cipheredFileBytes := Encryption(fileBytes, encryptedKey2)
				userlib.DatastoreSet(fileStructureLocation, cipheredFileBytes)
			} else {
				ErrorWrapper("Error Occured while marshalling the file structure", err)
			}
		} else {
			ErrorWrapper("Error occured while Unmarshalling the file content location, It might have be corrupted or modified", err)
		}

	} else {
		ErrorWrapper("Trying to store an empty file", err)
	}
	return
}

//GetFile : Used get the file data structure  given the bytes
func (file *File) GetFile(bytes, key []byte) bool {
	err := json.Unmarshal(bytes, file)
	if err != nil {
		return false
	}
	fileBytes, err := json.Marshal(file.ContentLocations)
	fileHash := GenerateHMAC(fileBytes, key)
	return file.Hash == fileHash
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.
// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the user has a STRONG password
// TODO : Check if user alreday exists

//InitUser : function used to create user
func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	byteArr, passwordByteArr, usernameByteArr := ConvertToBytes(username, password)
	userDataLocation := GenerateSha256Hash(byteArr) //corresponds to H1 in Design Document

	//Check if user already exists
	_, userExist := userlib.DatastoreGet(userDataLocation)
	if userExist {
		ErrorWrapper("User already exists", &err)
		return
	}
	(&userdata).SetUserData(username, password, userDataLocation)
	EncryptionKey1 := userlib.Argon2Key(passwordByteArr, usernameByteArr, uint32(userlib.AESKeySize))

	privateKey, err := GenerateRSAKeyWrapper()
	pubKey := privateKey.PublicKey
	userdata.UserPrivateKey = *privateKey
	userdata.FileDetails = make(map[string][]string)
	userdata.UserDataEncryptionKey = hex.EncodeToString(EncryptionKey1)

	//convert user data to bytes and generate hmac
	jsonDataUserDS, err := userdata.GetBytes()
	hmacString := GenerateHMAC(jsonDataUserDS, EncryptionKey1)

	//assign it to Message object, marshall it then encrypt
	message := Message{hex.EncodeToString(jsonDataUserDS), hmacString}
	unencryptedMessageBytes, err := message.GetBytes()
	_, encryptedMessageBytes := Encryption(unencryptedMessageBytes, EncryptionKey1)

	userlib.DatastoreSet(userDataLocation, encryptedMessageBytes)
	userlib.KeystoreSet(username, pubKey)

	return &userdata, err
}

// GetUser : This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
//GetUser : function used to get the user details
func GetUser(username string, password string) (userdataptr *User, err error) {

	byteArr, passwordByteArr, usernameByteArr := ConvertToBytes(username, password)
	userDataLocation := GenerateSha256Hash(byteArr) //corresponds to H1 in Design Document
	jsonData, ok := userlib.DatastoreGet(userDataLocation)
	EncryptionKey1 := userlib.Argon2Key(passwordByteArr, usernameByteArr, uint32(userlib.AESKeySize))
	userdataptr = nil
	if !ok {
		ErrorWrapper("Username Password Verification Unsuccessful", &err)
		return
	}
	var msg Message
	if len(jsonData) < userlib.BlockSize {
		ErrorWrapper("Error in Decryption", &err)
		return
	}
	_, decryptedMessageBytes := Decryption(jsonData, EncryptionKey1)

	unmarshalError := json.Unmarshal(decryptedMessageBytes, &msg)
	if unmarshalError != nil {
		ErrorWrapper("Unmarshalling error in Get User 1", &err)
		return
	}
	informationBytes, _ := hex.DecodeString(msg.Information)
	msgHMAC := GenerateHMAC(informationBytes, EncryptionKey1)
	if msgHMAC != msg.Hash {
		ErrorWrapper("HMAC Unequal. Integrity failed. Data has been changed", &err)
		return
	}
	var userdata User
	unmarshalError = json.Unmarshal(informationBytes, &userdata)
	if unmarshalError != nil {
		ErrorWrapper("Unmarshalling error in Get User 2", &err)
		return
	}
	userdataptr = &userdata

	return
}

//GenerateSha256Hash : function used to generate the hash for the given the message
func GenerateSha256Hash(message []byte) (encodedString string) {
	sha256 := userlib.NewSHA256()
	sha256.Write(message)
	hash := sha256.Sum(nil)
	return hex.EncodeToString(hash)
}

//Encryption : function used to encrypt the given message
func Encryption(message, key []byte) (encodedString string, encodedBytes []byte) {

	cipher := make([]byte, userlib.BlockSize+len(message))
	copy(cipher[:userlib.BlockSize], string(len(message)))
	iv := cipher[:userlib.BlockSize]
	cfbEncrypter := userlib.CFBEncrypter(key, iv)
	cfbEncrypter.XORKeyStream(cipher[userlib.BlockSize:], message)
	return hex.EncodeToString(cipher), cipher
}

//Decryption : function used to decrypt the given cipher
func Decryption(cipher, key []byte) (encodedString string, encodedBytes []byte) {
	iv := cipher[:userlib.BlockSize]
	ciphertext := cipher[userlib.BlockSize:]
	cfbDecrypter := userlib.CFBDecrypter(key, iv)
	cfbDecrypter.XORKeyStream(ciphertext, ciphertext)
	return hex.EncodeToString(ciphertext), ciphertext
}

//GenerateHMAC : function used to generate hmac for the given message
func GenerateHMAC(message []byte, keyHMAC []byte) string {
	hmacObj := userlib.NewHMAC(keyHMAC)
	hmacObj.Write(message)
	return hex.EncodeToString(hmacObj.Sum(nil))
}

//InitiateAppend : function used to append and encrypt the file.
func InitiateAppend(fileStructureLocation string, message, encryptedKey1Bytes []byte, err *error) {
	var getFileStructure error
	file, encryptedKey2Bytes, isValid := GetFileStructure(fileStructureLocation, encryptedKey1Bytes, &getFileStructure)
	if isValid && getFileStructure == nil {
		file.Append(message, encryptedKey2Bytes)
		file.StoreFile(fileStructureLocation, encryptedKey2Bytes, err)
	} else {
		ErrorWrapper("Error Occured GetFileStructure, It may be modified or invalid ", err)
	}
	return
}

//GenerateRSAKeyWrapper : function used to public and private key pair.
func GenerateRSAKeyWrapper() (*userlib.PrivateKey, error) {
	privateKey, err := userlib.GenerateRSAKey()
	if err != nil {
		ErrorWrapper("Error Occured while generating the public key private key pair", &err)
	}
	return privateKey, err
}

//ConvertToBytes : function used get bytes of the given username and password.
func ConvertToBytes(username, password string) (byteArr, passwordByteArr, usernameByteArr []byte) {
	byteArr = []byte(username + password)
	passwordByteArr = []byte(password)
	usernameByteArr = []byte(username)
	return
}

//GetFileStructureLocation : function used get location of file structure.
func GetFileStructureLocation(fileMetaData []string, err *error) (fileStructureLocation string, encryptedKey1Bytes []byte) {

	encryptedKey1 := fileMetaData[0]
	fileMetaLocation := fileMetaData[1]
	encryptedKey1Bytes, decodeError := hex.DecodeString(encryptedKey1)
	fileMetaBytes, isFileMetaExist := userlib.DatastoreGet(fileMetaLocation)
	if decodeError == nil && isFileMetaExist {
		if len(fileMetaBytes) < userlib.BlockSize {
			ErrorWrapper("Error in Decryption", err)
			return
		}
		_, messageBytes := Decryption(fileMetaBytes, encryptedKey1Bytes)
		var message Message

		if message.GetMessage(messageBytes, encryptedKey1) {

			fileStructureLocation = message.Information
		} else {
			ErrorWrapper("Hash of the file meta is not matching or been modified", err)
		}
	} else {
		ErrorWrapper("File Meta not found or File meta data might be modified", err)
	}
	return
}

//GetFileStructure : function used get file structe from the data store
func GetFileStructure(fileStructureLocation string, encryptedKey1Bytes []byte, err *error) (*File, []byte, bool) {
	cipheredFileStructure, isExist := userlib.DatastoreGet(fileStructureLocation)
	if isExist {

		fileStructureLocationBytes, decodeError := hex.DecodeString(fileStructureLocation)
		if decodeError == nil {

			encryptedKey2Bytes := userlib.Argon2Key(fileStructureLocationBytes, encryptedKey1Bytes, 16)
			if len(cipheredFileStructure) < userlib.BlockSize {
				ErrorWrapper("Error in Decryption", err)
				return nil, nil, false
			}
			_, fileStructureBytes := Decryption(cipheredFileStructure, encryptedKey2Bytes)
			var file File
			if file.GetFile(fileStructureBytes, encryptedKey2Bytes) {

				return &file, encryptedKey2Bytes, true

			}

			ErrorWrapper("Hashes of the file structure is not matching", err)

		} else {

			ErrorWrapper("Error while decoding file structue, It might be corrupted or modified", err)

		}
	} else {

		ErrorWrapper("File structure not found or File meta data is not matching", err)
	}
	return nil, nil, false

}

//ErrorWrapper : function used handle the error messages
func ErrorWrapper(errorMsg string, err *error) {
	*err = errors.New(strings.ToTitle(errorMsg))
}

//UpdateUserData : Updates userdata pointer data into data store
func UpdateUserData(userdata *User) (err error) {
	encryptionUserDataKey, _ := hex.DecodeString(userdata.UserDataEncryptionKey)
	jsonDataUserDS, er := userdata.GetBytes()
	if er != nil {
		ErrorWrapper("Error in UserData Extraction", &err)
		return
	}
	hmacString := GenerateHMAC(jsonDataUserDS, encryptionUserDataKey)

	msg := Message{hex.EncodeToString(jsonDataUserDS), hmacString}
	unencryptedMessageBytes, er2 := msg.GetBytes()
	if er2 != nil {
		ErrorWrapper("Error in UserData Extraction : msg.GetBytes", &err)
		return
	}
	_, encryptedMessageBytes := Encryption(unencryptedMessageBytes, encryptionUserDataKey)
	userDataLocation := userdata.UserDataLocation
	userlib.DatastoreSet(userDataLocation, encryptedMessageBytes)
	return
}

//EncryptAgain : Encrypts File Structure and Content again using new keys and locations passed
func EncryptAgain(file *File, oldEncryptionKey2Bytes []byte, newEncryptionKey2Bytes []byte,
	newEncryptionKey1Bytes []byte, newFileStructureLocation string, err *error) {
	var data []byte
	data, *err = file.GetFileContent(oldEncryptionKey2Bytes) //check
	if *err != nil {
		return
	}
	var newfile File
	newfile.Append(data, newEncryptionKey2Bytes)
	newfile.StoreFile(newFileStructureLocation, newEncryptionKey2Bytes, err)
	if *err != nil {
		return
	}
}
