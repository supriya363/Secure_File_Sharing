package assn1

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/fenilfadadu/CS628-assn1/userlib"
)

// You can actually import other stuff if you want IN YOUR TEST
// HARNESS ONLY.  Note that this is NOT considered part of your
// solution, but is how you make sure your solution is correct.

func TestInit(t *testing.T) {
	t.Log("Initialization test")
	userlib.DebugPrint = true
	//	someUsefulThings()

	userlib.DebugPrint = false
	_, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
	}
	// t.Log() only produces output if you run with "go test -v"
	// You probably want many more tests here.

	//added
	_, err2 := GetUser("alice", "fubar")
	if err2 != nil {
		// t.Error says the test fails
		t.Error("Failed to reload user", err)
	}

}

func TestStorage(t *testing.T) {

	// And some more tests, because
	_, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
	}
	u1, err := GetUser("alice", "fubar")
	u2, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}

	v1 := []byte("This is a test user 1")
	v2 := []byte("This is a test user 2")
	u1.StoreFile("file1", v1)
	u2.StoreFile("file1", v2)
	l1, err := u1.LoadFile("file1")
	if err != nil {
		t.Error("Error Occured while load file", err)
		return
	}

	err = u1.AppendFile("file1", v2)
	if err != nil {
		t.Error("Error Occured while load file", err)
		return
	}

	l2, err := u1.LoadFile("file1")
	if err != nil {
		t.Error("Error Occured while load file", err)
		return
	}

	l2, _ = u2.LoadFile("file1")

	l1Str := string(l1)
	l2Str := string(l2)

	u2.StoreFile("file1", v2)
	u1.StoreFile("file1", v1)
	userlib.DebugMsg(l1Str, l2Str)
	l1, _ = u1.LoadFile("file1")
	l2, _ = u2.LoadFile("file1")

	l1Str = string(l1)
	l2Str = string(l2)

	a1 := []byte("Append 1")
	a2 := []byte("Append 2")
	u1.AppendFile("file1", a1)
	u2.AppendFile("file1", a2)

	l1, _ = u1.LoadFile("file1")
	l2, _ = u2.LoadFile("file1")

	l1Str = string(l1)
	l2Str = string(l2)

	// t.Log("Loaded user : ", u1)

	// v2 := []byte("This is a test user 2")
	// u2.AppendFile("file1", v2)

	// l1, err2 := u.LoadFile("file1")

	// l2, err2 := u2.LoadFile("file1")
	// if err2 != nil {
	// 	t.Error("Failed to upload and download", err2)
	// }
	// if !reflect.DeepEqual(l1, l2) {
	// 	t.Error("Downloaded file is not the same", v, v2)
	// }
	// // And some more tests, because
	// userlib.DebugPrint = true

	// //changed by supriya
	// un, err := InitUser("alice", "fubar")
	// if err != nil {
	// 	// t.Error says the test fails
	// 	t.Error("Failed to initialize user", err)
	// }
	// // t.Log() only produces output if you run with "go test -v"
	// t.Log("Got user", un)
	// //changes ended

	// u, err := GetUser("alice", "fubar")
	// if err != nil {
	// 	t.Error("Failed to reload user", err)
	// 	return
	// }
	// t.Log("Loaded user", u)

	// v := []byte("This is a test")
	// u.StoreFile("file1", v)

	// v2 := []byte("This is a test23")

	// v2, err2 := u.LoadFile("file1")
	// if err2 != nil {
	// 	t.Error("Failed to upload and download", err2)
	// }
	// if !reflect.DeepEqual(v, v2) {
	// 	t.Error("Downloaded file is not the same", v, v2)
	// }
}

func TestDoubleStore(t *testing.T) {

	u1, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload alice", err)
	}

	v1, err3 := u1.LoadFile("file1")
	if err3 != nil {
		t.Error("No file1. Failed to upload and download", err3)
	}
	fmt.Print("After 1st Store : ", string(v1))
	v := []byte("This is new Test")
	u1.StoreFile("file1", v)
	v2, err5 := u1.LoadFile("file1")
	if err3 != nil {
		t.Error("Load Prob. Failed to upload and download", err5)
	}
	fmt.Print("After 2nd store: ", string(v2))

}

func TestAppend(t *testing.T) {
	u1, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload alice", err)
	}
	v1, err3 := u1.LoadFile("file1")
	if err3 != nil {
		t.Error("No file1. Failed to upload and download", err3)
	}
	fmt.Print("Old Content : ", string(v1))
	u1.AppendFile("file1", []byte("..Appended some data.."))
	v2, err2 := u1.LoadFile("file1")
	if err2 != nil {
		t.Error("No file1. Failed to upload and download", err3)
	}
	fmt.Print("\nCurrent Content : ", string(v2))
	u1.AppendFile("file1", []byte("..Appended more data.."))
	v2, err2 = u1.LoadFile("file1")
	if err2 != nil {
		t.Error("No file1. Failed to upload and download", err3)
	}
	fmt.Print("\nCurrent Content : ", string(v2))
}

func TestBasicShare(t *testing.T) {
	u1, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload alice", err)
	}
	u2, err2 := InitUser("bob", "1234")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
	}
	var v, v2 []byte
	v, err = u1.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
	}
	fmt.Print("Alice's Content := ", string(v))
	var msgid string
	msgid, err = u1.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
	}
	err = u2.ReceiveFile("file2", "alice", msgid)
	if err != nil {
		t.Error("Failed to receive the share message", err)
	}

	v2, err = u2.LoadFile("file2")
	fmt.Print("Bob's Content := ", string(v2))
	//test
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
	}

}

func TestAppendShare(t *testing.T) {
	var err error
	var u1, u2 *User
	var v1, v2 []byte
	u1, err = GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload alice", err)
	}
	u2, err = GetUser("bob", "1234")
	if err != nil {
		t.Error("Failed to reload alice", err)
	}

	err = u1.AppendFile("file1", []byte("Appended by alice"))
	v2, err = u2.LoadFile("file2")
	fmt.Println(string(v2))
	err = u2.AppendFile("file2", []byte("Appended by bob"))
	v1, err = u1.LoadFile("file1")
	fmt.Println(string(v1))
}

func TestTransitiveShare(t *testing.T) {
	// var err error
	// var u1, u2, u3 *User
	var v1, v2, v3 []byte
	var err error
	var u1, u3 *User
	// var v3 []byte
	u1, err = GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload alice", err)
	}
	_, err = GetUser("bob", "1234")
	if err != nil {
		t.Error("Failed to reload alice", err)
	}
	u3, err = InitUser("suppu", "stupid")
	if err != nil {
		t.Error("Failed to Initialize arun", err)
	}
	var msgid string
	//alice shares with suppu
	msgid, err = u1.ShareFile("file1", "suppu")
	if err != nil {
		t.Error("Failed to share the a file", err)
	}
	//suppu receives file
	err = u3.ReceiveFile("file3", "alice", msgid)
	if err != nil {
		t.Error("Failed to receive the share message", err)
	}
	v3, err = u3.LoadFile("file3")
	if err != nil {
		t.Error("Failed to load message", err)
	}

	fmt.Print("Current Content: ", string(v3), "\n")
	//suppu shares file with alice
	msgid, err = u3.ShareFile("file3", "alice")
	if err != nil {
		t.Error("Failed to share the a file", err)
	}
	//alice receives the file
	err = u1.ReceiveFile("file3", "suppu", msgid)
	if err != nil {
		t.Error("Failed to receive the share message", err)
	}
	fmt.Println("____________________________")
	v1, err = u1.LoadFile("file1")

	v2, err = u1.LoadFile("file3")
	fmt.Print("Before: \n", string(v1), "\n", string(v2), "\n")
	err = u1.AppendFile("file1", []byte("Added to file1"))
	v1, err = u1.LoadFile("file1")
	if err != nil {
		t.Error("Failed to load file1", err)
	}
	v2, err = u1.LoadFile("file3")
	if err != nil {
		t.Error("Failed to load file3", err)
	}
	fmt.Print("After : \n", string(v1), "\n", string(v2)+"\n")

	//Duplicate Share Test

}

func TestRevoke(t *testing.T) {
	var v1 []byte
	var err error
	var u1, u2 *User
	// var v3 []byte
	u1, err = InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload alice", err)
	}
	u2, err = InitUser("bob", "1234")
	if err != nil {
		t.Error("Failed to reload alice", err)
	}
	_, err = InitUser("suppu", "stupid")
	if err != nil {
		t.Error("Failed to reload suppu", err)
	}
	u1.StoreFile("file1", []byte("12345"))
	fmt.Print("Alice has stored data into file\n")
	var msguid string
	msguid, err = u1.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share file1", err)
	}
	err = u2.ReceiveFile("file2", "alice", msguid)
	if err != nil {
		t.Error("Failed to receive file2", err)
	}

	v1, err = u2.LoadFile("file2")

	fmt.Print("\nBob's can see: \n", string(v1), "\n")
	err = u1.RevokeFile("file1")
	if err != nil {
		t.Error("Failed to revoke file1", err)
	}
	v1, err = u1.LoadFile("file1")
	if err != nil {
		t.Error("Failed to load file1", err)
	}
	fmt.Print("ALICE: \n", string(v1))

	_, err = u2.LoadFile("file2")
	if err == nil {
		t.Error("Bob still able to access file", err)
	}

}

func TestMutateShare(t *testing.T) {
	// var v1 []byte
	var err error
	var u1, u2 *User
	// var v3 []byte
	u1, err = InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload alice", err)
	}
	u2, err = InitUser("bob", "1234")
	if err != nil {
		t.Error("Failed to reload alice", err)
	}
	_, err = InitUser("suppu", "stupid")
	if err != nil {
		t.Error("Failed to reload suppu", err)
	}
	u1.StoreFile("file1", []byte("12345"))
	fmt.Print("Alice has stored data into file\n")
	var msguid string
	msguid, err = u1.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share file1", err)
	}
	err = u2.ReceiveFile("file2", "alice", msguid)
	if err != nil {
		t.Error("Failed to receive file2", err)
	}
	userlib.DatastoreSet(u2.UserDataLocation, []byte("1234"))
	_, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to load", err)
	}
	// fmt.Print("\nBob's can see: \n", string(v1), "\n")
	// err = u1.RevokeFile("file1")
	// if err != nil {
	// 	t.Error("Failed to revoke file1", err)
	// }
	// v1, err = u1.LoadFile("file1")
	// if err != nil {
	// 	t.Error("Failed to load file1", err)
	// }
	// fmt.Print("ALICE: \n", string(v1))

	// _, err = u2.LoadFile("file2")
	// if err == nil {
	// 	t.Error("Bob still able to access file", err)
	// }
	// err = u2.ReceiveFile("file3", "alice", msguid)
	// if err != nil {
	// 	t.Error("Failed to receive file3", err)
	// }

}

// func TestShare2(t *testing.T)
// {
// 	u1, err := InitUser("supriya", "1234")
// 	if err != nil {
// 		t.Error("Failed to initialize supriya", err)
// 	}
// 	u2, err2 := InitUser("arun", "5678")
// 	if err2 != nil {
// 		t.Error("Failed to initialize arun", err2)
// 	}

// 	var v1, v2 []byte
// 	v1 = userlib.RandomBytes(4)
// 	var msgid string
// 	u1.StoreFile("file1", v1)
// 	msgid, err = u1.ShareFile("file1", "arun")
// 	if err != nil {
// 		t.Error("Failed to share the a file", err)
// 	}

// 	err = u2.ReceiveFile("file2", "supriya", msgid)
// 	if err != nil {
// 		t.Error("Failed to receive the share message", err)
// 	}
// 	v2, err = u2.LoadFile("file2")
// 	if err != nil {
// 		t.Error("Failed to download the file after sharing", err)
// 	}
// 	if !reflect.DeepEqual(v1, v2) {
// 		t.Error("Shared file is not the same", v1, v2)
// 	}
// 	err = u1.AppendFile("file1", userlib.RandomBytes(6))
// 	if err != nil {
// 		t.Error("Failed to append", err)
// 	}
// 	v2, err = u2.LoadFile("file2")
// 	if err != nil {
// 		t.Error("Failed to download the file after sharing", err)
// 	}
// 	if reflect.DeepEqual(v1, v2) {
// 		t.Error("Shared file is not the same", v1, v2)
// 	}

// 	err = u1.RevokeFile("file1")
// 	if err != nil {
// 		t.Error("Failed to revoke access", err)
// 	}
// 	v2, err = u2.LoadFile("file2")
// 	if err != nil {
// 		t.Error("Failed to download the file after sharing", err)
// 	}

// 	if !reflect.DeepEqual(v1, v2) {
// 		t.Error("Shared file is not the same", v1, v2)
// 	}
// }

// func TestShare(t *testing.T) {

// 	//Original TestShare
// 	u, err := GetUser("alice", "fubar")
// 	if err != nil {
// 		t.Error("Failed to reload user", err)
// 	}
// 	u2, err2 := InitUser("bob", "foobar")
// 	if err2 != nil {
// 		t.Error("Failed to initialize bob", err2)
// 	}

// 	var v, v2 []byte
// 	var msgid string

// 	v, err = u.LoadFile("file1")
// 	if err != nil {
// 		t.Error("Failed to download the file from alice", err)
// 	}

// 	msgid, err = u.ShareFile("file1", "bob")
// 	if err != nil {
// 		t.Error("Failed to share the a file", err)
// 	}
// 	err = u2.ReceiveFile("file2", "alice", msgid)
// 	if err != nil {
// 		t.Error("Failed to receive the share message", err)
// 	}

// 	v2, err = u2.LoadFile("file2")
// 	//test
// 	if err != nil {
// 		t.Error("Failed to download the file after sharing", err)
// 	}
// 	if !reflect.DeepEqual(v, v2) {
// 		t.Error("Shared file is not the same", v, v2)
// 	}
// 	//Orginal TestShare ends Here

// }
