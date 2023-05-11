package plc

import (
	"bytes"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"strings"

	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
	cbor "github.com/whyrusleeping/cbor-gen"
)

func formatHandle(handle string) string {
	if !strings.HasPrefix(handle, "at://") {
		handle = strings.TrimPrefix(strings.TrimPrefix(handle, "https://"), "http://")
		handle = "at://" + handle
	}
	return handle
}

func didForCreateOp(op cbor.CBORMarshaler) (string, error) {
	buf := new(bytes.Buffer)
	if err := op.MarshalCBOR(buf); err != nil {
		return "", err
	}

	h := sha256.Sum256(buf.Bytes())
	enchash := base32.StdEncoding.EncodeToString(h[:])
	enchash = strings.ToLower(enchash)
	return "did:plc:" + enchash[:24], nil
}

func getOperation(data json.RawMessage) (Operation, error) {
	dc := &operationChecker{}
	err := json.Unmarshal(data, dc)
	if err != nil {
		return nil, err
	}

	var o Operation
	switch dc.getType() {
	case string(create):
		o = &Create{}
		err := json.Unmarshal(data, o)
		if err != nil {
			return nil, err
		}
	case string(update):
		o = &Update{}
		err := json.Unmarshal(data, o)
		if err != nil {
			return nil, err
		}
	case string(tombstone):
		o = &Tombstone{}
		err := json.Unmarshal(data, o)
		if err != nil {
			return nil, err
		}
	}
	return o, nil
}

func getCID(op Operation) (string, error) {
	c, ok := op.(cbor.CBORMarshaler)
	if !ok {
		return "", fmt.Errorf("not cbor compatible")
	}

	buf := new(bytes.Buffer)
	err := c.MarshalCBOR(buf)
	if err != nil {
		return "", err
	}

	pref := cid.Prefix{
		Version:  1,
		Codec:    cid.DagCBOR,
		MhType:   mh.SHA2_256,
		MhLength: -1, // default length
	}

	prev, err := pref.Sum(buf.Bytes())
	if err != nil {
		return "", err
	}
	return prev.String(), nil
}

func getNextUpdate(op Operation, next func(*Update)) (*Update, error) {
	prev, err := getCID(op)
	if err != nil {
		return nil, err
	}

	nop := &Update{
		Type: update,
		Prev: &prev,

		RotationKeys:        op.getRecoveryKeys(),
		VerificationMethods: op.getVerificationMethods(),
		AlsoKnownAs:         op.getAlsoKnownAs(),
		Services:            op.getServices(),
	}

	next(nop)
	return nop, nil
}
