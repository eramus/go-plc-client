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

var ErrNotCBORCompatible = fmt.Errorf("plc client: not cbor compatible")
var ErrUnknownOperationType = fmt.Errorf("plc client: unknown operation type")

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
	switch dc.GetType() {
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
	default:
		return nil, ErrUnknownOperationType
	}
	return o, nil
}

func getCID(op Operation) (string, error) {
	c, ok := op.(cbor.CBORMarshaler)
	if !ok {
		return "", ErrNotCBORCompatible
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

		RotationKeys:        op.GetRotationKeys(),
		VerificationMethods: op.GetVerificationMethods(),
		AlsoKnownAs:         op.GetAlsoKnownAs(),
		Services:            op.GetServices(),
	}

	next(nop)
	return nop, nil
}
