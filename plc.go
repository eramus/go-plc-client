package plc

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	cbor "github.com/whyrusleeping/cbor-gen"
	did "github.com/whyrusleeping/go-did"
	otel "go.opentelemetry.io/otel"
)

var ErrIsTombstone = fmt.Errorf("plc client: did is marked as tombstone")

const (
	create    = "create"
	update    = "plc_operation"
	tombstone = "plc_tombstone"
)

type Client struct {
	Host string
	C    *http.Client
}

func New(host string) *Client {
	return &Client{
		Host: host,
		C:    http.DefaultClient,
	}
}

type operationChecker struct {
	Type string `json:"type"`
}

func (oc operationChecker) GetType() string {
	return oc.Type
}

type Operations []Operation

type Operation interface {
	GetType() string
	GetRotationKeys() []string
	GetAlsoKnownAs() []string
	GetServices() map[string]*Service
	GetVerificationMethods() map[string]string
}

type Create struct {
	SigningKey  string `json:"signingKey" cborgen:"signingKey"`
	RecoveryKey string `json:"recoveryKey" cborgen:"recoveryKey"`
	Handle      string `json:"handle" cborgen:"handle"`
	Service     string `json:"service" cborgen:"service"`

	Type string  `json:"type" cborgen:"type"`
	Prev *string `json:"prev" cborgen:"prev"`
	Sig  string  `json:"sig" cborgen:"sig,omitempty"`
}

func (c *Create) GetType() string {
	return create
}

func (c *Create) GetRotationKeys() []string {
	return []string{
		c.RecoveryKey,
		c.SigningKey,
	}
}

func (c *Create) GetAlsoKnownAs() []string {
	return []string{
		c.Handle,
	}
}

func (c *Create) GetServices() map[string]*Service {
	return map[string]*Service{
		"atproto_pds": &Service{
			Type:     "AtprotoPersonalDataServer",
			Endpoint: c.Service,
		},
	}
}

func (c *Create) GetVerificationMethods() map[string]string {
	return map[string]string{
		"atproto": c.SigningKey,
	}
}

func (c *Create) SetSignature(signature string) {
	c.Sig = signature
}

type Update struct {
	RotationKeys        []string            `json:"rotationKeys" cborgen:"rotationKeys"`
	VerificationMethods map[string]string   `json:"verificationMethods" cborgen:"verificationMethods"`
	AlsoKnownAs         []string            `json:"alsoKnownAs" cborgen:"alsoKnownAs"`
	Services            map[string]*Service `json:"services" cborgen:"services"`

	Type string  `json:"type" cborgen:"type"`
	Prev *string `json:"prev" cborgen:"prev"`
	Sig  string  `json:"sig" cborgen:"sig,omitempty"`
}

func (o *Update) GetType() string {
	return update
}

func (o *Update) GetRotationKeys() []string {
	return o.RotationKeys
}

func (o *Update) GetAlsoKnownAs() []string {
	return o.AlsoKnownAs
}

func (o *Update) GetServices() map[string]*Service {
	return o.Services
}

func (o *Update) GetVerificationMethods() map[string]string {
	return o.VerificationMethods
}

func (o *Update) SetSignature(signature string) {
	o.Sig = signature
}

type Tombstone struct {
	Type string  `json:"type" cborgen:"type"`
	Prev *string `json:"prev" cborgen:"prev"`
	Sig  string  `json:"sig" cborgen:"sig,omitempty"`
}

func (t *Tombstone) GetType() string {
	return tombstone
}

func (t *Tombstone) GetRotationKeys() []string {
	return nil
}

func (t *Tombstone) GetAlsoKnownAs() []string {
	return nil
}

func (t *Tombstone) GetServices() map[string]*Service {
	return nil
}

func (t *Tombstone) GetVerificationMethods() map[string]string {
	return nil
}

func (t *Tombstone) SetSignature(signature string) {
	t.Sig = signature
}

type Service struct {
	Type     string `json:"type" cborgen:"type"`
	Endpoint string `json:"endpoint" cborgen:"endpoint"`
}

type Health struct {
	Version string `json:"version"`
}

type AuditLog struct {
	Did       string      `json:"did"`
	Cid       string      `json:"cid""`
	Operation interface{} `json:"operation"`
	Nullified bool        `json:"nullified"`
	CreatedAt time.Time   `json:"createdAt"`
}

type DocumentData struct {
	DID                 string              `json:"did"`
	RotationKeys        []string            `json:"rotationKeys"`
	VerificationMethods map[string]string   `json:"verificationMethods"`
	AlsoKnownAs         []string            `json:"alsoKnownAs"`
	Services            map[string]*Service `json:"services"`
}

type Signable interface {
	cbor.CBORMarshaler

	SetSignature(string)
}

func (c *Client) get(ctx context.Context, url string, body any, parseFn func([]byte) error) error {
	if c.C == nil {
		c.C = http.DefaultClient
	}

	req, err := http.NewRequest("GET", c.Host+"/"+url, nil)
	if err != nil {
		return err
	}

	resp, err := c.C.Do(req.WithContext(ctx))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("get did request failed (code %d): %s", resp.StatusCode, resp.Status)
	}

	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if parseFn != nil {
		err = parseFn(buf)
	} else {
		err = json.Unmarshal(buf, body)
	}
	if err != nil {
		return err
	}
	return nil
}

func (c *Client) GetHealth(ctx context.Context) (*Health, error) {
	ctx, span := otel.Tracer("plc-client").Start(ctx, "plcGetDocument")
	defer span.End()

	var health = Health{}
	return &health, c.get(ctx, "_health", &health, nil)
}

func (c *Client) GetDocument(ctx context.Context, didstr string) (*did.Document, error) {
	ctx, span := otel.Tracer("plc-client").Start(ctx, "plcGetDocument")
	defer span.End()

	var doc = did.Document{}
	return &doc, c.get(ctx, didstr, &doc, nil)
}

func (c *Client) GetDocumentData(ctx context.Context, didstr string) (*DocumentData, error) {
	ctx, span := otel.Tracer("plc-client").Start(ctx, "plcGetDocumentData")
	defer span.End()

	var dd = DocumentData{}
	return &dd, c.get(ctx, didstr+"/data", &dd, nil)
}

func (c *Client) GetOperationLog(ctx context.Context, didstr string) (Operations, error) {
	ctx, span := otel.Tracer("plc-client").Start(ctx, "plcGetOperationLog")
	defer span.End()

	var ops Operations
	parseFn := func(buf []byte) error {
		var chks []json.RawMessage
		if err := json.Unmarshal(buf, &chks); err != nil {
			return err
		}

		for _, chk := range chks {
			d, err := getOperation(chk)
			if err != nil {
				return err
			}
			ops = append(ops, d)
		}
		return nil
	}
	return ops, c.get(ctx, didstr+"/log", ops, parseFn)
}

func (c *Client) GetLastOperation(ctx context.Context, didstr string) (Operation, error) {
	ctx, span := otel.Tracer("plc-client").Start(ctx, "plcGetLastOperation")
	defer span.End()

	var o Operation
	parseFn := func(buf []byte) error {
		var err error
		o, err = getOperation(buf)
		if err != nil {
			return err
		}
		return nil
	}
	return o, c.get(ctx, didstr+"/log/last", o, parseFn)
}

func (c *Client) GetAuditLog(ctx context.Context, didstr string) ([]*AuditLog, error) {
	ctx, span := otel.Tracer("plc-client").Start(ctx, "plcGetAuditLog")
	defer span.End()

	var audit []*AuditLog
	parseFn := func(buf []byte) error {
		var chks []json.RawMessage
		if err := json.Unmarshal(buf, &chks); err != nil {
			return err
		}

		alchk := struct {
			Operation json.RawMessage
		}{}

		for _, chk := range chks {
			if err := json.Unmarshal(chk, &alchk); err != nil {
				return err
			}

			d, err := getOperation(alchk.Operation)
			if err != nil {
				return err
			}

			al := &AuditLog{}
			if err := json.Unmarshal(chk, &al); err != nil {
				return err
			}
			al.Operation = d
			audit = append(audit, al)
		}
		return nil
	}
	return audit, c.get(ctx, didstr+"/log/audit", audit, parseFn)
}

func (c *Client) post(ctx context.Context, signer *did.PrivKey, didstr string, op Signable) (string, error) {
	if c.C == nil {
		c.C = http.DefaultClient
	}

	buf := new(bytes.Buffer)
	if err := op.MarshalCBOR(buf); err != nil {
		return "", err
	}

	sig, err := signer.Sign(buf.Bytes())
	if err != nil {
		return "", err
	}

	op.SetSignature(base64.RawURLEncoding.EncodeToString(sig))

	if len(didstr) == 0 {
		didstr, err = didForCreateOp(op)
		if err != nil {
			return "", err
		}
	}

	body, err := json.Marshal(op)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", c.Host+"/"+url.QueryEscape(didstr), bytes.NewReader(body))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.C.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("bad response from create call: %d %s", resp.StatusCode, resp.Status)
	}
	return didstr, nil
}

func (c *Client) CreateDID(ctx context.Context, signer *did.PrivKey, recoveryDID, handle, pdsEndpoint string) (string, error) {
	ctx, span := otel.Tracer("plc-client").Start(ctx, "plcCreateDID")
	defer span.End()

	op := &Create{
		Type:        create,
		SigningKey:  signer.Public().DID(),
		RecoveryKey: recoveryDID,
		Handle:      formatHandle(handle),
		Service:     pdsEndpoint,
	}
	return c.post(ctx, signer, "", op)
}

func (c *Client) UpdateVerificationMethod(ctx context.Context, signer *did.PrivKey, didstr, keyID, keyDID string) error {
	ctx, span := otel.Tracer("plc-client").Start(ctx, "plcUpdateVerificationMethod")
	defer span.End()

	last, err := c.GetLastOperation(ctx, didstr)
	if err != nil {
		return err
	} else if last.GetType() == tombstone {
		return ErrIsTombstone
	}

	next, err := getNextUpdate(last)
	if err != nil {
		return err
	}
	next.VerificationMethods[keyID] = keyDID

	_, err = c.post(ctx, signer, didstr, next)
	return err
}

func (c *Client) UpdateHandle(ctx context.Context, signer *did.PrivKey, didstr, handle string) error {
	ctx, span := otel.Tracer("plc-client").Start(ctx, "plcUpdateHandle")
	defer span.End()

	last, err := c.GetLastOperation(ctx, didstr)
	if err != nil {
		return err
	} else if last.GetType() == tombstone {
		return ErrIsTombstone
	}

	handle = formatHandle(handle)
	next, err := getNextUpdate(last)
	if err != nil {
		return err
	}
	pos := -1
	for i := 0; i < len(next.AlsoKnownAs); i++ {
		if strings.HasPrefix(next.AlsoKnownAs[i], "at://") {
			pos = i
			break
		}
	}
	if pos < 0 {
		next.AlsoKnownAs = append(next.AlsoKnownAs, handle)
	} else {
		next.AlsoKnownAs[pos] = handle
	}

	_, err = c.post(ctx, signer, didstr, next)
	return err
}

func (c *Client) UpdatePDS(ctx context.Context, signer *did.PrivKey, didstr, pdsEndpoint string) error {
	ctx, span := otel.Tracer("plc-client").Start(ctx, "plcUpdatePDS")
	defer span.End()

	last, err := c.GetLastOperation(ctx, didstr)
	if err != nil {
		return err
	} else if last.GetType() == tombstone {
		return ErrIsTombstone
	}

	next, err := getNextUpdate(last)
	if err != nil {
		return err
	}
	next.Services["atproto_pds"] = &Service{
		Type:     "AtprotoPersonalDataServer",
		Endpoint: pdsEndpoint,
	}

	_, err = c.post(ctx, signer, didstr, next)
	return err
}

func (c *Client) UpdateRotationKeys(ctx context.Context, signer *did.PrivKey, didstr string, rotationKeys []string) error {
	ctx, span := otel.Tracer("plc-client").Start(ctx, "plcUpdateRotationKeys")
	defer span.End()

	last, err := c.GetLastOperation(ctx, didstr)
	if err != nil {
		return err
	} else if last.GetType() == tombstone {
		return ErrIsTombstone
	}

	next, err := getNextUpdate(last)
	if err != nil {
		return err
	}
	next.RotationKeys = rotationKeys

	_, err = c.post(ctx, signer, didstr, next)
	return err
}

func (c *Client) SetTombstone(ctx context.Context, signer *did.PrivKey, didstr string) error {
	ctx, span := otel.Tracer("plc-client").Start(ctx, "plcSetTombstone")
	defer span.End()

	last, err := c.GetLastOperation(ctx, didstr)
	if err != nil {
		return err
	} else if last.GetType() == tombstone {
		return ErrIsTombstone
	}

	prev, err := getCID(last)
	if err != nil {
		return err
	}

	next := &Tombstone{
		Type: tombstone,
		Prev: &prev,
	}
	_, err = c.post(ctx, signer, didstr, next)
	return err
}
