package proto

import (
	"crypto/sha256"
	"net/url"
	"strings"

	"github.com/AccumulateNetwork/accumulated/types"

	"github.com/AccumulateNetwork/SMT/common"
)

// GenTransaction
// Every transaction that goes through the Accumulate protocol is packaged
// as a GenTransaction.  This means we implement this once, and most of the
// transaction validation and processing is done in one and only one way.
type GenTransaction struct {
	Signature   []*ED25519Sig // Signature(s) of the transaction
	Routing     uint64        // The first 8 bytes of the hash of the identity
	ChainID     []byte        // The hash of the chain URL
	Transaction []byte        // The transaction that follows
}

func (t *GenTransaction) SetRoutingChainID(destURL string) error {
	u, err := url.Parse(destURL)
	if err != nil {
		return err
	}
	host := strings.ToLower(u.Host)
	h := sha256.Sum256([]byte(host))
	t.Routing = uint64(h[0])<<56 | uint64(h[1])<<48 | uint64(h[2])<<40 |
		uint64(h[3])<<32 | uint64(h[4])<<24 | uint64(h[5])<<16 |
		uint64(h[6])<<8 | uint64(h[7])
	t.ChainID = types.GetChainIdFromChainPath(&destURL)[:]
	return nil
}

// ValidateSig
// We validate the signature of the transaction.
func (t *GenTransaction) ValidateSig() bool {
	h := sha256.Sum256(t.MarshalBinary())
	for _, v := range t.Signature {
		if !v.Verify(h[:]) {
			return false
		}
	}
	return true
}

// MarshalBinary
// Marshal the portion of the transaction that must be signed
func (t *GenTransaction) MarshalBinary() (data []byte) {
	data = append(data, common.Uint64Bytes(t.Routing)...)
	data = append(data, common.SliceBytes(t.ChainID)...)

	return data
}

// UnMarshal
// Create the binary representation of the GenTransaction
func (t *GenTransaction) Marshal() (data []byte) {
	sLen := uint64(len(t.Signature))
	if sLen == 0 {
		panic("must have signed transactions")
	}
	data = common.Uint64Bytes(sLen)
	for _, v := range t.Signature {
		data = append(data, v.Marshal()...)
	}
	data = append(data, t.MarshalBinary()...)

	return data
}

func (t *GenTransaction) UnMarshal(data []byte) []byte {
	slen, data := common.BytesUint64(data)
	if slen < 1 || slen > 100 {
		panic("signature length out of range")
	}
	for i := uint64(0); i < slen; i++ {
		sig := new(ED25519Sig)
		data = sig.Unmarshal(data)
		t.Signature = append(t.Signature, sig)
	}
	t.Routing, data = common.BytesUint64(data)
	t.ChainID, data = common.BytesSlice(data)
	return data
}

// GetTransactionType
// Returns the type of the enclosed transaction
func (t *GenTransaction) GetTransactionType() (txType uint64) {
	txType, _ = common.BytesUint64(t.Transaction)
	return txType
}

func (t *GenTransaction) GetRouting() uint64 {
	return t.Routing
}

func (t *GenTransaction) GetChainID() []byte {
	return t.ChainID
}

func (t *GenTransaction) GetSignature() []*ED25519Sig {
	return t.Signature
}
