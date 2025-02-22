package api

import (
	"encoding/json"

	"github.com/AccumulateNetwork/accumulate/types"
)

const DefaultPaginationSize = 20

// API Request Support Structure

// Signer holds the ADI and public key to use to verify the transaction
type Signer struct {
	PublicKey types.Bytes32 `json:"publicKey" form:"publicKey" query:"publicKey" validate:"required"`
	Nonce     uint64        `json:"nonce" form:"nonce" query:"nonce" validate:"required"`
}

// APIRequestRaw will leave the data payload intact which is required for signature verification
type APIRequestRaw struct {
	Wait bool             `json:"wait" form:"wait" query:"wait"`
	Tx   *APIRequestRawTx `json:"tx" form:"tx" query:"tx" validate:"required"`
}

// APIRequestRawTx is used to maintain the integrety of the Data field when it is read in
// The data field is used to verify the signature.  The transaction ledger is the
// concatenation of ( sha256(Signer.URL) | Data | Timestamp ).  The txid is the sha256(ledger)
// and the signature is ed25519( ledger )
type APIRequestRawTx struct {
	Sponsor types.String       `json:"sponsor" form:"sponsor" query:"sponsor" validate:"required"`
	Data    *json.RawMessage   `json:"data" form:"data" query:"data" validate:"required"`
	Signer  *Signer            `json:"signer" form:"signer" query:"signer" validate:"required"`
	Sig     types.Bytes64      `json:"sig" form:"sig" query:"sig" validate:"required"`
	KeyPage *APIRequestKeyPage `json:"keyPage" form:"keyPage" query:"keyPage" validate:"required"`
}

// APIRequestKeyPage specifies the key page used to sign the transaction. The
// index is the index of the key page within its key book. The height is the
// height of the key page chain.
type APIRequestKeyPage struct {
	Height uint64 `json:"height" form:"height" query:"height" validate:"required"`
	Index  uint64 `json:"index" form:"index" query:"index"`
}

// APIRequestURL is used to unmarshal URL param into API methods, that retrieves data by URL
type APIRequestURL struct {
	URL  types.String `json:"url" form:"url" query:"url" validate:"required"`
	Wait bool         `json:"wait" form:"wait" query:"wait"`
}

// APIRequestChainId is used to unmarshal URL param into API methods, that retrieves data by URL
type APIRequestChainId struct {
	ChainId types.Bytes `json:"chainId" form:"chainId" query:"chainId" validate:"required"`
	Wait    bool        `json:"wait" form:"wait" query:"wait"`
}

// APIRequestTxId is used to unmarshal URL param into API methods, that retrieves data by URL
type APIRequestTxId struct {
	TxId types.Bytes `json:"txid" form:"txid" query:"txid" validate:"required"`
	Wait bool        `json:"wait" form:"wait" query:"wait"`
}

// APIRequestURLPagination is APIRequestURL with pagination params
type APIRequestURLPagination struct {
	APIRequestURL
	Start int64 `json:"start" validate:"number,gte=0"`
	Limit int64 `json:"limit" validate:"number,gt=0"`
}

// APIDataResponse is used in "get" API method response
type APIDataResponse struct {
	Type        types.String       `json:"type" form:"type" query:"type" validate:"oneof:adi,token,tokenAccount,tokenTx,tx,sigSpec,sigSpecGroup,assignSigSpec,addCredits,directory,version"`
	MerkleState *MerkleState       `json:"merkleState,omitempty" form:"merkleState" query:"merkleState"`
	Data        *json.RawMessage   `json:"data" form:"data" query:"data"`
	Sponsor     types.String       `json:"sponsor" form:"sponsor" query:"sponsor" validate:"required"`
	KeyPage     *APIRequestKeyPage `json:"keyPage" form:"keyPage" query:"keyPage" validate:"required"`
	TxId        *types.Bytes       `json:"txid" form:"txid" query:"txid"`
	//the following are optional available only if pending chain has not been purged
	Signer *Signer          `json:"signer,omitempty" form:"signer" query:"signer"`
	Sig    *types.Bytes64   `json:"sig,omitempty" form:"sig" query:"sig"`
	Status *json.RawMessage `json:"status,omitempty" form:"status" query:"status"`
}

type MerkleState struct {
	Count uint64        `json:"count,omitempty" form:"count" query:"count"`
	Roots []types.Bytes `json:"roots,omitempty" form:"roots" query:"roots"`
}

// APIDataResponsePagination is APIDataResponse with pagination data
type APIDataResponsePagination struct {
	Data  []*APIDataResponse `json:"data"`
	Type  types.String       `json:"type"`
	Start int64              `json:"start"`
	Limit int64              `json:"limit"`
	Total int64              `json:"total"`
}

// UnmarshalJSON is custom Unmarshal for APIRequestURLPagination
func (p *APIRequestURLPagination) UnmarshalJSON(data []byte) error {

	type APIRequestURLPaginationAlias APIRequestURLPagination

	test := &APIRequestURLPaginationAlias{
		Limit: int64(DefaultPaginationSize),
	}
	err := json.Unmarshal(data, test)
	if err != nil {
		return err
	}

	*p = APIRequestURLPagination(*test)
	return nil
}
