package api

import (
	"context"

	"github.com/tendermint/tendermint/libs/bytes"
	core "github.com/tendermint/tendermint/rpc/core/types"
	tm "github.com/tendermint/tendermint/types"
)

//go:generate go run ../../cmd/gentypes --package api types.yml
//go:generate go run github.com/golang/mock/mockgen -source types.go -destination ../../mock/api/types.go

type Querier interface {
	QueryUrl(url string) (*QueryResponse, error)
	QueryDirectory(url string) (*QueryResponse, error)
	QueryChain(id []byte) (*QueryResponse, error)
	QueryTx(id []byte) (*QueryResponse, error)
	QueryTxHistory(url string, start, count int64) (*QueryMultiResponse, error)
}

// ABCIQueryClient is a subset of from TM/rpc/client.ABCIClient for sending
// queries.
type ABCIQueryClient interface {
	ABCIQuery(ctx context.Context, path string, data bytes.HexBytes) (*core.ResultABCIQuery, error)
}

// ABCIBroadcastClient is a subset of from TM/rpc/client.ABCIClient for
// broadcasting transactions.
type ABCIBroadcastClient interface {
	CheckTx(ctx context.Context, tx tm.Tx) (*core.ResultCheckTx, error)
	BroadcastTxAsync(context.Context, tm.Tx) (*core.ResultBroadcastTx, error)
	BroadcastTxSync(context.Context, tm.Tx) (*core.ResultBroadcastTx, error)
}
