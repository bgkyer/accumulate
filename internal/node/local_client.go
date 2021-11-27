package node

import (
	"context"
	"errors"

	"github.com/tendermint/tendermint/libs/bytes"
	"github.com/tendermint/tendermint/rpc/client/local"
	core "github.com/tendermint/tendermint/rpc/core/types"
	tm "github.com/tendermint/tendermint/types"
)

type LocalClient struct {
	client *local.Local
	queue  []tm.Tx
}

func NewLocalClient() *LocalClient {
	c := new(LocalClient)
	return c
}

func (c *LocalClient) Set(client *local.Local) {
	c.client = client
	queue := c.queue
	c.queue = nil
	for _, tx := range queue {
		_, _ = client.BroadcastTxAsync(context.Background(), tx)
	}
}

func (c *LocalClient) ABCIQuery(ctx context.Context, path string, data bytes.HexBytes) (*core.ResultABCIQuery, error) {
	if c.client == nil {
		return nil, errors.New("not initialized")
	}
	return c.client.ABCIQuery(ctx, path, data)
}

func (c *LocalClient) CheckTx(ctx context.Context, tx tm.Tx) (*core.ResultCheckTx, error) {
	if c.client == nil {
		return nil, errors.New("not initialized")
	}
	return c.client.CheckTx(ctx, tx)
}

func (c *LocalClient) BroadcastTxAsync(ctx context.Context, tx tm.Tx) (*core.ResultBroadcastTx, error) {
	if c.client == nil {
		c.queue = append(c.queue, tx)
		return &core.ResultBroadcastTx{Hash: tx.Hash()}, nil
	}
	return c.client.BroadcastTxAsync(ctx, tx)
}

func (c *LocalClient) BroadcastTxSync(ctx context.Context, tx tm.Tx) (*core.ResultBroadcastTx, error) {
	if c.client == nil {
		return nil, errors.New("not initialized")
	}
	return c.client.BroadcastTxSync(ctx, tx)
}
