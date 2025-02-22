package query

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/AccumulateNetwork/accumulate/types"
)

type ResponseTxHistory struct {
	Transactions []ResponseByTxId `json:"txs"`
	Total        int64            `json:"total"`
}

type RequestTxHistory struct {
	ChainId types.Bytes32
	Start   int64
	Limit   int64
}

func (*RequestTxHistory) Type() types.QueryType { return types.QueryTypeTxHistory }

func (t *ResponseTxHistory) MarshalBinary() (data []byte, err error) {
	var buff bytes.Buffer
	var d [8]byte
	binary.LittleEndian.PutUint64(d[:], uint64(t.Total))
	buff.Write(d[:])

	binary.LittleEndian.PutUint64(d[:], uint64(len(t.Transactions)))
	buff.Write(d[:])

	for i := range t.Transactions {
		d, err := t.Transactions[i].MarshalBinary()
		if err != nil {
			return nil, err
		}
		buff.Write(d)
	}

	return buff.Bytes(), nil
}

func (t *ResponseTxHistory) UnmarshalBinary(data []byte) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("error unmarshaling ResponseTxHistory data %v", r)
		}
	}()

	t.Total = int64(binary.LittleEndian.Uint64(data[:]))
	data = data[8:]

	l := int(binary.LittleEndian.Uint64(data[:]))
	data = data[8:]

	if len(data) < l {
		return fmt.Errorf("insufficient txid data for given range")
	}

	t.Transactions = make([]ResponseByTxId, l)
	j := 0
	for i := 0; i < l; i++ {
		err = t.Transactions[i].UnmarshalBinary(data[j:])
		if err != nil {
			return err
		}
		j += t.Transactions[i].Size()
	}
	return nil
}

func (t *RequestTxHistory) MarshalBinary() (data []byte, err error) {
	var buff bytes.Buffer
	var d [8]byte
	binary.LittleEndian.PutUint64(d[:], uint64(t.Start))
	buff.Write(d[:])

	binary.LittleEndian.PutUint64(d[:], uint64(t.Limit))
	buff.Write(d[:])

	buff.Write(t.ChainId[:])

	return buff.Bytes(), nil
}

func (t *RequestTxHistory) UnmarshalBinary(data []byte) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("error unmarshaling RequestTxHistory %v", r)
		}
	}()

	t.Start = int64(binary.LittleEndian.Uint64(data[:]))
	t.Limit = int64(binary.LittleEndian.Uint64(data[8:]))
	t.ChainId.FromBytes(data[16:])
	return nil
}
