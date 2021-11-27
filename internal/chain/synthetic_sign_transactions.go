package chain

import (
	"fmt"

	"github.com/AccumulateNetwork/accumulate/protocol"
	"github.com/AccumulateNetwork/accumulate/types"
	"github.com/AccumulateNetwork/accumulate/types/api/transactions"
)

type SyntheticSignTransactions struct{}

func (SyntheticSignTransactions) Type() types.TxType { return types.TxTypeSyntheticSignTransactions }

func (SyntheticSignTransactions) Validate(st *StateManager, tx *transactions.GenTransaction) error {
	body := new(protocol.SyntheticSignTransactions)
	err := tx.As(body)
	if err != nil {
		return fmt.Errorf("invalid payload: %v", err)
	}

	for _, entry := range body.Transactions {
		state, err := st.LoadSynthTxn(entry.Txid)
		if err != nil {
			return err
		}

		synTxn := state.Restore()
		synTxn.Signature = append(synTxn.Signature, &transactions.ED25519Sig{
			Nonce:     entry.Nonce,
			Signature: entry.Signature,
			PublicKey: tx.Signature[0].PublicKey,
		})

		if !synTxn.ValidateSig() {
			return fmt.Errorf("invalid signature for txn %X", entry.Txid)
		}

		st.AddSynthTxnSig(tx.Signature[0].PublicKey, &entry)
	}

	return nil
}
