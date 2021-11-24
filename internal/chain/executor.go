package chain

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/AccumulateNetwork/accumulate/internal/abci"
	accapi "github.com/AccumulateNetwork/accumulate/internal/api"
	"github.com/AccumulateNetwork/accumulate/internal/url"
	"github.com/AccumulateNetwork/accumulate/protocol"
	"github.com/AccumulateNetwork/accumulate/smt/common"
	"github.com/AccumulateNetwork/accumulate/smt/storage"
	"github.com/AccumulateNetwork/accumulate/types"
	"github.com/AccumulateNetwork/accumulate/types/api/query"
	"github.com/AccumulateNetwork/accumulate/types/api/transactions"
	"github.com/AccumulateNetwork/accumulate/types/state"
)

const chainWGSize = 4

type Executor struct {
	db        *state.StateDB
	key       ed25519.PrivateKey
	query     *accapi.Query
	executors map[types.TxType]TxExecutor

	wg      *sync.WaitGroup
	mu      *sync.Mutex
	chainWG map[uint64]*sync.WaitGroup
	leader  bool
	height  int64
	dbTx    *state.DBTransaction
}

var _ abci.Chain = (*Executor)(nil)

func NewExecutor(query *accapi.Query, db *state.StateDB, key ed25519.PrivateKey, executors ...TxExecutor) (*Executor, error) {
	m := new(Executor)
	m.db = db
	m.executors = map[types.TxType]TxExecutor{}
	m.key = key
	m.wg = new(sync.WaitGroup)
	m.mu = new(sync.Mutex)
	m.query = query

	for _, x := range executors {
		if _, ok := m.executors[x.Type()]; ok {
			panic(fmt.Errorf("duplicate executor for %d", x.Type()))
		}
		m.executors[x.Type()] = x
	}

	fmt.Printf("Loaded height=%d hash=%X\n", db.BlockIndex(), db.EnsureRootHash())
	return m, nil
}

func (m *Executor) queryByUrl(u *url.URL) ([]byte, encoding.BinaryMarshaler, error) {
	qv := u.QueryValues()
	switch {
	case qv.Get("txid") != "":
		// Query by transaction ID
		txid, err := hex.DecodeString(qv.Get("txid"))
		if err != nil {
			return nil, nil, fmt.Errorf("invalid txid %q: %v", qv.Get("txid"), err)
		}

		v, err := m.queryByTxId(txid)
		return []byte("tx"), v, err

	default:
		// Query by chain URL
		v, err := m.queryByChainId(u.ResourceChain())
		return []byte("chain"), v, err
	}
}

func (m *Executor) queryByChainId(chainId []byte) (*query.ResponseByChainId, error) {
	qr := query.ResponseByChainId{}

	// This intentionally uses GetPersistentEntry instead of GetCurrentEntry.
	// Callers should never see uncommitted values.
	obj, err := m.db.GetPersistentEntry(chainId, false)
	// Or a transaction
	if errors.Is(err, storage.ErrNotFound) {
		obj, err = m.db.GetTransaction(chainId)
	}
	// Not a state entry or a transaction
	if errors.Is(err, storage.ErrNotFound) {
		return nil, fmt.Errorf("%w: no chain or transaction found for %X", storage.ErrNotFound, chainId)
	}
	// Some other error
	if err != nil {
		return nil, fmt.Errorf("failed to locate chain entry for chain id %x: %v", chainId, err)
	}

	err = obj.As(new(state.ChainHeader))
	if err != nil {
		return nil, fmt.Errorf("unable to extract chain header for chain id %x: %v", chainId, err)
	}

	qr.Object = *obj
	return &qr, nil
}

func (m *Executor) queryDirectoryByChainId(chainId []byte) (*protocol.DirectoryQueryResult, error) {
	b, err := m.db.GetIndex(state.DirectoryIndex, chainId, "Metadata")
	if err != nil {
		return nil, err
	}

	md := new(protocol.DirectoryIndexMetadata)
	err = md.UnmarshalBinary(b)
	if err != nil {
		return nil, err
	}

	resp := new(protocol.DirectoryQueryResult)
	resp.Entries = make([]string, md.Count)
	for i := range resp.Entries {
		b, err := m.db.GetIndex(state.DirectoryIndex, chainId, uint64(i))
		if err != nil {
			return nil, fmt.Errorf("failed to get entry %d", i)
		}
		resp.Entries[i] = string(b)
	}
	return resp, nil
}

func (m *Executor) queryByTxId(txid []byte) (*query.ResponseByTxId, error) {
	var err error

	qr := query.ResponseByTxId{}
	qr.TxState, err = m.db.GetTx(txid)
	if errors.Is(err, storage.ErrNotFound) {
		return nil, fmt.Errorf("tx %X %w", txid, storage.ErrNotFound)
	} else if err != nil {
		return nil, fmt.Errorf("invalid query from GetTx in state database, %v", err)
	}
	qr.TxPendingState, err = m.db.GetPendingTx(txid)
	if !errors.Is(err, storage.ErrNotFound) && err != nil {
		//this is only an error if the pending states have not yet been purged or some other database error occurred
		return nil, fmt.Errorf("%w: error in query for pending chain on txid %X", storage.ErrNotFound, txid)
	}

	qr.TxSynthTxIds, err = m.db.GetSyntheticTxIds(txid)
	if !errors.Is(err, storage.ErrNotFound) && err != nil {
		//this is only an error if the transactions produced synth tx's or some other database error occurred
		return nil, fmt.Errorf("%w: error in query for synthetic txid txid %X", storage.ErrNotFound, txid)
	}

	qr.TxId.FromBytes(txid)

	return &qr, nil
}

func (m *Executor) Query(q *query.Query) (k, v []byte, err error) {
	switch q.Type {
	case types.QueryTypeTxId:
		txr := query.RequestByTxId{}
		err := txr.UnmarshalBinary(q.Content)
		if err != nil {
			return nil, nil, err
		}
		qr, err := m.queryByTxId(txr.TxId[:])
		if err != nil {
			return nil, nil, err
		}
		k = []byte("tx")
		v, err = qr.MarshalBinary()
		if err != nil {
			return nil, nil, fmt.Errorf("%v, on Chain %x", err, txr.TxId[:])
		}
	case types.QueryTypeTxHistory:
		txh := query.RequestTxHistory{}
		err := txh.UnmarshalBinary(q.Content)
		if err != nil {
			return nil, nil, err
		}

		thr := query.ResponseTxHistory{}
		txids, maxAmt, err := m.db.GetTxRange(&txh.ChainId, txh.Start, txh.Start+txh.Limit)
		if err != nil {
			return nil, nil, fmt.Errorf("error obtaining txid range %v", err)
		}
		thr.Total = maxAmt
		for i := range txids {
			qr, err := m.queryByTxId(txids[i][:])
			if err != nil {
				return nil, nil, err
			}
			thr.Transactions = append(thr.Transactions, *qr)
		}
		k = []byte("tx-history")
		v, err = thr.MarshalBinary()
		if err != nil {
			return nil, nil, fmt.Errorf("error marshalling payload for transaction history")
		}
	case types.QueryTypeUrl:
		chr := query.RequestByUrl{}
		err := chr.UnmarshalBinary(q.Content)
		if err != nil {
			return nil, nil, err
		}
		u, err := url.Parse(*chr.Url.AsString())
		if err != nil {
			return nil, nil, fmt.Errorf("invalid URL in query %s", chr.Url)
		}

		var obj encoding.BinaryMarshaler
		k, obj, err = m.queryByUrl(u)
		if err != nil {
			return nil, nil, err
		}
		v, err = obj.MarshalBinary()
		if err != nil {
			return nil, nil, fmt.Errorf("%v, on Url %s", err, chr.Url)
		}
	case types.QueryTypeDirectoryUrl:
		chr := query.RequestByUrl{}
		err := chr.UnmarshalBinary(q.Content)
		if err != nil {
			return nil, nil, err
		}
		u, err := url.Parse(*chr.Url.AsString())
		if err != nil {
			return nil, nil, fmt.Errorf("invalid URL in query %s", chr.Url)
		}
		dir, err := m.queryDirectoryByChainId(u.ResourceChain())
		if err != nil {
			return nil, nil, err
		}
		k = []byte("directory")
		v, err = dir.MarshalBinary()
		if err != nil {
			return nil, nil, fmt.Errorf("%v, on Url %s", err, chr.Url)
		}
	case types.QueryTypeChainId:
		chr := query.RequestByChainId{}
		err := chr.UnmarshalBinary(chr.ChainId[:])
		if err != nil {
			return nil, nil, err
		}
		obj, err := m.queryByChainId(chr.ChainId[:])
		if err != nil {
			return nil, nil, err
		}
		k = []byte("chain")
		v, err = obj.MarshalBinary()
		if err != nil {
			return nil, nil, fmt.Errorf("%v, on Chain %x", err, chr.ChainId)
		}
	default:
		return nil, nil, fmt.Errorf("unable to query for type, %s (%d)", q.Type.Name(), q.Type.AsUint64())
	}
	return k, v, err
}

// BeginBlock implements ./abci.Chain
func (m *Executor) BeginBlock(req abci.BeginBlockRequest) {
	m.leader = req.IsLeader
	m.height = req.Height
	m.chainWG = make(map[uint64]*sync.WaitGroup, chainWGSize)
	m.dbTx = m.db.Begin()
}

func (m *Executor) check(tx *transactions.GenTransaction) (*StateManager, error) {
	if tx.TransactionType() == types.TxTypeSyntheticGenesis {
		return NewStateManager(m.dbTx, tx)
	}

	if len(tx.Signature) == 0 {
		return nil, fmt.Errorf("transaction is not signed")
	}

	if !tx.ValidateSig() {
		return nil, fmt.Errorf("invalid signature")
	}

	txt := tx.TransactionType()

	st, err := NewStateManager(m.dbTx, tx)
	if errors.Is(err, storage.ErrNotFound) {
		switch txt {
		case types.TxTypeSyntheticCreateChain, types.TxTypeSyntheticDepositTokens:
			// TX does not require a sponsor - it may create the sponsor
		default:
			return nil, fmt.Errorf("sponsor not found: %v", err)
		}
	} else if err != nil {
		return nil, err
	}

	if txt.IsSynthetic() {
		return st, m.checkSynthetic(st, tx)
	}

	sigGroup := new(protocol.SigSpecGroup)
	switch sponsor := st.Sponsor.(type) {
	case *protocol.AnonTokenAccount:
		return st, m.checkAnonymous(st, tx, sponsor)

	case *state.AdiState, *state.TokenAccount, *protocol.SigSpec:
		if (sponsor.Header().SigSpecId == types.Bytes32{}) {
			return nil, fmt.Errorf("sponsor has not been assigned to an SSG")
		}
		err := st.LoadAs(sponsor.Header().SigSpecId, sigGroup)
		if err != nil {
			return nil, fmt.Errorf("invalid SigSpecId: %v", err)
		}

	case *protocol.SigSpecGroup:
		sigGroup = sponsor

	default:
		// The TX sponsor cannot be a transaction
		// Token issue chains are not implemented
		return nil, fmt.Errorf("invalid sponsor: chain type %v cannot sponsor transactions", sponsor.Header().Type)
	}

	if tx.SigInfo.PriorityIdx >= uint64(len(sigGroup.SigSpecs)) {
		return nil, fmt.Errorf("invalid sig spec index")
	}

	sigSpec := new(protocol.SigSpec)
	err = st.LoadAs(sigGroup.SigSpecs[tx.SigInfo.PriorityIdx], sigSpec)
	if err != nil {
		return nil, fmt.Errorf("invalid sig spec: %v", err)
	}

	// TODO check height

	for i, sig := range tx.Signature {
		ks := sigSpec.FindKey(sig.PublicKey)
		if ks == nil {
			return nil, fmt.Errorf("no key spec matches signature %d", i)
		}

		if ks.Nonce >= sig.Nonce {
			return nil, fmt.Errorf("invalid nonce")
		}
		// TODO add pending update for the nonce
	}

	return st, nil
}

func (m *Executor) checkSynthetic(st *StateManager, tx *transactions.GenTransaction) error {
	//placeholder for special validation rules for synthetic transactions.
	//need to verify the sender is a legit bvc validator also need the dbvc receipt
	//so if the transaction is a synth tx, then we need to verify the sender is a BVC validator and
	//not an impostor. Need to figure out how to do this. Right now we just assume the synth request
	//sender is legit.
	return nil
}

func (m *Executor) checkAnonymous(st *StateManager, tx *transactions.GenTransaction, account *protocol.AnonTokenAccount) error {
	u, err := account.ParseUrl()
	if err != nil {
		// This shouldn't happen because invalid URLs should never make it
		// into the database.
		return fmt.Errorf("invalid sponsor URL: %v", err)
	}

	urlKH, _, err := protocol.ParseAnonymousAddress(u)
	if err != nil {
		// This shouldn't happen because invalid URLs should never make it
		// into the database.
		return fmt.Errorf("invalid anonymous token URL: %v", err)
	}

	for i, sig := range tx.Signature {
		sigKH := sha256.Sum256(sig.PublicKey)
		if !bytes.Equal(urlKH, sigKH[:20]) {
			return fmt.Errorf("signature %d's public key does not match the sponsor", i)
		}

		if account.Nonce >= sig.Nonce {
			return fmt.Errorf("invalid nonce")
		}
	}

	// TODO add pending update for the nonce

	return nil
}

// CheckTx implements ./abci.Chain
func (m *Executor) CheckTx(tx *transactions.GenTransaction) error {
	err := tx.SetRoutingChainID()
	if err != nil {
		return err
	}

	st, err := m.check(tx)
	if err != nil {
		return err
	}

	executor, ok := m.executors[types.TxType(tx.TransactionType())]
	if !ok {
		return fmt.Errorf("unsupported TX type: %v", types.TxType(tx.TransactionType()))
	}

	return executor.Validate(st, tx)
}

func (m *Executor) recordTransactionError(txPending *state.PendingTransaction, chainId *types.Bytes32, txid []byte, err error) error {
	txPending.Status = json.RawMessage(fmt.Sprintf("{\"code\":\"1\", \"error\":\"%v\"}", err))
	txPendingObject := new(state.Object)
	e, err1 := txPending.MarshalBinary()
	txPendingObject.Entry = e
	if err1 != nil {
		err = fmt.Errorf("failed marshaling pending tx (%v) on error: %v", err1, err)
		return err
	}
	err1 = m.dbTx.AddTransaction(chainId, txid, txPendingObject, nil)
	if err1 != nil {
		err = fmt.Errorf("error adding pending tx (%v) on error %v", err1, err)
	}
	return err
}

// DeliverTx implements ./abci.Chain
func (m *Executor) DeliverTx(tx *transactions.GenTransaction) (*protocol.TxResult, error) {
	m.wg.Add(1)

	// If this is done async (`go m.deliverTxAsync(tx)`), how would an error
	// get back to the ABCI callback?
	// > errors would not go back to ABCI callback. The errors determine what gets kept in tm TX history, so as far
	// > as tendermint is concerned, it will keep everything, but we don't care because we are pruning tm history.
	// > For reporting errors back to the world, we would to provide a different mechanism for querying
	// > tx status, which can be done via the pending chains.  Thus, going on that assumption, because each
	// > identity operates independently, we can make the validation process highly parallel, and sync up at
	// > the commit when we go to write the states.
	// go func() {

	defer m.wg.Done()

	if tx.Transaction == nil || tx.SigInfo == nil || len(tx.ChainID) != 32 {
		return nil, fmt.Errorf("malformed transaction")
	}

	txt := types.TxType(tx.TransactionType())
	executor, ok := m.executors[txt]
	txPending := state.NewPendingTransaction(tx)
	chainId := types.Bytes(tx.ChainID).AsBytes32()
	if !ok {
		err := fmt.Errorf("unsupported TX type: %v", tx.TransactionType().Name())
		return nil, m.recordTransactionError(txPending, &chainId, tx.TransactionHash(), err)
	}

	tx.TransactionHash()

	m.mu.Lock()
	group, ok := m.chainWG[tx.Routing%chainWGSize]
	if !ok {
		group = new(sync.WaitGroup)
		m.chainWG[tx.Routing%chainWGSize] = group
	}

	group.Wait()
	group.Add(1)
	defer group.Done()
	m.mu.Unlock()

	st, err := m.check(tx)
	if err != nil {
		err = fmt.Errorf("failed check: %v", err)
		return nil, m.recordTransactionError(txPending, &chainId, tx.TransactionHash(), err)
	}

	// Validate
	// TODO result should return a list of chainId's the transaction touched.
	err = executor.Validate(st, tx)
	if err != nil {
		err = fmt.Errorf("rejected by chain: %v", err)
		return nil, m.recordTransactionError(txPending, &chainId, tx.TransactionHash(), err)
	}

	// Ensure the genesis transaction can only be processed once
	if executor.Type() == types.TxTypeSyntheticGenesis {
		delete(m.executors, types.TxTypeSyntheticGenesis)
	}

	// If we get here, we were successful in validating.  So, we need to
	// split the transaction in 2, the body (i.e. TxAccepted), and the
	// validation material (i.e. TxPending).  The body of the transaction
	// gets put on the main chain, and the validation material gets put on
	// the pending chain which is purged after about 2 weeks
	txAccepted, txPending := state.NewTransaction(txPending)
	txAcceptedObject := new(state.Object)
	txAcceptedObject.Entry, err = txAccepted.MarshalBinary()
	if err != nil {
		return nil, m.recordTransactionError(txPending, &chainId, tx.TransactionHash(), err)
	}

	txPendingObject := new(state.Object)
	txPending.Status = json.RawMessage(fmt.Sprintf("{\"code\":\"0\"}"))
	txPendingObject.Entry, err = txPending.MarshalBinary()
	if err != nil {
		return nil, m.recordTransactionError(txPending, &chainId, tx.TransactionHash(), err)
	}

	// Store the tx state
	err = m.dbTx.AddTransaction(&chainId, tx.TransactionHash(), txPendingObject, txAcceptedObject)
	if err != nil {
		return nil, err
	}

	// Store pending state updates, queue state creates for synthetic transactions
	err = st.commit()
	if err != nil {
		return nil, m.recordTransactionError(txPending, &chainId, tx.TransactionHash(), err)
	}

	// Process synthetic transactions generated by the validator
	refs, err := m.submitSyntheticTx(tx.TransactionHash(), st)
	if err != nil {
		return nil, err
	}

	r := new(protocol.TxResult)
	r.SyntheticTxs = refs
	return r, nil
}

// EndBlock implements ./abci.Chain
func (m *Executor) EndBlock(req abci.EndBlockRequest) {}

// Commit implements ./abci.Chain
func (m *Executor) Commit() ([]byte, error) {
	m.wg.Wait()

	mdRoot, numStateChanges, err := m.dbTx.Commit(m.height)
	if err != nil {
		// This should never happen
		panic(fmt.Errorf("fatal error, block not set, %v", err))
	}

	_ = numStateChanges
	// // If we have no transactions this block then don't publish anything
	// if m.leader && numStateChanges > 0 {
	// 	// Now we create a synthetic transaction and publish to the directory
	// 	// block validator
	// 	dbvc := DeliverTxResult{}
	// 	dbvc.SyntheticTransactions = make([]*transactions.GenTransaction, 1)
	// 	dbvc.SyntheticTransactions[0] = &transactions.GenTransaction{}
	// 	dcAdi := "dc"
	// 	dbvc.SyntheticTransactions[0].ChainID = types.GetChainIdFromChainPath(&dcAdi).Bytes()
	// 	dbvc.SyntheticTransactions[0].Routing = types.GetAddressFromIdentity(&dcAdi)
	// 	//dbvc.Submissions[0].Transaction = ...

	// 	//broadcast the root
	// 	//m.processValidatedSubmissionRequest(&dbvc)
	// }

	m.query.BatchSend()

	fmt.Printf("DB time %f\n", m.db.TimeBucket)
	m.db.TimeBucket = 0
	return mdRoot, nil
}

func (m *Executor) nextSynthCount() (uint64, error) {
	k := storage.ComputeKey("SyntheticTransactionCount")
	b, err := m.dbTx.Read(k)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		return 0, err
	}

	var n uint64
	if len(b) > 0 {
		n, _ = common.BytesUint64(b)
	}
	m.dbTx.Write(k, common.Uint64Bytes(n+1))
	return n, nil
}

func (m *Executor) submitSyntheticTx(parentTxId types.Bytes, st *StateManager) (tmRef []*protocol.TxSynthRef, err error) {
	if m.leader {
		tmRef = make([]*protocol.TxSynthRef, len(st.submissions))
	}

	// Need to pass this to a threaded batcher / dispatcher to do both signing
	// and sending of synth tx. No need to spend valuable time here doing that.
	for i, sub := range st.submissions {
		// Generate a synthetic tx and send to the router. Need to track txid to
		// make sure they get processed.

		body, err := sub.body.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal synthetic transaction payload: %v", err)
		}

		tx := new(transactions.GenTransaction)
		tx.SigInfo = new(transactions.SignatureInfo)
		tx.SigInfo.URL = sub.url.String()
		tx.SigInfo.MSHeight = 1
		tx.SigInfo.PriorityIdx = 0
		tx.Transaction = body

		// TODO Populate nonce with something better
		tx.SigInfo.MSHeight = uint64(m.height)
		tx.SigInfo.Nonce, err = m.nextSynthCount()
		if err != nil {
			return nil, err
		}

		// Create the state object to store the unsigned pending transaction
		txSynthetic := state.NewPendingTransaction(tx)
		txSyntheticObject := new(state.Object)
		synthTxData, err := txSynthetic.MarshalBinary()
		if err != nil {
			return nil, err
		}
		txSyntheticObject.Entry = synthTxData
		m.dbTx.AddSynthTx(parentTxId, tx.TransactionHash(), txSyntheticObject)

		// TODO In order for other BVCs to be able to validate the synthetic
		// transaction, a wrapped signed version must be resubmitted to this BVC network
		// and the UNSIGNED version of the transaction along with the Leader address will
		// be stored in a SynthChain in the SMT on this BVC.  The BVC's will validate
		// the synth transaction against the receipt and EVERYONE will then send out the wrapped
		// TX along with the proof from the directory chain. If by end block there are still
		// unprocessed synthetic TX's the current leader takes over, invalidates the previous
		// leader's signed tx, signs the unprocessed synth tx, and tries again with the
		// new leader.  By EVERYONE submitting the leader signed synth tx to the designated
		// BVC network it takes advantage of the flood-fill gossip network tendermint will
		// provide and ensure the synth transaction will be picked up.

		// Batch synthetic transactions generated by the validator
		if m.leader {
			ed := new(transactions.ED25519Sig)
			//only if a leader we will need to sign and batch the tx's.
			//in future releases this will be submitted to this BVC to the next block for validation
			//of the synthetic tx by all the bvc nodes before being dispatched, along with DC receipt
			ed.PublicKey = m.key[32:]
			err := ed.Sign(tx.SigInfo.Nonce, m.key, tx.TransactionHash())
			if err != nil {
				return nil, fmt.Errorf("error signing sythetic transaction, %v", err)
			}

			tx.Signature = append(tx.Signature, ed)
			ti, err := m.query.BroadcastTx(tx, nil)
			if err != nil {
				return nil, err
			}

			tmRef[i] = new(protocol.TxSynthRef)
			tmRef[i].Type = uint64(tx.TransactionType())
			tmRef[i].Url = tx.SigInfo.URL
			copy(tmRef[i].Hash[:], tx.TransactionHash())
			copy(tmRef[i].TxRef[:], ti.ReferenceId)
		}
	}

	return tmRef, nil
}
