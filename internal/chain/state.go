package chain

import (
	"encoding"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/AccumulateNetwork/accumulate/internal/genesis"
	"github.com/AccumulateNetwork/accumulate/internal/url"
	"github.com/AccumulateNetwork/accumulate/protocol"
	"github.com/AccumulateNetwork/accumulate/smt/storage"
	"github.com/AccumulateNetwork/accumulate/types"
	"github.com/AccumulateNetwork/accumulate/types/api/transactions"
	"github.com/AccumulateNetwork/accumulate/types/state"
)

type StateManager struct {
	dbTx        *state.DBTransaction
	stores      map[[32]byte]*storeState
	chains      map[[32]byte]state.Chain
	writes      map[storage.Key][]byte
	submissions []*submittedTx
	storeCount  int
	txHash      types.Bytes32
	txType      types.TxType

	Sponsor        state.Chain
	SponsorUrl     *url.URL
	SponsorChainId [32]byte
}

type storeState struct {
	isCreate bool
	order    int
	chainId  *[32]byte
	record   state.Chain
}

// NewStateManager creates a new state manager and loads the transaction's
// sponsor. If the sponsor is not found, NewStateManager returns a valid state
// manager along with a not-found error.
func NewStateManager(dbTx *state.DBTransaction, tx *transactions.GenTransaction) (*StateManager, error) {
	m := new(StateManager)
	m.dbTx = dbTx
	m.chains = map[[32]byte]state.Chain{}
	m.stores = map[[32]byte]*storeState{}
	m.writes = map[storage.Key][]byte{}
	m.txHash = types.Bytes(tx.TransactionHash()).AsBytes32()
	m.txType = tx.TransactionType()

	// The genesis TX is special
	if tx.TransactionType() == types.TxTypeSyntheticGenesis {
		m.SponsorUrl = protocol.AcmeUrl()
		m.Sponsor = genesis.ACME
		return m, nil
	}

	// The sponsor URL must be valid
	var err error
	m.SponsorUrl, err = url.Parse(tx.SigInfo.URL)
	if err != nil {
		return nil, err
	}

	// Find the sponsor
	copy(m.SponsorChainId[:], m.SponsorUrl.ResourceChain())
	m.Sponsor, err = m.Load(m.SponsorChainId)
	if err == nil {
		return m, nil
	}

	// If the sponsor doesn't exist, that might be OK
	if errors.Is(err, storage.ErrNotFound) {
		return m, fmt.Errorf("sponsor %q %w", m.SponsorUrl, err)
	}
	return nil, err
}

type submittedTx struct {
	url  *url.URL
	body encoding.BinaryMarshaler
}

// LoadString loads a chain by URL and unmarshals it.
func (m *StateManager) LoadString(s string) (state.Chain, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %v", err)
	}

	return m.LoadUrl(u)
}

// LoadUrl loads a chain by URL and unmarshals it.
func (m *StateManager) LoadUrl(u *url.URL) (state.Chain, error) {
	var chainId [32]byte
	copy(chainId[:], u.ResourceChain())
	return m.Load(chainId)
}

// LoadStringAs loads a chain by URL and unmarshals it as a specific type.
func (m *StateManager) LoadStringAs(s string, v interface{}) error {
	u, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("invalid URL: %v", err)
	}

	return m.LoadUrlAs(u, v)
}

// LoadUrlAs loads a chain by URL and unmarshals it as a specific type.
func (m *StateManager) LoadUrlAs(u *url.URL, v interface{}) error {
	var chainId [32]byte
	copy(chainId[:], u.ResourceChain())
	return m.LoadAs(chainId, v)
}

// Load loads a chain by ID and unmarshals it.
func (m *StateManager) Load(chainId [32]byte) (state.Chain, error) {
	record, ok := m.chains[chainId]
	if ok {
		return record, nil
	}

	obj, err := m.dbTx.GetCurrentEntry(chainId[:])
	if err != nil {
		return nil, err
	}

	record, err = unmarshalRecord(obj)
	if err != nil {
		return nil, err
	}

	if m.chains == nil {
		m.chains = map[[32]byte]state.Chain{}
	}
	m.chains[chainId] = record
	return record, nil
}

// LoadAs loads a chain by ID and unmarshals it as a specific type.
func (m *StateManager) LoadAs(chainId [32]byte, v interface{}) (err error) {
	record, err := m.Load(chainId)
	if err != nil {
		return err
	}

	rv := reflect.ValueOf(v)
	rr := reflect.ValueOf(record)
	if !rr.Type().AssignableTo(rv.Type()) {
		return fmt.Errorf("want %T, got %T", v, record)
	}

	// Catch reflection panic
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("failed to load chain: unable to write to %T", v)
		}
	}()
	rv.Elem().Set(rr.Elem())
	return nil
}

// store adds a chain to the cache.
func (m *StateManager) store(record state.Chain, isCreate bool) {
	u, err := record.Header().ParseUrl()
	if err != nil {
		// The caller must ensure the chain URL is correct
		panic(fmt.Errorf("attempted to add an invalid chain: %v", err))
	}

	var chainId [32]byte
	copy(chainId[:], u.ResourceChain())
	m.chains[chainId] = record

	s, ok := m.stores[chainId]
	if !ok {
		s = new(storeState)
		m.stores[chainId] = s
	}

	s.chainId = &chainId
	s.record = record
	s.isCreate = isCreate
	s.order = m.storeCount
	m.storeCount++
}

// Update queues a record for storage in the database. The queued update will
// fail if the record does not already exist, unless it is created by a
// synthetic transaction, or the record is a transaction.
func (m *StateManager) Update(record ...state.Chain) {
	for _, r := range record {
		m.store(r, false)
	}
}

// Create queues a record for a synthetic chain create transaction. Will panic
// if called by a synthetic transaction. Will panic if the record is a
// transaction.
func (m *StateManager) Create(record ...state.Chain) {
	if m.txType.IsSynthetic() {
		panic("Called StateManager.Create from a synthetic transaction!")
	}
	for _, r := range record {
		if r.Header().Type.IsTransaction() {
			panic("Called StateManager.Create with a transaction record!")
		}
		m.store(r, true)
	}
}

// Submit queues a synthetic transaction for submission.
func (m *StateManager) Submit(url *url.URL, body encoding.BinaryMarshaler) {
	if m.txType.IsSynthetic() {
		panic("Called StateManager.Submit from a synthetic transaction!")
	}
	m.submissions = append(m.submissions, &submittedTx{url, body})
}

// commit writes pending records to the database.
func (m *StateManager) commit() error {
	for k, v := range m.writes {
		m.dbTx.Write(k, v)
	}

	// Create an ordered list of state stores
	stores := make([]*storeState, 0, len(m.stores))
	for _, store := range m.stores {
		stores = append(stores, store)
	}
	sort.Slice(stores, func(i, j int) bool { return stores[i].order < stores[j].order })

	// Push pending writes to the database
	create := map[string]*protocol.SyntheticCreateChain{}
	for _, store := range stores {
		data, err := store.record.MarshalBinary()
		if err != nil {
			return fmt.Errorf("failed to marshal record: %v", err)
		}

		switch {
		case store.isCreate:
			// Create: create a new record by adding it to a synthetic create
			// chain TX. All of the records created by a given synthetic create
			// chain MUST belong to the same routing location. Since routing
			// locations will change as the network grows, we cannot guarentee
			// that two different identities will route the same. So we will
			// create a synthetic create chain for each identity.

			// Parse the URL
			u, err := store.record.Header().ParseUrl()
			if err != nil {
				return fmt.Errorf("record has invalid URL: %v", err)
			}

			// If we have not created a synthetic create chain for this record's
			// identity, create one
			id := u.Identity()
			idStr := strings.ToLower(id.String())
			scc, ok := create[idStr]
			if !ok {
				scc = new(protocol.SyntheticCreateChain)
				scc.Cause = m.txHash

				// Submit just holds a reference to scc, so this will work fine
				m.Submit(id, scc)
				create[idStr] = scc
			}

			scc.Chains = append(scc.Chains, protocol.ChainParams{Data: data})

		default:
			// Update: update an existing record. Non-synthetic transactions are
			// not allowed to create records, so we must check if the record
			// already exists. The record may have been added to the DB
			// transaction already, so in order to actually know if the record
			// exists on disk, we have to use GetPersistentEntry.

			_, err = m.dbTx.GetPersistentEntry((*store.chainId)[:], false)
			switch {
			case err == nil:
				// If the record already exists, update it

			case !errors.Is(err, storage.ErrNotFound):
				// Handle unexpected errors
				return fmt.Errorf("failed to check for an existing record: %v", err)

			case store.record.Header().Type.IsTransaction():
				// Non-synthetic transactions are allowed to create transaction
				// records

			case m.txType.IsSynthetic():
				// Synthetic transactions are allowed to create records

			default:
				// Non-synthetic transactions are NOT allowed to create records
				// (except for TX records)
				return fmt.Errorf("cannot create a data record in a non-synthetic transaction")
			}

			m.dbTx.AddStateEntry((*types.Bytes32)(store.chainId), &m.txHash, &state.Object{Entry: data})
		}
	}

	return nil
}

func unmarshalRecord(obj *state.Object) (state.Chain, error) {
	header := new(state.ChainHeader)
	err := obj.As(header)
	if err != nil {
		return nil, err
	}

	var record state.Chain
	switch header.Type {
	// TODO DC, BVC, Token
	case types.ChainTypeIdentity:
		record = new(state.AdiState)
	case types.ChainTypeTokenAccount:
		record = new(state.TokenAccount)
	case types.ChainTypeLiteTokenAccount:
		record = new(protocol.AnonTokenAccount)
	case types.ChainTypeTransactionReference:
		record = new(state.TxReference)
	case types.ChainTypeTransaction:
		record = new(state.Transaction)
	case types.ChainTypePendingTransaction:
		record = new(state.PendingTransaction)
	case types.ChainTypeKeyPage:
		record = new(protocol.SigSpec)
	case types.ChainTypeKeyBook:
		record = new(protocol.SigSpecGroup)
	default:
		return nil, fmt.Errorf("unrecognized chain type %v", header.Type)
	}

	err = obj.As(record)
	if err != nil {
		return nil, err
	}

	return record, nil
}

func (s *StateManager) WriteIndex(index state.Index, chain []byte, key interface{}, value []byte) {
	k := storage.ComputeKey(string(index), chain, key)
	s.writes[k] = value
}

func (s *StateManager) GetIndex(index state.Index, chain []byte, key interface{}) ([]byte, error) {
	k := storage.ComputeKey(string(index), chain, key)
	w, ok := s.writes[k]
	if ok {
		return w, nil
	}
	return s.dbTx.GetIndex(index, chain, key)
}

func (m *StateManager) AddDirectoryEntry(u *url.URL) error {
	return AddDirectoryEntry(m, u)
}

func AddDirectoryEntry(db interface {
	WriteIndex(index state.Index, chain []byte, key interface{}, value []byte)
	GetIndex(index state.Index, chain []byte, key interface{}) ([]byte, error)
}, u *url.URL) error {
	md := new(protocol.DirectoryIndexMetadata)
	idc := u.IdentityChain()
	b, err := db.GetIndex(state.DirectoryIndex, idc, "Metadata")
	if err == nil {
		err = md.UnmarshalBinary(b)
	}
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		return fmt.Errorf("failed to load metadata: %v", err)
	}

	c := md.Count
	md.Count++
	b, err = md.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %v", err)
	}

	db.WriteIndex(state.DirectoryIndex, idc, "Metadata", b)
	db.WriteIndex(state.DirectoryIndex, idc, c, []byte(u.String()))
	return nil
}
