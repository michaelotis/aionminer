// Modified AION Foundation 2017-2018
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_BLOCK_H
#define BITCOIN_PRIMITIVES_BLOCK_H

#include "primitives/transaction.h"
#include "serialize.h"
#include "uint256.h"

/** Nodes collect new transactions into a block, hash them into a hash tree,
* and scan through nonce values to make the block's hash satisfy proof-of-work
* requirements.  When they solve the proof-of-work, they broadcast the block
* to everyone and the block is added to the block chain.  The first transaction
* in the block is a special one that creates a new coin owned by the creator
* of the block.
*/

class CBlockHeader
{
public:
	// header
	static const size_t HEADER_SIZE = 4 + 32 + 32 + 32 + 4 + 4 + 32; // excluding Equihash solution
	static const int32_t CURRENT_VERSION = 4;
	int32_t nVersion;
	uint256 hashPrevBlock;
	uint256 hashMerkleRoot;
	uint256 hashReserved;
	uint32_t nTime;
	uint32_t nBits;
	uint256 nNonce;
	std::vector<unsigned char> nSolution;

	CBlockHeader()
	{
		SetNull();
	}

	ADD_SERIALIZE_METHODS;

	template <typename Stream, typename Operation>
	inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
		READWRITE(this->nVersion);
		nVersion = this->nVersion;
		READWRITE(hashPrevBlock);
		READWRITE(hashMerkleRoot);
		READWRITE(hashReserved);
		READWRITE(nTime);
		READWRITE(nBits);
		READWRITE(nNonce);
		READWRITE(nSolution);
	}

	void SetNull()
	{
		nVersion = CBlockHeader::CURRENT_VERSION;
		hashPrevBlock.SetNull();
		hashMerkleRoot.SetNull();
		hashReserved.SetNull();
		nTime = 0;
		nBits = 0;
		nNonce = uint256();
		nSolution.clear();
	}

	bool IsNull() const
	{
		return (nBits == 0);
	}

	uint256 GetHash() const;

	int64_t GetBlockTime() const
	{
		return (int64_t)nTime;
	}
};


class CBlock : public CBlockHeader
{
public:
	// network and disk
	std::vector<CTransaction> vtx;

	// memory only
	mutable std::vector<uint256> vMerkleTree;

	CBlock()
	{
		SetNull();
	}

	CBlock(const CBlockHeader &header)
	{
		SetNull();
		*((CBlockHeader*)this) = header;
	}

	ADD_SERIALIZE_METHODS;

	template <typename Stream, typename Operation>
	inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
		READWRITE(*(CBlockHeader*)this);
		READWRITE(vtx);
	}

	void SetNull()
	{
		CBlockHeader::SetNull();
		vtx.clear();
		vMerkleTree.clear();
	}

	CBlockHeader GetBlockHeader() const
	{
		CBlockHeader block;
		block.nVersion = nVersion;
		block.hashPrevBlock = hashPrevBlock;
		block.hashMerkleRoot = hashMerkleRoot;
		block.hashReserved = hashReserved;
		block.nTime = nTime;
		block.nBits = nBits;
		block.nNonce = nNonce;
		block.nSolution = nSolution;
		return block;
	}

	// Build the in-memory merkle tree for this block and return the merkle root.
	// If non-NULL, *mutated is set to whether mutation was detected in the merkle
	// tree (a duplication of transactions in the block leading to an identical
	// merkle root).
	uint256 BuildMerkleTree(bool* mutated = NULL) const;

	std::vector<uint256> GetMerkleBranch(int nIndex) const;
	static uint256 CheckMerkleBranch(uint256 hash, const std::vector<uint256>& vMerkleBranch, int nIndex);
	std::string ToString() const;
};


/**
* Custom serializer for CBlockHeader that omits the nonce and solution, for use
* as input to Equihash.
*/
class CEquihashInput : private CBlockHeader
{
public:
	CEquihashInput(const CBlockHeader &header)
	{
		CBlockHeader::SetNull();
		*((CBlockHeader*)this) = header;
	}

	ADD_SERIALIZE_METHODS;

	template <typename Stream, typename Operation>
	inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
		READWRITE(this->nVersion);
		nVersion = this->nVersion;
		READWRITE(hashPrevBlock);
		READWRITE(hashMerkleRoot);
		READWRITE(hashReserved);
		READWRITE(nTime);
		READWRITE(nBits);
	}
};


/** Describes a place in the block chain to another node such that if the
* other node doesn't have the same branch, it can find a recent common trunk.
* The further back it is, the further before the fork it may be.
*/
struct CBlockLocator
{
	std::vector<uint256> vHave;

	CBlockLocator() {}

	CBlockLocator(const std::vector<uint256>& vHaveIn)
	{
		vHave = vHaveIn;
	}

	ADD_SERIALIZE_METHODS;

	template <typename Stream, typename Operation>
	inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
		if (!(nType & SER_GETHASH))
			READWRITE(nVersion);
		READWRITE(vHave);
	}

	void SetNull()
	{
		vHave.clear();
	}

	bool IsNull() const
	{
		return vHave.empty();
	}
};

class ABlockHeader
{
public:
	// AION header

	/*
	Parent hash: 32 bytes
	CoinBase: 32 bytes
	StateRoot: 32 bytes
	TxTrie: 32 bytes
	ReceiptTrieRoot: 32 bytes
	logsBloom: 256 bytes
	Difficulty: 16 bytes
	Timestamp: 8 bytes
	Number: 8 bytes
	extraData: 32 bytes
	EnergyConsumed: 8 bytes
	EnergyLimit: 8 bytes

	Total: 484 bytes
	*/

	// static const size_t HEADER_SIZE = 32 + 32 + 32 + 32 + 32 + 256 + 16 + 8 + 8 + 32 + 8 + 8; // excluding Equihash solution and nonce

	// uint256 parentHash;
	// uint256 coinBase;
	// uint256 stateRoot;
	// uint256 txTrie;
	// uint256 receiptTreeRoot;
	// uint2048 logsBloom;
	// uint128 difficulty;
	// uint64_t timeStamp;
	// uint64_t number;
	// uint256 extraData;
	// uint64_t energyConsumed;
	// uint64_t energyLimit;

	// uint256 nNonce;
	// std::vector<unsigned char> nSolution;

	static const size_t HEADER_SIZE = 32; //headerHash

	uint256 headerHash;

	uint256 nNonce;
	std::vector<unsigned char> nSolution;

	ABlockHeader()
	{
		SetNull();
	}

	ADD_SERIALIZE_METHODS;

	template <typename Stream, typename Operation>
	inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {

		// READWRITE(parentHash);
		// READWRITE(coinBase);
		// READWRITE(stateRoot);
		// READWRITE(txTrie);
		// READWRITE(receiptTreeRoot);
		// READWRITE(logsBloom);
		// READWRITE(difficulty);
		// READWRITE(timeStamp);
		// READWRITE(number);
		// READWRITE(extraData);
		// READWRITE(energyConsumed);
		// READWRITE(energyLimit);

		READWRITE(headerHash);

		READWRITE(nNonce);
		READWRITE(nSolution);
	}

	void SetNull()
	{
		headerHash.SetNull();
		// parentHash.SetNull();
		// coinBase.SetNull();
		// stateRoot.SetNull();
		// txTrie.SetNull();
		// receiptTreeRoot.SetNull();
		// logsBloom.SetNull();
		// difficulty.SetNull();
		// timeStamp = 0;
		// number = 0;
		// extraData.SetNull();
		// energyConsumed = 0;
		// energyLimit = 0;
		nNonce = uint256();
		nSolution.clear();
	}

	// bool IsNull() const
	// {
	// 	return (number == 0);
	// }

	uint256 GetHash() const;

	// int64_t GetBlockTime() const
	// {
	// 	return timeStamp;
	// }
};


class ABlock : public ABlockHeader
{
public:
	// network and disk
	//std::vector<CTransaction> vtx;

	// memory only
	mutable std::vector<uint256> vMerkleTree;

	ABlock()
	{
		SetNull();
	}

	ABlock(const ABlockHeader &header)
	{
		SetNull();
		*((ABlockHeader*)this) = header;
	}

	ADD_SERIALIZE_METHODS;

	template <typename Stream, typename Operation>
	inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
		READWRITE(*(ABlockHeader*)this);
		//READWRITE(vtx);
	}

	void SetNull()
	{
		ABlockHeader::SetNull();
		//vtx.clear();
		//vMerkleTree.clear();
	}

	ABlockHeader GetBlockHeader() const
	{
		ABlockHeader block;

		block.headerHash = headerHash;
		// block.parentHash = parentHash;
		// block.coinBase = coinBase;
		// block.stateRoot = stateRoot;
		// block.txTrie = txTrie;
		// block.receiptTreeRoot = receiptTreeRoot;
		// block.logsBloom = logsBloom;
		// block.difficulty = difficulty;
		// block.timeStamp = timeStamp;
		// block.number = number;
		// block.extraData = extraData;
		// block.energyConsumed = energyConsumed;
		// block.energyLimit = energyLimit;
		block.nNonce = nNonce;
		block.nSolution = nSolution;
		return block;
	}

	std::string ToString() const;
};


/**
* Custom serializer for ABlockHeader that omits the nonce and solution, for use
* as input to Equihash.
*/
class AEquihashInput : private ABlockHeader
{
public:
	AEquihashInput(const ABlockHeader &header)
	{
		ABlockHeader::SetNull();
		*((ABlockHeader*)this) = header;
	}

	ADD_SERIALIZE_METHODS;

	template <typename Stream, typename Operation>
	inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {

		// READWRITE(parentHash);
		// READWRITE(coinBase);
		// READWRITE(stateRoot);
		// READWRITE(txTrie);
		// READWRITE(receiptTreeRoot);
		// READWRITE(logsBloom);
		// READWRITE(difficulty);
		// READWRITE(timeStamp);
		// READWRITE(number);
		// READWRITE(extraData);
		// READWRITE(energyConsumed);
		// READWRITE(energyLimit);

		READWRITE(headerHash);
	}
};

#endif // BITCOIN_PRIMITIVES_BLOCK_H