    // Copyright (c) 2016-2018 Clearmatics Technologies Ltd
// SPDX-License-Identifier: LGPL-3.0+
pragma solidity ^0.4.23;

//import "../DxInteracts.sol";

import "./libraries/RLP.sol";
import "./libraries/PatriciaTrie.sol";

contract EventEmitterVerifier {
    function verify(bytes20 _contractEmittedAddress, bytes memory _rlpReceipt, bytes20 _expectedAddress) public returns (bool);
}

/*
    This function contract is the consumer of an event and performs some execution thereafter. In practice, this would
    be written by a contract designer that intends to consume specific events from another chain. As such all behaviour
    and dependence on such event must be defined here.

    Common custom behaviour may include:
    * Keeping an array of transaction hashes denoting the specific events from that transaction that
    have already been consumed to restrict multiple consumption or 'double spend' of events.
    * Extending the amount of expected event parameters above the stack limit. This might then require some other method
    of passing expected parameters to the contract possibly via RLP-encoding to compress all data to a single argument
    and decoding them within the `verifyAndExecute` function.
    * Including multiple event verifiers if a function requires proof of multiple state transitions from other chains.
    This would also bloat the local scope which is prone to 'stack too deep' issues which would require custom
    workarounds.
*/
contract DxiTriggerPostSellOrder {



    EventEmitterVerifier verifier;

    constructor() public {
        //verifier = EventEmitterVerifier(_verifierAddr);
    }


    /*  
        verifyAndExecute

        Core parameters for verification
        param: _chainId (bytes32)   Chain ID of the chain that the event being consumed was emitted on. This may require
                                    altering to (bytes) if proofs from multiple chains are needed.
        param: _blockHash (bytes32) Block hash of block with event to be consumed. This may require altering to (bytes)
                                    if proofs from multiple chains are needed.
        param: _contractEmittedAddress (bytes20)    Contract address of the source of event emission. This may require
                                                    altering to (bytes) if proofs from multiple chains are needed.
        param: _path (bytes)    RLP-encoded transaction index of the relevant transaction that emitted the event being
                                consumed. If multiple proofs are required, multiple paths supplied must be RLP-encoded
                                and an extra (bool) parameter provided to denote multiple paths included.
        param: _tx (bytes) RLP-encoded transaction object provided by proof generation.
        param: _txNodes (bytes) RLP_encoded transaction nodes provided by proof generation.
        param: _receipt (bytes) RLP-encoded receipt object provided by proof generation.
        param: _receiptNodes (bytes) RLP-encoded receipt nodes provided by proof generation.

        Custom parameters for verification
        param: _expectedAddress (bytes20) The expected address value in the event parameter being consumed.

        This is the only public function apart from the constructor and is the only interface to this contract. This 
        function wraps the verification and execution which only fires after a successful slew of verifications. As
        noted, stack restrictions will make it harder to implement multiple event consumption. Suggestions made here may
        not be the best way to achieve this but are possible methods. It may end up requiring separate functions for
        each event and persisting the consumption state of each event per tx hash and using that to allow or prevent
        verified execution. In our case, it is simple as we only consume a single event.
        */
    function verifyAndExecute(
        bytes32 _blockHash,
        bytes memory _proof
        //bytes20 _contractEmittedAddress,
        //bytes20 _expectedAddress
    ) public {
        CheckProofs(_blockHash, _proof);

        //require(verifier.verify(_contractEmittedAddress, receipt, _expectedAddress), "Event verification failed.");
        //dxInteracts.postSellOrder(sellToken, buyToken, auctionIndex, amount);
    }
    using RLP for RLP.RLPItem;
    using RLP for RLP.Iterator;
    using RLP for bytes;

    function CheckProofs(bytes32 _blockHash, bytes _proof) public returns (bytes memory){
        RLP.RLPItem[] memory proof = _proof.toRLPItem().toList();

        require(proof.length == 5, "Malformed proof");

        assert(CheckRootsProof(_blockHash, proof[2].toBytes(), proof[4].toBytes()));
        assert(CheckTxProof(_blockHash, proof[1].toBytes(), proof[2].toBytes(), proof[0].toBytes()));
        assert(CheckReceiptProof(_blockHash, proof[3].toBytes(), proof[4].toBytes(), proof[0].toBytes()));

        return proof[3].toBytes();
    }

    /*
    * CheckTxProof
    * param: _id (bytes32) Unique id of chain submitting block from
    * param: _blockHash (bytes32) Block hash of block being submitted
    * param: _value (bytes) RLP-encoded transaction object array with fields defined as: https://github.com/ethereumjs/ethereumjs-tx/blob/0358fad36f6ebc2b8bea441f0187f0ff0d4ef2db/index.js#L50
    * param: _parentNodes (bytes) RLP-encoded array of all relevant nodes from root node to node to prove
    * param: _path (bytes) Byte array of the path to the node to be proved
    *
    * emits: VerifiedTxProof(chainId, blockHash, proofType)
    *        chainId: (bytes32) hash of the chain verifying proof against
    *        blockHash: (bytes32) hash of the block verifying proof against
    *        proofType: (uint) enum of proof type
    *
    * All data associated with the proof must be constructed and provided to this function. Modifiers restrict execution
    * of this function to only allow if the chain the proof is for is registered to this contract and if the block that
    * the proof is for has been submitted.
    */
    function CheckTxProof(
        bytes32 _blockHash,
        bytes _value,
        bytes _parentNodes,
        bytes _path
    )
        internal
        returns (bool)
    {

        bytes32 txRoot = 0x21f807836a9178a9cee846ae940221d1bafaba375a1b1bc779eb0596a59bafa7;

        verifyProof(_value, _parentNodes, _path, txRoot);

        return true;
    }

    /*
    * CheckReceiptProof
    * param: _id (bytes32) Unique id of chain submitting block from
    * param: _blockHash (bytes32) Block hash of block being submitted
    * param: _value (bytes) RLP-encoded receipt object array with fields defined as: https://github.com/ethereumjs/ethereumjs-tx/blob/0358fad36f6ebc2b8bea441f0187f0ff0d4ef2db/index.js#L50
    * param: _parentNodes (bytes) RLP-encoded array of all relevant nodes from root node to node to prove
    * param: _path (bytes) Byte array of the path to the node to be proved
    *
    * emits: VerifiedTxProof(chainId, blockHash, proofType)
    *        chainId: (bytes32) hash of the chain verifying proof against
    *        blockHash: (bytes32) hash of the block verifying proof against
    *        proofType: (uint) enum of proof type
    *
    * All data associated with the proof must be constructed and paddChainrovided to this function. Modifiers restrict execution
    * of this function to only allow if the chain the proof is for is registered to this contract and if the block that
    * the proof is for has been submitted.
    */
    function CheckReceiptProof(
        bytes32 _blockHash,
        bytes _value,
        bytes _parentNodes,
        bytes _path
    )
        internal
        returns (bool)
    {
        verifyProof(_value, _parentNodes, _path, getRootNodeHash(_parentNodes));

        return true;
    }

    /*
    * CheckRootsProof
    * param: _id (bytes32) Unique id of chain submitting block from
    * param: _blockHash (bytes32) Block hash of block being submitted
    * param: _txNodes (bytes) RLP-encoded relevant nodes of the Tx trie
    * param: _receiptNodes (bytes) RLP-encoded relevant nodes of the Receipt trie
    *
    * emits: VerifiedTxProof(chainId, blockHash, proofType)
    *        chainId: (bytes32) hash of the chain verifying proof against
    *        blockHash: (bytes32) hash of the block verifying proof against
    *        proofType: (uint) enum of proof type
    *
    * All data associated with the proof must be constructed and provided to this function. Modifiers restrict execution
    * of this function to only allow if the chain the proof is for is registered to this contract and if the block that
    * the proof is for has been submitted.
    */
    function CheckRootsProof(
        bytes32 _blockHash,
        bytes _txNodes,
        bytes _receiptNodes
    )
        internal
        returns (bool)
    {
        //assert( m_blockheaders[_blockHash].txRootHash == getRootNodeHash(_txNodes) );
        //assert( m_blockheaders[_blockHash].receiptRootHash == getRootNodeHash(_receiptNodes) );

        return true;
    }

    function verifyProof(bytes _value, bytes _parentNodes, bytes _path, bytes32 _hash) internal {
        assert( PatriciaTrie.verifyProof(_value, _parentNodes, _path, _hash) );
    }

/*
========================================================================================================================

    Helper Functions

========================================================================================================================
*/

    /*
    * @description      returns the root node of an RLP encoded Patricia Trie
	* @param _rlpNodes  RLP encoded trie
	* @returns          root hash
	*/
    function getRootNodeHash(bytes _rlpNodes) private view returns (bytes32) {
        RLP.RLPItem[] memory nodeList = _rlpNodes.toRLPItem().toList();

        bytes memory b_nodeRoot = RLP.toBytes(nodeList[0]);

        return keccak256(b_nodeRoot);
    }


}






//     function CheckProofs(bytes32 _blockHash, bytes memory _proof) public returns (bytes memory){
//         RLP.RLPItem[] memory proof = RLP.toRLPItem(_proof).toList();
//         //RLP.RLPItem memory proof = RLP.toRLPItem(_proof);
//         //emit ProofData(proof[0].toBytes(), proof[1].toBytes(), proof[2].toBytes(), proof[3].toBytes(), proof[4].toBytes());
//         //require(proof.length == 5, "Malformed proof");

//         //assert(CheckRootsProof(_blockHash, proof[2].toBytes(), proof[4].toBytes()));
//         //assert(CheckTxProof(_blockHash, proof[1].toBytes(), proof[2].toBytes(), proof[0].toBytes()));
//         //assert(CheckReceiptProof(_blockHash, proof[3].toBytes(), proof[4].toBytes(), proof[0].toBytes()));
//         bytes memory temp = "0x2123423234324324242432";
//         return temp;
//     }
//     event ProofData(bytes, bytes, bytes, bytes, bytes);
//     /*
//     * CheckTxProof
//     * param: _id (bytes32) Unique id of chain submitting block from
//     * param: _blockHash (bytes32) Block hash of block being submitted
//     * param: _value (bytes) RLP-encoded transaction object array with fields defined as: https://github.com/ethereumjs/ethereumjs-tx/blob/0358fad36f6ebc2b8bea441f0187f0ff0d4ef2db/index.js#L50
//     * param: _parentNodes (bytes) RLP-encoded array of all relevant nodes from root node to node to prove
//     * param: _path (bytes) Byte array of the path to the node to be proved
//     *
//     * emits: VerifiedTxProof(chainId, blockHash, proofType)
//     *        chainId: (bytes32) hash of the chain verifying proof against
//     *        blockHash: (bytes32) hash of the block verifying proof against
//     *        proofType: (uint) enum of proof type
//     *
//     * All data associated with the proof must be constructed and provided to this function. Modifiers restrict execution
//     * of this function to only allow if the chain the proof is for is registered to this contract and if the block that
//     * the proof is for has been submitted.
//     */
//     function CheckTxProof(
//         bytes32 _blockHash,
//         bytes memory _value,
//         bytes memory _parentNodes,
//         bytes memory _path
//     )
//         //onlyExistingBlocks(_blockHash)
//         internal
//         returns (bool)
//     {
//         emit TxRoot(getRootNodeHash(_parentNodes));
        
//         bytes32 txRoot = getRootNodeHash(_parentNodes);

//         verifyProof(_value, _parentNodes, _path, txRoot);

//         emit VerifiedProof(_blockHash, uint(ProofType.TX));
//         return true;
//     }
//     event TxRoot(bytes32);
    
//     // function stringToBytes32(string memory source) public returns (bytes32 result) {
//     //     bytes memory tempEmptyStringTest = bytes(source);
//     //     if (tempEmptyStringTest.length == 0) {
//     //         return 0x0;
//     //     }

//     //     assembly {
//     //         result := mload(add(source, 32))
//     //     }
//     // }

//     /*
//     * CheckReceiptProof
//     * param: _id (bytes32) Unique id of chain submitting block from
//     * param: _blockHash (bytes32) Block hash of block being submitted
//     * param: _value (bytes) RLP-encoded receipt object array with fields defined as: https://github.com/ethereumjs/ethereumjs-tx/blob/0358fad36f6ebc2b8bea441f0187f0ff0d4ef2db/index.js#L50
//     * param: _parentNodes (bytes) RLP-encoded array of all relevant nodes from root node to node to prove
//     * param: _path (bytes) Byte array of the path to the node to be proved
//     *
//     * emits: VerifiedTxProof(chainId, blockHash, proofType)
//     *        chainId: (bytes32) hash of the chain verifying proof against
//     *        blockHash: (bytes32) hash of the block verifying proof against
//     *        proofType: (uint) enum of proof type
//     *
//     * All data associated with the proof must be constructed and paddChainrovided to this function. Modifiers restrict execution
//     * of this function to only allow if the chain the proof is for is registered to this contract and if the block that
//     * the proof is for has been submitted.
//     */
//     function CheckReceiptProof(
//         bytes32 _blockHash,
//         bytes memory _value,
//         bytes memory _parentNodes,
//         bytes memory _path
//     )
//         //onlyExistingBlocks(_blockHash)
//         internal
//         returns (bool)
//     {
//         //verifyProof(_value, _parentNodes, _path, getRootNodeHash(_parentNodes));

//         emit VerifiedProof(_blockHash, uint(ProofType.RECEIPT));
//         return true;
//     }

//     /*
//     * CheckRootsProof
//     * param: _id (bytes32) Unique id of chain submitting block from
//     * param: _blockHash (bytes32) Block hash of block being submitted
//     * param: _txNodes (bytes) RLP-encoded relevant nodes of the Tx trie
//     * param: _receiptNodes (bytes) RLP-encoded relevant nodes of the Receipt trie
//     *
//     * emits: VerifiedTxProof(chainId, blockHash, proofType)
//     *        chainId: (bytes32) hash of the chain verifying proof against
//     *        blockHash: (bytes32) hash of the block verifying proof against
//     *        proofType: (uint) enum of proof type
//     *
//     * All data associated with the proof must be constructed and provided to this function. Modifiers restrict execution
//     * of this function to only allow if the chain the proof is for is registered to this contract and if the block that
//     * the proof is for has been submitted.
//     */
//     function CheckRootsProof(
//         bytes32 _blockHash,
//         bytes memory _txNodes,
//         bytes memory _receiptNodes
//     )
//         //onlyExistingBlocks(_blockHash)
//         internal
//         returns (bool)
//     {
//         //assert( m_blockheaders[_blockHash].txRootHash == getRootNodeHash(_txNodes) );
//         //assert( m_blockheaders[_blockHash].receiptRootHash == getRootNodeHash(_receiptNodes) );

//         emit VerifiedProof(_blockHash, uint(ProofType.ROOTS));
//         return true;
//     }

//     function verifyProof(bytes memory _value, bytes memory _parentNodes, bytes memory _path, bytes32 _hash) internal {
//         //require(PatriciaTrie.verifyProof(_value, _parentNodes, _path, _hash), "verification failed");
//         PatriciaTrie.verifyProof(_value, _parentNodes, _path, _hash);
//     }

// /*
// ========================================================================================================================

//     Helper Functions

// ========================================================================================================================
// */

//     /*
//     * @description      returns the root node of an RLP encoded Patricia Trie
// 	* @param _rlpNodes  RLP encoded trie
// 	* @returns          root hash
// 	*/
//     function getRootNodeHash(bytes memory _rlpNodes) private view returns (bytes32) {
//         RLP.RLPItem[] memory nodeList = RLP.toRLPItem(_rlpNodes).toList();

//         bytes memory b_nodeRoot = RLP.toBytes(nodeList[0]);

//         return keccak256(b_nodeRoot);
//     }


//}

