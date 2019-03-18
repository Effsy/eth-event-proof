// Copyright (c) 2016-2018 Clearmatics Technologies Ltd
// SPDX-License-Identifier: LGPL-3.0+
pragma solidity ^0.5.2;

//import "../DxInteracts.sol";
import "./Verifier.sol";

contract EventEmitterVerifier {
    function verify(bytes20 _contractEmittedAddress, bytes memory _rlpReceipt) public returns (bool);
}

contract DxiTriggerPostSellOrder {

    EventEmitterVerifier eventVerifier;

    constructor(address _verifierAddr) public {
        eventVerifier = EventEmitterVerifier(_verifierAddr);
    }

    function verifyAndExecute(
        bytes memory _proof,
        bytes memory _blockHeader,
        bytes20 _contractEmittedAddress
        
    ) public {
        bytes memory receipt = Verifier.CheckProofs(_proof, _blockHeader);

        //require(verifier.verify(_contractEmittedAddress, receipt), "Event verification failed.");
        //dxInteracts.postSellOrder(sellToken, buyToken, auctionIndex, amount);
    }

}