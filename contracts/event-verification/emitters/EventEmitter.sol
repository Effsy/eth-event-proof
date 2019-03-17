pragma solidity ^0.4.23;

contract EventEmitter {

    event EventOfInterest();

    function emitEvent() public {
        emit EventOfInterest();
    }

}

