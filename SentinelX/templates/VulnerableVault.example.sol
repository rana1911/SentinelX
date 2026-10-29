// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

contract VulnerableVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // VULNERABLE: external call happens before the balance is zeroed,
    // classic reentrancy.
    function withdraw() external {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "no balance");
        (bool ok, ) = msg.sender.call{value: bal}("");
        require(ok, "transfer failed");
        balances[msg.sender] = 0;
    }

    receive() external payable {}
}
