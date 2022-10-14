// SPDX-License-Identifier: MIT
//
// A simplified implementation of Hawk
// Author: Siqi

pragma solidity ^0.8.0;

import * as Cash from "./CashBase.sol";

contract Hawk is Cash.Cashbase {
    struct Freezeitem{
        bytes32 p;
        bytes32 cm;
        bytes32 ctH;
        bytes32 ctL;
    }

    uint constant DEPTH = 8;
    uint constant N = 2;
    Cash.PourVerifier public pourVerifier;
    Cash.FreezeVerifier public freezeVerifier;
    Cash.ComputeVerifier public computeVerifier;
    Cash.FinalizeVerifier public finalizeVerifier;
    Cash.WithdrawVerifier public withdrawVerifier;

    bytes32[1 << (DEPTH + 1)] public hashes;
    uint public cur;
    address public owner;
    address public manager;
    bytes32[4] public epk;
    mapping(bytes32 => bool) public nullifier;
    Freezeitem[] public freezeCoins;
    bool public finalized;

    constructor(
        Cash.PourVerifier _pourVerifier, 
        Cash.FreezeVerifier _freezeVerifier, 
        Cash.ComputeVerifier _computeVerifier, 
        Cash.FinalizeVerifier _finalizeVerifier,
        Cash.WithdrawVerifier _withdrawVerifier,
        address _manager,
        bytes32[4] memory _epk
    ) {
        owner = msg.sender;
        pourVerifier = _pourVerifier;
        freezeVerifier = _freezeVerifier;
        computeVerifier = _computeVerifier;
        finalizeVerifier = _finalizeVerifier;
        withdrawVerifier = _withdrawVerifier;
        manager = _manager;
        epk = _epk;
        cur = 0;
        finalized = false;
    }

    function addCoin(bytes32 p, bytes32 coin) internal {
        bytes32 h = sha256(abi.encodePacked(p, coin));
        for (uint i = 0; i < cur; i++) {
            // assert (p,coin) not in Coins
            // Time complexity is O(n), which needs improvement
            if (hashes[(1<<DEPTH) + i] == h) revert("coin already exists");
        }
        hashes[(1 << DEPTH) + cur] = h;
        uint n = ((1 << DEPTH) + cur) >> 1;
        while (n > 0) {
            hashes[n] = sha256(abi.encodePacked(hashes[n << 1], hashes[n << 1 | 1]));
            n >>= 1;
        }
        cur += 1;
    }

    function mint(bytes32 p, bytes32 s) external payable override returns(uint){
        require(cur < (1 << (DEPTH + 1)));
        require(msg.value > 0 && msg.value <= type(uint32).max);
        bytes32 coin = sha256(abi.encodePacked(s, msg.value));
        addCoin(p, coin);
        return cur - 1;
    }

    function pour(Cash.Proof memory proof, bytes32 sn1, bytes32 p1, bytes32 coin1, bytes32 p2, bytes32 coin2) external override returns(uint){
        uint[32] memory input = [uint(0), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        bytes32 sub = bytes32(uint((1 << 32) - 1));
        bytes32 tmp = hashes[1];
        for (uint i = 8; i > 0; i--) {
            input[i - 1] = uint(tmp & sub); tmp >>= 32;
        }
        tmp = sn1;
        for (uint i = 16; i > 8; i--) {
            input[i - 1] = uint(tmp & sub); tmp >>= 32;
        }
        tmp = coin1;
        for (uint i = 24; i > 16; i--) {
            input[i - 1] = uint(tmp & sub); tmp >>= 32;
        }
        tmp = coin2;
        for (uint i = 32; i > 24; i--) {
            input[i - 1] = uint(tmp & sub); tmp >>= 32;
        }
        require(pourVerifier.verifyTx(proof, input));
        require(!nullifier[sn1]);
        nullifier[sn1] = true;
        addCoin(p1, coin1);
        addCoin(p2, coin2);
        return cur - 1;
    }

    function freeze(Cash.Proof memory proof, bytes32 p, bytes32 sn, bytes32 cm) external override{
        uint[32] memory input = [uint(0), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        bytes32 sub = bytes32(uint((1 << 32) - 1));
        bytes32 tmp = hashes[1];
        for (uint i = 8; i > 0; i--) {
            input[i - 1] = uint(tmp & sub); tmp >>= 32;
        }
        tmp = sn;
        for (uint i = 16; i > 8; i--) {
            input[i - 1] = uint(tmp & sub); tmp >>= 32;
        }
        tmp = cm;
        for (uint i = 24; i > 16; i--) {
            input[i - 1] = uint(tmp & sub); tmp >>= 32;
        }
        tmp = p;
        for (uint i = 32; i > 24; i--) {
            input[i - 1] = uint(tmp & sub); tmp >>= 32;
        }
        require(freezeVerifier.verifyTx(proof, input));
        require(!nullifier[sn]);
        nullifier[sn] = true;
        freezeCoins.push(Freezeitem({p : p, cm : cm, ctH : 0, ctL : 0}));
    }
    function compute(Cash.Proof memory proof, bytes32 cm, bytes32[2] memory ct) external override{
        uint n = freezeCoins.length;
        uint x = n;
        for (uint i = 0; i < n; i++) {
            if (freezeCoins[i].cm == cm) {
                x = i;
                break;
            } 
        }
        require(x < n, "no freeze cm found");
        uint[28] memory input = [uint(epk[0]), uint(epk[1]), uint(epk[2]), uint(epk[3]), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        bytes32 sub = bytes32(uint((1 << 32) - 1));
        bytes32 tmp = cm;
        for (uint i = 12; i > 4; i--) {
            input[i - 1] = uint(tmp & sub); tmp >>= 32;
        }
        tmp = ct[0];
        for (uint i = 20; i > 12; i--) {
            input[i - 1] = uint(tmp & sub); tmp >>= 32;
        }
        tmp = ct[1];
        for (uint i = 28; i > 20 ; i--) {
            input[i - 1] = uint(tmp & sub); tmp >>= 32;
        }
        require(computeVerifier.verifyTx(proof, input), "proof rejected");
        freezeCoins[x].ctH = ct[0];
        freezeCoins[x].ctL = ct[1];
    }
    
    function finalize(Cash.Proof memory proof, uint32 out, bytes32[2] memory coin, bytes32[2][2] memory ct) external override{
        require(msg.sender == manager);
        require(!finalized);
        require(freezeCoins.length >= N);
        uint[65] memory input = [uint(0), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        bytes32 sub = bytes32(uint((1 << 32) - 1));
        input[0] = out;
        bytes32 tmp = (freezeCoins[0].ctH == 0 && freezeCoins[0].ctL == 0) ? bytes32(0) : freezeCoins[0].cm;
        for (uint i = 9; i > 1; i--) {
            input[i - 1] = uint(tmp & sub); tmp >>= 32;
        }
        tmp = (freezeCoins[1].ctH == 0 && freezeCoins[1].ctL == 0) ? bytes32(0) : freezeCoins[1].cm;
        for (uint i = 17; i > 9; i--) {
            input[i - 1] = uint(tmp & sub); tmp >>= 32;
        }
        tmp = coin[0];
        for (uint i = 25; i > 17; i--) {
            input[i - 1] = uint(tmp & sub); tmp >>= 32;
        }
        tmp = coin[1];
        for (uint i = 33; i > 25; i--) {
            input[i - 1] = uint(tmp & sub); tmp >>= 32;
        }
        tmp = ct[0][0];
        for (uint i = 41; i > 33; i--) {
            input[i - 1] = uint(tmp & sub); tmp >>= 32;
        }
        tmp = ct[0][1];
        for (uint i = 49; i > 41; i--) {
            input[i - 1] = uint(tmp & sub); tmp >>= 32;
        }
        tmp = ct[1][0];
        for (uint i = 57; i > 49; i--) {
            input[i - 1] = uint(tmp & sub); tmp >>= 32;
        }
        tmp = ct[1][1];
        for (uint i = 65; i > 57; i--) {
            input[i - 1] = uint(tmp & sub); tmp >>= 32;
        }
        require(finalizeVerifier.verifyTx(proof, input));
        finalized = true;
        for (uint i = 0; i < N; i++) {
            addCoin(freezeCoins[i].p, coin[i]);
            freezeCoins[i].ctH = ct[i][0];
            freezeCoins[i].ctL = ct[i][1];
        }
    }

    /*function computePublic(Proof memory proof, bytes32 cm, uint32 indata, uint32 val) external payable override{
        // since the on-chain smart contracts instead of a off-chain manager takes the role of computation in this version, 
        // the coin value should be revealed while computing
        // User sends the value and zkp of knowing the randomness s to reveal a coin
        // Once a coin is revealed, the contract sends the corrresponding value to the msg sender.
        // Note that there is no need to compute a zero-knowledge proof of membership within the frozen pool 
        // as is needed in a freeze transaction
        require(freezeCoins[cm] == msg.sender);
        require(val > 0);
        uint[10] memory input = [uint(0), 0, 0, 0, 0, 0, 0, 0, 0, 0];
        bytes32 sub = bytes32(uint((1 << 32) - 1));
        bytes32 tmp = cm;
        for (uint i = 8; i > 0; i--) {
            input[i - 1] = uint(tmp & sub); tmp >>= 32;
        }
        input[8] = indata;
        input[9] = val;
        require(computeVerifier.verifyTx(proof, input));
        freezeCoins[cm] = address(0);
        payable(msg.sender).transfer(val);
    }*/

    /*function withdraw(Proof memory proof, bytes32 cm, bytes32 p, bytes32 coin) external{ 
        // user sends the newly constructed coin (P, coin) and 
        // zk-proves that its value equals to that of the frozen coin
        // Note that there is no need to compute a zero-knowledge proof of membership within the frozen pool 
        // as is needed in a freeze transaction
        require(freezeCoins[cm] == msg.sender);
        uint[16] memory input = [uint(0), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        bytes32 sub = bytes32(uint((1 << 32) - 1));
        bytes32 tmp = cm;
        for (uint i = 8; i > 0; i--) {
            input[i - 1] = uint(tmp & sub); tmp >>= 32;
        }
        tmp = coin;
        for (uint i = 16; i > 8; i--) {
            input[i - 1] = uint(tmp & sub); tmp >>= 32;
        }
        require(withdrawVerifier.verifyTx(proof, input));
        freezeCoins[cm] = address(0);
        addCoin(p, coin);
    }*/

   

    function getBranch(uint x) external view returns(bytes32[DEPTH] memory){
        require(x < cur);
        uint n = ((1 << DEPTH) + x);
        bytes32[DEPTH] memory res;
        for (uint i = 0; i < DEPTH; i++) {
            res[i] = hashes[n ^ 1];
            n >>= 1;
        }
        return res;
    }
    
}
