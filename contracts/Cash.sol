// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
library Pairing {
    struct G1Point {
        uint X;
        uint Y;
    }
    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint[2] X;
        uint[2] Y;
    }
    /// @return the generator of G1
    function P1() pure internal returns (G1Point memory) {
        return G1Point(1, 2);
    }
    /// @return the generator of G2
    function P2() pure internal returns (G2Point memory) {
        return G2Point(
            [10857046999023057135944570762232829481370756359578518086990519993285655852781,
             11559732032986387107991004021392285783925812861821192530917403151452391805634],
            [8495653923123431417604973247489272438418190587263600148770280649306958101930,
             4082367875863433681332203403145435568316851327593401208105741076214120093531]
        );
    }
    /// @return the negation of p, i.e. p.addition(p.negate()) should be zero.
    function negate(G1Point memory p) pure internal returns (G1Point memory) {
        // The prime q in the base field F_q for G1
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }
    /// @return r the sum of two points of G1
    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
    }


    /// @return r the product of a point on G1 and a scalar, i.e.
    /// p == p.scalar_mul(1) and p.addition(p) == p.scalar_mul(2) for all points p.
    function scalar_mul(G1Point memory p, uint s) internal view returns (G1Point memory r) {
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require (success);
    }
    /// @return the result of computing the pairing check
    /// e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
    /// For example pairing([P1(), P1().negate()], [P2(), P2()]) should
    /// return true.
    function pairing(G1Point[] memory p1, G2Point[] memory p2) internal view returns (bool) {
        require(p1.length == p2.length);
        uint elements = p1.length;
        uint inputSize = elements * 6;
        uint[] memory input = new uint[](inputSize);
        for (uint i = 0; i < elements; i++)
        {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[1];
            input[i * 6 + 3] = p2[i].X[0];
            input[i * 6 + 4] = p2[i].Y[1];
            input[i * 6 + 5] = p2[i].Y[0];
        }
        uint[1] memory out;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
        return out[0] != 0;
    }
    /// Convenience method for a pairing check for two pairs.
    function pairingProd2(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = a1;
        p1[1] = b1;
        p2[0] = a2;
        p2[1] = b2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for three pairs.
    function pairingProd3(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](3);
        G2Point[] memory p2 = new G2Point[](3);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for four pairs.
    function pairingProd4(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2,
            G1Point memory d1, G2Point memory d2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p1[3] = d1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        p2[3] = d2;
        return pairing(p1, p2);
    }
}

struct Proof {
    Pairing.G1Point a;
    Pairing.G2Point b;
    Pairing.G1Point c;
}

contract Verifier {
    //using Pairing for *;
    struct VerifyingKey {
        Pairing.G1Point alpha;
        Pairing.G2Point beta;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.alpha = Pairing.G1Point(uint256(0x2ee0d16b464776d4e6a65a645ad8a86e59ee56f844ec449955faa6073eecf420), uint256(0x1c209ff1d9f2c500426d529f84885c20bdd680183a997f686b4b019131399e8b));
        vk.beta = Pairing.G2Point([uint256(0x024a84c3301468c3a584a47e82876f9a7af6e6cd2a3ae2f7447a3febafa511f7), uint256(0x0876d77d166d05b00b496e433ea1c1d647cc75ae75bdb28661d557899a7550d4)], [uint256(0x11e3861c8927b6a6b986578219755e2f348631b90931f6739364d8e1c1cca3c7), uint256(0x198a255f04e7ac2350a5c5b192326a7917307aec74bdb80f6bc5e7b04b83a5b0)]);
        vk.gamma = Pairing.G2Point([uint256(0x1344123e589b507cd7d42450e471acfb4789ce85d43f48ebdf70cec8dac29f8e), uint256(0x09de7de7753bed9f7669453229810463f626eaae22ead4f6c82ada0a5c3e064c)], [uint256(0x148f093bd1485dacd40b07a0e43c1760bc3d4233ed3bc3029d724138a63fa053), uint256(0x15107641cf20f63eda84b253a88329bc080df69b9178615c4add73da36189fa7)]);
        vk.delta = Pairing.G2Point([uint256(0x1013be2856ccb28b7f20b8d01cfecb61e08e20e00b5e17e78ad8d09fd0f52b00), uint256(0x28ef44cc007035c986686de0a0b56a3842e3249da2c457d0fb0bae05af4a5dda)], [uint256(0x08c7887bea988fd228c6d3a3123ff6cd5db795ddfa43d3a05fb07198c202c0f8), uint256(0x1f9f798aebad04b9bdb4dd1e455feb2c88d1427f2ef22c7e87d1f0bf1aa88431)]);
        vk.gamma_abc = new Pairing.G1Point[](49);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x1cc6b7d8ff32c6b0f899cfe7dad50187b6d585a664bd93f41c842e0318182158), uint256(0x1ec80b39f9777d28fb9af3420800aa1d9d7f91aaf8e39bb7fee5088a5409a499));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x0b0404356a8f9ede3afbdaa0b5c0e16470d3bcd3c73a684385bb3f22c8ab92a0), uint256(0x1b1cae0a74602ea2895b4420c38f6f46a1c618362128e85212c330afcc3347e8));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x00a367042d7a5841eaab786ffa3cadc0ceef7e655b7a7707e46a6c833ab84eb6), uint256(0x234b5b0654a71601fdfc6c54f244e5db8199cd274605c7ec6c7dd2bfb1f4b008));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x1b853e6d449ec8abcf123a322259cb93b4ea2886a9cc18106450709a21af2153), uint256(0x281831d92d8c4c79fb6b7265a0bf8c6e21ff90b558b7135ca7468feb2cacdfe6));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x2d1b084801197ded870434a54247cae6d35bfb006b57469506b8cc3c401bcdfc), uint256(0x2461b5a2e20674bb993c6293224655cc07861a81187cee7ab588cee62f745ccb));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x2f695bb958de14619f062851fc8b2a0d02442620b0e4020f2782420e4a999c67), uint256(0x3051640c5b929975a894a6a5b5f0732bd251e79cf01a19f885717fbbbfb5cdce));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x05ba680667855941337633774db5aa955ac7e8108269449f10297e4d5cdeffe2), uint256(0x1e14bb9fc6b95f270e0e5a2985c1124a64b4ab2d9f08fc82a68f6cfcfdde45bd));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x15415ac61b92d75669ad3413a4a434cbb6875cec2458308de6e7f7932f821f0f), uint256(0x17e3354bef2141ea75f060a4499f6bceb16c3adfb767f310e877e6974b91efd3));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x00344e21ead967ba03415bb6498cfdfbd21fa0699a1fe5e44e15103fb4c03627), uint256(0x0b0e6c075a22974dbb8f0b11ee8b07f3fa4c67c17fe70b8e17c6f4f675fde4c4));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x0cfc17149fb6189069dd1a29379a5d81023b20426115419fb03b1fea220e1f49), uint256(0x23aebdfd071ab1086b712beafc81c3ab5a7abe28fd354383d8cb2e34bc415989));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x056286ce6020971fada5998bd33384779ffd023c0ac686d1c58eb4318ef8c51f), uint256(0x01757fb9cd9c001d34da951895ff24678810bfae11f90db48e3e99a4b78f5276));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x0d6bdd77575f7f81634d01a53aa9e9a19b2e3c617551a5128ae10e90ffacac90), uint256(0x04e7966e7b8ae8ea2c2ac5b3cd31094221cf1569a5581f14cb730a851a75d2ef));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x00c02182659ff2f266feccd656cbc60c7105e3bd2bbb30cea58229e26a1601ad), uint256(0x24bbb3e1026c4772d96d830ce3e81feec4fd45b9b3d2fdcc771ceb7f88a31697));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x2393858603fa9af4e73f7a42defafc3472db7c230a9758991e2c5c300dfc80a1), uint256(0x23d6c3f51aab6009f56a25b1616a28528308224a8656f8f31d782061ec98d322));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x1f05fc3cfcd0a6ae233e38da6ebd1ec87286d408a69ae8082a7e262667aa6c8c), uint256(0x0b8ead1931a6da68a4df59b8c3b5152e7355e6b15238ff4e2b6e94afb9809de9));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x27a0943533477a20f88f7b742265ae65c4c8e58b033aa62c15174466d799b15e), uint256(0x066d8ac9cd5330313e949c4458b79c125f7ef88bb3ab512a63d1c5ca5a931677));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x033a207eb40c0a46beb4cb5d0c113a80a1e44901be77ad77841e89f6ca4c7e6a), uint256(0x026cffbd2a1f736a2abc82f16e5341cdc694c1d8668d55166f7d210c47cc6deb));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x0fff3b3027d6373fc247114fb75d7a501fc44a407364d53a64679f46e2310d28), uint256(0x1bcc84c92f6b384b467503ec252af5bc88ea60a92e4b243960fc5047519e9bf4));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x2f65dbca194e5a379caeb7cd5142fba27ea4a5f2d6afbb319b100f81d54ede7b), uint256(0x074c5527c1b535541b3f634952ff7a660da71d4b6551b6d2d3fa9cccf4acfac1));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x1917d9ea15242877c2c79dcaa87fd62b451e872d09e40b6efe83201fbd5cb796), uint256(0x2d30be670d20184bad00ba8bf6117133888bf6ce74573a722e2c5a13b9e7fd8c));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x20e5739f01a440f032711fc66dea109b9f6c3dd4825321a3fa44dcaa441dfd34), uint256(0x182e4779fbede956952c852735b20c8fa875452197d89daaf70dbd7b798745b2));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x0682562e332772e182b128d817d03b186ddaa5842577ed7c43eeae79d17cd285), uint256(0x0b04c62c58b2a9862f05217b4f35360c352e5ab1b70f51e4628de335c7235bd8));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x0a58c57b7a4e8948ea70f917708d97242527f5b92a78295a5503fe76a1c0e2ba), uint256(0x235f7fdc423b5add871452b95449029f50b09f6a94c73413811c75f55c61fce5));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x1a81b5af4e3b919006f81ae32da07d5d0e0a964cc4bf524e9c2870d9bc9e4e72), uint256(0x0431bf425d5b2cabd9019d3519a8fd202ffef3d0dc8a4dbe5a4be84a04ba2d01));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x22d02d0eb71e76d56eb65e74f09a51d87080b2aedfec5dda6af17cf2288f369a), uint256(0x2de859b70f06ed0ea13985994902ae0c44811ce33882882392a9a901a2b8455a));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x066c0ef7df6b3e887b3211fc494c4d91fd1826e10f14473dec5106456eefc3e4), uint256(0x18b0f82ccb8adeafaccfedfa4583ada3686c97423a80f4e716866951c8364e46));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x0115186431d1463864b3e791581e9fc95391edab7ff6fa7a5fc4d1f764970b5c), uint256(0x2909bf49d82db04e75d9f080639918cc8ae24bcacb88f762190ba49ba3ca58e7));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x14ce19d55cbc05a0b1d5ddce9bf8779fe8f1fbbb9e13b6f394ebe874ca3678b6), uint256(0x1b3eb997ef9b72d01a8a98c5b527834dac2a9941f0223fdfccfdd49b54daf4a2));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x0c9a2a6330f992c175f2e21a370f5dac2c9b130749b6a44b0d30216cc953c721), uint256(0x2d8e46462072f88328ab2ebe15cf63e3df838308b5d4e5afe994d40c9a9ec259));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x1fde91b772ea8a5332cb62829bc68ba17a765372e7383a98ee76cc7bd2fc15d2), uint256(0x17542826e3632ad20afa3c4d92ff89563069656296f3de66f2fa72f0e439be7b));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x1b327aa62bcb8b7aab9cf028fedf9a683299269ff1eb9ed97b2efdc78cf7e085), uint256(0x0d65b3b154e79257c4c9be8672d06edbccca54230afd9f89b89fd1a471184563));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x1bc268247194ed98ab4b627e1911511e7ec92125fbda786ab1b5291e0ef644d2), uint256(0x1f8e8af902b407f7b240c0a42fce5f54370aa187dbf2727c70a602646506121b));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x0e99eadb95cbe7ef75badf355fa9c8dad7337ecee58a2f6aee863f8004453f48), uint256(0x266aa02accad1d4e90b7af15a6004d7c3bb1872641bfefa7eabce9b8b7d8c4eb));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x170748026c3e4384cd6fd731a2129b9b7887ac1a8a5050776f6d052a3d8e97cf), uint256(0x2f964ca182dcb3901e60f9c5a3868376c6b05dc03c6ecb213bcc6be24d9cc8ec));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x22e8c06111db5c479e55336136909927ed65aea2d4f22559c2a05c51c497b7b2), uint256(0x11e84f8120788390210d1271cb8b63b6060e18c6ec5601f7ee5c8d6e8ddbb48d));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x03e5a0f340cd73b3c277e028f3702a71eec25f1fd1082bd1e87c7e5733888446), uint256(0x25a4be6e59df0122933ff1517bfbbfbdea6143126a5887e19fe00a3f3619dc1c));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x2b38016822ec871884771a7f1405ea03b345d116d0b8477b2db297e8c491308c), uint256(0x09dcd0b85f97a6d80d007fe27eefff2eae8b291bc7faa3630c5b7ab1fa746c6e));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x0725a7d20d30e2bcd6de4899bf04d8fd97f52777f8badaf16c99e631603fabd2), uint256(0x1e16332d2f339b4e20cc30ad5b752437f7fb16e30e9a941f9217448815375a49));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x04c4e538e2cfa77510944e4d6a2493376e41277d3585438e423aca473de52042), uint256(0x187bf6cace595afe8bf128b10f4ef8baaccac7078f132c76d28f68fa34b016a7));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x22682065488b1270b996f0e950d4f3185f19602c56b8f5329284928d099fb701), uint256(0x0ab6e0000174dcb05f2c3e865f631d973556128b0f05c0117c0a731bc8c230e5));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x16d446b06245c825d5e9cbabd941489b194223b2b1b3e62fd8616946ca6364fc), uint256(0x2fc4201bbeeaf89103287d669f0004732b2b44184240196dc093a9eb0a19d0b0));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x0f4fbc18058754ea2c789e62d591d8e7d69ed4cc672628e14309fa9f0d85a0b9), uint256(0x23aeff9fd6ff4ef38c390315f70aa596bf60556936bdfaed8be422126907b8ae));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x1895292c7c06515a7b72fedcadd841a279364a19ed8144aacab9a52094c599fd), uint256(0x12b73f7b887dc6c2249a6a878501508281abbdae61b55a0c781b8b8ec9d911da));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x0d57439d79aefab845924145ad1699392020d8d33f64c3a38a07a40c92b8c0c6), uint256(0x13a995a38930aad46d2a42032bf94d8d90d74e081b31c536bfac37953d8a7a98));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x1105caecfb68946f48ebb3046e9579a14bdba97c5e74c172c7b54c8561812073), uint256(0x05d75b6c042cef33a4c9bf6d66bcb62495b9d11cfc22e777ba035712b6ec591d));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x2d57f904cdb7106aa4dadd78f82303c0a88d72f4bee93250518d50237fa24580), uint256(0x10b112bfd640d31d822b61351708ea36d37e4263dd585bac600fb3e37510909b));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x302385fe1c17ef068e2bba09009f2311cea9d65588b060882008e0b7961d5c0f), uint256(0x2ede3eae52894710e7720a5c24ed8591d4804672a175a22ce396a1fe98f24f40));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x0a9ce1266c442b4f64d54e15bb81e2d539a031d6412bf1e233b54d8c7ed0f736), uint256(0x0ae17a41d8aae6b0f65f7251b3efa014e56c105727316009ed62f340fc45394c));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x09ce7ba95f9e6d7fa36a8edd72f4274ee955f2f2682e4fbfabe851470caf236e), uint256(0x07652d85119fba62dd96607ed07ff5a9b512fee1035068da43995b8b62793c55));
    }
    function verify(uint[] memory input, Proof memory proof) internal view returns (uint) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.gamma_abc.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field);
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.gamma_abc[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.gamma_abc[0]);
        if(!Pairing.pairingProd4(
             proof.a, proof.b,
             Pairing.negate(vk_x), vk.gamma,
             Pairing.negate(proof.c), vk.delta,
             Pairing.negate(vk.alpha), vk.beta)) return 1;
        return 0;
    }
    function verifyTx(
            Proof memory proof, uint[48] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](48);
        
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            return true;
        } else {
            return false;
        }
    }
}


contract Cash {
    uint constant DEPTH = 8;
    Verifier public verifier;
    bytes32[1 << (DEPTH + 1)] public hashes;
    uint public cur;
    address public owner;
    mapping(bytes32 => bool) public nullifier;

    constructor(Verifier _verifier) {
        owner = msg.sender;
        cur = 0;
        verifier = _verifier;
    }

    function addCoin(bytes32 p, bytes32 coin) internal {
        bytes32 h = sha256(abi.encodePacked(p, coin));
        for (uint i = 0; i < cur; i++) {
            // assert (p,coin) not in Coins
            // Time Complexity O(n), which needs improvement
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

    function mint(bytes32 p, bytes32 s) public payable returns(uint){
        require(cur < (1 << (DEPTH + 1)));
        require(msg.value <= type(uint32).max);
        bytes32 coin = sha256(abi.encodePacked(s, msg.value));
        addCoin(p, coin);
        return cur - 1;
    }

    function pour(Proof memory proof, bytes32 sn1, bytes32 p1, bytes32 coin1, bytes32 p2, bytes32 coin2) public{
        uint[48] memory input = [uint(0), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        bytes32 sub = bytes32(uint((1 << 32) - 1));
        bytes32 tmp = hashes[1];
        for (uint i = 8; i > 0; i--) {
            input[i - 1] = uint(tmp & sub); tmp >>= 32;
        }
        tmp = sn1;
        for (uint i = 16; i > 8; i--) {
            input[i - 1] = uint(tmp & sub); tmp >>= 32;
        }
        tmp = p1;
        for (uint i = 24; i > 16; i--) {
            input[i - 1] = uint(tmp & sub); tmp >>= 32;
        }
        tmp = coin1;
        for (uint i = 32; i > 24; i--) {
            input[i - 1] = uint(tmp & sub); tmp >>= 32;
        }
        tmp = p2;
        for (uint i = 40; i > 32; i--) {
            input[i - 1] = uint(tmp & sub); tmp >>= 32;
        }
        tmp = coin2;
        for (uint i = 48; i > 40; i--) {
            input[i - 1] = uint(tmp & sub); tmp >>= 32;
        }
        require(verifier.verifyTx(proof, input));
        require(!nullifier[sn1]);
        nullifier[sn1] = true;
        addCoin(p1, coin1);
        addCoin(p2, coin2);
        // Send code there
        //
    }

    function getBranch(uint x) public view returns(bytes32[DEPTH] memory){
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
