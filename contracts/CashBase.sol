// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;
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

contract PourVerifier {
    //using Pairing for *;
    struct VerifyingKey {
        Pairing.G1Point alpha;
        Pairing.G2Point beta;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.alpha = Pairing.G1Point(uint256(0x2bd14c3917969cda751c5e6a84b6ec4b90be023b7ea2ca0351acd1e8e3e9cc43), uint256(0x2fb9e586134dabb87ceb84032402e3e2326e1feda27fca543e2839f3fd352088));
        vk.beta = Pairing.G2Point([uint256(0x2b9e81312d7992249a8f61cfc96868c8c394484c86dd9ba578a1e62f96f038ea), uint256(0x183b218011632e30c94f988cc85a737a3a39f968f55ba960e4c279967786dc57)], [uint256(0x0c81a9d3451d7d552f597226847757ca95f1d6336a101879a08b17db15593e3e), uint256(0x1e5ee724cb016a6caba7739f74a8ef0416f623d02880ffdc2432136c3792a874)]);
        vk.gamma = Pairing.G2Point([uint256(0x04f37a553d9a26176c40904c80dca16161e0a98e53d8b404638b04143b6c1c3c), uint256(0x0d320d7013321f77213a230338aace1e04c9e605df39aa34271478cff5a6d2f0)], [uint256(0x217beeac592934fc87ffc270b82cc4b589eeb8266d08af4615c199129b4b839b), uint256(0x06381db3a7f5c2700ed5dc642b4e0ddca6cc462bf7e9f1e3d7a5a07884608ed8)]);
        vk.delta = Pairing.G2Point([uint256(0x173fc05edfbcbba0a8465e68857e4ee1a552932d4396b1cdc3d0ec7a86318e0b), uint256(0x2266d632fe183614b48d69480281a6b608ce75f68737cd6d6fc5b60700462afd)], [uint256(0x29064b05f91b5fce9e6e3335a09834443388ee84119f49fcef18f9438c1e87a5), uint256(0x1ebc0df6ab7f24101f0530576a31758eb4ed0df73c86791f3e2c661213cd7d12)]);
        vk.gamma_abc = new Pairing.G1Point[](33);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x0005332a0e9a40c88a93ae727ba7c1985ee71a2760c94f17ab776ad366d36cde), uint256(0x0f551e5cec7c456ea0a9ed007898704ef571b26c50c2ec154d6ac11b9af33312));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x088cb77eea7c03272aa22506612c9f30a4fdef27802bae29f6974efb21433760), uint256(0x169e4bc4e25a18dcfb345ac90ebe015bd53e73700ccd73d706b06a166989a708));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x168ce7e9dbed3e2c774c72f62d36113ec0ce92d8ddf5b8ff30b417b19562c3e9), uint256(0x1f0ee74ef9961ff0f2e6569f1220b024ec17f247e6a4ca3bb548dd8c335d51df));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x2a07aa860c484a51222f97c26f58524cdc12b202eca0a9c77c9ebd935466980d), uint256(0x05233099356a0a8601debf8e1201705a55e05b4f4382b1978bfcb50c70e3e618));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x2eab93718f481bf670ba3c98d2f3f9471b9c377b8bc5caefafb9f2e3d0415f13), uint256(0x2042b830a584f41c93671aa1368536f7d50a4d1b172d96eecc5462b4b84dddf4));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x0973b9270c19d678f6f176264612ef7ccc71d5f58f2f7241aa05ac727b1cfb4c), uint256(0x0366817dd20bfbf97ed572cee7eaf1190727ddbb55e79adf73b03f841c94f052));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x21a9a69cb9c9831db2aca8cc984f589b421305ada5503e1addd1f178a43a8fe5), uint256(0x0c6dc06b43e6cc011c75ec14741f33ee291738793768715a65f372dd41e6af0c));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x0bb62af0772491b70a85572d14d9f9b626d4422aa46f7b0b9e0aa9616eae3ca8), uint256(0x25caa2dc0a43da9b25f061505365152b64894f05b235422585e68ee6c3e0ffa3));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x269a05b9b458124a258e85e6a03ed1590bbf66c5afbdc215d175913d45a86a78), uint256(0x09496408c2acc59014be53e87e896069c89ac5fcef61991a5c78bbbc0a405459));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x1b5e07c3b43a38bb29a4c9088fdc12cb7a7a2623e3170581491d63662f519cd1), uint256(0x19953b4772c1d405a21be94a689318ecb8bf8219d73ad1d7ad26dc7faab0d968));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x044379a3e84ae8fad0858b156658c96b8aa9a81b4a4eadf10fae4352771fc7f0), uint256(0x2932789e34e7ce3854fc436cc55e444c803f7e6fe66a07f5a346c03f2ed2be58));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x19ef0ea54f8e9531ef07cd310dcec08c6502174717df7bdc372669a842b75a66), uint256(0x2f77366a76e3c52d54f807bc81d50c090461d0ee897d532a8422c006d23690bd));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x1a278b099960b08d4e5d1e9627b4451d0ac31495db8f367873abc23cd7330efa), uint256(0x13c1c30af50acd7cf173168e3a9a0d2b007e6d409fbd2e01c25b972d12948b85));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x0f66997905d74aa2099d05fd4dcffcc86fec0532a6ed756b80238c5c6d7e1d99), uint256(0x2cb87b66b54cf010913a51a445fb98220c7a44639af6216fe0f55e0746f9accc));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x2005cc4e89f50086edf9c52ad63d85934ea5b1c3aa64af9b45a7e70030042de6), uint256(0x19de8b7196b95a743f061313e906d56871501ac1ca582093cc9e07c7d5f49e6b));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x2b4e61629bb701b4ad8348cd5e99164b10225cc8a46f1bba42012c12b2d3882d), uint256(0x044a51e02e0d86b3123cb8bc248d448c4320fc29e591c336845ab0b22d115be5));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x29cedff6912b7c5e39be91c86ce8bc3b3d0ca5a23d3039c6f5e96f8d22a32ff5), uint256(0x13a95093919a78f45be3ef5ee8f74ff42f9636c8601ed18abb2f63281fc0615b));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x0e4beb0f7361fd1adfbd3b2eb2ab1233a38febe14597324254aaf83bf63cc0bb), uint256(0x1b28e81c87215aa58e4853ae9ef02afe14cc1eae8d69022e220257a23c9d1284));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x2493eca6f7a773b44007c259b3797fec50b155a87c0f3dd106f1772dcb2ccd24), uint256(0x23253437468e0daedf341c817dbd8f3772c36393770239cd9bfa430a9f2fe5ea));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x23424f9d2d053d07bb879252306607056b1f699f065601c838f626ed77571f41), uint256(0x2c2b75a2fcc86ce9e19535f6af5057a83e44e1b484d9140c2c81510e835f8779));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x0db8962835b1e7cc1cf82abec5e8c4122230211d094a9261c243ec5fda0b846b), uint256(0x09c8b081715e52d05def458b28c161d15d445d90d4d358e02e2bf5a5c0e0cbb1));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x18305885ed62a967c11eac2f75d491a323eab31b260b82521c07af04bfc32459), uint256(0x279aff57f5070301e29981e720ed3d71716d28404c8433379e0dd09902fa50e0));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x1c44276d6c72629ef97dd67ef15a02e8a490f663b393ef553830e4822afad347), uint256(0x0f878cd4dff9bd5ecda95b12074c19f7c78b56ac7d2c25e2f77b8497961f2c97));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x247555d8caddf5eba2518312f8cce3581d99d7a78d0f54d71f9f2b26a4001bb9), uint256(0x283ecb14c6e290248d4483864268cf78bca9746d16d37fd5401d3ff3c1cf9ef5));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x16bbe3122b62477f7d9290f6231b3cdf05bf1f34b5def9f4c33e22de0d77a0c0), uint256(0x1cb802d9ac315bf88a771bd45223be46b543305dbe41e24f3769c0559a57bf52));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x278c86b2dcc5c1492734b4db8a1b23fe67668ca288d0846fda3efa27dedcc36c), uint256(0x04af31290bbe0faa350a2f00f48a0469bb9f89e4e95131479362fc5ffdf0094e));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x1358fc833ef95a7456f12e2dd825ff9a05eb202b78a16ed633bd69aadf63ba9f), uint256(0x2dc94823e48cc4747eb3cb50eea8c981f44690e5070e35b6957fadc7fb4b51dc));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x080b545e8d0749a835151b145bf8da660601fb66cd601938f3c648b235dcf7a9), uint256(0x081863ec537c55ed70e5c2eb5af016836f3f23473162e5294fa1e01fd3f0019e));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x095a8ccee6869eb53a7b6852451e6bc9f8c95a1fbfe12b085447cee578c70c3e), uint256(0x2fed504972e91aad906d2e5f9033e4143d6d5a6cecb905e6a8753a9d8d915a4e));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x04944899da8e24870e2fb456df44e82e7412d5d887f1a244e226c8f3b45dbce1), uint256(0x0c98012126f772ab4602760ed13552e15b77b33227448fd26d5e3d217640e6a3));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x0409251a1592988d2d7685ab4ce534b4463058a8ba057d55956a875685c122e3), uint256(0x1797d8d321f7760abaf5e67ad96500249fc35f9f25b68d29e78fedc393347c23));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x10fa11ded7fa321868dd25572935a4d1cc71d4f1163c78a33bfbc6243553cd41), uint256(0x2260caa2532bd81a0705818a3423e757cd1d9edd36f0cd926452a889d8750a6c));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x2ff95d31cf37f50621f19719a2f8da934926e2c8a27dc6e921014b61a38c7e35), uint256(0x27f7ea90406600650d982f0832e1c82c83eabedffcd972f2016c698a369967a9));
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
            Proof memory proof, uint[32] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](32);
        
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

contract FreezeVerifier {
    //using Pairing for *;
    struct VerifyingKey {
        Pairing.G1Point alpha;
        Pairing.G2Point beta;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.alpha = Pairing.G1Point(uint256(0x06be264cf682bd4a700989fcc2ef6065de071d38a7ec9bfa68e9b1d4168d817e), uint256(0x0f738d387f66059d9512f12bab8d06d17a0b3a4abf49a30435102808d4b9ee56));
        vk.beta = Pairing.G2Point([uint256(0x2f09c96ec72e5afba1310a428fd7376372a135347f05d909bbe267699157fe37), uint256(0x07a1e224b976674956d437db294a948ded141206d189805273ee1147daf36963)], [uint256(0x2ae6e1076b6845b510808eaa75cbb4283a9b6a448b8c82fecbfac91f4d420ed1), uint256(0x2d276c8bc7a2ba8bcfdbaa03054da9f7e589a50780801ce5279ae93368ea4023)]);
        vk.gamma = Pairing.G2Point([uint256(0x14768d3f0c58b0b35414f2eb6a861ee425932abef444b39707a24fcb1cf4c12e), uint256(0x1ebcf06357ee51ff7f8226f7729d5518ce85f28232e287a0e3365395643fd4a6)], [uint256(0x047e8e88d80e2d52295e1dedce5efa976b8f47195fe9049f75be7d77a0b238dd), uint256(0x005f4194b850f2141e3c311e3535810952371918cd01591ef4dc281a34a02cc2)]);
        vk.delta = Pairing.G2Point([uint256(0x1b1cf7987c3970d3940cd987a0d9a63694a2170c901b1da101ae28d29c412444), uint256(0x2efef13fc0fc7bd3b298291f5f589e553ccd7f6af36b42c2b8ef6eb3ea99a9f0)], [uint256(0x1c3f6501a593542ca3e3ef3613ae8f62d79cc050a4045c0275cc96fe505c4d08), uint256(0x1258f072960317f3901b281de98a0a129e5cf658560404a485cc3f716061afea)]);
        vk.gamma_abc = new Pairing.G1Point[](33);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x0334cc62bf446b074e9ac6864f6e85d2b91b9f1e6a044aaccf39c9c80c5f9ded), uint256(0x1fa66ce429992e24d7890ef102bc188e4ce67325647c3d4d462a925b77bc34a8));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x19d901dccd5f8efe89819b8d203edfe827a6ede9b1b2492542d7c49bd9682ca5), uint256(0x21bf86eaa57f104c13f771990b57097f0945ded27432881a6b5c16f74e2c7db2));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x0fb29c36ebea14ab29b35f9f7cb020848fed8327ba48bf3572b8ab535e1a1c10), uint256(0x2e71eebdfd6fa10e5999787ff05fb85dacc18b6977f2a5d2ed50bc6edda2c1c6));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x26f59838272b8f74b9a190ca1f44ad1b75281af1b11b7d92f7148dbd90278e4c), uint256(0x04edc6b068ee0ad4b674e0daf9e66d66ab31b46a5c9ede30f9925271cfe76e10));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x0ed1c7f800da7b762fd283bb8eaef05b8ddc55fd4ae1e22a059015f859be2124), uint256(0x0321ceb99043d2a537699b94204e17be24ef4d56df92ad4ceac441028b09fc7c));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x28c2e7ac46f95ae604549a2e19290309eaf2c488d86a6ef93d64a431ecb4e57e), uint256(0x2f2eb218f70833eb6d60d0c69778823c3b2d2e7c80f4d6315d719cf7ae68a1d8));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x13c0f0ee2f6df859431bf72ff3023caa194dbca72d99f8eded697cec055d0e65), uint256(0x1970ff85e93624f67f48a7fa67cf41fcdf038bd3b285f95f30a628c0faa88534));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x2d26ad35bba8d1fb7644e7106d192617974e1fb9d0c5758c9a23492fa9049fcf), uint256(0x2509cf098a960eaf7d48bc5b52109946f6d9e1d541896207cf8fa44c818be6ae));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x07e7aa49fe189c8c6e40522181c8439406e72ba4d808bdb70b7d28039faeed98), uint256(0x2d6ec44e5ece52d5e134828a0b76403a0366e5e4b4de6168504c929f23f70a3f));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x2400913782816e8d5462944ff0151682538ef22b39258ee2dff26f0ab75d26b9), uint256(0x0545356b789da342b46d73b8b64d7999802f1336e87690cd3bbb99b13dcc4620));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x2531f1dcd585aa15fdb61491be6d01831b212c3c7c18f276c045e5ee2856312f), uint256(0x21aabc5621c4c92aea0f49dc91b77f6e14e803dad8d27020efbded3dc6a95fe8));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x11a463b034ffe8962499422c131001460c148d0385ac67e9be1e9f913ba50838), uint256(0x0ae0bcbe46404b8134f1b13875035bd7ec1c360940326afaa0ac3390ebd8f980));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x2effb80661968326655dd84a98e77fa9c2808f4e36fb28f771e309514350aeab), uint256(0x18af66bd9bab4ddbb4738a29411738e2bac34c3dcfa136adeb2595ef2c89830e));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x10a1e897e63dbdcb902e65796ff0d6fedae7a5de57ecbe19044b30a73bdad3bd), uint256(0x271e91a80f7537c8a5795db5c9e2b7c27caa93a297e98499b5d05e8b63c2fd3e));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x1a039ce4b0b876b833aedf198d6c20b6d216ec5483fe101f5d53f5d4fb03ba08), uint256(0x20f1085b1bf70c9f0cad85c0c5bf62be1e4dc22c09008ca9422ae79ffac9460f));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x09fb7407a8f920a547cbef2a355bb0add30a9e724a22639f4504aa6e2c65ec2b), uint256(0x1f1bbf3accde0d06ffd24482d28528bfd1432f2d0ab4beb881794c4016a966b8));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x1bb9425d54f647ac080a33639f0bbc0851d5571b509fb3b911f0238d8d5f625a), uint256(0x135020b018f0111db547d88e0d646bc568b1d04fe92bb2bc7bfe30191efc80ec));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x0f47e18b84a6f2e72d2517ea2c9955f1e5366402bbd26284ff75ed3d5eb52634), uint256(0x1af1ed26120158c639e3d2e72d51dbb2c5c919e9fec26277aa3c4ba2f6740665));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x1826aba84edbc95c9f3a17cda01054030475297472ccab9d283a52724824687c), uint256(0x1dff1cc9014997628388fb1573533681c39b1539eee1d4152a8317cdc5065022));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x13b2be8b4fd98718806063511187564acfa9461be8adc1fd2e16b0184d387844), uint256(0x0b9bc39ff6aa7f2a1a5f27731f25486eb51dab912a7375c0041f939ee4f6e806));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x0352fcbfde1be7aef8d2326aa690c0738be4c4585ba29abfa84d24745f69ea1a), uint256(0x2677f8808f28e9ddac15982fde9c8e72012b814fa2b8efa97066227a2903ae2f));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x1d0c031398f83b6488bb43901d72a22d52ba4920f2d586b07af08ca568f82c17), uint256(0x0196f418b2a7dbc3f3b9c42e4bf5a0fd542a6c480595ce0bd47016c5a4bfc93e));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x194537ac8b3c237b30d08f5ac4781eb3c010f762962d70a5846033c30fcc66fc), uint256(0x0396b5e78fa25f14833b316de39d3ff5e1ca2c1de2f300ded0e946e0fa4aea62));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x2bed30698efb6e3b92e738b57db05d62aa2c5bc0daf9090c21a9316f07d697f0), uint256(0x1100a3700746c9be1690cb0f954e088c7c162461d78823f7203491da432bb698));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x0b4a499e3b945006861a7a7ba8da541f0d2908574292db76ae23c9278ab1ac0b), uint256(0x29affb4d965cc8f916ccfd7a5cd0f85351dfd536805ea182741f96e5d6f77ed0));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x2a7feddcf1003f5e0cff9f1e7c2df21607b67d370c4f19f24863aca652d6bc2d), uint256(0x2e4025be36c696ebd0c680bcc8384436598e968e6902946437c3689087f44716));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x0dfbe0a17ff97d80f08760778954a492c5a8367c6a570d0f1cd3467a2234d668), uint256(0x1202abb7f711a195fc9b1ad04450750693f2ed92c74b13c37233c86a5b10537f));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x2058d6a275b97b469ebe732dc794700c94bd7244de8122bb8192fbe3241bde86), uint256(0x2a29546e5294af47fe2857c4ac0555eb6ea2621ca9d18650728cbe964bc52bbb));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x23d176ece0d573d14278294d79a66bdf491dfdc42980efafd4363fa8867f50c5), uint256(0x3049e08496f2dce7ee0a88ceebf6b93c6f9854b2765dd8ceb54092e830588773));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x25632772e2ec99f750b1b69e973354bb240b3217014dac374766b9da645ae6e8), uint256(0x0b3a5f4bfce82bf8bc7852072f563ab5e0d8caea084ee5a1c228cfe3e07f73a6));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x1240de519a460f057bd4248b62f7d1d943fd12c38e569d24cd53726c7f995827), uint256(0x15b84500680589c00a27c204ca5244df2b34d2bf4dc3af9d4b8e5c98eb68b4b6));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x01319fc0af80eb01d13e1cc6e52ab48d22d453b350770a3c5fc881755f7adc3d), uint256(0x024e7831f3d2d8cececd866d89494ff16807b7343816f331a42f7352a404d75b));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x156acdcaa4dc88aa5eb5622c7c9c09014f527631ec792752611cf022dbe3d929), uint256(0x249fbaa1dbccdee7d7b2943c3dd96cea913ce3153a5c71b720dcbc099e0df579));
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
            Proof memory proof, uint[32] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](32);
        
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



contract ComputeVerifier {
    //using Pairing for *;
    struct VerifyingKey {
        Pairing.G1Point alpha;
        Pairing.G2Point beta;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.alpha = Pairing.G1Point(uint256(0x1ad0eef73b27cf58bb3b61d06f48eb40f548ecaf72f1e85d4648c9fa3db33cad), uint256(0x2af80183c06dc43cea7c0d25670955e328de4bd78185a608cdd3540fc4336716));
        vk.beta = Pairing.G2Point([uint256(0x2799457376671c09e31068afd44b79e329eb5fec945030224c0f7699e59551d6), uint256(0x0aab1cf2a18186db2a294ec459c3439c3e802ab7d82b970e46fe399a373fe84e)], [uint256(0x2db3cec3bb29ce6f47d67383dfe0ef6b026a405848fd7154d0f7d0c88103b47c), uint256(0x2500672ac0e96a9c05a4a968d50b9b9823f3fb3d78021e14ebf26fa0255985a4)]);
        vk.gamma = Pairing.G2Point([uint256(0x005bfdac2c5e4630a4228dfade9af21e906975be2137feda69120b07a58c6053), uint256(0x2457d9721b0d4c206440825757bce1221da4162ec676af7f5e282a194810a595)], [uint256(0x205e7afe8998db5d2242e39107fdfd2a9b6f31aa301e857655cd7af10273b214), uint256(0x21a9b1043435cc6b75d054f40ad547a6db689874413b69cc657ad2cd164c650e)]);
        vk.delta = Pairing.G2Point([uint256(0x23bdf99272ebbb3b5ebaf458c7c587ee4f4c63ee5be9f57b4369f14017d39614), uint256(0x1d0893775186edcce52a05bcdc2d9c34b3b526f4ca2ea4da375571da165c909e)], [uint256(0x183a8d26c5e93fdd6802fd8f9aaeaaf5d5bfe45c3133d4383105acd96e90125d), uint256(0x1e047d67c03b66b6b3a707f6fbe2bb9c194ac2bc098d1722d9f2e88aba036ba2)]);
        vk.gamma_abc = new Pairing.G1Point[](29);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x14450315690aa716cc838930baed5ef7380c136f73c727bcb6a1e841f23097fa), uint256(0x28bce4d0df2bccbaefacb0d99899a5b45b5e0281b5689ae3696572345568c50f));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x27cfaf3cb71ca3e403288119953817b0972e13d5472a4082fccccee30a97cc50), uint256(0x25ce05d65b75e15afe2d66b39222b1df5beec75294d350ee3a9fe133fceb3462));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x13dcaf816895990081dc7c6ed183e42d6639db9480bbca7eb0e41e517e69132f), uint256(0x06c831025e747f77508875ebc74cd0b1e143ab0ffc7ddf3165bba89dc6ed9535));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x1ae82681fd3bbc8e827afdc76f556a0214d742d12fd1fcd5f6b38b1d26cb0af8), uint256(0x1ca4dc0bdefecfa127937d2d62ed62559c539e406f2564ef55fc853163e48017));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x10026d0a7f14c09b0ec56161591f9cf287c90962fba64b92edc1617003c100e7), uint256(0x05a348baebe9748495d585414f1bd46e8890440a5f007ea6e7ab443206a7d857));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x1085be0532939de5fc417ab5fab38a2b58a2a3c53e001a57d46fb4b1e07fb8b8), uint256(0x1bb80e3d558850d325c17739bcc2bbc35d6fb6c745229e16fa49f1c7680fb9ba));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x2145f06ac798cc685d24a1f5fcfb060bbaea9575a2c4d0fed5ee8b3890db9d5f), uint256(0x139be92bd0b837d8afe092da38453d84244dccfaa0e3499d96bc291316254b33));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x0b40f3b23c93a94da9872f01687b8e5a608124b9c288a4672121118522b241ac), uint256(0x0be2eef700861d9972625125722516a55ed3a1f368f43f8ae5085a82d08ce361));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x24008255d80497aa0c1d759d2a111339eae2a35f1c35c4261d146b2e0d5cddb4), uint256(0x033451766aa6df1279c118cfb913ede6bf11d754c8f800d0d4664987627e4122));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x1b9607364c83fa6440f318e42733e598205df9d5c9de60a3df3052a83cce1257), uint256(0x246298591d432e541115948e565b1161d75a26d03f20661eeb2fb54c77b13473));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x0482b08e3680ec349b9db50a91f78e5d1f206784597439515e073136919ebeae), uint256(0x24bbf61aec0cf37b4a82a66ee87f2575a22c47cdc3407a1954ff437cee18e66d));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x0da1ab7a2798e7e99b8aaae62054b829da0b62508cec3ca1dd630ca6164ee894), uint256(0x14e3fdf2850a4e0ea7377218b586fe095ef2b40897e4efce7f20da4ca1a2d7b7));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x0fdbee5001c44a120b202a7219bd84e55760882859f8172031cac38b4f8451ef), uint256(0x1443536c6beee788c5713a44808c1f15e008916cbf6634436f036cc5ed316c0b));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x1891638348e2789a6254a7ce911cb008dbdfaa16be262a6014815d5f096d1124), uint256(0x1b1784526e66bdcd73af8f82b554ab2aff2609dd407cf82b3fc669c75141c127));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x0983eacee3b896752bbe2b50efb6c97461fb2f9c6746eac479f94c543aba6bf0), uint256(0x1138d37675dbbdf52427f08d7cab2019c12c7ae83da7fda9fd79ac97b4a8a076));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x15294a55d1ba0bb4ca079b64c1968a8dd4366982262c17b9c63a115d7c7af96c), uint256(0x08bdea2c3dd3a864eb7ba9c12d579f56a7d2f799ec040e3587244f8a27584f02));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x18aaa96edef3ef835bc126be7fb36c855881c2b46998469ea5bef6623faf1d74), uint256(0x26c1766535eb66c99e552c61f7f0cb6f8f1eb2bc92684e5d1d7588f945910f9c));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x2aef5d125e67eb95ffc2d3c1f5bd4d31c01f81f44c3e1360b466ae7e3128156a), uint256(0x2150335796647603301a4493a2b05c06cbe3de6661b706653eea5de3f6e19700));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x1a9733574008d3d4297f57aef17d83fcf72a67a78c3d115c4d3c21b0ce13cf53), uint256(0x0b269c14013ca37959714a066015bf8c85967a16e43faf11ec4f7caa213b8c71));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x2bed346d26f2d374b232f617b591b473032f76679cefaf07db51e51e1f681662), uint256(0x2dec4084683a985fcca0fda8d99d2599f86864e0dd5ed277795260626b535761));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x00496549acffe845584d160237dcc67f51fb6b997f664c18abf7a100bed2a367), uint256(0x2632e51f294b620eeec07df8b5a0ddcf8c6b43489fe026b6ff544bf1500a0167));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x0f91028e974bbdeda0aa60377d6748e4c30f8a2f2de9145c58ee5c45f2398a0b), uint256(0x2678fc0fcff4ce0f5f96234d67e19e8a86d43df5eccd1a32301af3399ab6c067));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x30201d7f2012735693531b912d8e5f2f86375c6cd3b95110f4ac387e7d60e99e), uint256(0x2c2cd92efa4867072a3668cc26971ae8434916508467c08cae8414901c152bed));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x0b00c2d35c9f1ca3417b092ed7ff621b5b5417e254985276575226d0093c97e9), uint256(0x124be38086378390b2d6dd7617f7e9e0629b0ed48766f6477559e5d619f846d1));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x16967de0c8184a4afa23596dddce435f9ad24ba96ce9dff9b85869b6fa11becd), uint256(0x009ef10234be5bdc7e602ba0d81753ef8ad5bc488f00e742282a317f97923f54));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x23cae1f07fec09d4cfb85a8bdf77ff0266edacc5ed65c4cf6d0cba7b87262b5a), uint256(0x0970642de43abe74460ec45c95da4deb3f50c11022c1e364c0fd7b3c5a13fd11));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x14d1d529b862d3fef7251f6eab3ef394b705bd0cc95b501a3d60598caec2a03a), uint256(0x1df68d000223448140a8feadb96a587e424a3979ceb35d865685e5c18d0fa5b6));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x048e392a53f3bab66f1037723d6f223d6f60177eae4bec3deb3084178a5e5629), uint256(0x141cedb1178b38aada481db4cec62f75fe61aad527a95c9ca836a59ccc954547));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x1d28a726b056e447897b1be1ff3fe9b7bde61b7678e6abf0ee42bbdd7f8d2651), uint256(0x2c0a6f686261b19465ccb07e800b32b9e84edd8f3cd1b79b79a0d2deb3718726));
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
            Proof memory proof, uint[28] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](28);
        
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


contract WithdrawVerifier {
    //using Pairing for *;
    struct VerifyingKey {
        Pairing.G1Point alpha;
        Pairing.G2Point beta;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.alpha = Pairing.G1Point(uint256(0x2673b2bde9a380351edd8ff1cd09e4cbbd114db8bd906952f1dd10bd045afdaf), uint256(0x25d90b1531be06dd80f725b38870aa64ef1bcbf812227fb03afbaa713536cbda));
        vk.beta = Pairing.G2Point([uint256(0x17aab6ab092a60e360806c6af958282021cb2b226d10c64dd7f26830277fd53e), uint256(0x13a2e1b94be603601c2a4009a7cec6d273758046099d6315339f66bfcb943f6a)], [uint256(0x0f58efeb0043d2de3dc11b0b1e7a2900fbbd62a6ef1b51e558590bffa2e6819e), uint256(0x2fcb33587f72cdfd79bcbc5f79525ca7df00cda2d627784ac987b58129b9f9d7)]);
        vk.gamma = Pairing.G2Point([uint256(0x0c5a011e2e8618c609d12a9d17a62c3cd4a4c56ea11267a26514e8501bf88a6a), uint256(0x0dfaddf61bdfa9dba4e7b5da57cf68906ff4c8270ab5bb3a0582e71fcdf8e535)], [uint256(0x2572be9a6ec8d7e981a0db097074096e9410aafae7fb6f0466e1ac1f4ec5a96b), uint256(0x192fdf22ef10466cc5c005c67bd26d90be9e45db544c0a477206d22762ff43a7)]);
        vk.delta = Pairing.G2Point([uint256(0x28f1728753de1c88944c2b1002919600bc2d906a3a03a6e6b85771b32d260480), uint256(0x22a9144d3f2222450d4feeb620d68ee2409c3c5f7c298a933dbf1b986e8772ea)], [uint256(0x15c5edbcaa54cffe20da1cc58466e50078061df71f61bed0f80784d0e7c70907), uint256(0x26dd65d41e2446710e5a4f9a102d3e716bfd180ae4b33404069f29725ddfcf52)]);
        vk.gamma_abc = new Pairing.G1Point[](17);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x24f52232f93d88cffd9d670b0102e9cb95d39ffd847e21f210b882860fca9cd6), uint256(0x005113bb8496eb8e41058a06953bdf5f9c2b078dcb9c0a638a859dab38893588));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x22f26eca0397a733bc75d8c892897f241db1984d1112e9c302c89c040c1cc25f), uint256(0x03948a26f694b6d14b8c911ed8952c72fa16d6dd46e14280c9bcb00dce72d483));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x27430a9b1d474fea3c7f1b07f97c8e9d9ff3a984e2cb1df5d4f5f1b97b5b3dc1), uint256(0x2f1d1205d5f8dfcbe82e6f6699d98e3273f7426a610b38c39ddd4f280ad43fc7));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x189e842c00696dd0f1c8b78f3ce0a12904a6e96f18a243b35ce7ba5d125a633c), uint256(0x208bb52efa3b8afdec0cd602fd6d61a10dc5a228f3cd5a3b4cb996f3325db934));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x13258a689fe3342281381ec4aec7dd226657696e9910a0686044cda7988911ad), uint256(0x2936ce0c18bc248e195d564032843e547ea2cd043c70c8883602f765c16b4d88));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x1dbe4426c83ff5ddabea922886483a96b130b5641bd34b78b3b53e144882059c), uint256(0x1810ff3627e465d1f09a004e156b9499c89506d6dd0f840a5923fbd8751e3677));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x0223bc7cddb0eba94d41febd8813a1e39c3670b4cd67c815f5152ba8585fad5e), uint256(0x12d2b3996dc9603dddaad099f057884394ebfd994cef7c456298df13144e643b));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x18a386def8bda1cc53b596e0588e6347da303a5649171b2813ca1465ee45bcd0), uint256(0x1c4a094013309239ed4498f6056a2ea391ffb4fc58245bce118faef030124e17));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x134e8607cbab978ea103109abcff40bd905b787102c1d3d26ae0fad14c51d077), uint256(0x129ab83f16c82d13f158e6fd478b181e600b63fb80569eeeff8e8faca659e930));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x09a455d7a94fc5e510dd94121edab0ad707576d24eac8259cc5d7426a466be8f), uint256(0x15875343a383aeaa1a6e14fe1072229015de7b8fd8436d0624e407a4e5db520a));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x06e60a59012323a7dab35978edec1cdf1bc56051f4f5ab0f3cc1f742a53987e0), uint256(0x26b93f39968d5c04fda059870afcb35d64261c892dd4826bd78427585058818a));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x22ac6c3110854c98e3e18c55c86d053abe0d092025071e72a309ab00ac8a11da), uint256(0x1a1f3a0f251e6c1b6e671a65410d2a90e4bc92a7e7b1d526f4a1e549363a847a));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x12c8ef6983b4194a07296ddf72855173bad023fc6c68bf0640965c3b05142ed4), uint256(0x0b2381d62e8e3803afa70396b916d263597d8532f3a88d2fcc3dc4f001e50401));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x125996602589cab123437c656b89998812a7dc55992641aea04cdec13bbd00f2), uint256(0x05af02df021dbcc07d7bd5103ce5d5033b71ed1691d8cf642d190f960fe1d239));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x1ead5377e44663f47d7e9e6643329b7181e88947f8947e7917779540a066da25), uint256(0x249e0d43836b15af0fb891924be99bd96a7a7edf6f3713870e7d226e33a73504));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x168d9ce6beb934737da91cef56a5dd8ebf1cb7d266dfb6cdc1c3b172ebb71a41), uint256(0x1ae8a575968dfa427b394fa005fb4c39852e502687f59257686eaed8752f6258));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x174f641045d635db055de280ec93c637081e9b0cdecd0049a98c4d4594b990cd), uint256(0x156e15db4a0ab51ad130382137c5ada7894af891d726893358ce5de41aa4f970));
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
            Proof memory proof, uint[16] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](16);
        
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

contract FinalizeVerifier {
    //using Pairing for *;
    struct VerifyingKey {
        Pairing.G1Point alpha;
        Pairing.G2Point beta;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.alpha = Pairing.G1Point(uint256(0x1f76394d461ed8680db11d06f1f15df0cecf63582f85de96131d2863aa73fe8d), uint256(0x1018c35717d0df8547cf80054a09416d3307a0d484029be8649f132b0f9ac2f9));
        vk.beta = Pairing.G2Point([uint256(0x241bc9c871c85d3b80423f08bbd7039ff911576de9b048aeae63294a570fa7d2), uint256(0x253825a90434e425c72d4b0215816a7d0af0ae949a8a027119ffd9e1ca7e48d6)], [uint256(0x10c5ffeacc5cfcbeff6cbc5470bc3b58925208cdb8dd677949826cdfb85c5f4e), uint256(0x20a2b4cb63144aee98030d43c3b8b51f047299f9aaa35cdf7986dd93c699f209)]);
        vk.gamma = Pairing.G2Point([uint256(0x0bdab12799621400102e666dd9e28b608094f3f966b4142d4a049bcae64948ff), uint256(0x14d89305d39e46bf917849bec422e822c747d51c5baeb92a7184d15e88289b88)], [uint256(0x124c1b7e3a6234b3f272e9b1d48d8099446a6d51470383c18ec1caebbb8eaca4), uint256(0x05d2de6caf473b1d42f3eed0b66977190bc37cddf4539f5e477bc1862f68a611)]);
        vk.delta = Pairing.G2Point([uint256(0x159aa17322226fe9430967ef47fadd90cd0b39827ff0bbb3dd925e5211419135), uint256(0x1413c874c6a1e3ec613166b33691643014b7e8142b07e59957b1e6260a61178b)], [uint256(0x0d37e0d45113086b650c7c7ba73f851d37edba99067e3c2fef5cd30991914bd1), uint256(0x181e78fbbfb2cb99f3818e95d7b13353bbe81bb59a73d307f1b9bf2a03443cac)]);
        vk.gamma_abc = new Pairing.G1Point[](66);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x1abc6bad74d18f958641af0bd42290d8e79a156d8363096ae35acbd0bfe3248c), uint256(0x1b3a7375cbf99dd2cb3679114f122de99a67e387b5e97058b4ca729b2d756316));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x2fdd28822f634daca4c58d50d506ec9f06bae97860ad2c93b04d95cfedc78354), uint256(0x12fdc7f0ccec833d03d28276ff33d81d678d66b4f530434419436f08878c51a6));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x16eb67f126abedbc0f55060cbdcb3b2ec5f47e54a355f291e5d5b7b22fb122ac), uint256(0x1153ab1f31582f22cb3e7004cd6f143f7f55b5d8c527a299e50996840ac1de01));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x1d230bc3a512db8455f68a31ad48b1c033e7579dd4cf10b5e1e651558b31b7e7), uint256(0x1a61f5cab93b82722210ad0429756348594405e27ef141e154a6f3b24efd6ab3));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x1c50875a25969f25647d4f89ec7bce30ea179ea3a230f5be3d7c3096f903722c), uint256(0x0d48d7904128e88f4c8b6970fe695ede7b0edf39eb0b5bfbd4773472bcd771aa));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x0c6adbc52646960b149a7a5957a20279267d138cfc93ef658c45054d58c4f8c9), uint256(0x2148e78fa25d3e04a09d022f36050a08b43b341ffae8ebccad5dc23aae7be30f));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x08492f8670f7d7e2c285e97d408bfe0260d31fc065cc39f485196254652025bc), uint256(0x0bab261aad90f85172bd7d2375ee327f6b37ee7ef130a3991bc18ce2e5686fd1));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x21a962bf425b525826c396315d2e13a790bd07926597db16f8f1ff65daed19ed), uint256(0x2a103ba60b9c891014c1677b41ef594242942440882692f5790d5ad128c8616f));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x29b4d79b6801346e41b3d236dc80eeaefd0bb534ad96e6584779e7c42c0ef3c5), uint256(0x23bafc1ebc8481403b96b9687dc23c7162dfac708d182cdb53986dbd51fe829b));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x2f2e09bb23f4aa8101deacc0b6ececf0a0a6764e77c889027eaaecc0e4cece70), uint256(0x16ec91294446fc3f8eed301c673fccc7ddc628fcad098535d472e2e7316de54e));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x1b3df3bc4c95c1ce0f31f7d8a2928549daf5fc4969330c521a856ac8b5afa5af), uint256(0x2d033fb69f83bc1ccd1b019899960eb7a7e47f5ab72f1475a9aa797b02ed06d5));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x02552a551dbeaf5684be142c87609cb9df5a35fc8286baa30be1bee703460688), uint256(0x16d626e4c467eed896d9a23beff1cb3cb4524360b8c276ca0964d90e7c7ce202));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x0a038a9db7b64b659add5615aa886513abba3d0379118ba726bc5b10b1a79970), uint256(0x1d51ab8a2a840814b60b08ff39f402332f3224cf5b9c309823c51575013b4380));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x132d487db68839ed4cb134022ed331d53a89bba3ff89bfdd0b23ab5bd40cd0f4), uint256(0x020819c65001d6c5847b0148c035c29e17885c1e2fb52eca249f82132dfd5c70));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x096076cf289602e72279ac609faeba1ae53e6383d6e8a1d69ee982efb4b19d1d), uint256(0x082408368cd9deac41551b19789e76f65cdf16af022da96071ad41c6e33064fe));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x0e876a8d806fa9318cc36d89693aecc66e1900c00cbdc9375efd5748aa1eca9d), uint256(0x0b38d8ed6c0b2660bbbae51b55f032e419321c2db74c6c7d69b89ab6db9c00f8));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x1cc1c2370c9843c605cf12cb68b326f9ca58a971c79a387a8fa6ebdaa3574112), uint256(0x20d6d9f2edb4a67de1a4e0df487345afad09fb8f2b1672849685a813321c9b6d));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x134b36f07abfbc18d4f60171fd5590884087d577a5fe2f536c6094f9d49d9319), uint256(0x2bcbc5e5c453cf462a4698d4d9dee5418bec85b48f9006151b15be9ba8d06355));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x2a2ef64b9eae9c00fcacc5578ca7050ffb7eeb41e25dbf37bb7f3560a7479d86), uint256(0x1c3acc1b28074bd01be1a48fc61aa300ae2eb5bb2cc716c47ff0a72b78420525));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x22dc7f355ef456ef85ef24890648469f620b7d9889d524411b303cc350b0a714), uint256(0x1e3dd78080c58366004e526a3269a292928472a0ad149f6e82901c69ee8ae3a3));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x0298edfd4279ac20041bef3273cb21ae3a13aaceb7705fdc278092bbc23e7f5a), uint256(0x263fb49a32323a0d9f0e6be4af02cfe941add6f02c96ca558788d6a7e59e33cd));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x2f49c05cfb55772fff73957e3f6315e4e6c5d1be78ccd1f8fc4ca6ca4f2016ad), uint256(0x0a4b14b9797be19d3ae5d16c5053a5566a74f04013c55b3ff9a05fb3dee1181a));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x2e22901cee820aa1e1a7569a2612aa68351dc8363343209f9fe3dcc45f10073b), uint256(0x0209f66c159d5e6f32b61a4839be9b3e0edcba486fe02ccc1bef875b3f94bd52));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x06bc9cc4326f129bc8629913165fa7a38e8225edd28a15be4b3fc52111d77470), uint256(0x1cb04ff621ce687bc26af4a30c760e95de93daf47cc624ed19fdeaa566a902ee));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x0fc0007a069707f20128719ad4146a30706e893dd01e4a647d5dfa809f8408fc), uint256(0x056d4f1e354f74d60ff3e99d2c67705ec7fcd95342b7cda7a5e1e97b92ffa250));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x0340cda2df79b193418f6d651519885352b3c22d8afd6bcbee870210322a8d23), uint256(0x12649853695ca1b2d14a763ba261f6710f167d14990b2dd00ca0b463e5399799));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x275cfbe84525eba3c1ff431c1d3f6c70a595758a10d135c368a399bb20de81e5), uint256(0x14811acafc82938569b50cb15f07c00b8e48380ae177fe9512b064ba49890e6a));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x1f3c07ea35af3e7f0813c4576aa00cd253228cd96d258730c0715dc3873a5605), uint256(0x1d8815e152d2d6de74e10978414469e368b343b23dc2c70a2bc247db4c28c7dd));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x14e9cc06d5644499aaf3bda031e4ffc8ce3aba16a14df2f5d3238513403e0e54), uint256(0x18d1e6c728563e75e55dc2efdcf435292fcee98b45f08a6e5306b976b716003e));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x1b38d0d2eb75710b8011fa524b8a80830fc9678f2af15d9293822e0c660198ea), uint256(0x1ce5ca2d3deeb7b2776f51c6f5a2ec522927ce178438acf92ecda439c25e40ce));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x2e90a8e551c5de281309e1f29428840b7edb1aff29d5ae73951442003d1e29e1), uint256(0x2697c4686f2dccbe108e64ddb3bef77ad4934d79dcfa58eaca8aa547f492ce96));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x019bd0a2e165f1f8ee63adf92f1f820e6be87f60ad0c2ad1b60cf49cbbde052f), uint256(0x02a8cf5d154c7f1931e40c583b40221d877a4125809c25726a9b580eb332e8a9));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x0d696af69547206e1946e18c1de37ddc579f72ea575efaa2a0d76d85ef6241b5), uint256(0x105eb4e49949d3b22d948cf2ca683ccdc261d8f0e83018d7ca1d3efd797d9e1d));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x1b1baf1bc2b47c9e2db069515b23da32da91f127f2e2f514ab11e82e1dc0d72c), uint256(0x111f507fcb458445f8263d8de83fb98c47eed889a1c27f280408a0b4ad7c0bb4));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x1426338abaa8704409e1a2c5b7dfd98b8ea21f6664b6cd992cdc4fbe2fbb4902), uint256(0x14bce339a010e66dec0efc1b3499195773af101b456f58fb4ea0c6d850f328c3));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x160dbbf214fed46f753bcb94d92c742676ef41494bf19e9bff1640e139cd1ed8), uint256(0x1982082eb06194659b9270b32ebfc98652804533168e6cdb2fb31a3477f92034));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x238cff697fa914ecaa3bbad327db099f36a466f8608db895f8752ce1149f0306), uint256(0x0a4415ca485c1730b5fbfff9c5a7e0b6b263431a8fe3ac09da3491796f15b53b));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x1ea12ca1999bc7eaae46f8a42753dbe71e08c6d4a231c46af8eb55e145728cde), uint256(0x2888e60bd0133ded8801186abad90ab30425670ee3be4bbfb1afd6d20a013d1c));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x2035dc8776e3bf7135905c54fd8f137a3c551217e68d6debfd6202bff9d0d580), uint256(0x29f060e506850cb60d725f42b86ad0d101e24cf5dd433ddda8c858f59298860b));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x05db5eaa27bdcf2b2b9444e683a641ceb42b32328fd6a66cee07864bbd010ebb), uint256(0x1b56c593f8431a079e3beb7ee089cdf113da2ed5e93ccf765dda1d6a6b107d67));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x13a233375adbbd3ccc88faa60ab89c7129ee3c858e771754f1216271bd60f2fd), uint256(0x23b2e44c05fce663703795ee3e9b2bd2832fc53550c4b8d06927f89ccbd10ace));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x057d17ba6bf6c4105a235f73edc3ad73608844046b648b427af79a32ec09d286), uint256(0x12e39964f660cda2d6b4841916521601f4728e53fc652ecd14a85522688d0620));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x100bac3c35f488ae202b75036dbf4b518441270a25626cb8ac7aee0a86ecca55), uint256(0x00af36f7d1ffd253ef86a1370752f6da6ae8521f05f457bfe7244818982fa66c));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x04dd6ff4183a9ea253968bbd5cf5d6b6733b6109cb70b6bf68735e4e1e9616f6), uint256(0x0b31fd141495a19ee8ad56cc22e3420481ff4b7c5e6e8d62abf6f34fe7087d36));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x0f40ce308f5d3f4a55506e43242058cc5e1cabf2d13a12874961a0e2bab499eb), uint256(0x121c9f44666341befcace20e36cb7a15f961042cc577f20b36cbf6e1caa37b0c));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x12e3e35d6807ab300e949ba6f3b041cf4bfee0517ac1c436b317fe0b90ecb867), uint256(0x0c3be3f60a7b5a93d59396ee7f818823c992a616a4edd354ab033be5098682e6));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x211a6ba0bd3d7c9991b764e073a3bb8bb9b24a6785ddbbed90ec26a60909134c), uint256(0x23389f72196fad3404709766bc2d3c6888ac315a637bb5ec6dd881c8462fffa6));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x05d6ae9d93f778561418b0fd349d2c96b34d9c4d2cab1e57c97b3114e31a3716), uint256(0x12a5e09ebd7c66d796cec0e634118f6511b127ccf819b69be49d4d4d57fbb5f8));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x0a3de3eb2cd0a71fc14e42318a5fb65b686b3c239b916918dff316451ca1343e), uint256(0x0dd0a4b14b095a3403ccbbe2766051c69254b251e598edc70d75db1f087c27ba));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x2fed4b9c65da111792f2bb579aec4801bda36db859116a1e14e80d5018eceb71), uint256(0x2ffb2cecfd7874f1f3e24b385ad4dbcc365ab6413a652dd523d7e3206c944307));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x291aca33460190c7009b65612ab8277471cb72b292f91e4c194c34ad466da248), uint256(0x2a1bdfde3692afd2d05f554e63f5203cf3089f188ff8227514223fe17df0d99b));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x0b4b18a971ed4ebfdce1b0b241694f574599dad533e7696cacae3407c3478b5e), uint256(0x1255456e6e590fae31cd029e0eecc4fa00eecdb07f289a6fa4133ed41b482417));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x3042743693b0f697a3c85957641f701d021eddb5cabffe5eb2359adbe885b8a0), uint256(0x149a7977223fbda0a4f8fa9e2d2b9106e46f60ab82a84269a4c0f9ccdaeb09ec));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x113134394823a7402b0c66dd0c7243fd5d4216f4793eee426f767588aa519c9d), uint256(0x226a452d55047373f9422bc0544df79045b2ed1d214f30763d03b5be89561d99));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x300d0c2cd43500f050a35ad8318ba647ab3b50a2eb5da55ecb3df01718e0c11d), uint256(0x0693863496fb12bf4544cb144e487827f112fe3c9a83d1cadba3d31b7f4545ea));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x1cf4bf46b0b33d7b78ac33160f2342946ccaae7253d0b95d1ef1782a92f33a83), uint256(0x0873403d9062f99f89f0f0bd6f90ecc8f139e25f2ddaea66abcbcaa2382da55c));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x1093829cfda2d9f03d23192d2255f8149898ab2a5669e8a0c5a45cea58eae813), uint256(0x05b78cefe053241656382b96fe73d1a8c6dea9ac7965a702cb21d61427cc20d7));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x032b9c20221d950b0b4773603d1dedf79df0bc7aa7492aadcd1fa88754f4271f), uint256(0x006553551eb48859791870210b7aacfa7752ddb373ec44aaefc7b18180800f31));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x24f6607f3656d1b7d4b269dce8dd1d40f2af392edb9acee7e1cb41dfdab8a736), uint256(0x29bdd74e34ce40559f5e82a759556a49b1bddd78c8c4eb8875a6eb59e59f9e30));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x25ac61019bd8939766d73710aa265dadaa97b15f03bbc9faa7bcf75455eb49c7), uint256(0x0275c29062264e2cd6e7af2a82f6998214fffc6d33d06e283e162b322dc0d44a));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x1af13a4a56d9e9e79debb0442380654f286826bee556c7685787dedaf51ab10d), uint256(0x15b6b1f6b87b91e2a8016cec4a3525b31bd07ef5bd1443192dfe7787b5bfa5ad));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x1963152f44b7c3413b58e0345d76024a1c949b300fd38942470dcb222fc323df), uint256(0x1a080598a1f7706a9a35637f849d52b73b1dbce7554f1e913dfa39e38ffbc681));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x1adf950655b6950b51fe20b0ecb3f129cab284b3fef3d0532d2d8019732e02fc), uint256(0x142d569357ee21193e6aed165f50e063124f2cad92462ec382682dd99201a5d9));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x17c60e78ef4c85599cdbe0008698423eb22474a6c2126408037344aab84cdae3), uint256(0x003d024a558cadbe06ada43bdc031d6babb6041d7e9e86f3497410bf31cd8ecd));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x2f876698c3681b841de7b1b9e5bef07c9d12b87d0bfde57272f1f83418f43e16), uint256(0x02b8135fa6d61d020546ff12353ba626017918e28eba74c801f4d2cb978abd07));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x1e20c15c66e6e1456e22a8c8ae0c866d40014a9829f96b4947a87fcd55440a2f), uint256(0x0243f238ba0c5de2a1ab785e41eaa3a3fd11e753ef95160108b9127659feed7b));
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
            Proof memory proof, uint[65] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](65);
        
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


interface Cashbase{
    function mint(bytes32 p, bytes32 s) external payable returns(uint);
    function pour(Proof memory proof, bytes32 sn1, bytes32 p1, bytes32 coin1, bytes32 p2, bytes32 coin2) external returns(uint);
    function freeze(Proof memory proof, bytes32 p, bytes32 sn, bytes32 cm) external;
    function compute(Proof memory proof, bytes32 p, bytes32[2] memory ct, uint[4] memory epk_user) external;
    function finalize(Proof memory proof, uint32 out, bytes32[2] memory coin, bytes32[2][2] memory ct) external;
}
