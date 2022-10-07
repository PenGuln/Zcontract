// SPDX-License-Identifier: MIT
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// A simplified implementation of Hawk
// Author: Siqi

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
        vk.alpha = Pairing.G1Point(uint256(0x116cf6e73f4b173b6fdea44fda0f0f1576c4f1890827a84e97957a34632ce78b), uint256(0x00fdddef86fb961c1ba50d6cb32b4847d8649667b52c0b6b369ea9676ea429c2));
        vk.beta = Pairing.G2Point([uint256(0x0bc7fe9a7ec9661ace05ea364fc3cebff73ca503db26d78b1f1d686bda1576a7), uint256(0x2cf67c6f3351b0ce02002a40a65e0d693d6c3dd0775d7422fea95a26d884f6a4)], [uint256(0x2e8d28932298c4fd60cae429d7f6fcc9ef0507d39c0eb5364c027a11da1dd90c), uint256(0x1f79a592ba866c25ddd9854bbc30ab1eb85a09ab048c8b8766cd9fafac89a9e5)]);
        vk.gamma = Pairing.G2Point([uint256(0x2547b045c49e392a3f5ed9df89a487fb1bda4b153101f68917c4854707695d54), uint256(0x1b5350c05f60702a69c0429764a1277d1a754d16af346b5d53ea1222a87c8bb5)], [uint256(0x2db956894070a65402abc3b8274889fea75fc46ce39f252052705941cc365038), uint256(0x0446315b2275dfc8f8fc5d4c5f56723b5d8b4bce05fcba2d60c2095bc1f61cfb)]);
        vk.delta = Pairing.G2Point([uint256(0x304d32e3cbe0bfc3fe612c305fa5afe28278456641ffbd070d5a08cf8b5246a3), uint256(0x27e8a846474779c03d505093359586fe2e78943216ac929deef57dd7465c88d4)], [uint256(0x06eeeaa9b75d8e009247f398c8ebce8eecef6120033f2c92fbf52595ac2af0db), uint256(0x2fcaa551b2fa305db6f97b68ac9e72a0a4af99e7b5c839c0c4228c6f312761aa)]);
        vk.gamma_abc = new Pairing.G1Point[](25);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x0dd0eb56c9b8f59c5a680b9c52a8e1a5862f8b30e050bac0df76c1c39cf2bb69), uint256(0x23d743082468f8e98fc2ccfa47e60326def0d252c16739370019e595452ebeac));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x0218950b486298676983c7195a5d3c4ae029199ca956962401c68e3744fb0e0c), uint256(0x12f5f83ffea1e97e4b94e927f1cf13de035550a26bf3884d44c08bb5d66b4e1d));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x2ddc6278b354d5b154d043107eda36d6314ac2ff68f195b97d952ea908f7e5f0), uint256(0x190d9c6a07139b253226aa172ca7487b5abb1fd04d70bfbcdc1640f586b6fca7));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x1d45845d3c1fa4583be89359110046a96423b9e60013517c1f83998e44ebdf42), uint256(0x1ee511c3fa76675cb42982689e287d8dd7ddda5c39b4d7957930520ecacdf20b));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x15c952990c1fd75e69600733705c45c1241206f1e0b1df5a17e0eec14e4c1f49), uint256(0x28211c1b38c045c46137298e9fd9fd89b041a64e72ab402b8b58d0a8701493aa));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x19ed70e4760b5bcb4efad39c4b7328656f1ad1a1cf28b40163a90a50df22018e), uint256(0x2c70a5e16630b8a6600c16c00d4669382c7f1bb3720aa08a17458c4a5a93da8d));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x0462de1ac32eeacc0b70ffa9319a015a09beebae765f61a280f618f67d05cf39), uint256(0x303fc1476ae9d7a643f54e283604530c358d9a1e9cccb94e35c45361d127cede));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x08003449ad2ae6b8803fc353874e261ca612529c6fbcc7ad983ecc3d8ca96e30), uint256(0x0f05f75e3c91f7c4a4c4b0cb720a7ca56246045fd7e64eee86fdf4d4893a7803));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x035b5441d8203f3c24004d37cff403dcf1d44fd48fbed4ae2d68f82e38843777), uint256(0x2de9ecf48dea34f3db99e00459264727c3f07401daba4c7c4fea6fcfde5bcdbb));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x27bdaa1c7eccb7362c8c41e24918d9358410c9a7f96d58d119343da5dccabc17), uint256(0x22013b0af804810b7ec0b9faf6d16c232c5b767fb3bb5f99151aa5f4cba7bdfd));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x16f224a6fd71a10e944394df2e0fe9bda02a0106fc690565b031be3013a841db), uint256(0x02e2821b1a36d2c3f0538adff4a9499c65db9de3341f123e0c41d1b91ce56e52));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x11147b7a2725db23a8e6848ccf44ca85574a47e1ccc4b9c34896cf2526f0c0a0), uint256(0x1dced171cbae2b36d05f4b0ad198673f18be7622a3593d078e1ef5fd79bf7483));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x2cfbd0fc1ffecaf0f7ade847f2e640cc0f6a7407f25a11eb74748c7744a9ba7c), uint256(0x1101f4076e3d12839e9626769741e1156a489c0698aec32c6beccf03798b162c));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x238c272668e813a7b6ea4069e001963ea2e1ae8ee2d04744a7dde00cfa34c963), uint256(0x1ed85992509398ebae084e4ab33237eec17a5f99042703965f533de46454e288));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x01819bdabf18613538519694df1a4771ab673c8d9cf4bd375eac16761e449352), uint256(0x13be4ddf952eab502bf9b3164709581a7f949e0b3927c41df9afb9d1876f8cb5));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x14f886a0f24d5e4b1a9886e7e7811f5570eff1e8e1a6d3e03768a9da7e6e29a3), uint256(0x288ef48ea51ee0b3d8e2c9e8b4b82d388b4b80969bf86d1ceccb276ab4c908e3));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x0972dcf04fd319491aa88d7884d25fee3f5cb9f74c3859dffc03e3190f67db06), uint256(0x1d1d85f9defa4768552a78e24a3d02998c207c97e945235e9320b322ed64b4f9));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x147bbb679d6d62f5eb21a4bebc061948da356b512ec1383e644138b64dca3ea2), uint256(0x158b5733e2f295d1cdc090add394e48b931feb332829eafb946031c1217649f4));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x14467f7c74a21b787f833ac472c6c6ebe6af6ab70391ea35002ac53d952be097), uint256(0x2072c03cfd3a57e573444ade9bf5c2632d0a6d8665f997173dacc39358a5871e));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x2c65152f94fd41d7869025f7801c8db6fa4a71a2efa2d3301d5309506e539ce2), uint256(0x0e30516c9d7cd6b12496005c6bf07bfd8bf90414e4f842580085c1805f6d545d));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x077da18032b6b03cca1f80bd3982832e51dff5f41356209046c510bbaf3ad28e), uint256(0x14c7cfc36c9951efdc3eb742737ae0809d6436de9f2fd0f56810ad94e209c2a5));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x06390aaa71bb779fa6987755fef6b8fb4178d2dccbd79245b69b5dd4f55bb073), uint256(0x1587ce6fe018dab25322473a6d7d1e2821ba9367d247c5e14b354303a700ea5c));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x28e52bdcedac9d40695451116b08864f17ebba18fbb96efd8cf3c0e868a184b0), uint256(0x0bed409db7f6098dff7f79d84aa8aacbec17cc49aa25687774679d70ac49f106));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x221d0b02a67a5afb231b6b4f09c67cdf167ffeacc4180d8ce9c74cd9572b2a8e), uint256(0x01b4c04989af9d0b47f4b5d9b0ce50235832e00c03c557ddd1503327ba7a909f));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x1f5166f68001e7f1db4983fda39f767de15ea61baafe9382ac81e2a83aa11bf2), uint256(0x1bea2bc1236a2eda6d34cff8685011e0e0d855cf40313cb620bb0b12317044f9));
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
            Proof memory proof, uint[24] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](24);
        
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
        vk.alpha = Pairing.G1Point(uint256(0x17bdb2e2676c925ba95a3a280874553d6b3ca9b74f070d402c06c34a13ac1f8a), uint256(0x23071c39510339574ecb9cd0b50fa2eefc99223cf2d68aee61295f0d7d64bb6c));
        vk.beta = Pairing.G2Point([uint256(0x277319f67155757e0107c50c85744f1739aa25d21714324d8afdb86e0e4a486c), uint256(0x1c6e42b2b4a958483e2a431ae4052594aa4560fe1c9057684edcc3d247075cd2)], [uint256(0x08cefa1d1a3616d2acef0bd4ec71ced0ab9d04373fdabecbbb2057e385489d9c), uint256(0x2b1a4c4da45d9f1a74fea21421c9b8fbcc7acc9ec85f9baea9261412582abf2c)]);
        vk.gamma = Pairing.G2Point([uint256(0x05d4befce4ea655bff7927b81b097f4fe2e008fcc3006609f5ee4a19b34b5946), uint256(0x2bda7028984072c5a59e2e465caebb5bd0d2669952193df8f224289ae35c8477)], [uint256(0x151b45315bd6ededadaeb37b921370c68c44b4790c0fd679e477d0c1188f96e0), uint256(0x0b8fe4186ccde762a270e95a47678f6d95120d434d17b892f3144de745be02b1)]);
        vk.delta = Pairing.G2Point([uint256(0x0bc0ac349a8d4dd57251b63d5fee00c7180b1c49f32527c1f745cadbc08a99bb), uint256(0x089291ccd7e7e7215a0484ede8607f50474aaf1c85961ea66ff5232903b3b8e8)], [uint256(0x27503d3d147859087a8c62de2dc2842ebd7343265588fc0933b4dfc38afb7aca), uint256(0x27adf86df0cb55556ad23fad6999ccf40705843d25514f8a095baa3e8bca33e1)]);
        vk.gamma_abc = new Pairing.G1Point[](11);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x0561bb4ac84e97cd10d96767abc01bae0e298740c72e8333c3a5628af57ed9aa), uint256(0x2578b3ffc456cfd512fe70aa6f843ba6d12686fe5744201eac29dc16eb1c23ca));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x01f4e0bc91059893ea13eb485378f333335952a1389a7fe942b06087cb51fc42), uint256(0x0db864159dc9276af936b503d2416839c9ef541a9813b2004dfd0e6cb24bfc22));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x0108cd4410b18c1f0fd34c0389b6be9a19fffa56ecff8e6bcb00df7687208ffb), uint256(0x1dda3517c956cc934fb49c166c4b78504ac86d4934ccf07282cf98bcd77bf988));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x25f3ef678b1429ba73fab4b6347f9553c85d62091215a08fc97cb4f7c6a36279), uint256(0x2ecc54fd57b850f07b2c9ea760b73fcb931889b029df5af0deead69d5bc100e8));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x2022f2a3f96ab6424d7b23c304c8bdbe5d547a6fec5a2a886215322e4d490876), uint256(0x1e485be2316ecc5ab40a7328b692243b64f1c422a059e26e0b3b9a11bfb567d6));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x0a84fc91124ac31f19a04dfbefc258c599c2a91de6581f0360b69ecd975c4ad0), uint256(0x29d34f4e55ab9cc0e598d57f3ff2d04425bbef5623b66df78b7eb1ab5aa6129e));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x0130d6b5bca89aeba64f89c35c1bcaff65062f9f30eab16e6a62a40841e03588), uint256(0x27aa6dacb61315bd1bc9572e5e269051c95e850609d155833bd4402e257f1c38));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x14c933b5cae21f4b2401a870d8493c81d11341411769c8f66fb616cbb725b2c7), uint256(0x2b2ba475f3ed5787d1220371d70ed72ac563f8b1ff595532f0aea8ca73781ba9));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x09739d48220034f73528e6578fe058034e95b02d45e3f7d35baa96483719b553), uint256(0x09f5c1fea4d0690a1340054cdfda32f5992fe8629816acb4a39c077ba3fc2076));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x24cecd8b1079f5fd0cdd2852dd2d7cc702a5a1ed8342deee6367baa6e7f8a867), uint256(0x2d57922d02493eecfba03e22c96b369a1947db5f454c019d1b2c1d85f480951c));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x061cbb2703559f9770fe57fe727ff97cd624a2659ff3276be30c0aadda422ce7), uint256(0x1e0aebad2b460b5bea6be453fb82c4b868f77c0fad3a14e86b47de632eb547c1));
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
            Proof memory proof, uint[10] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](10);
        
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



contract Cash {
    uint constant DEPTH = 8;
    PourVerifier public pourVerifier;
    FreezeVerifier public freezeVerifier;
    ComputeVerifier public computeVerifier;
    WithdrawVerifier public withdrawVerifier;

    bytes32[1 << (DEPTH + 1)] public hashes;
    uint public cur;
    address public owner;
    mapping(bytes32 => bool) public nullifier;
    mapping(bytes32 => bool) public freezeCoins;

    constructor(PourVerifier _verifier) {
        owner = msg.sender;
        cur = 0;
        pourVerifier = _verifier;
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

    function mint(bytes32 p, bytes32 s) public payable returns(uint){
        require(cur < (1 << (DEPTH + 1)));
        require(msg.value <= type(uint32).max);
        bytes32 coin = sha256(abi.encodePacked(s, msg.value));
        addCoin(p, coin);
        return cur - 1;
    }

    function pour(Proof memory proof, bytes32 sn1, bytes32 p1, bytes32 coin1, bytes32 p2, bytes32 coin2) public{
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
    }

    function freeze(Proof memory proof, bytes32 sn, bytes32 cm) public{
        uint[24] memory input = [uint(0), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
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
        require(freezeVerifier.verifyTx(proof, input));
        require(!nullifier[sn]);
        nullifier[sn] = true;
        freezeCoins[cm] = true;
    }

    function compute(Proof memory proof, bytes32 cm, uint32 indata, uint32 val) public payable{
        // since the on-chain smart contracts instead of a off-chain manager takes the role of computation in this version, 
        // the coin value should be revealed while computing
        // User sends the value and zkp of knowing the randomness s to reveal a coin
        // Once a coin is revealed, the contract sends the corrresponding value to the msg sender.
        // Note that there is no need to compute a zero-knowledge proof of membership within the frozen pool 
        // as is needed in a freeze transaction
        require(freezeCoins[cm]);
        uint[10] memory input = [uint(0), 0, 0, 0, 0, 0, 0, 0, 0, 0];
        bytes32 sub = bytes32(uint((1 << 32) - 1));
        bytes32 tmp = cm;
        for (uint i = 8; i > 0; i--) {
            input[i - 1] = uint(tmp & sub); tmp >>= 32;
        }
        input[8] = indata;
        input[9] = val;
        require(computeVerifier.verifyTx(proof, input));
        freezeCoins[cm] = false;
        payable(msg.sender).transfer(val);
    }

    function withdraw(Proof memory proof, bytes32 cm, bytes32 p, bytes32 coin) public { 
        // user sends the newly constructed coin (P, coin) and 
        // zk-proves that its value equals to that of the frozen coin
        // Note that there is no need to compute a zero-knowledge proof of membership within the frozen pool 
        // as is needed in a freeze transaction
        require(freezeCoins[cm]);
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
        freezeCoins[cm] = false;
        addCoin(p, coin);
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
