#include "gtest/gtest.h"

#include "crypto/cipher/aes.hh"

#include "crypto/testutils/compat_tester.hh"

#include <random>

const crypto::bytestring nist_aes_pt_block =
    crypto::bytestring::from_hex("00112233445566778899aabbccddeeff");
const crypto::bytestring nist_aes128_key_block =
    crypto::bytestring::from_hex("000102030405060708090a0b0c0d0e0f");
const crypto::bytestring nist_aes256_key_block =
    crypto::bytestring::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
const crypto::bytestring nist_aes128_ct_block =
    crypto::bytestring::from_hex("69c4e0d86a7b0430d8cdb78070b4c55a");
const crypto::bytestring nist_aes256_ct_block =
    crypto::bytestring::from_hex("8ea2b7ca516745bfeafc49904b496089");

/**
 * Convenience structure used to input test vectors from NIST.
 */
struct CAVSTestVector {
    int count;
    crypto::bytestring key;
    crypto::bytestring iv;
    crypto::bytestring input;
    crypto::bytestring output;

    CAVSTestVector(int no, const char *key_hex, const char *iv_hex,
                   const char *input_hex, const char *output_hex) {
        count = no;
        key = crypto::bytestring::from_hex(key_hex);
        iv = crypto::bytestring::from_hex(iv_hex);
        input = crypto::bytestring::from_hex(input_hex);
        output = crypto::bytestring::from_hex(output_hex);
    }
};

// Test vectors from NIST MMT test, for AES CBC
const CAVSTestVector CBCMMTEncVectors128[] = {
    CAVSTestVector(0, "1f8e4973953f3fb0bd6b16662e9a3c17",
                   "2fe2b333ceda8f98f4a99b40d2cd34a8",
                   "45cf12964fc824ab76616ae2f4bf0822",
                   "0f61c4d44c5147c03c195ad7e2cc12b2"),
    CAVSTestVector(
        1, "0700d603a1c514e46b6191ba430a3a0c",
        "aad1583cd91365e3bb2f0c3430d065bb",
        "068b25c7bfb1f8bdd4cfc908f69dffc5ddc726a197f0e5f720f730393279be91",
        "c4dc61d9725967a3020104a9738f23868527ce839aab1752fd8bdb95a82c4d00"),
    CAVSTestVector(2, "3348aa51e9a45c2dbe33ccc47f96e8de",
                   "19153c673160df2b1d38c28060e59b96",
                   "9b7cee827a26575afdbb7c7a329f887238052e3601a7917456ba61251c2"
                   "14763d5e1847a6ad5d54127a399ab07ee3599",
                   "d5aed6c9622ec451a15db12819952b6752501cf05cdbf8cda34a457726d"
                   "ed97818e1f127a28d72db5652749f0c6afee5"),
    CAVSTestVector(3, "b7f3c9576e12dd0db63e8f8fac2b9a39",
                   "c80f095d8bb1a060699f7c19974a1aa0",
                   "9ac19954ce1319b354d3220460f71c1e373f1cd336240881160cfde46eb"
                   "fed2e791e8d5a1a136ebd1dc469dec00c4187722b841cdabcb22c1be8a1"
                   "4657da200e",
                   "19b9609772c63f338608bf6eb52ca10be65097f89c1e0905c42401fd477"
                   "91ae2c5440b2d473116ca78bd9ff2fb6015cfd316524eae7dcb95ae738e"
                   "beae84a467"),
    CAVSTestVector(4, "b6f9afbfe5a1562bba1368fc72ac9d9c",
                   "3f9d5ebe250ee7ce384b0d00ee849322",
                   "db397ec22718dbffb9c9d13de0efcd4611bf792be4fce0dc5f25d4f577e"
                   "d8cdbd4eb9208d593dda3d4653954ab64f05676caa3ce9bfa795b08b67c"
                   "eebc923fdc89a8c431188e9e482d8553982cf304d1",
                   "10ea27b19e16b93af169c4a88e06e35c99d8b420980b058e34b4b8f132b"
                   "13766f72728202b089f428fecdb41c79f8aa0d0ef68f5786481cca29e21"
                   "26f69bc14160f1ae2187878ba5c49cf3961e1b7ee9"),
    CAVSTestVector(5, "bbe7b7ba07124ff1ae7c3416fe8b465e",
                   "7f65b5ee3630bed6b84202d97fb97a1e",
                   "2aad0c2c4306568bad7447460fd3dac054346d26feddbc9abd911091401"
                   "1b4794be2a9a00a519a51a5b5124014f4ed2735480db21b434e99a911bb"
                   "0b60fe0253763725b628d5739a5117b7ee3aefafc5b4c1bf446467e7bf5"
                   "f78f31ff7caf187",
                   "3b8611bfc4973c5cd8e982b073b33184cd26110159172e44988eb5ff566"
                   "1a1e16fad67258fcbfee55469267a12dc374893b4e3533d36f5634c3095"
                   "583596f135aa8cd1138dc898bc5651ee35a92ebf89ab6aeb5366653bc60"
                   "a70e0074fc11efe"),
    CAVSTestVector(6, "89a553730433f7e6d67d16d373bd5360",
                   "f724558db3433a523f4e51a5bea70497",
                   "807bc4ea684eedcfdcca30180680b0f1ae2814f35f36d053c5aea6595a3"
                   "86c1442770f4d7297d8b91825ee7237241da8925dd594ccf676aecd46ca"
                   "2068e8d37a3a0ec8a7d5185a201e663b5ff36ae197110188a23503763b8"
                   "218826d23ced74b31e9f6e2d7fbfa6cb43420c7807a8625",
                   "406af1429a478c3d07e555c5287a60500d37fc39b68e5bbb9bafd6ddb22"
                   "3828561d6171a308d5b1a4551e8a5e7d572918d25c968d3871848d2f166"
                   "35caa9847f38590b1df58ab5efb985f2c66cfaf86f61b3f9c0afad6c963"
                   "c49cee9b8bc81a2ddb06c967f325515a4849eec37ce721a"),
    CAVSTestVector(7, "c491ca31f91708458e29a925ec558d78",
                   "9ef934946e5cd0ae97bd58532cb49381",
                   "cb6a787e0dec56f9a165957f81af336ca6b40785d9e94093c6190e51526"
                   "49f882e874d79ac5e167bd2a74ce5ae088d2ee854f6539e0a94796b1e1b"
                   "d4c9fcdbc79acbef4d01eeb89776d18af71ae2a4fc47dd66df6c4dbe1d1"
                   "850e466549a47b636bcc7c2b3a62495b56bb67b6d455f1eebd9bfefecbc"
                   "a6c7f335cfce9b45cb9d",
                   "7b2931f5855f717145e00f152a9f4794359b1ffcb3e55f594e33098b51c"
                   "23a6c74a06c1d94fded7fd2ae42c7db7acaef5844cb33aeddc6852585ed"
                   "0020a6699d2cb53809cefd169148ce42292afab063443978306c582c18b"
                   "9ce0da3d084ce4d3c482cfd8fcf1a85084e89fb88b40a084d5e972466d0"
                   "7666126fb761f84078f2"),
    CAVSTestVector(8, "f6e87d71b0104d6eb06a68dc6a71f498",
                   "1c245f26195b76ebebc2edcac412a2f8",
                   "f82bef3c73a6f7f80db285726d691db6bf55eec25a859d3ba0e0445f26b"
                   "9bb3b16a3161ed1866e4dd8f2e5f8ecb4e46d74a7a78c20cdfc7bcc9e47"
                   "9ba7a0caba9438238ad0c01651d5d98de37f03ddce6e6b4bd4ab03cf9e8"
                   "ed818aedfa1cf963b932067b97d776dce1087196e7e913f7448e3824450"
                   "9f0caf36bd8217e15336d35c149fd4e41707893fdb84014f8729",
                   "b09512f3eff9ed0d85890983a73dadbb7c3678d52581be64a8a8fc586f4"
                   "90f2521297a478a0598040ebd0f5509fafb0969f9d9e600eaef33b1b93e"
                   "ed99687b167f89a5065aac439ce46f3b8d22d30865e64e45ef8cd30b698"
                   "4353a844a11c8cd60dba0e8866b3ee30d24b3fa8a643b328353e06010fa"
                   "8273c8fd54ef0a2b6930e5520aae5cd5902f9b86a33592ca4365"),
    CAVSTestVector(9, "2c14413751c31e2730570ba3361c786b",
                   "1dbbeb2f19abb448af849796244a19d7",
                   "40d930f9a05334d9816fe204999c3f82a03f6a0457a8c475c94553d1d11"
                   "6693adc618049f0a769a2eed6a6cb14c0143ec5cccdbc8dec4ce560cfd2"
                   "06225709326d4de7948e54d603d01b12d7fed752fb23f1aa4494fbb0013"
                   "0e9ded4e77e37c079042d828040c325b1a5efd15fc842e44014ca4374bf"
                   "38f3c3fc3ee327733b0c8aee1abcd055772f18dc04603f7b2c1ea69ff66"
                   "2361f2be0a171bbdcea1e5d3f",
                   "6be8a12800455a320538853e0cba31bd2d80ea0c85164a4c5c261ae4854"
                   "17d93effe2ebc0d0a0b51d6ea18633d210cf63c0c4ddbc27607f2e81ed9"
                   "113191ef86d56f3b99be6c415a4150299fb846ce7160b40b63baf1179d1"
                   "9275a2e83698376d28b92548c68e06e6d994e2c1501ed297014e702cdef"
                   "ee2f656447706009614d801de1caaf73f8b7fa56cf1ba94b631933bbe57"
                   "7624380850f117435a0355b2b"),
};

const CAVSTestVector CBCMMTDecVectors128[] = {
    CAVSTestVector(0, "6a7082cf8cda13eff48c8158dda206ae",
                   "bd4172934078c2011cb1f31cffaf486e",
                   "f8eb31b31e374e960030cd1cadb0ef0c",
                   "940bc76d61e2c49dddd5df7f37fcf105"),
    CAVSTestVector(
        1, "625eefa18a4756454e218d8bfed56e36",
        "73d9d0e27c2ec568fbc11f6a0998d7c8",
        "5d6fed86f0c4fe59a078d6361a142812514b295dc62ff5d608a42ea37614e6a1",
        "360dc1896ce601dfb2a949250067aad96737847a4580ede2654a329b842fe81e"),
    CAVSTestVector(2, "fd6e0b954ae2e3b723d6c9fcae6ab09b",
                   "f08b65c9f4dd950039941da2e8058c4e",
                   "e29e3114c8000eb484395b256b1b3267894f290d3999819ff35da03e646"
                   "3c186c4d7ebb964941f1986a2d69572fcaba8",
                   "a206385945b21f812a9475f47fddbb7fbdda958a8d14c0dbcdaec36e8b2"
                   "8f1f6ececa1ceae4ce17721d162c1d42a66c1"),
    CAVSTestVector(
        3, "7b1ab9144b0239315cd5eec6c75663bd",
        "0b1e74f45c17ff304d99c059ce5cde09",
        "d3f89b71e033070f9d7516a6cb4ea5ef51d6fb63d4f0fea089d0a60e47bbb3c2e10e9b"
        "a3b282c7cb79aefe3068ce228377c21a58fe5a0f8883d0dbd3d096beca",
        "b968aeb199ad6b3c8e01f26c2edad444538c78bfa36ed68ca76123b8cdce615a01f611"
        "2bb80bfc3f17490578fb1f909a52e162637b062db04efee291a1f1af60"),
    CAVSTestVector(4, "36466b6bd25ea3857ea42f0cac1919b1",
                   "7186fb6bdfa98a16189544b228f3bcd3",
                   "9ed957bd9bc52bba76f68cfbcde52157a8ca4f71ac050a3d92bdebbfd7c"
                   "78316b4c9f0ba509fad0235fdafe90056ad115dfdbf08338b2acb1c807a"
                   "88182dd2a882d1810d4302d598454e34ef2b23687d",
                   "999983467c47bb1d66d7327ab5c58f61ddb09b93bd2460cb78cbc12b5fa"
                   "1ea0c5f759ccc5e478697687012ff4673f6e61eecaeda0ccad2d674d309"
                   "8c7d17f887b62b56f56b03b4d055bf3a4460e83efa"),
    CAVSTestVector(
        5, "89373ee6e28397640d5082eed4123239",
        "1a74d7c859672c804b82472f7e6d3c6b",
        "1bcba44ddff503db7c8c2ec4c4eea0e827957740cce125c1e11769842fa97e25f1b892"
        "69e6d77923a512a358312f4ba1cd33f2d111280cd83e1ef9e7cf7036d55048d5c27365"
        "2afa611cc81b4e9dac7b5078b7c4716062e1032ead1e3329588a",
        "45efd00daa4cdc8273ef785cae9e944a7664a2391e1e2c449f475acec0124bbc229443"
        "31678617408a1702917971f4654310ffb9229bec6173715ae512d37f93aaa6abf009f7"
        "e30d65669d1db0366b5bce4c7b00f871014f5753744a1878dc57"),
    CAVSTestVector(6, "bab0cceddc0abd63e3f82e9fbff7b8aa",
                   "68b9140f300490c5c942f66e777eb806",
                   "c65b94b1f291fa9f0600f22c3c0432c895ad5d177bcccc9ea44e8ec339c"
                   "9adf43855b326179d6d81aa36ef59462fd86127e9d81b0f286f93306bf7"
                   "4d4c79e47c1b3d4b74edd3a16290e3c63b742e41f20d66ceee794316bb6"
                   "3d3bd002712a1b136ba6185bd5c1dab81b07db90d2af5e5",
                   "c5585ff215bbb73ba5393440852fb199436de0d15e55c631f877670aa3e"
                   "da9f672eb1f876f09544e63558436b8928000db2f02a5ad90f95b05ac4c"
                   "f49e198e617e7678480fdf0efacc6aae691271e6cdd3541ebf719a1ccae"
                   "db24e2f80f92455dd5910cb5086b0960a3942ec182dcbd7"),
    CAVSTestVector(
        7, "9c702898efa44557b29ed283f5bc0293",
        "cec6e1b82e8b2a591a9fa5ff1cf5cc51",
        "ba9f646755dacc22911f51d7de2f7e7cb0bc0b75257ea44fe883edb055c7c28ede04c3"
        "a0adcb10128ad4517d0093fa16bb0bcd2635e7a0ba92c7609bc8d8568002a7a9834737"
        "24d256513aa7d51b477aabec1975ab5faf2872a6407e922180eff02f1ef86a4591c8bd"
        "3d143da6f0ef0e4806f94ace0d5b0151c99640fccbc843",
        "1d1f8d81bdc3e2c7cb057f408e6450000c5aaed3260ff1e87fbb6f324df6887ffd8f78"
        "d7e2a04c9ed9deda9d64482d2b002f4a2b78d8b4f691875c8295d4a64b22257ceaf713"
        "ed2f4b92530d7ad7151d629acda882b4829577a43990b0948c1149c22fe4273656d1b0"
        "8833930e8b06709a94579a78fc220f7057bbc1fa9f6563"),
    CAVSTestVector(8, "5674636dbdb38f705f0b08c372ef4785",
                   "3f20ce0509b57420d53b6be4d0b7f0a9",
                   "198351f453103face6655666fe90bdbd9630e3733b2d66c013a634e91f2"
                   "bf015bd2d975d71b26322e44defa32d4e9dce50363557046ece08ba38f2"
                   "58dae5fd3e5049c647476c81e73482e40c171d89f9fea29452caf995733"
                   "589b0061464fbd5dabe27dc5ea463a3deeb7dcb43664ae6a65c498c1438"
                   "83ab8e83b51e5410b181647602443dc3cfffe86f0205398fa83c",
                   "6d40fd2f908f48ce19241b6b278b1b1676dffd4a97ce9f8a1574c33bc59"
                   "237deb536bee376fd6c381e6987700e39283aa111cf1a59f26fae6fb670"
                   "0bf012646a2ab80239bf5e1632329043aa87d7911978b36523a2bc0bed9"
                   "a9737ccf7a00baa2f3822b4e9e742e168e7069290705fed2eb63aa044b7"
                   "8f97dd33a8d6b24741ec1fd8c8db79d93b884e762dba0f406961"),
    CAVSTestVector(
        9, "97a1025529b9925e25bbe78770ca2f99",
        "d4b4eab92aa9637e87d366384ed6915c",
        "22cdc3306fcd4d31ccd32720cbb61bad28d855670657c48c7b88c31f4fa1f93c01b57d"
        "a90be63ead67d6a325525e6ed45083e6fb70a53529d1fa0f55653b942af59d78a26603"
        "61d63a7290155ac5c43312a25b235dacbbc863faf00940c99624076dfa44068e7c554c"
        "9038176953e571751dfc0954d41d113771b06466b1c8d13e0d4cb675ed58d1a619e154"
        "0970983781dc11d2dd8525ab5745958d615defda",
        "e8b89150d8438bf5b17449d6ed26bd72127e10e4aa57cad85283e8359e089208e84921"
        "649f5b60ea21f7867cbc9620560c4c6238db021216db453c9943f1f1a60546173daef2"
        "557c3cdd855031b353d4bf176f28439e48785c37d38f270aa4a6faad2baabcb0c0b2d1"
        "dd5322937498ce803ba1148440a52e227ddba4872fe4d81d2d76a939d24755adb8a7b8"
        "452ceed2d179e1a5848f316f5c016300a390bfa7")
};

const CAVSTestVector CBCMMTEncVectors256[] = {
    CAVSTestVector(
        0, "6ed76d2d97c69fd1339589523931f2a6cff554b15f738f21ec72dd97a7330907",
        "851e8764776e6796aab722dbb644ace8", "6282b8c05c5c1530b97d4816ca434762",
        "6acc04142e100a65f51b97adf5172c41"),
    CAVSTestVector(
        1, "dce26c6b4cfb286510da4eecd2cffe6cdf430f33db9b5f77b460679bd49d13ae",
        "fdeaa134c8d7379d457175fd1a57d3fc",
        "50e9eee1ac528009e8cbcd356975881f957254b13f91d7c6662d10312052eb00",
        "2fa0df722a9fd3b64cb18fb2b3db55ff2267422757289413f8f657507412a64c"),
    CAVSTestVector(
        2, "fe8901fecd3ccd2ec5fdc7c7a0b50519c245b42d611a5ef9e90268d59f3edf33",
        "bd416cb3b9892228d8f1df575692e4d0", "8d3aa196ec3d7c9b5bb122e7fe77fb1295"
                                            "a6da75abe5d3a510194d3a8a4157d5c89d"
                                            "40619716619859da3ec9b247ced9",
        "608e82c7ab04007adb22e389a44797fed7de090c8c03ca8a2c5acd9e84df37fbc58ce8"
        "edb293e98f02b640d6d1d72464"),
    CAVSTestVector(
        3, "0493ff637108af6a5b8e90ac1fdf035a3d4bafd1afb573be7ade9e8682e663e5",
        "c0cd2bebccbb6c49920bd5482ac756e8",
        "8b37f9148df4bb25956be6310c73c8dc58ea9714ff49b643107b34c9bff096a94fedd6"
        "823526abc27a8e0b16616eee254ab4567dd68e8ccd4c38ac563b13639c",
        "05d5c77729421b08b737e41119fa4438d1f570cc772a4d6c3df7ffeda0384ef84288ce"
        "37fc4c4c7d1125a499b051364c389fd639bdda647daa3bdadab2eb5594"),
    CAVSTestVector(
        4, "9adc8fbd506e032af7fa20cf5343719de6d1288c158c63d6878aaf64ce26ca85",
        "11958dc6ab81e1c7f01631e9944e620f",
        "c7917f84f747cd8c4b4fedc2219bdbc5f4d07588389d8248854cf2c2f89667a2d7bcf5"
        "3e73d32684535f42318e24cd45793950b3825e5d5c5c8fcd3e5dda4ce9246d18337ef3"
        "052d8b21c5561c8b660e",
        "9c99e68236bb2e929db1089c7750f1b356d39ab9d0c40c3e2f05108ae9d0c30b04832c"
        "cdbdc08ebfa426b7f5efde986ed05784ce368193bb3699bc691065ac62e258b9aa4cc5"
        "57e2b45b49ce05511e65"),
    CAVSTestVector(
        5, "73b8faf00b3302ac99855cf6f9e9e48518690a5906a4869d4dcf48d282faae2a",
        "b3cb97a80a539912b8c21f450d3b9395",
        "3adea6e06e42c4f041021491f2775ef6378cb08824165edc4f6448e232175b60d0345b"
        "9f9c78df6596ec9d22b7b9e76e8f3c76b32d5d67273f1d83fe7a6fc3dd3c49139170fa"
        "5701b3beac61b490f0a9e13f844640c4500f9ad3087adfb0ae10",
        "ac3d6dbafe2e0f740632fd9e820bf6044cd5b1551cbb9cc03c0b25c39ccb7f33b83aac"
        "fca40a3265f2bbff879153448acacb88fcfb3bb7b10fe463a68c0109f028382e3e557b"
        "1adf02ed648ab6bb895df0205d26ebbfa9a5fd8cebd8e4bee3dc"),
    CAVSTestVector(
        6, "9ddf3745896504ff360a51a3eb49c01b79fccebc71c3abcb94a949408b05b2c9",
        "e79026639d4aa230b5ccffb0b29d79bc",
        "cf52e5c3954c51b94c9e38acb8c9a7c76aebdaa9943eae0a1ce155a2efdb4d46985d93"
        "5511471452d9ee64d2461cb2991d59fc0060697f9a671672163230f367fed1422316e5"
        "2d29eceacb8768f56d9b80f6d278093c9a8acd3cfd7edd8ebd5c293859f64d2f8486ae"
        "1bd593c65bc014",
        "34df561bd2cfebbcb7af3b4b8d21ca5258312e7e2e4e538e35ad2490b6112f0d7f148f"
        "6aa8d522a7f3c61d785bd667db0e1dc4606c318ea4f26af4fe7d11d4dcff0456511b4a"
        "ed1a0d91ba4a1fd6cd9029187bc5881a5a07fe02049d39368e83139b12825bae2c7be8"
        "1e6f12c61bb5c5"),
    CAVSTestVector(
        7, "458b67bf212d20f3a57fce392065582dcefbf381aa22949f8338ab9052260e1d",
        "4c12effc5963d40459602675153e9649",
        "256fd73ce35ae3ea9c25dd2a9454493e96d8633fe633b56176dce8785ce5dbbb84dbf2"
        "c8a2eeb1e96b51899605e4f13bbc11b93bf6f39b3469be14858b5b720d4a522d36feed"
        "7a329c9b1e852c9280c47db8039c17c4921571a07d1864128330e09c308ddea1694e95"
        "c84500f1a61e614197e86a30ecc28df64ccb3ccf5437aa",
        "90b7b9630a2378f53f501ab7beff039155008071bc8438e789932cfd3eb1299195465e"
        "6633849463fdb44375278e2fdb1310821e6492cf80ff15cb772509fb426f3aeee27bd4"
        "938882fd2ae6b5bd9d91fa4a43b17bb439ebbe59c042310163a82a5fe5388796eee35a"
        "181a1271f00be29b852d8fa759bad01ff4678f010594cd"),
    CAVSTestVector(
        8, "d2412db0845d84e5732b8bbd642957473b81fb99ca8bff70e7920d16c1dbec89",
        "51c619fcf0b23f0c7925f400a6cacb6d",
        "026006c4a71a180c9929824d9d095b8faaa86fc4fa25ecac61d85ff6de92dfa8702688"
        "c02a282c1b8af4449707f22d75e91991015db22374c95f8f195d5bb0afeb03040ff896"
        "5e0e1339dba5653e174f8aa5a1b39fe3ac839ce307a4e44b4f8f1b0063f738ec18acdb"
        "ff2ebfe07383e734558723e741f0a1836dafdf9de82210a9248bc113b3c1bc8b4e252c"
        "a01bd803",
        "0254b23463bcabec5a395eb74c8fb0eb137a07bc6f5e9f61ec0b057de305714f8fa294"
        "221c91a159c315939b81e300ee902192ec5f15254428d8772f79324ec43298ca21c00b"
        "370273ee5e5ed90e43efa1e05a5d171209fe34f9f29237dba2a6726650fd3b1321747d"
        "1208863c6c3c6b3e2d879ab5f25782f08ba8f2abbe63e0bedb4a227e81afb36bb66455"
        "08356d34"),
    CAVSTestVector(
        9, "48be597e632c16772324c8d3fa1d9c5a9ecd010f14ec5d110d3bfec376c5532b",
        "d6d581b8cf04ebd3b6eaa1b53f047ee1",
        "0c63d413d3864570e70bb6618bf8a4b9585586688c32bba0a5ecc1362fada74ada32c5"
        "2acfd1aa7444ba567b4e7daaecf7cc1cb29182af164ae5232b002868695635599807a9"
        "a7f07a1f137e97b1e1c9dabc89b6a5e4afa9db5855edaa575056a8f4f8242216242bb0"
        "c256310d9d329826ac353d715fa39f80cec144d6424558f9f70b98c920096e0f2c855d"
        "594885a00625880e9dfb734163cecef72cf030b8",
        "fc5873e50de8faf4c6b84ba707b0854e9db9ab2e9f7d707fbba338c6843a18fc6faceb"
        "af663d26296fb329b4d26f18494c79e09e779647f9bafa87489630d79f4301610c2300"
        "c19dbf3148b7cac8c4f4944102754f332e92b6f7c5e75bc6179eb877a078d471900902"
        "1744c14f13fd2a55a2b9c44d18000685a845a4f632c7c56a77306efa66a24d05d088dc"
        "d7c13fe24fc447275965db9e4d37fbc9304448cd")
};
const CAVSTestVector CBCMMTDecVectors256[] = {
    CAVSTestVector(
        0, "43e953b2aea08a3ad52d182f58c72b9c60fbe4a9ca46a3cb89e3863845e22c9e",
        "ddbbb0173f1e2deb2394a62aa2a0240e", "d51d19ded5ca4ae14b2b20b027ffb020",
        "07270d0e63aa36daed8c6ade13ac1af1"),
    CAVSTestVector(
        1, "addf88c1ab997eb58c0455288c3a4fa320ada8c18a69cc90aa99c73b174dfde6",
        "60cc50e0887532e0d4f3d2f20c3c5d58",
        "6cb4e2f4ddf79a8e08c96c7f4040e8a83266c07fc88dd0074ee25b00d445985a",
        "98a8a9d84356bf403a9ccc384a06fe043dfeecb89e59ce0cb8bd0a495ef76cf0"),
    CAVSTestVector(
        2, "54682728db5035eb04b79645c64a95606abb6ba392b6633d79173c027c5acf77",
        "2eb94297772851963dd39a1eb95d438f", "e4046d05385ab789c6a72866e08350f93f"
                                            "583e2a005ca0faecc32b5cfc323d461c76"
                                            "c107307654db5566a5bd693e227c",
        "0faa5d01b9afad3bb519575daaf4c60a5ed4ca2ba20c625bc4f08799addcf89d19796d"
        "1eff0bd790c622dc22c1094ec7"),
    CAVSTestVector(
        3, "7482c47004aef406115ca5fd499788d582efc0b29dc9e951b1f959406693a54f",
        "485ebf2215d20b816ea53944829717ce",
        "6c24f19b9c0b18d7126bf68090cb8ae72db3ca7eabb594f506aae7a2493e5326a5afae"
        "4ec4d109375b56e2b6ff4c9cf639e72c63dc8114c796df95b3c6b62021",
        "82fec664466d585023821c2e39a0c43345669a41244d05018a23d7159515f8ff4d88b0"
        "1cd0eb83070d0077e065d74d7373816b61505718f8d4f270286a59d45e"),
    CAVSTestVector(
        4, "3ae38d4ebf7e7f6dc0a1e31e5efa7ca123fdc321e533e79fedd5132c5999ef5b",
        "36d55dc9edf8669beecd9a2a029092b9",
        "d50ea48c8962962f7c3d301fa9f877245026c204a7771292cddca1e7ffebbef00e86d7"
        "2910b7d8a756dfb45c9f1040978bb748ca537edd90b670ecee375e15d98582b9f93b63"
        "55adc9f80f4fb2108fb9",
        "8d22db30c4253c3e3add9685c14d55b05f7cf7626c52cccfcbe9b99fd8913663b8b1f2"
        "2e277a4cc3d0e7e978a34782eb876867556ad4728486d5e890ea738243e3700a696d6e"
        "b58cd81c0e60eb121c50"),
    CAVSTestVector(
        5, "d30bfc0b2a19d5b8b6f8f46ab7f444ee136a7fa3fbdaf530cc3e8976339afcc4",
        "80be76a7f885d2c06b37d6a528fae0cd",
        "31e4677a17aed120bd3af69fbb0e4b645b9e8c104e280b799ddd49f1e241c3ccb7d40e"
        "1c6ff226bf04f8049c51a86e2981cf1331c824d7d451746ccf77fc22fd3717001ee519"
        "13d81f7a06fb0037f309957579f695670f2c4c7397d2d990374e",
        "0b6e2a8213169b3b78db6de324e286f0366044e035c6970afbf0a1a5c32a05b24ba706"
        "cd9c6609737651a81b2bcf4c681dc0861983a5aec76e6c8b244112d64d489e84328974"
        "737394b83a39459011727162652b7aa793bfb1b71488b7dec96b"),
    CAVSTestVector(
        6, "64a256a663527ebea71f8d770990b4cee4a2d3afbfd33fb12c7ac300ef59e49a",
        "18cce9147f295c5c00dbe0424089d3b4",
        "d99771963b7ae5202e382ff8c06e035367909cd24fe5ada7f3d39bfaeb5de98b04eaf4"
        "989648e00112f0d2aadb8c5f2157b64581450359965140c141e5fb631e43469d65d1b7"
        "370eb3b396399fec32cced294a5eee46d6547f7bbd49dee148b4bc31d6c493cfd28f39"
        "08e36cb698629d",
        "f7e0f79cfddd15ed3600ab2d29c56ba3c8e96d1a896aff6dec773e6ea4710a77f2f4ec"
        "646b76efda6428c175d007c84aa9f4b18c5e1bac5f27f7307b737655eee813f7e1f588"
        "0a37ac63ad1666e7883083b648454d45786f53ea3db1b5129291138abe40c79fcb7ab7"
        "c6f6b9ea133b5f"),
    CAVSTestVector(
        7, "31358e8af34d6ac31c958bbd5c8fb33c334714bffb41700d28b07f11cfe891e7",
        "144516246a752c329056d884daf3c89d",
        "b32e2b171b63827034ebb0d1909f7ef1d51c5f82c1bb9bc26bc4ac4dccdee8357dca61"
        "54c2510ae1c87b1b422b02b621bb06cac280023894fcff3406af08ee9be1dd72419bec"
        "cddff77c722d992cdcc87e9c7486f56ab406ea608d8c6aeb060c64cf2785ad1a159147"
        "567e39e303370da445247526d95942bf4d7e88057178b0",
        "cfc155a3967de347f58fa2e8bbeb4183d6d32f7427155e6ab39cddf2e627c572acae02"
        "f1f243f3b784e73e21e7e520eacd3befafbee814867334c6ee8c2f0ee7376d3c72728c"
        "de7813173dbdfe3357deac41d3ae2a04229c0262f2d109d01f5d03e7f848fb50c28849"
        "146c02a2f4ebf7d7ffe3c9d40e31970bf151873672ef2b"),
    CAVSTestVector(
        8, "5b4b69339891db4e3337c3486f439dfbd0fb2a782ca71ef0059819d51669d93c",
        "2b28a2d19ba9ecd149dae96622c21769",
        "ba21db8ec170fa4d73cfc381687f3fa188dd2d012bef48007f3dc88329e22ba32fe235"
        "a315be362546468b9db6af6705c6e5d4d36822f42883c08d4a994cc454a7db292c4ca1"
        "f4b62ebf8e479a5d545d6af9978d2cfee7bc80999192c2c8662ce9b4be11af40bd68f3"
        "e2d5685bb28c0f3dc08017c0aba8263e6fdc45ed7f9893bf14fd3a86c418a35c5667e6"
        "42d59985",
        "a0bb1d2fdeb7e6bf34c690fe7b72a5e9d65796aa57982fe340c286d6923dbddb426566"
        "ff58e9c0b3af52e4db446f6cc5daa5bfcf4e3c85db5a5638e670c370cce128db22c975"
        "42a64a63846f18a228d3462a11376dcb71f66ec52ebda474f7b6752915b0801797974b"
        "c51eb1218127fed60f1009430eb5089fb3ba5f28fad24c518ccddc2501393ceb6dffc4"
        "6a159421"),
    CAVSTestVector(
        9, "87725bd43a45608814180773f0e7ab95a3c859d83a2130e884190e44d14c6996",
        "e49651988ebbb72eb8bb80bb9abbca34",
        "5b97a9d423f4b97413f388d9a341e727bb339f8e18a3fac2f2fb85abdc8f135deb3005"
        "4a1afdc9b6ed7da16c55eba6b0d4d10c74e1d9a7cf8edfaeaa684ac0bd9f9d24ba6749"
        "55c79dc6be32aee1c260b558ff07e3a4d49d24162011ff254db8be078e8ad07e648e6b"
        "f5679376cb4321a5ef01afe6ad8816fcc7634669c8c4389295c9241e45fff39f3225f7"
        "745032daeebe99d4b19bcb215d1bfdb36eda2c24",
        "bfe5c6354b7a3ff3e192e05775b9b75807de12e38a626b8bf0e12d5fff78e4f1775aa7"
        "d792d885162e66d88930f9c3b2cdf8654f56972504803190386270f0aa43645db187af"
        "41fcea639b1f8026ccdd0c23e0de37094a8b941ecb7602998a4b2604e69fc04219585d"
        "854600e0ad6f99a53b2504043c08b1c3e214d17cde053cbdf91daa999ed5b47c37983b"
        "a3ee254bc5c793837daaa8c85cfc12f7f54f699f")
};

/**
 * Tests an implementation against NIST test vectors for AES-128 and AES-256,
 * both encrpyt and decrypt.
 */
void test_nist_vectors(crypto::AESBase *aes) {
    crypto::bytestring output(16);

    // Test AES-128
    aes->set_key(nist_aes128_key_block.cmem());
    // Encrypt
    aes->encrypt_block(nist_aes_pt_block.cptr(), output.ptr());
    EXPECT_EQ(nist_aes128_ct_block, output);
    // Decrypt
    aes->decrypt_block(nist_aes128_ct_block.cptr(), output.ptr());
    EXPECT_EQ(nist_aes_pt_block, output);

    // Test AES-256
    aes->set_key(nist_aes256_key_block.cmem());
    // Encrypt
    aes->encrypt_block(nist_aes_pt_block.cptr(), output.ptr());
    EXPECT_EQ(nist_aes256_ct_block, output);
    // Decrypt
    aes->decrypt_block(nist_aes256_ct_block.cptr(), output.ptr());
    EXPECT_EQ(nist_aes_pt_block, output);
}

/**
 * Tests an implementation against CBC test vectors for AES-128 and AES-256
 * provided by NIST.
 */
void test_cbc_vectors(crypto::AESBase *aes) {
    crypto::bytestring output(16);

    // FIXME: use C++11 magic to replace four blocks of code below
    // with one

    // Test AES-128
    for (size_t i = 0; i < sizeof(CBCMMTEncVectors128) / sizeof(CBCMMTEncVectors128[0]); i++) {
        const CAVSTestVector &vec = CBCMMTEncVectors128[i];
        aes->set_key(vec.key.cmem());
        aes->encrypt_cbc(vec.input, vec.iv, output);
        EXPECT_EQ(vec.output, output);
    }
    for (size_t i = 0; i < sizeof(CBCMMTDecVectors128) / sizeof(CBCMMTDecVectors128[0]); i++) {
        const CAVSTestVector &vec = CBCMMTDecVectors128[i];
        aes->set_key(vec.key.cmem());
        aes->decrypt_cbc(vec.input, vec.iv, output);
        EXPECT_EQ(vec.output, output);
    }

    // Test AES-256
    for (size_t i = 0; i < sizeof(CBCMMTEncVectors256) / sizeof(CBCMMTEncVectors256[0]); i++) {
        const CAVSTestVector &vec = CBCMMTEncVectors256[i];
        aes->set_key(vec.key.cmem());
        aes->encrypt_cbc(vec.input, vec.iv, output);
        EXPECT_EQ(vec.output, output);
    }
    for (size_t i = 0; i < sizeof(CBCMMTDecVectors256) / sizeof(CBCMMTDecVectors256[0]); i++) {
        const CAVSTestVector &vec = CBCMMTDecVectors256[i];
        aes->set_key(vec.key.cmem());
        aes->decrypt_cbc(vec.input, vec.iv, output);
        EXPECT_EQ(vec.output, output);
    }
}

TEST(ReferenceAES, NISTVectors) {
    crypto::ReferenceAES aes;
    test_nist_vectors(&aes);
}

TEST(ReferenceAES, CBCVectors) {
    crypto::ReferenceAES aes;
    test_cbc_vectors(&aes);
}

TEST(ReferenceAES, SelfCompat) {
    crypto::ReferenceAES aesA, aesB;
    crypto::test_randomized_compat(&aesA, &aesB, 10000);
}

TEST(IntelAES, NISTVectors) {
    crypto::IntelAES aes;
    test_nist_vectors(&aes);
}

TEST(IntelAES, CBCVectors) {
    crypto::IntelAES aes;
    test_cbc_vectors(&aes);
}

TEST(IntelAES, SelfCompat) {
    crypto::IntelAES aesA, aesB;
    crypto::test_randomized_compat(&aesA, &aesB, 10000);
}

TEST(IntelAES, ReferenceCompat) {
    crypto::ReferenceAES aesA;
    crypto::IntelAES aesB;
    crypto::test_randomized_compat(&aesA, &aesB, 10000);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
