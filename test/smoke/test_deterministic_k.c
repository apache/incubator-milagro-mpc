#include "amcl/mpc.h"
#include "amcl/ecp_SECP256K1.h"

int test_external(char *sk_hex, char *message, char *expected_k_hex)
{
    int sk_len = strlen(sk_hex) / 2;
    char sk[sk_len];
    octet SK = {0, sk_len, sk};
    OCT_fromHex(&SK, sk_hex);

    int message_len = strlen(message);
    char m[message_len];
    octet M = {0, message_len, m};
    OCT_jstring(&M, message);

    int expected_k_len = strlen(expected_k_hex) / 2;
    char k[expected_k_len];
    octet K = {0, expected_k_len, k};

    MPC_DETERMINISTIC_K_RFC_6979(&SK, &M, &K);

    char expected_k[expected_k_len];
    octet EXPECTED_K = {0, expected_k_len, expected_k};
    OCT_fromHex(&EXPECTED_K, expected_k_hex);

    int result = OCT_comp(&K, &EXPECTED_K);

    if (result != 1) {
        printf("K EXPECT: ");
        OCT_output(&EXPECTED_K);
        printf("K ACTUAL: ");
        OCT_output(&K);
    }

    return result;
}

void MPC_DETERMINISTIC_K_RFC_6979_INTERNAL(octet *SK, octet *M, octet *K, int sha, BIG_256_56 q);

int test_internal(int sha, char * q_hex, char *sk_hex, char *message, char *expected_k_hex)
{
    int sk_len = strlen(sk_hex) / 2;
    char sk[sk_len];
    octet SK = {0, sk_len, sk};
    OCT_fromHex(&SK, sk_hex);

    int message_len = strlen(message);
    char m[message_len];
    octet M = {0, message_len, m};
    OCT_jstring(&M, message);

    int expected_k_len = strlen(expected_k_hex) / 2;
    char k[expected_k_len];
    octet K = {0, expected_k_len, k};

    int q_len = strlen(q_hex) / 2;
    char q[q_len];
    octet Q = {0, q_len, q};
    OCT_fromHex(&Q, q_hex);
    BIG_256_56 curve_order;
    BIG_256_56_fromBytesLen(curve_order, Q.val, Q.len);

    MPC_DETERMINISTIC_K_RFC_6979_INTERNAL(&SK, &M, &K, sha, curve_order);

    char expected_k[expected_k_len];
    octet EXPECTED_K = {0, expected_k_len, expected_k};
    OCT_fromHex(&EXPECTED_K, expected_k_hex);

    int result = OCT_comp(&K, &EXPECTED_K);

    if (result != 1) {
        printf("K EXPECT: ");
        OCT_output(&EXPECTED_K);
        printf("K ACTUAL: ");
        OCT_output(&K);
    }

    return result;
}

int main(int argc, char **argv)
{
    int result = 1;

    // Test vectors generated by Majid for SECP256K1
    result &= test_external("84c52bf5943968f431fddcc7433c231d8805a455ab4ec1d755d6691666ed4b52", "sample", "1a021d3a3d8a6488ceaa4c809d21d465f43e2eda5461684a3f888b078cfa47c2");
    result &= test_external("6825cdf8993a2bd3a0be436b3d98c34ffcb98244175cdecc9acd6637b70810d4", "sample", "36ec880a6fa5ad89c1e0099c620cf1ab371462fa718a8289196b0e8ae119ce3f");
    result &= test_external("efda9dcf5bb0134b66dfa50b668b55368d9ed5498d453848cee22a92d6bae955", "sample", "24ea4f587594206a7aa152cfa42dc8ee1844c0a2db6ad74414370a940cda4963");
    result &= test_external("0e222845fa78fa1daf4733667e2672f8b421f37236bdc4ebd95a0585e2c837c2", "sample", "fe69a7abea737c954029355c2ae5b8297f3ae19a2e8e4451f26eb4e38ec1293b");
    result &= test_external("be0c9a90c055f7c26f2c2fe5e2fb9d42af785c8a4f26a4920a70767691729015", "sample", "ab53b4ab434b6b68157a7d88576efe874d2ccd2a74c2320bdc5eab2332bb5672");
    result &= test_external("b439da94cb6f898d039d4ebce21b3d01fe91ab9a9b7a1d0c882e242093239f42", "sample", "fe0fa7753f5b8c40cf61a7d875b942b5e93d4fd83885605a9896c618858b0c06");
    result &= test_external("7b3574d5ebffff043a1c11450b8420a1f51c008a1eb8a6f56ef11a3e7534b382", "sample", "4faf38702c23fb4e82a72a6ac61e5b19e7edee50452b7a4c58447e7339d5ffb2");
    result &= test_external("3864ad4d895644b67d22a37b0548ec86597574e2d8297a3fb63c37da97352ef0", "sample", "d39ac4b96896b8726a0ef3c127b7be473d13bcab6a8949cba57cbb7f6a335a73");
    result &= test_external("e20e05784878c10ca34cf3220a2f9b6f1ded6351f9af528ecef13906a081d7ec", "sample", "5bb68b74241c1a596f2b4da2f3c1d4e5bf780ce5213c357f4884af7ce6657b25");
    result &= test_external("fcb9e85ece3623e3118ce5e375f1397961d71c379b558e0c84e221e2f9f00f3b", "sample", "01bd52122355a4ae25a8c1f2298bfe2153d5d26651809f34f38f358f65f83cc8");
    result &= test_external("d71a42fe334c5fc02cced84e57576914e5ab39dc35569dfa3b218136ff0a3564", "sample", "4b2460919b9eb45367a538be93a42c0984749ffd7d36dcede277b0f347059a73");
    result &= test_external("6c761db9347aa7b546742a59a5ebbfdb3d5760a2a6ad8f0c1cfdff99981573be", "sample", "afd7b6edb8d926acfd52ac295528e0bd55e8aed380202602d8349b93f1bd7a63");
    result &= test_external("26a86113f9e09f0b192e7ba622cf8394ebf256f69794753feb35d3cc95bd5173", "sample", "1078dcd3fe245a5aa8d842692fc61e8bb098bcbb25a19c48ef9534e541341255");
    result &= test_external("904c413df7fc1e9ac54ac8cc31c41a5059c75786d28a7823cde350120f6308fb", "sample", "b98516e8c510373087070edede187feaee957412c407b651ddb0d03776769df8");
    result &= test_external("affe928309c3836b915a88a750e541a998a4e10f6d59ac0e1039cd764418bbb1", "sample", "504c16f5dcd3f139e32334e3f3605b05f9345e80257e613a8bae5d36fedebccc");
    result &= test_external("916082c5c28b6fd775e149ee69f4547baa133dc6c8ed7f842f4c86ba6965c487", "sample", "ff8fedad4bff05066a8155e52259442e2b7824b03dd62c11e8428379292331af");
    result &= test_external("6fae7b675c364852cb7c02c453aa21f27b1f84dd4306d38c72e8ec3153d89e1c", "sample", "abd14c89dc8c0c1ad6a2124516320466680289225c01896347d41624301cdb8e");
    result &= test_external("0c6f2419521fb9fc5807dae83ee7a3e593ac802f80810dbcda1b1861d93690fe", "sample", "e51c76357cb1f873444d462856086101a5b8393e52260431abd82df973371681");
    result &= test_external("4425681133d172e14e0cdeb4d18ef45af8786d92e2867d03f6423a12a454b3d4", "sample", "edd2ff4711730ad2c4290b7e4436111d12d8df0e47e611ebde4d8706834bc6e4");
    result &= test_external("48c8b17748e81166676ae8aa05a1557628920c026cf4ceda9966d37bf293e203", "sample", "932aa8a1da812da70a8f01c1d3603c22401316de51334c6c327422e118ac77c3");
    result &= test_external("191ec6e1230a573c03e4847331d37b66eaad005477a19336b0131e448a48a7a3", "sample", "f5e44956267685a684da5e47de1d8e399b2792bbc8fcb2143540e1901ad2d105");
    result &= test_external("3733ba2481fca2bbaf9140018be00da9f36dade5130dfda46d6d6886f8660b24", "sample", "941d1efab5cddba1505355f59fe96203291a9b26381d9c4bd93b57857cf1eb17");
    result &= test_external("e35ef3df99974f30f253bb6b054ba1eed2c3a4b14a69b464b371507e0042d05e", "sample", "8f05069b425cfabc73503d729f5d00df735ee5f8bd535f35f5cf8c69a099640f");
    result &= test_external("318bc95ca8a8198a9cc09b881027e34f0286c2a01c76a5bfbbb65b22866d639f", "sample", "f9fedcf7f9e8f1ac890a904ce6e546467e4519d716715f585779e650eda74012");
    result &= test_external("b19a976f52f0a8a771329c237f5e60ff2de0fb0a4fc6e2d0272c6944f0dc1ddb", "sample", "3bcf4492802e069c7b24d82024e816ff43f4d5caa9614a1010ec981fcd24863c");
    result &= test_external("58e173197f448a7e3dbb3448548c30158384aa075fbaf354419fe85c22410aeb", "sample", "3b4970a76281c6c118ad3ec10c74d994eee01bd9b618a51c58575a28800b66fc");
    result &= test_external("f042f5e8726e444d594e977e72af5fbf3162a85e55257a513195ca03249f2566", "sample", "80d3224ebd57af5b145fbd78c9c29e81bf9db7952539db4ece0107f4ad568042");
    result &= test_external("ee386d1bbd1ed4bdbe09eb1ff6836224e0ac2494ddc225474f4dd50f4076f386", "sample", "ad9fab4f03c6a050251df157c169c447ac465a1dfdc0cbe5da60a12b2b95ca10");
    result &= test_external("fd440937c0586b83edf26c0323d6e4e205444da2803ca8ffdbda3f250c8a2c69", "sample", "4e00d3db511eb51fe4937d601afb82e6272806a4ad655189d19feaaf5b81efd7");
    result &= test_external("75671cd62c1d700f461dca09e67b842a540083832e1c712d45e07e02ffa4839f", "sample", "e5933adc2394ccadbdfee0db281c9cb6b3f1891f38adfae1f4aa8611c4174776");
    result &= test_external("12abbd7658900029f094cbaac07647e52fb3b991ca69b5fea873be2136459a96", "sample", "aed095eb1f71cd5ac76a8030ae77f8287d4e205866e80ab2d0de0887beed5f52");
    result &= test_external("636ffe388c90f2b214121e380bb858cc88e4f37beb9a8bf2554dd848643e7d73", "sample", "90afbfa612b507cf1f3a366b09798d1adb3cbc9bbb7aef680767d47e6b871c5c");
    result &= test_external("9bd61ba64613ccab34b8a106a08e607b3d2134f4f20926d4bf3e6ded44baa93b", "sample", "fce287fda2d24043b0f109c5af18b12311790374a286c770647fe06681abd633");
    result &= test_external("59cf58543d797f7550e9a2f6d24f2e121cefa111a90e105f720928ad93907738", "sample", "158acd43f8be7c97f460b494c6a5a4f7c2ff9bb5fb60af01f002127723af9c2e");
    result &= test_external("e021e3c08ef9e60fae80ca8f3e58f29767fe6813a1cc6fbc7b9b6db4c181b9c4", "sample", "b649307caa04b78dd5741013f4bf436001c57d0cd02f554eccc05d9af50c5dfc");
    result &= test_external("ec1ac845712fc735a3b1badd0cbc13b662dbf8d130966681aa8f9b7840911237", "sample", "6b23f49b73d5cbb26ad31dd78f7d830ee1b0489b904b97569219d19c49232ff5");
    result &= test_external("cf8f3d58e9ca99b981ca7fa447693726514d23b32662f8cb028fb1e97d14a9d8", "sample", "ebcd38681f54936878e2dce7c14a26cff4e79ee4ba5f5d84e7230a7f0b0c8abc");
    result &= test_external("4ad81b37c8af9e0f9689cf6fb50b1cc67d396b8c70e194611aadd551b47691d5", "sample", "a179fd971c89c3011a3d6357aa23a65ce8e811fa2e8790e6e7d0925713277b46");
    result &= test_external("7d83b63979e36af94b79074747df2dc68fba0abc505328476c55c0010bd0a6aa", "sample", "e5c6b71c288159b4516214608de7e29f4aec1233df05e91cfefee088cbde3e48");
    result &= test_external("45528f0322c563467f141d8bb768dbf0468591f6a86819825d6402a9f54c4044", "sample", "60aa46c10b080b66913d9b064dc81f479cfcab01ba161df9c5c300af5d87770c");
    result &= test_external("40abeab6336629a86b138f19c18ee3e8c0d5997dbbb3df179d0d261bbfb37048", "sample", "b568666d98a393a8b68731cdb49287e057f9d0f680b269cf5ab403520015b1fd");
    result &= test_external("ee4de99cef3187918ddecea51219e0c562f4b83440438ae33a35f94f62015c48", "sample", "67cc936c4fbef211d0b4575958667af165b3b2214877fc5a6bbc4f06e9057bb6");
    result &= test_external("de5289232c5eb083026be2927a5b3be3b2a72525851da8001ef5c2bd8ff1c729", "sample", "55626b9d4dc606cdcd908df0ce5c91abac40df045a4c8229bcd96a703f94bb64");
    result &= test_external("4b47e408285b888c7720cabc910bfa7bbc58b5ee02e2e1b9151340b5c7bc6b39", "sample", "92a5ceca6b2d6f3459e2c3f942bdbfd5143c9c3466b3598b598147cbdc8d8c04");
    result &= test_external("b4b2a88351823e0d0340d024723d367c891d4a59713b1123e61a5f8d2e20ba01", "sample", "906a49c7fc59296d2ae12fdd3b33e1c9d14a0d517722cf10b64365d0201a0dd2");
    result &= test_external("add261a7f4f861fd5a4d0f85ad7f21a6daee67830f2a0b755c9e31b7c56012bd", "sample", "5e60ea6c6a9626ff659458f2098519e4184f11f321a23696303d451a81d6acbe");
    result &= test_external("cf06a0f35383b2ab5e8a935ce91ac97d9f90588592c8cbdee077d8347da1b6be", "sample", "2b0f6283fe815728085679ba2ae94a740e6f5e3cfee2ea5f7ad7e5a686a650b4");
    result &= test_external("c7b3073ee126e1b5d547c532d569327c9fc5e66f3c6cecf79a05645eb8109a5c", "sample", "9c784de007320a39029d514211cd35280eb59ca565006abedfd368c15e93c4be");
    result &= test_external("eebf3f7fe5549e0dfca9cf0c1bae5a94270be9bb406b212e7eff598b42240511", "sample", "c3a5fbaca9c4ca7668e29e7e04c622911c9dc6aa4a35f05b8570cd21e3330879");
    result &= test_external("b5ece63af6922e892ccf3f08d75f8b85143801fbd0ba6d21dc7d8bf58927963a", "sample", "d1e248fbcff2372abcb2592bcfa6248111a0d78cbe0ba3fdfcca0e9721b886da");
    result &= test_external("7c5868d5bf619b69ba5b59196432c415fabff6436d31a2fdcae0c5664db3d9e8", "sample", "6a2a9dfaf7b164649c1aa672ca05ca617c9d69fd52196688724ab2d0afc0b7ca");
    result &= test_external("5fbe11360091a4450f59418cb97ba77a59123ff0177fd77cbb397a361446f803", "sample", "0771f1f44ced16db6d3ff27340b669d0bc8c8cbd26e2f6da77ebabcfa7e69fdb");
    result &= test_external("1c1b9de8705f5427961ad4332e8ba5f172356b314a3fa9e242e4caf1c49d13ef", "sample", "b0d3d204b6cbaecbd5a0525e54a6d740007f7dc40ed3a5d461081df43ab2e6da");
    result &= test_external("a9ea1e214964c64d72cdad63b4c27a877c6a1b06b916cbb3ed303c07d7c0f2fb", "sample", "ee19fad93f877592a31004e1f6e877206b475ece9a642391119aeedbdc21cad6");
    result &= test_external("4b9af2e5bd55027f0b59377c15ed9f3df5a2ff098a265c9794638fb8b352b424", "sample", "b3e69a5c7132f121d8c8a99f4960378db5c143c12409092d4b4ecced6ef11582");
    result &= test_external("88ba07eb3be3ebcad8b0cfe606683a90be4168a8daf60294048e7a1f4780e830", "sample", "09490056c35ef81a8a7a1edcd0380461309a96585d1093ce294c55f99d6b961b");
    result &= test_external("eaf5ba00bcd1e3662ff2a3b61347c46e4be071650673493120b34b11bd813f73", "sample", "60b5c4fbc7766400d20b6d3792b3ae0eeae508ba0399aee35b2fdd0671f6fea2");
    result &= test_external("47413beec84d3484ef1feb4cb1c7ad362a23b2216dbeef6c234fb8843b3136d2", "sample", "a86960943679c11279c30cd16fc227750214638783456b3a7f99344bca53dbc8");
    result &= test_external("00610d73fe2bd4fe46d842fef66356337656accc360c88ca925955e98cade18e", "sample", "2a3074a3ddeb40849f0ef309018cf485c4a7c84bbe276106d142907331fce5e5");
    result &= test_external("4b8ab54e48704527e0655140c9737c543124d710c78c06656a0e00ed0e393a96", "sample", "4dabab7cb7454389c3b7bec0d42c519e06a590c48a159a2519f509b63933abc7");
    result &= test_external("9983cc04810c9cd23eb4aaef193564ba9ce2f5db534c87aaa21e2e4a5ff8bcd4", "sample", "81e7667fc8423e3764029a30c4d0c62481ccd65ea429998cd9c6e0c8f8548b5f");
    result &= test_external("81e540fd8b84dd4b15b1bcb3354b23ee0460485fc5c13f20223896b3cb247a1b", "sample", "e977b54e5971cc6b5b7f566c5e15ff7471071a965bb00fb1fbea0f5d1e929dcf");
    result &= test_external("b029499c313b592a75802e87f0a194993aeb756de5a67057b7318e567b7ac7c2", "sample", "da550c80d2d3cf5358eb7bb3e69c6345b1cd8c269b63776e0de1c95f46434902");
    result &= test_external("e74b536525d2bfc977da8820af85c39e8063509ecbdd0f21dc07784fb93b531c", "sample", "5bc61c83980b8da1c2427d5612d5382fd269e0a4409c50e7216879da9461d8e1");
    result &= test_external("f5bf90c6449f766b01c196600be1c8704395dd3847369adbbcdc2cbf6cc8d601", "sample", "1c3faceddcd0ba910bf38850134e72ab145881a22eba3638a163d4c5a3956964");
    result &= test_external("f1f3851284df9f2d47ad0e3d6281ef8cd004f778cafbe44635f974f725344fc3", "sample", "878eb240c55c4c08d741b7e3a928841adab6fe9a5e58979f88dcbfc475acff02");
    result &= test_external("983ef754f120e5afde8a01349615579f8111f16ad33e7edc1828e4a1318f0f17", "sample", "1c6c0683785d448e05cde65424b7aa21290225d5fabda6d728885fe4666160d4");
    result &= test_external("3823de15e5e2e8bcf6d2e628603ff75c0647590427e2f7d9f67dd67b1c987e74", "sample", "0d8b9c9602bbc5e3882800e33a92087f40214a53746a9e6c6ca4bc2c08370ac7");
    result &= test_external("a393ccd79ca4835411bfb3444e7d31d02b2067fe68b999dcdea3666d064945c4", "sample", "c7021930aafd2cc9553d4ea7532ee8636c8ee0c97456395b649c086a3c16ba46");
    result &= test_external("edac4b0c2b05beadd91f75f0c3baf5f1b88a1d047e76317def2c3d9146033192", "sample", "9ae5ad6397fb93e441531cff9ae3f32be5a5e8a233e98efcd14969888c4c2a09");
    result &= test_external("bc00235f9a33da966d7cde8dd443402c5854d0e9048a7ab1b60cfe2096107f75", "sample", "c1c606271076e7ccf15bb8389f3dad4022f87efe674449d1a8f359f3b23869f1");
    result &= test_external("914042ce661ea3fb78097ec71a247801dff1fbdebed7759705b812617f6eab86", "sample", "57c1ef22145c104c7785b22eace65e8bca714a94962d3488e14e0be47cb3bd7f");
    result &= test_external("fde33b2d08a9b09ceb1a9dbdbd1f6cedfec3ec8d0dde1de81fb19475d6a844ce", "sample", "f4c9557d8f7fa1b982a24d5a50b0e7f0be43ec297f7f15811fc69e3c5a4b63cd");
    result &= test_external("4cc00e2b948c9f02239007eb0274483fd0d20cbfe74a4d171979215f459fd6a4", "sample", "16da60fee83fbd3cc0806f9a7487c135efff07f14937076f6601ff0cdcba2227");
    result &= test_external("e0e5165dc356e1a750ee736aa027586530ba0def8a9eafdaef3a4e599a41b708", "sample", "866c4fa0c7725d4c713bca59b6d4f2dcb55218c3a6dfb595f68ef1ac30751496");
    result &= test_external("df346a58a975bf4f17e0f6508e0e764b29c13d4d24c10ebb12ba1fa6ed24bce4", "sample", "2e86d8d45848f74e8fc741203cb8101d07630c980a25cdbf3ed417001b1b602f");
    result &= test_external("4eba97f6784356e27930ffc691913ce736114b82fe602ae3f500283732ff4644", "sample", "012dd435d7e0c5747f6477ec4353ed42efcb70384f2cef0899fbfcaea1866655");
    result &= test_external("2e50b098ea5a008553638f265d76300d45ecdc49d191b6b2ee4b4afa1f9c7fa8", "sample", "16f50902674a2ac8ca2d1028a06fc4e4659c8b64729a8f853881eff9849109a7");
    result &= test_external("f1e4e25b56b4603cc3fd7f94264125c215bbdb3001b3958896d22c832b3aeb5b", "sample", "6aa06a9bf0eac0ca23de3a25795d6201f54fb28a4f1142502579e0c9ddc30ab0");
    result &= test_external("8ba91897612fbdf7a9e95e1826ebc1781c6f951ea8ab0f40a1415d24b161a596", "sample", "f8fa5f9fd6a824e1631be024d0647f161323a575943c6dd4fe962e85646f3fec");
    result &= test_external("b60d4c417d4e8e9bac425027f9f5c11365685ff4a2873e7f59ae0080d6f80806", "sample", "dad1c804d886df68327467c88b10a8f7830fbdf7be8da8ed14c784a0d43fb481");
    result &= test_external("5ed6859e963ad199701cae0a2097058eb24f5382ce66414a840a595f8b976a34", "sample", "47f4ffc9d1b11cef303b8d2af33bcd9a609732e47eea582ad6572e30fe969e0a");
    result &= test_external("4f423ea3758925269d6cbd4e5cebee2b39bb32c2c73c673c92b21e2da5ab275b", "sample", "3bbb95f52c1df36a97ba178659afc3f87ba2c442f5d5cd74913ea656dee95d02");
    result &= test_external("16a8d63a2c5152856ed6eb2f060568c1afc0306ef9192dcc2770df6bcb17b99a", "sample", "5f6173d54996e220c851e956cfe84b49aab2332085f7258e746390e6fd675c01");
    result &= test_external("3b3ba2bf188297083674cdb36f3ef6b22eec8744e7e33f5ab331af481b161c58", "sample", "772e38da47cb49c1b314f1be6d47e237f694f6fc26b8088a4b60b33f711c7543");
    result &= test_external("e20a75e83ab22b201eef10958ca775149eb101e53b82bd229bb2f070418e573c", "sample", "18c6ceebe51fb75db8262b738d96d7bfea24dd8950f9f37d4fa85e3013df8d6b");
    result &= test_external("db4286b91ac0532a722eb557bb956f6cfcd3251e5a7685ca47fc3688878e9573", "sample", "d624da04e0320477c718fe7fd81d899e469a6cab60f300ac21d80c141a0e09e5");
    result &= test_external("efd91c474b054a8bd3a774bd3807b4e78a702e0fce46311a4a5486a812d31b47", "sample", "dea324ea928af22da9d3a9374125012362575e3703554f938881449d8d0f29d0");
    result &= test_external("794212f6c5a19ffa3b99603c76a04fc636fcebb171018110ef2b7ebb7b8f523a", "sample", "d721a3180679e25a80fb52d4ba58517963462ed322e534872f9ed2851f60bf69");
    result &= test_external("dc1c842a84882a59efaacf2543a23c586864127ccea4ee94fa4369062bb50f36", "sample", "f3cbe7c2a66229a0960d8ca1f8e11c0bcdaaa7766a399afdccda872765665e55");
    result &= test_external("ff2f4fe7d3e39f0a7e83b0f5e92a2c55f5f3ab58d6fcca7cf84eb001728722d4", "sample", "dcea339057707f324a9f0b138695d4b85d4dcdfebbab39cc9a418349b3841451");
    result &= test_external("c9a799e0df28c8f9060e68c3f6533e443a911479d4c52456ec8c5dc5d1c50c18", "sample", "ce7faed1b6f0cb2bebe17d959848e0b957ae182e6002bb5d72954e080cecb896");
    result &= test_external("63a6e439c87d3b984b94aa2444a7b30606f288f2954effc7bde225c84a4ea014", "sample", "2fdcfc6a1c59244128b142d8293ab6433c941dfd85ab8a603a6b7de9f01a6634");
    result &= test_external("1389f561bf16191afb8e285c4365a16c20cb12fa8e311af51f31cdf0e4a6c82b", "sample", "44f8f992ad7c2985125925e3a92f652748cc826d42281f255a4567e44fbb3a47");
    result &= test_external("c8616c0168041da9abfb42c2ab1b976828cce4ea5f42cbcbe2d6a20e12643a27", "sample", "70194c9a9170d458a8a7a0909060d3f9ccc24b095fd13859b98d7401a95244fb");
    result &= test_external("b2f9f149b3a5c549a5dbb0e53ad9b214a053c24dcc4bd579ad609e35c79cc305", "sample", "fdda45a594d389454199b67f9988c124b4368d7f85137629943d98e7910f2b7f");
    result &= test_external("7461d1f8309dff3f1f7dfbdfa22698d15837deac5d6df93609f012b25623808b", "sample", "94c7e45ca301f90931d6aae9503ea7f684a1ecf10ca6fc9609fc5ef7020f1616");
    result &= test_external("ba6e33383120b1d00cfb38d81bb136b210295ce7a9725ca12154c91cf1fd0fd5", "sample", "3f3010733ae4e7b803aaa795621d4df31a3b9bb8cd3e61bc65447832c0d0843b");
    result &= test_external("11c29cb7a87e0271eee38c4a1d9199f35d4003f0249cd40f7f969e1c55a4740d", "sample", "e8410b8a454213c94d214550515d094375a28c8feeb6d0a5ef99f405ab1db3ae");
    result &= test_external("4261138662f0ea5994b8440cb5dc6286a9d20c80dee4ff7bf2b68792630db3ce", "sample", "02b463032ea7d1b1876e96b7923084904132c22c878564cdc70bd4f392cba329");

    // A.2.1
    char *DSA_1024 = "996F967F6C8E388D9E28D01E205FBA957A5698B1";
    char *a_2_1_sk = "411602CB19A6CCC34494D79D98EF1E7ED5AF25F7";
    result &= test_internal(SHA256, DSA_1024, a_2_1_sk, "sample", "519BA0546D0C39202A7D34D7DFA5E760B318BCFB");
    result &= test_internal(SHA384, DSA_1024, a_2_1_sk, "sample", "95897CD7BBB944AA932DBC579C1C09EB6FCFC595");
    result &= test_internal(SHA512, DSA_1024, a_2_1_sk, "sample", "09ECE7CA27D0F5A4DD4E556C9DF1D21D28104F8B");
    result &= test_internal(SHA256, DSA_1024, a_2_1_sk, "test", "5A67592E8128E03A417B0484410FB72C0B630E1A");
    result &= test_internal(SHA384, DSA_1024, a_2_1_sk, "test", "220156B761F6CA5E6C9F1B9CF9C24BE25F98CD89");
    result &= test_internal(SHA512, DSA_1024, a_2_1_sk, "test", "65D2C2EEB175E370F28C75BFCDC028D22C7DBE9C");

    // A.2.2
    char *DSA_2048 = "F2C3119374CE76C9356990B465374A17F23F9ED35089BD969F61C6DDE9998C1F";
    char *a_2_2_sk = "69C7548C21D0DFEA6B9A51C9EAD4E27C33D3B3F180316E5BCAB92C933F0E4DBC";
    result &= test_internal(SHA256, DSA_2048, a_2_2_sk, "sample", "8926A27C40484216F052F4427CFD5647338B7B3939BC6573AF4333569D597C52");
    result &= test_internal(SHA384, DSA_2048, a_2_2_sk, "sample", "C345D5AB3DA0A5BCB7EC8F8FB7A7E96069E03B206371EF7D83E39068EC564920");
    result &= test_internal(SHA512, DSA_2048, a_2_2_sk, "sample", "5A12994431785485B3F5F067221517791B85A597B7A9436995C89ED0374668FC");
    result &= test_internal(SHA256, DSA_2048, a_2_2_sk, "test", "1D6CE6DDA1C5D37307839CD03AB0A5CBB18E60D800937D67DFB4479AAC8DEAD7");
    result &= test_internal(SHA384, DSA_2048, a_2_2_sk, "test", "206E61F73DBE1B2DC8BE736B22B079E9DACD974DB00EEBBC5B64CAD39CF9F91C");
    result &= test_internal(SHA512, DSA_2048, a_2_2_sk, "test", "AFF1651E4CD6036D57AA8B2A05CCF1A9D5A40166340ECBBDC55BE10B568AA0AA");

    // A.2.3
    char *NIST_P_192 = "FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831";
    char *a_2_3_sk = "6FAB034934E4C0FC9AE67F5B5659A9D7D1FEFD187EE09FD4";
    result &= test_internal(SHA256, NIST_P_192, a_2_3_sk, "sample", "32B1B6D7D42A05CB449065727A84804FB1A3E34D8F261496");
    result &= test_internal(SHA384, NIST_P_192, a_2_3_sk, "sample", "4730005C4FCB01834C063A7B6760096DBE284B8252EF4311");
    result &= test_internal(SHA512, NIST_P_192, a_2_3_sk, "sample", "A2AC7AB055E4F20692D49209544C203A7D1F2C0BFBC75DB1");
    result &= test_internal(SHA256, NIST_P_192, a_2_3_sk, "test", "5C4CE89CF56D9E7C77C8585339B006B97B5F0680B4306C6C");
    result &= test_internal(SHA384, NIST_P_192, a_2_3_sk, "test", "5AFEFB5D3393261B828DB6C91FBC68C230727B030C975693");
    result &= test_internal(SHA512, NIST_P_192, a_2_3_sk, "test", "0758753A5254759C7CFBAD2E2D9B0792EEE44136C9480527");

    // A.2.4
    char *NIST_P_224 = "FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D";
    char *a_2_4_sk = "F220266E1105BFE3083E03EC7A3A654651F45E37167E88600BF257C1";
    result &= test_internal(SHA256, NIST_P_224, a_2_4_sk, "sample", "AD3029E0278F80643DE33917CE6908C70A8FF50A411F06E41DEDFCDC");
    result &= test_internal(SHA384, NIST_P_224, a_2_4_sk, "sample", "52B40F5A9D3D13040F494E83D3906C6079F29981035C7BD51E5CAC40");
    result &= test_internal(SHA512, NIST_P_224, a_2_4_sk, "sample", "9DB103FFEDEDF9CFDBA05184F925400C1653B8501BAB89CEA0FBEC14");
    result &= test_internal(SHA256, NIST_P_224, a_2_4_sk, "test", "FF86F57924DA248D6E44E8154EB69F0AE2AEBAEE9931D0B5A969F904");
    result &= test_internal(SHA384, NIST_P_224, a_2_4_sk, "test", "7046742B839478C1B5BD31DB2E862AD868E1A45C863585B5F22BDC2D");
    result &= test_internal(SHA512, NIST_P_224, a_2_4_sk, "test", "E39C2AA4EA6BE2306C72126D40ED77BF9739BB4D6EF2BBB1DCB6169D");

    // A.2.5
    char *NIST_P_256 = "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551";
    char *a_2_5_sk = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";
    result &= test_internal(SHA256, NIST_P_256, a_2_5_sk, "sample", "A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60");
    result &= test_internal(SHA384, NIST_P_256, a_2_5_sk, "sample", "09F634B188CEFD98E7EC88B1AA9852D734D0BC272F7D2A47DECC6EBEB375AAD4");
    result &= test_internal(SHA512, NIST_P_256, a_2_5_sk, "sample", "5FA81C63109BADB88C1F367B47DA606DA28CAD69AA22C4FE6AD7DF73A7173AA5");
    result &= test_internal(SHA256, NIST_P_256, a_2_5_sk, "test", "D16B6AE827F17175E040871A1C7EC3500192C4C92677336EC2537ACAEE0008E0");
    result &= test_internal(SHA384, NIST_P_256, a_2_5_sk, "test", "16AEFFA357260B04B1DD199693960740066C1A8F3E8EDD79070AA914D361B3B8");
    result &= test_internal(SHA512, NIST_P_256, a_2_5_sk, "test", "6915D11632ACA3C40D5D51C08DAF9C555933819548784480E93499000D9F0B7F");

    // A.2.6 - not tested because we are only supporting curve orders of 256 bits or less
    // A.2.7 - not tested because we are only supporting curve orders of 256 bits or less

    // A.2.8
    char *NIST_K_163 = "04000000000000000000020108A2E0CC0D99F8A5EF";
    char *a_2_8_sk = "009A4D6792295A7F730FC3F2B49CBC0F62E862272F";
    result &= test_internal(SHA256, NIST_K_163, a_2_8_sk, "sample", "023AF4074C90A02B3FE61D286D5C87F425E6BDD81B");
    result &= test_internal(SHA384, NIST_K_163, a_2_8_sk, "sample", "02132ABE0ED518487D3E4FA7FD24F8BED1F29CCFCE");
    result &= test_internal(SHA512, NIST_K_163, a_2_8_sk, "sample", "000BBCC2F39939388FDFE841892537EC7B1FF33AA3");
    result &= test_internal(SHA256, NIST_K_163, a_2_8_sk, "test", "0193649CE51F0CFF0784CFC47628F4FA854A93F7A2");
    result &= test_internal(SHA384, NIST_K_163, a_2_8_sk, "test", "037C73C6F8B404EC83DA17A6EBCA724B3FF1F7EEBA");
    result &= test_internal(SHA512, NIST_K_163, a_2_8_sk, "test", "0331AD98D3186F73967B1E0B120C80B1E22EFC2988");

    // A.2.9
    char *NIST_K_233 = "8000000000000000000000000000069D5BB915BCD46EFB1AD5F173ABDF";
    char *a_2_9_sk = "103B2142BDC2A3C3B55080D09DF1808F79336DA2399F5CA7171D1BE9B0";
    result &= test_internal(SHA256, NIST_K_233, a_2_9_sk, "sample", "73552F9CAC5774F74F485FA253871F2109A0C86040552EAA67DBA92DC9");
    result &= test_internal(SHA384, NIST_K_233, a_2_9_sk, "sample", "17D726A67539C609BD99E29AA3737EF247724B71455C3B6310034038C8");
    result &= test_internal(SHA512, NIST_K_233, a_2_9_sk, "sample", "0E535C328774CDE546BE3AF5D7FCD263872F107E807435105BA2FDC166");
    result &= test_internal(SHA256, NIST_K_233, a_2_9_sk, "test", "2CE5AEDC155ACC0DDC5E679EBACFD21308362E5EFC05C5E99B2557A8D7");
    result &= test_internal(SHA384, NIST_K_233, a_2_9_sk, "test", "1B4BD3903E74FD0B31E23F956C70062014DFEFEE21832032EA5352A055");
    result &= test_internal(SHA512, NIST_K_233, a_2_9_sk, "test", "1775ED919CA491B5B014C5D5E86AF53578B5A7976378F192AF665CB705");

    // A.2.10 - not tested because we are only supporting curve orders of 256 bits or less
    // A.2.11 - not tested because we are only supporting curve orders of 256 bits or less
    // A.2.12 - not tested because we are only supporting curve orders of 256 bits or less

    // A.2.13
    char *NIST_B_163 = "040000000000000000000292FE77E70C12A4234C33";
    char *a_2_13_sk = "035318FC447D48D7E6BC93B48617DDDEDF26AA658F";
    result &= test_internal(SHA256, NIST_B_163, a_2_13_sk, "sample", "03D7086A59E6981064A9CDB684653F3A81B6EC0F0B");
    result &= test_internal(SHA384, NIST_B_163, a_2_13_sk, "sample", "03B1E4443443486C7251A68EF184A936F05F8B17C7");
    result &= test_internal(SHA512, NIST_B_163, a_2_13_sk, "sample", "02EDF5CFCAC7553C17421FDF54AD1D2EF928A879D2");
    result &= test_internal(SHA256, NIST_B_163, a_2_13_sk, "test", "038145E3FFCA94E4DDACC20AD6E0997BD0E3B669D2");
    result &= test_internal(SHA384, NIST_B_163, a_2_13_sk, "test", "0375813210ECE9C4D7AB42DDC3C55F89189CF6DFFD");
    result &= test_internal(SHA512, NIST_B_163, a_2_13_sk, "test", "025AD8B393BC1E9363600FDA1A2AB6DF40079179A3");

    // A.2.14
    char *NIST_B_233 = "01000000000000000000000000000013E974E72F8A6922031D2603CFE0D7";
    char *a_2_14_sk = "007ADC13DD5BF34D1DDEEB50B2CE23B5F5E6D18067306D60C5F6FF11E5D3";
    result &= test_internal(SHA256, NIST_B_233, a_2_14_sk, "sample", "0034A53897B0BBDB484302E19BF3F9B34A2ABFED639D109A388DC52006B5");
    result &= test_internal(SHA384, NIST_B_233, a_2_14_sk, "sample", "004D4670B28990BC92EEB49840B482A1FA03FE028D09F3D21F89C67ECA85");
    result &= test_internal(SHA512, NIST_B_233, a_2_14_sk, "sample", "00DE108AAADA760A14F42C057EF81C0A31AF6B82E8FBCA8DC86E443AB549");
    result &= test_internal(SHA256, NIST_B_233, a_2_14_sk, "test", "000376886E89013F7FF4B5214D56A30D49C99F53F211A3AFE01AA2BDE12D");
    result &= test_internal(SHA384, NIST_B_233, a_2_14_sk, "test", "003726870DE75613C5E529E453F4D92631C03D08A7F63813E497D4CB3877");
    result &= test_internal(SHA512, NIST_B_233, a_2_14_sk, "test", "009CE5810F1AC68810B0DFFBB6BEEF2E0053BB937969AE7886F9D064A8C4");

    // A.2.15 - not tested because we are only supporting curve orders of 256 bits or less
    // A.2.16 - not tested because we are only supporting curve orders of 256 bits or less
    // A.2.17 - not tested because we are only supporting curve orders of 256 bits or less

    if (result == 1) {
        printf("SUCCESS\n");
    } else {
        printf("FAIL\n");
    }
}
