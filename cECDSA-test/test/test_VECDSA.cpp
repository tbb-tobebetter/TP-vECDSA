#define DEBUG

#include "../src/VECDSA.hpp"


void test_VECDSA()
{
    cout << "begin the basic correctness test >>>" << endl; 

    VECDSA_PP pp; 
    VECDSA_PP_new(pp); 
    VECDSA_Setup(pp); 

    size_t TEST_NUM = 10000;
    cout << "TEST_NUM =" <<TEST_NUM << endl; 


	auto start_time_dumb = chrono::steady_clock::now(); 
    BIGNUM *kk_1 = BN_new();
    BN_random(kk_1);  

    EC_POINT *KK_1 = EC_POINT_new(group);
    EC_POINT_mul(group, KK_1, kk_1, NULL, NULL, bn_ctx); // K_1 = k_1*G

	auto end_time_dumb = chrono::steady_clock::now(); 
    auto running_time_dumb = end_time_dumb - start_time_dumb;
    cout << "dumb_time = " 
    << chrono::duration <double, milli> (running_time_dumb).count() << " ms" << endl;

    VECDSA_KP keypair[TEST_NUM];
    for(auto i = 0; i < TEST_NUM; i++)
    {
    VECDSA_KP_new(keypair[i]); 
    }

    auto start_time_KeyG = chrono::steady_clock::now(); 
    //VECDSA_KeyGen(VECDSA_PP &pp, VECDSA_KP &keypair)

    for(auto i = 0; i < TEST_NUM; i++)
    {
    VECDSA_KeyGen(pp, keypair[i]);
	}

    auto end_time_KeyG = chrono::steady_clock::now(); 
    auto running_time_KeyG = end_time_KeyG - start_time_KeyG;
    cout << "(all) key generation takes time = " 
    << chrono::duration <double, milli> (running_time_KeyG).count() << " ms" << endl;
    

    VECDSA_SIG SIG[TEST_NUM];
    for(auto i = 0; i < TEST_NUM; i++)
    { 
    VECDSA_SIG_new(SIG[i]);
    } 

    VECDSA_Random Random[TEST_NUM];
    for(auto i = 0; i < TEST_NUM; i++)
    { 
    VECDSA_Random_new(Random[i]);
    }



    auto start_time_offline = chrono::steady_clock::now(); 
    //VECDSA_Sign(VECDSA_PP &pp, BIGNUM *&sk_1, BIGNUM *&sk_2, string &message, VECDSA_SIG &SIG)
    for(auto i = 0; i < TEST_NUM; i++)
    {
    offline(pp, Random[i], SIG[i]);
    }

    auto end_time_offline = chrono::steady_clock::now(); 
    auto running_time_offline = end_time_offline - start_time_offline;
    cout << "offline takes time = " 
    << chrono::duration <double, milli> (running_time_offline).count() << " ms" << endl;




    string message = "hahaha";  

    auto start_time_Sign = chrono::steady_clock::now(); 
    //VECDSA_Sign(VECDSA_PP &pp, BIGNUM *&sk_1, BIGNUM *&sk_2, string &message, VECDSA_SIG &SIG)
    for(auto i = 0; i < TEST_NUM; i++)
    {
    VECDSA_Sign(pp, keypair[i].sk_1, keypair[i].sk_2, message, Random[i],SIG[i]);
	}

    auto end_time_Sign = chrono::steady_clock::now(); 
    auto running_time_Sign = end_time_Sign - start_time_Sign;
    cout << "(A and B)sign message takes time = " 
    << chrono::duration <double, milli> (running_time_Sign).count() << " ms" << endl;


    auto start_time_Verf = chrono::steady_clock::now(); 
    //VECDSA_Verify(VECDSA_PP &pp, EC_POINT *&pk_1,EC_POINT *&pk_2, string &message, VECDSA_SIG &SIG)

    for(auto i = 0; i < TEST_NUM; i++)
    {
    VECDSA_Verify(pp, keypair[i].pk_1, keypair[i].pk_2, message, SIG[i]);
	}
    auto end_time_Verf = chrono::steady_clock::now(); 
    auto running_time_Verf = end_time_Verf - start_time_Verf;
    cout << "verify signature takes time = " 
    << chrono::duration <double, milli> (running_time_Verf).count() << " ms" << endl;
 
    VECDSA_PP_free(pp);

    for(auto i = 0; i < TEST_NUM; i++)
    { 
    VECDSA_KP_free(keypair[i]); 
    VECDSA_SIG_free(SIG[i]);
    } 
    BN_free(kk_1);
    EC_POINT_free(KK_1);
    
}



int main()
{  
    global_initialize(NID_X9_62_prime256v1);   


    SplitLine_print('-'); 
    cout << "VECDSA Signature test begins >>>>>>" << endl; 
    SplitLine_print('-'); 

    test_VECDSA();
    

    SplitLine_print('-'); 
    cout << "VECDSA Signature test finishes <<<<<<" << endl; 
    SplitLine_print('-'); 

    

    global_finalize();

    
    
    return 0; 
}



