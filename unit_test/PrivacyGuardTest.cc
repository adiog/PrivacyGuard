#include <gtest/gtest.h>
#include <PrivacyGuard.h>
#include <gpgme.h>

TEST(PrivacyGuardTestSuite, PrivacyGuardTestCase) {
    privacyGuard::initialize();

    privacyGuard::Context context;

    std::string test = "to jest testowy kawalek wiadomosci";

    privacyGuard::Key key = context.getKey("oauth@quicksave.io");

    privacyGuard::Data in(test);
    privacyGuard::Data out = context.sign(in);

    std::string test_signed = out.read();
    std::cout << test_signed;

    privacyGuard::Data verifyData(test_signed);
    privacyGuard::Data crap;
    privacyGuard::Data crap2;

    ASSERT_TRUE(context.verify(verifyData));
}