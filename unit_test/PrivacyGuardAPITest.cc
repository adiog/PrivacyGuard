#include <gtest/gtest.h>
#include <PrivacyGuard.h>
#include <gpgme.h>
#include <PrivacyGuardAPI.h>

TEST(PrivacyGuardAPITestSuite, PrivacyGuardAPITestCase) {
    std::string s = privacyGuard::API::sign();
    ASSERT_FALSE(privacyGuard::API::verify("dupa"));
    ASSERT_TRUE(privacyGuard::API::verify(s));
}