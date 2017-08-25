
#pragma once

#include <gpgme.h>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <thread>

#define FLAGS_GPG_USER_ID "oauth@quicksave.io"

namespace privacyGuard {

class API
{
public:
    static std::string sign()
    {
        Context context = privacyGuard::API::withContext();
        privacyGuard::Key key = context.getKey(FLAGS_GPG_USER_ID);

        privacyGuard::Data in(std::string(""));
        privacyGuard::Data out = context.sign(in);

        return out.read();
    }

    static bool verify(const std::string &signature)
    {
        Context context = privacyGuard::API::withContext();
        privacyGuard::Key key = context.getKey(FLAGS_GPG_USER_ID);

        privacyGuard::Data sig(signature);

        return context.verify(sig);
    }

private:
    static Context withContext()
    {
        static std::once_flag initialize_flag;
        std::call_once(initialize_flag, []() { privacyGuard::initialize(); });
        return privacyGuard::Context();
    }
};
}
