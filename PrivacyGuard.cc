#include "PrivacyGuard.h"

#include <iostream>

namespace privacyGuard {

void initialize()
{
    gpgme_check_version(nullptr);
    PrivacyGuard_INVOKE(gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP));
    setlocale(LC_ALL, "");
    gpgme_set_locale(nullptr, LC_CTYPE, setlocale(LC_CTYPE, nullptr));
}
}
