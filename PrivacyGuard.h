
#pragma once

#include <gpgme.h>
#include <iostream>
#include <stdexcept>


namespace privacyGuard {
class Exception : public std::runtime_error
{
    using std::runtime_error::runtime_error;
};
}

#define PrivacyGuard_INVOKE(command)                                                                           \
    do                                                                                                         \
    {                                                                                                          \
        gpg_error_t err = (command);                                                                           \
        if (err)                                                                                               \
        {                                                                                                      \
            fprintf(stderr, "%s:%d: %s: %s\n", __FILE__, __LINE__, gpgme_strsource(err), gpgme_strerror(err)); \
            throw privacyGuard::Exception("");                                                                 \
        }                                                                                                      \
    } while (0)

namespace privacyGuard {

void initialize();

class Data
{
public:
    Data()
    {
        PrivacyGuard_INVOKE(gpgme_data_new(&data));
    }

    Data(const std::string& buffer)
            : Data()
    {
        write(buffer);
    }

    Data(const char* filename)
            : Data()
    {
        const int copyflag = 1;
        PrivacyGuard_INVOKE(gpgme_data_new_from_file(&data, filename, copyflag));
        rewind();
    }

    ~Data()
    {
        gpgme_data_release(data);
    }

    std::string read()
    {
        std::string output;

        const int buffer_size = 4096U;
        char buffer[buffer_size];

        rewind();

        ssize_t chunk_size;
        while ((chunk_size = gpgme_data_read(data, buffer, buffer_size)) > 0)
        {
            output += std::string(buffer, static_cast<unsigned long>(chunk_size));
        }

        rewind();

        return output;
    }

    void write(const std::string& buffer)
    {
        if (gpgme_data_write(data, buffer.c_str(), buffer.size()) != buffer.size())
        {
            throw privacyGuard::Exception("");
        }
        rewind();
    }

    gpgme_data_t* get()
    {
        return &data;
    }

private:
    void rewind()
    {
        PrivacyGuard_INVOKE(gpgme_data_seek(data, 0, SEEK_SET));
    }

    gpgme_data_t data;
};

class Key
{
public:
    Key(gpgme_key_t key)
            : key(key)
    {
    }

    ~Key()
    {
        gpgme_key_release(key);
    }

private:
    gpgme_key_t key;
};

class Context
{
public:
    Context()
    {
        PrivacyGuard_INVOKE(gpgme_new(&ctx));
        gpgme_set_textmode(ctx, 1);
        gpgme_set_armor(ctx, 1);
        PrivacyGuard_INVOKE(gpgme_set_protocol(ctx, GPGME_PROTOCOL_OpenPGP));
    }

    ~Context()
    {
        gpgme_release(ctx);
    }

    Key getKey(const char* user_id)
    {
        gpgme_key_t key = nullptr;
        gpgme_error_t err;

        PrivacyGuard_INVOKE(gpgme_op_keylist_start(ctx, user_id, 0));
        PrivacyGuard_INVOKE(gpgme_op_keylist_next(ctx, &key));
        return Key(key);
    }

    /*
    void genkey()
    {
        PrivacyGuard_INVOKE(gpgme_op_genkey(ctx, "<GnupgKeyParams format=\"internal\">\nKey-Type: default\nSubkey-Type: default\nName-Real: AG\nName-Email: adiog@qucksave.io\nExpire-date: 0\nPassphrase: abc\n</GnupgKeyParams>", *pubkey.get(), *seckey.get()));
    }

    void createkey()
    {
        //     PrivacyGuard_INVOKE(gpgme_op_createkey(ctx, "adiog@qucksave.io", "default", 0, 0, nullptr, GPGME_CREATE_SIGN));
    }
    void import(Data& keydata)
    {
        PrivacyGuard_INVOKE(gpgme_op_import(ctx, *keydata.get()));
    }*/

    Data sign(Data& in)
    {
        Data out;
        PrivacyGuard_INVOKE(gpgme_op_sign(ctx, *in.get(), *out.get(), GPGME_SIG_MODE_DETACH));
        gpgme_sign_result_t sign_result = gpgme_op_sign_result(ctx);
        if (sign_result)
        {
            return out;
        }
        else
        {
            throw privacyGuard::Exception("");
        }
    }

    bool verify(Data& sig)
    {
        try
        {
            return do_verify(sig);
        }
        catch (privacyGuard::Exception& exception)
        {
            return false;
        }
    }

private:
    bool do_verify(Data& sig)
    {
        Data signed_text;
        Data plaintext;
        PrivacyGuard_INVOKE(gpgme_op_verify(ctx, *sig.get(), *signed_text.get(), *plaintext.get()));  //*signed_text.get(), *plaintext.get()));
        gpgme_verify_result_t verify_result = gpgme_op_verify_result(ctx);
        return static_cast<bool>(verify_result);
    }

    Data seckey;
    Data pubkey;
    gpgme_ctx_t ctx;
};
}
