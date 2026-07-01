// GPL-3.0-or-later. Links BICYCL (see NOTICE). CLASP stage-one CL backend.
#include <sstream>
#include <memory>
#include <gmp.h>
#include "bicycl.hpp"

using namespace BICYCL;

static Mpz mpz_from_dec(const std::string &s) { return Mpz(s); }
static std::string mpz_to_dec(const Mpz &m) {
    std::ostringstream os; os << m; return os.str();
}

struct ClContext {
    std::unique_ptr<CL_HSMqk> C;
    std::unique_ptr<CL_HSMqk::SecretKey> sk;
    std::unique_ptr<CL_HSMqk::PublicKey> pk;
    RandGen randgen;

    ClContext(int sec_bits) {
        SecLevel chosen = *SecLevel::All().begin();
        for (const SecLevel s : SecLevel::All())
            if ((int)s.nbits() == sec_bits) chosen = s;
        C  = std::make_unique<CL_HSMqk>(2*chosen.nbits(), 1, chosen, randgen);
        sk = std::make_unique<CL_HSMqk::SecretKey>(C->keygen(randgen));
        pk = std::make_unique<CL_HSMqk::PublicKey>(C->keygen(*sk));
    }

    std::shared_ptr<CL_HSMqk::CipherText> enc(const std::string &m_dec) {
        CL_HSMqk::ClearText m(*C, mpz_from_dec(m_dec));
        Mpz r(randgen.random_mpz(C->encrypt_randomness_bound()));
        return std::make_shared<CL_HSMqk::CipherText>(C->encrypt(*pk, m, r));
    }
    std::shared_ptr<CL_HSMqk::CipherText> add(
            const std::shared_ptr<CL_HSMqk::CipherText> &a,
            const std::shared_ptr<CL_HSMqk::CipherText> &b) {
        return std::make_shared<CL_HSMqk::CipherText>(
            C->add_ciphertexts(*pk, *a, *b, randgen));
    }
    std::shared_ptr<CL_HSMqk::CipherText> scal(
            const std::shared_ptr<CL_HSMqk::CipherText> &a,
            const std::string &s_dec) {
        return std::make_shared<CL_HSMqk::CipherText>(
            C->scal_ciphertexts(*pk, *a, mpz_from_dec(s_dec), randgen));
    }
    std::string dec(const std::shared_ptr<CL_HSMqk::CipherText> &c) {
        CL_HSMqk::ClearText m = C->decrypt(*sk, *c);
        return mpz_to_dec(m);
    }
    std::string cleartext_bound() const {
        return mpz_to_dec(C->cleartext_bound());
    }
};
