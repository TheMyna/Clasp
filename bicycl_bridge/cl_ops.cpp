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
    // Non-re-randomizing add (fixed r = 0): bare nucomp composition, ~us.
    // Safe for accumulating partial sums that are never revealed; the final
    // ciphertext is re-randomized once by the caller.
    std::shared_ptr<CL_HSMqk::CipherText> add_norand(
            const std::shared_ptr<CL_HSMqk::CipherText> &a,
            const std::shared_ptr<CL_HSMqk::CipherText> &b) {
        Mpz zero(0UL);
        return std::make_shared<CL_HSMqk::CipherText>(
            C->add_ciphertexts(*pk, *a, *b, zero));
    }
};

// ---- Stage two: real 2-of-2 threshold via CL_Threshold_Static (IACR 2024/717).
// Drives both players in one process: distributed keygen with VSS, and
// threshold decryption with the decryption proof produced and verified.
struct ThresholdContext {
    std::unique_ptr<CL_HSMqk> C;
    RandGen randgen;
    std::unique_ptr<CL_Threshold_Static> p0;
    std::unique_ptr<CL_Threshold_Static> p1;
    const size_t soundness = 128;

    ThresholdContext(int sec_bits) {
        SecLevel chosen = *SecLevel::All().begin();
        for (const SecLevel s : SecLevel::All())
            if ((int)s.nbits() == sec_bits) chosen = s;
        C = std::make_unique<CL_HSMqk>(2*chosen.nbits(), 1, chosen, randgen);

        // two players, n=2, t=1 (threshold t+1 = 2 => 2-of-2)
        p0 = std::make_unique<CL_Threshold_Static>(*C, 2, 1, 0, soundness);
        p1 = std::make_unique<CL_Threshold_Static>(*C, 2, 1, 1, soundness);

        // --- keygen dealing ---
        p0->keygen_dealing(*C, randgen);
        p1->keygen_dealing(*C, randgen);

        // --- exchange shares/commitments/proofs (sender id is the first arg) ---
        // player 1 receives from player 0 (sender j=0)
        p1->keygen_add_share(0, p0->y_k(1));
        p1->keygen_add_commitments(0, p0->C());
        p1->keygen_add_proof(0, p0->batch_proof());
        // player 0 receives from player 1 (sender j=1)
        p0->keygen_add_share(1, p1->y_k(0));
        p0->keygen_add_commitments(1, p1->C());
        p0->keygen_add_proof(1, p1->batch_proof());

        // --- check/verify then extract ---
        if (!p0->keygen_check_verify_all_players(*C))
            throw std::runtime_error("keygen verify failed at player 0");
        if (!p1->keygen_check_verify_all_players(*C))
            throw std::runtime_error("keygen verify failed at player 1");
        p0->keygen_extract(*C);
        p1->keygen_extract(*C);
    }

    std::shared_ptr<CL_HSMqk::CipherText> enc(const std::string &m_dec) {
        CL_HSMqk::ClearText m(*C, mpz_from_dec(m_dec));
        Mpz r(randgen.random_mpz(C->encrypt_randomness_bound()));
        return std::make_shared<CL_HSMqk::CipherText>(C->encrypt(p0->pk(), m, r));
    }
    std::shared_ptr<CL_HSMqk::CipherText> add(
            const std::shared_ptr<CL_HSMqk::CipherText> &a,
            const std::shared_ptr<CL_HSMqk::CipherText> &b) {
        return std::make_shared<CL_HSMqk::CipherText>(
            C->add_ciphertexts(p0->pk(), *a, *b, randgen));
    }
    std::shared_ptr<CL_HSMqk::CipherText> add_norand(
            const std::shared_ptr<CL_HSMqk::CipherText> &a,
            const std::shared_ptr<CL_HSMqk::CipherText> &b) {
        Mpz zero(0UL);
        return std::make_shared<CL_HSMqk::CipherText>(
            C->add_ciphertexts(p0->pk(), *a, *b, zero));
    }
    std::shared_ptr<CL_HSMqk::CipherText> scal(
            const std::shared_ptr<CL_HSMqk::CipherText> &a,
            const std::string &s_dec) {
        return std::make_shared<CL_HSMqk::CipherText>(
            C->scal_ciphertexts(p0->pk(), *a, mpz_from_dec(s_dec), randgen));
    }
    std::string cleartext_bound() const {
        return mpz_to_dec(C->cleartext_bound());
    }

    // real 2-of-2 threshold decryption, with proofs produced and verified
    std::string threshold_dec(const std::shared_ptr<CL_HSMqk::CipherText> &ct) {
        p0->decrypt_partial(*C, randgen, *ct);
        p1->decrypt_partial(*C, randgen, *ct);
        // exchange partials
        p0->decrypt_add_partial_dec(1, p1->part_dec());
        p1->decrypt_add_partial_dec(0, p0->part_dec());
        // verify the other player's decryption proof
        if (!p0->decrypt_verify_player_decryption(*C, 1))
            throw std::runtime_error("bad partial-dec proof from player 1");
        if (!p1->decrypt_verify_player_decryption(*C, 0))
            throw std::runtime_error("bad partial-dec proof from player 0");
        CL_HSMqk::ClearText m;
        p0->decrypt_combine(m, *C, *ct);
        return mpz_to_dec(m);
    }
};
