#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>

#include "aes.h"
#include "rsa.h"



void rsa_priv_deinit(rsa_priv_t *priv) {
  if (!priv) {
    return;
  }

  BN_clear_free(priv->p);
  BN_clear_free(priv->q);
  BN_clear_free(priv->dp);
  BN_clear_free(priv->dq);
  BN_clear_free(priv->q_inv);
}


void rsa_pub_deinit(rsa_pub_t *pub) {
  if (!pub) {
    return;
  }

  BN_clear_free(pub->n);
}


void rsa_keypair_deinit(rsa_keypair_t* kp) {
  if (!kp) {
    return;
  }

  rsa_pub_deinit(&kp->pub);

  rsa_priv_deinit(&kp->priv);
}


static BIGNUM* calc_phi_n(BIGNUM *n, BIGNUM *p, BIGNUM *q) {
  BIGNUM *phi = BN_dup(n);

  BN_sub(phi, phi, p);
  BN_sub(phi, phi, q);
  BN_add_word(phi, 1UL);

  return phi;
}

/*
// just for example. DO NOT USE.
// This implementation will instead use the common e = 65537, which is
// prime, safe, and compatible with the rest of the world.
static bool e_is_valid(BIGNUM *e, BIGNUM *phi, BN_CTX *ctx) {

  // at least bigger than 1.
  if (BN_is_zero(e) || BN_is_one(e)) {
    return false;
  }

  BIGNUM *gcd = BN_new();
  BN_gcd(gcd, e, phi, ctx);

  bool ret = BN_is_one(gcd);

  BN_clear_free(gcd);

  return ret;
}


static BIGNUM* calc_e(BIGNUM *phi, BN_CTX *ctx) {
  BIGNUM *e = BN_new();

  do {
    BN_rand_range(e, phi);
  } while(!e_is_valid(e, phi, ctx));

  return e;
}
*/


BIGNUM *BN_dup_m1(BIGNUM *bn) {
  BIGNUM *ret = BN_dup(bn);

  BN_sub_word(ret, 1);

  return ret;
}


// returns the value of n (mod p-1)
BIGNUM* n_mod_p_m1(BIGNUM* n, BIGNUM *p, BN_CTX *ctx) {
  BIGNUM *p_m1 = BN_dup_m1(p);

  BIGNUM *ret = BN_new();

  BN_mod(ret, n, p_m1, ctx);

  BN_clear_free(p_m1);

  return ret;
}


bool rsa_keypair_init(rsa_keypair_t* kp) {
  BN_CTX* ctx = BN_CTX_new();

  kp->priv.p = BN_new();
  BN_generate_prime_ex(kp->priv.p, RSA_KEY * 4, 1, NULL, NULL, NULL);

  kp->priv.q = BN_new();
  do {
    BN_generate_prime_ex(kp->priv.q, RSA_KEY * 4, 1, NULL, NULL, NULL);
  } while(!BN_cmp(kp->priv.p, kp->priv.q));

  kp->pub.n = BN_new();

  BN_mul(kp->pub.n, kp->priv.p, kp->priv.q, ctx);

  BIGNUM *phi = calc_phi_n(kp->pub.n, kp->priv.p, kp->priv.q);

  BIGNUM *e = BN_new();

  BN_set_word(e, RSA_EXP);

  BIGNUM *d = BN_mod_inverse(NULL, e, phi, ctx);

  // Chinese remainder theorem: calculate the two smaller d values
  // dp = d (mod p-1)
  // dq = d (mod q-1)

  kp->priv.dp = n_mod_p_m1(d, kp->priv.p, ctx);
  kp->priv.dq = n_mod_p_m1(d, kp->priv.q, ctx);

  // q^-1 (mod p) is also given, to make calculations faster.

  kp->priv.q_inv = BN_mod_inverse(NULL, kp->priv.q, kp->priv.p, ctx);

  BN_clear_free(d);
  BN_clear_free(e);
  BN_clear_free(phi);
  BN_CTX_free(ctx);
  return true;
}


static BIGNUM* file_read_bn(FILE *f, size_t len) {
  // look out for overflows!
  byte buf[len];

  if (fread(buf, 1, len, f) != len) {
    return NULL;
  }

  BIGNUM *ret = BN_new();

  BN_bin2bn(buf, len, ret);

  return ret;
}


static bool file_write_bn(FILE *f, BIGNUM *bn, size_t len) {
  // look out for overflows!
  byte buf[len];

  memset(buf, 0, len);

  BN_bn2bin(bn, buf);

  return fwrite(buf, 1, len, f) == len;

}


bool rsa_read_privkey(rsa_priv_t *key, FILE *f) {
  return (key->p = file_read_bn(f, RSA_KEY / 2))
      && (key->q = file_read_bn(f, RSA_KEY / 2))
      && (key->dp = file_read_bn(f, RSA_KEY / 2))
      && (key->dq = file_read_bn(f, RSA_KEY / 2))
      && (key->q_inv = file_read_bn(f, RSA_KEY / 2));
}


bool rsa_read_pubkey(rsa_pub_t *key, FILE *f) {
  return (key->n = file_read_bn(f, RSA_KEY));
}


bool rsa_write_privkey(rsa_priv_t key, FILE *f) {
  return file_write_bn(f, key.p, RSA_KEY / 2)
      && file_write_bn(f, key.q, RSA_KEY / 2)
      && file_write_bn(f, key.dp, RSA_KEY / 2)
      && file_write_bn(f, key.dq, RSA_KEY / 2)
      && file_write_bn(f, key.q_inv, RSA_KEY / 2);
}


bool rsa_write_pubkey(rsa_pub_t key, FILE *f) {
  return file_write_bn(f, key.n, RSA_KEY);
}


void BN_out(BIGNUM *bn, const char *n) {

  char *buf = BN_bn2hex(bn);

  printf("%s = %s\n", n, buf);

  OPENSSL_free(buf);
}


BIGNUM* calculate_h(BIGNUM *q_inv, BIGNUM *mp, BIGNUM *mq, BIGNUM *p, BN_CTX *ctx) {
  BIGNUM *m_diff = BN_new();
  BN_sub(m_diff, mp, mq);

  BIGNUM *h = BN_new();
  BN_mod_mul(h, q_inv, m_diff, p, ctx);

  BN_clear_free(m_diff);

  return h;
}


/*
 * Decryptation using the Chinese Remainder Algorithm.
 *
 */
byte* rsa_decrypt_block(rsa_priv_t key, const byte *block, size_t len, size_t *rlen) {
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *c = BN_new();

  BN_bin2bn(block, len, c);

  /* CRT: calculate the two modular exponentiations
   * > mp = c^dp (mod p)
   * > mq = c^dq (mod q)
   */

  BIGNUM *mp = BN_new();
  BN_mod_exp(mp, c, key.dp, key.p, ctx);

  BIGNUM *mq = BN_new();
  BN_mod_exp(mq, c, key.dq, key.q, ctx);

  // CRT: calculate h = q_inv * (mp - mq) (mod p)

  BIGNUM *h = calculate_h(key.q_inv, mp, mq, key.p, ctx);

  // CRT: the message m is
  // m = mq + hq

  BIGNUM *m = BN_new();
  BN_mul(m, h, key.q, ctx);
  BN_add(m, m, mq);

  size_t blen = BN_num_bytes(m);

  if (rlen) {
    *rlen = blen;
  }

  byte *ret = calloc(blen, 1);

  BN_bn2bin(m, ret);

  BN_clear_free(m);
  BN_clear_free(h);
  BN_clear_free(mq);
  BN_clear_free(mp);
  BN_clear_free(c);
  BN_CTX_free(ctx);

  return ret;
}


/*
 * Decrypt an RSA_KEY sized block with the private key, using the basic algorithm
 * (CRT is preferred)
 */
/*byte* rsa_decrypt_block(rsa_priv_t key, const byte *block, size_t len, size_t *rlen) {
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *c = BN_new();

  BN_bin2bn(block, len, c);

  BIGNUM *m = BN_new();
  BN_mod_exp(m, c, key.d, key.n, ctx);

  size_t blen = BN_num_bytes(m);

  if (rlen) {
    *rlen = blen;
  }

  byte *ret = calloc(blen, 1);

  BN_bn2bin(m, ret);

  BN_clear_free(m);
  BN_clear_free(c);
  BN_CTX_free(ctx);

  return ret;
}*/


byte* rsa_encrypt_block(rsa_pub_t key, const byte *block, size_t len, size_t *rlen) {
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *m = BN_new();

  BIGNUM *e = BN_new();

  BN_set_word(e, RSA_EXP);

  BN_bin2bn(block, len, m);

  BIGNUM *c = BN_new();
  BN_mod_exp(c, m, e, key.n, ctx);

  size_t blen = BN_num_bytes(c);

  if (rlen) {
    *rlen = blen;
  }

  byte *ret = calloc(blen, 1);

  BN_bn2bin(c, ret);

  BN_clear_free(e);
  BN_clear_free(m);
  BN_clear_free(c);
  BN_CTX_free(ctx);

  return ret;
}
