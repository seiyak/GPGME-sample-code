/* t-encrypt-sign.c - Regression test.
   Copyright (C) 2000 Werner Koch (dd9jn)
   Copyright (C) 2001, 2002, 2003, 2004 g10 Code GmbH

   This file is part of GPGME.

   GPGME is free software; you can redistribute it and/or modify it
   under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 2.1 of
   the License, or (at your option) any later version.

   GPGME is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.  */

/* We need to include config.h so that we know whether we are building
   with large file system (LFS) support. */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <gpgme.h>

#include "t-support.h"

/*
static void
check_result (gpgme_sign_result_t result, gpgme_sig_mode_t type)
{
  if (result->invalid_signers)
    {
      fprintf (stderr, "Invalid signer found: %s\n",
	       result->invalid_signers->fpr);
      exit (1);
    }
  if (!result->signatures || result->signatures->next)
    {
      fprintf (stderr, "Unexpected number of signatures created\n");
      exit (1);
    }
  if (result->signatures->type != type)
    {
      fprintf (stderr, "Wrong type of signature created\n");
      exit (1);
    }
  if (result->signatures->pubkey_algo != GPGME_PK_DSA)
    {
      fprintf (stderr, "Wrong pubkey algorithm reported: %i\n",
	       result->signatures->pubkey_algo);
      exit (1);
    }
  if (result->signatures->hash_algo != GPGME_MD_SHA1
      && result->signatures->hash_algo != GPGME_MD_RMD160)
    {
      fprintf (stderr, "Wrong hash algorithm reported: %i\n",
	       result->signatures->hash_algo);
      exit (1);
    }
  if (result->signatures->sig_class != 0)
    {
      fprintf (stderr, "Wrong signature class reported: %u\n",
	       result->signatures->sig_class);
      exit (1);
    }
  if (strcmp ("A0FF4590BB6122EDEF6E3C542D727CC768697734",
	      result->signatures->fpr))
    {
      fprintf (stderr, "Wrong fingerprint reported: %s\n",
	       result->signatures->fpr);
      exit (1);
    }
}
*/

int
main (int argc, char **argv)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;
  gpgme_data_t in, out,plain;
  gpgme_key_t key[3] = { NULL, NULL, NULL },skey;
  gpgme_encrypt_result_t result;
  gpgme_sign_result_t sign_result;
  gpgme_verify_result_t vresult;
  char *agent_info;

  init_gpgme (GPGME_PROTOCOL_OpenPGP);

  err = gpgme_new (&ctx);
  fail_if_err (err);
  gpgme_set_textmode (ctx, 1);
  gpgme_set_armor (ctx, 1);

  /* Might want to comment gpgme_ctx_set_engine_info() below. */
  err = gpgme_ctx_set_engine_info (ctx,GPGME_PROTOCOL_OpenPGP,
        "/opt/gnupg-2.0.30/bin/gpg2",NULL);
  fail_if_err (err);

  agent_info = getenv("GPG_AGENT_INFO");
  if (!(agent_info && strchr (agent_info, ':')))
    gpgme_set_passphrase_cb (ctx, passphrase_cb, NULL);

  /* Include signature within key. */
  gpgme_keylist_mode_t kmode = gpgme_get_keylist_mode(ctx);
  kmode |= GPGME_KEYLIST_MODE_SIGS;
  err = gpgme_set_keylist_mode(ctx,kmode);
  fail_if_err (err);

  /* Generate test keys. */
  char *fprs[3];
  err = generate_test_keys (ctx,3,fprs,NULL);
  fail_if_err (err);
  err = gpgme_get_key (ctx,fprs[0],&key[0],0);
  fail_if_err (err);
  err = gpgme_get_key (ctx,fprs[1],&key[1],0);
  fail_if_err (err);
  err = gpgme_get_key (ctx,fprs[2],&skey,0);
  fail_if_err (err);

  /* Add test key as a signer. */
  err = gpgme_signers_add (ctx,skey);
  fail_if_err (err);

  err = gpgme_data_new_from_mem (&in, "Hallo Leute\n", 12, 0);
  fail_if_err (err);

  err = gpgme_data_new (&out);
  fail_if_err (err);

  err = gpgme_op_encrypt_sign (ctx, key, GPGME_ENCRYPT_ALWAYS_TRUST, in, out);
  fail_if_err (err);
  /* Reset read position to 0 on in otherwise GPG_ERR_NO_DATA would occur when
     gpgme_op_sign() is called consecutively. */
  gpgme_data_seek (in, 0, SEEK_SET);
  /* Reset read position to 0 on out otherwise GPG_ERR_NO_DATA would occur when
     gpgme_op_verify() is called on out consecutively. */
  gpgme_data_seek (out, 0, SEEK_SET);
  result = gpgme_op_encrypt_result (ctx);
  if (result->invalid_recipients)
    {
      fprintf (stderr, "Invalid recipient encountered: %s\n",
	       result->invalid_recipients->fpr);
      exit (1);
    }
  sign_result = gpgme_op_sign_result (ctx);
  check_sign_result(skey,sign_result,GPGME_SIG_MODE_NORMAL,
                    skey->subkeys->next->fpr);
  /* Verify signature. */
  err = gpgme_data_new (&plain);
  fail_if_err (err);
  err = gpgme_op_verify(ctx,out,NULL,plain);
  fail_if_err (err);
  vresult = gpgme_op_verify_result(ctx);
  if (!(vresult->signatures->summary & GPGME_SIGSUM_VALID))
    {
      fprintf (stderr, "Signature is not valid in %s,%d\n",__func__,__LINE__);
      exit (1);
    }
  fail_if_err (err);
  print_data (out);
  gpgme_data_release (in);
  gpgme_data_release (out);
  gpgme_data_release (plain);

  /* Now a second time using symmetric encryption.  */
  err = gpgme_data_new_from_mem (&in, "Hallo Leute\n", 12, 0);
  fail_if_err (err);

  err = gpgme_data_new (&out);
  fail_if_err (err);

  err = gpgme_op_encrypt_sign (ctx, NULL, GPGME_ENCRYPT_ALWAYS_TRUST, in, out);
  fail_if_err (err);
  /* Reset read position to 0 on in otherwise GPG_ERR_NO_DATA would occur when
     gpgme_op_sign() is called consecutively. */
  gpgme_data_seek (in, 0, SEEK_SET);
  /* Reset read position to 0 on out otherwise GPG_ERR_NO_DATA would occur when
     gpgme_op_verify() is called on out consecutively. */
  gpgme_data_seek (out, 0, SEEK_SET);
  sign_result = gpgme_op_sign_result (ctx);
  print_data (out);
  check_sign_result(skey,sign_result,GPGME_SIG_MODE_NORMAL,
                    skey->subkeys->next->fpr);
  /* Verify signature. */
  err = gpgme_data_new (&plain);
  fail_if_err (err);
  err = gpgme_op_verify(ctx,out,NULL,plain);
  fail_if_err (err);
  vresult = gpgme_op_verify_result(ctx);
  if (!(vresult->signatures->summary & GPGME_SIGSUM_VALID))
    {
      fprintf (stderr, "Signature is not valid in %s,%d\n",__func__,__LINE__);
      exit (1);
    }
  fail_if_err (err);
  gpgme_data_release (in);
  gpgme_data_release (out);
  gpgme_data_release (plain);

  free(fprs[0]);
  free(fprs[1]);
  free(fprs[2]);
  delete_test_key(ctx,key[0]);
  delete_test_key(ctx,key[1]);
  delete_test_key(ctx,skey);
  gpgme_release (ctx);
  return 0;
}
