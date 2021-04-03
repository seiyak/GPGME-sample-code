/* t-decrypt-verify.c - Regression test.
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
#include <errno.h>
#include <unistd.h>

#include <gpgme.h>

#include "t-support.h"

static void
check_verify_result (gpgme_verify_result_t result, unsigned int summary,
		     char *fpr, gpgme_error_t status)
{
  gpgme_signature_t sig;

  sig = result->signatures;
  if (!sig || sig->next)
    {
      fprintf (stderr, "%s:%i: Unexpected number of signatures\n",
	       __FILE__, __LINE__);
      exit (1);
    }
  if ((sig->summary & summary) != summary)
    {
      fprintf (stderr, "%s:%i: Unexpected signature summary: 0x%x\n",
	       __FILE__, __LINE__, sig->summary);
      exit (1);
    }
  if (strcmp (sig->fpr, fpr))
    {
      fprintf (stderr, "%s:%i: Unexpected fingerprint: %s\n",
	       __FILE__, __LINE__, sig->fpr);
      exit (1);
    }
  if (gpgme_err_code (sig->status) != status)
    {
      fprintf (stderr, "%s:%i: Unexpected signature status: %s\n",
	       __FILE__, __LINE__, gpgme_strerror (sig->status));
      exit (1);
    }
  if (sig->notations)
    {
      fprintf (stderr, "%s:%i: Unexpected notation data\n",
	       __FILE__, __LINE__);
      exit (1);
    }
  if (sig->wrong_key_usage)
    {
      fprintf (stderr, "%s:%i: Unexpectedly wrong key usage\n",
	       __FILE__, __LINE__);
      exit (1);
    }
  if (sig->validity == GPGME_VALIDITY_UNKNOWN)
    {
      fprintf (stderr, "%s:%i: Unexpected validity: %i\n",
	       __FILE__, __LINE__, sig->validity);
      exit (1);
    }
  if (gpgme_err_code (sig->validity_reason) != GPG_ERR_NO_ERROR)
    {
      fprintf (stderr, "%s:%i: Unexpected validity reason: %s\n",
	       __FILE__, __LINE__, gpgme_strerror (sig->validity_reason));
      exit (1);
    }
}


int 
main (int argc, char *argv[])
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;
  gpgme_data_t in, out/*,plain*/;
  gpgme_key_t key[3] = { NULL, NULL, NULL },skey;
  gpgme_encrypt_result_t result;
  gpgme_sign_result_t sign_result;
  gpgme_decrypt_result_t decrypt_result;
  gpgme_verify_result_t verify_result;
  char *agent_info;

  init_gpgme (GPGME_PROTOCOL_OpenPGP);

  err = gpgme_new (&ctx);
  fail_if_err (err);

  /* Might want to comment gpgme_ctx_set_engine_info() below/ */
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

  gpgme_data_release (in);
  err = gpgme_data_new (&in);
  fail_if_err (err);

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

  err = gpgme_op_decrypt_verify (ctx,out,in);
  fail_if_err (err);
  decrypt_result = gpgme_op_decrypt_result (ctx);
  if (decrypt_result->unsupported_algorithm)
    {
      fprintf (stderr, "%s:%i: unsupported algorithm: %s\n",
	       __FILE__, __LINE__, decrypt_result->unsupported_algorithm);
      exit (1);
    }    
  print_data (in);
  verify_result = gpgme_op_verify_result (ctx);
  check_verify_result (verify_result, GPGME_SIGSUM_VALID,
		       skey->subkeys->next->fpr,
		       GPG_ERR_NO_ERROR);

  gpgme_data_release (in);
  gpgme_data_release (out);

  free(fprs[0]);
  free(fprs[1]);
  free(fprs[2]);
  delete_test_key(ctx,key[0]);
  delete_test_key(ctx,key[1]);
  delete_test_key(ctx,skey);
  gpgme_release (ctx);
  return 0;
}
