/* t-decrypt.c - Regression test.
   Copyright (C) 2000 Werner Koch (dd9jn)
   Copyright (C) 2001, 2003, 2004 g10 Code GmbH

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

int 
main (int argc, char *argv[])
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;
  gpgme_data_t in,out;
  gpgme_genkey_result_t gen_result;
  gpgme_encrypt_result_t enc_result;
  gpgme_decrypt_result_t dec_result;
  gpgme_key_t keys[2] = {NULL,NULL};

  char *agent_info;
  agent_info = getenv("GPG_AGENT_INFO");
  if (!(agent_info && strchr (agent_info, ':')))
    gpgme_set_passphrase_cb (ctx, passphrase_cb, NULL);

  init_gpgme (GPGME_PROTOCOL_OpenPGP);

  err = gpgme_new (&ctx);
  fail_if_err (err);
  gpgme_set_armor (ctx,1);

  /* Might want to comment gpgme_ctx_set_engine_info() below. */
  err = gpgme_ctx_set_engine_info(ctx,GPGME_PROTOCOL_OpenPGP,
	"/opt/gnupg-2.0.30/bin/gpg2",NULL);
  fail_if_err (err);

  /* Generate test key for encryption. */
  err = generate_test_key (ctx,NULL);
  fail_if_err (err);
  gen_result = gpgme_op_genkey_result (ctx);

  /* Search key for encryption. */
  gpgme_key_t key;
  err = gpgme_get_key (ctx,gen_result->fpr,&key,1);
  fail_if_err (err);

  /* Initialize input buffer. */
  err = gpgme_data_new_from_mem (&in,"Hallo Leute\n", 12, 0);
  fail_if_err (err);

  /* Initialize output buffer. */
  err = gpgme_data_new (&out);
  fail_if_err (err);

  /* Encrypt data. */
  keys[0] = key;
  err = gpgme_op_encrypt (ctx,keys,GPGME_ENCRYPT_ALWAYS_TRUST,in,out);
  fail_if_err (err);
  enc_result = gpgme_op_encrypt_result (ctx);
  if (enc_result->invalid_recipients)
    {
      fprintf (stderr, "Invalid recipient encountered: %s\n",
	       enc_result->invalid_recipients->fpr);
      exit (1);
    }
  print_data (out);

  /* out stores encrypted data and it's the input for decryption. Use in as
     the output for decryption. */
  gpgme_data_release (in);
  err = gpgme_data_new (&in);
  fail_if_err (err);

  /* Decrypt data. */
  err = gpgme_op_decrypt (ctx,out,in);
  fail_if_err (err);
  dec_result = gpgme_op_decrypt_result (ctx);
  if (dec_result->unsupported_algorithm)
    {
      fprintf (stderr, "%s:%i: unsupported algorithm: %s\n",
	       __FILE__, __LINE__, dec_result->unsupported_algorithm);
      exit (1);
    }
  print_data (in);

  err = delete_test_key (ctx,key);
  fail_if_err (err);

  gpgme_data_release (in);
  gpgme_data_release (out);
  gpgme_release (ctx);
  return 0;
}
