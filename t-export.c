/* t-export.c - Regression test.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <gpgme.h>

#include "t-support.h"


int 
main (int argc, char **argv)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;
  gpgme_data_t  out;
  gpgme_key_t key[4] = {NULL,NULL,NULL,NULL};
  gpgme_key_t ekey[2] = {NULL,NULL};

  init_gpgme (GPGME_PROTOCOL_OpenPGP);

  err = gpgme_new (&ctx);
  fail_if_err (err);
  gpgme_set_armor (ctx,1);

  /* Might want to comment gpgme_ctx_set_engine_info() below. */
  err = gpgme_ctx_set_engine_info (ctx,GPGME_PROTOCOL_OpenPGP,
        "/opt/gnupg-2.0.30/bin/gpg2",NULL);
  fail_if_err (err);

  /* Generate test keys. */
  char *fprs[3];
  err = generate_test_keys (ctx,3,fprs,NULL);
  fail_if_err (err);
  err = gpgme_get_key (ctx,fprs[0],&key[0],0);
  fail_if_err (err);
  err = gpgme_get_key (ctx,fprs[1],&key[1],0);
  fail_if_err (err);
  err = gpgme_get_key (ctx,fprs[2],&key[2],0);
  fail_if_err (err);

  err = gpgme_data_new (&out);
  fail_if_err (err);

  /* Export key[2] only. */
  ekey[0] = key[2];
  err = gpgme_op_export_keys (ctx,ekey,0,out);
  fail_if_err (err);

  fflush (NULL);
  fputs ("Begin Result:\n", stdout);
  print_data (out);
  fputs ("End Result.\n", stdout);
  gpgme_data_release (out);

  free(fprs[0]);
  free(fprs[1]);
  free(fprs[2]);
  delete_test_key(ctx,key[0]);
  delete_test_key(ctx,key[1]);
  delete_test_key(ctx,key[2]);
  gpgme_release (ctx);
  return 0;
}
