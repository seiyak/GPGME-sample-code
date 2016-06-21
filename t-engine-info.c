/* We need to include config.h so that we know whether we are building
   with large file system (LFS) support. */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <gpgme.h>

#include "t-support.h"

int 
main (int argc, char **argv)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;
  const char *parms = "<GnupgKeyParms format=\"internal\">\n"
    "Key-Type: DSA\n"
    "Key-Length: 1024\n"
    "Subkey-Type: ELG-E\n"
    "Subkey-Length: 1024\n"
    "Name-Real: Joe Tester\n"
    "Name-Comment: (pp=abc)\n"
    "Name-Email: joe@foo.bar\n"
    "Expire-Date: 0\n"
    "Passphrase: abc\n"
    "</GnupgKeyParms>\n";
  gpgme_genkey_result_t result;

  init_gpgme (GPGME_PROTOCOL_OpenPGP);

  err = gpgme_new (&ctx);
  fail_if_err (err);

  /* Might want to comment gpgme_ctx_set_engine_info() or change
   * the 2nd argument for a non default directory on your machine. */
  err = gpgme_ctx_set_engine_info (ctx,GPGME_PROTOCOL_OpenPGP,
        "/opt/gnupg-2.0.30/bin/gpg2","/home/seiyak/.gnupg/users/sample");
  fail_if_err (err);

  err = gpgme_op_genkey (ctx, parms, NULL, NULL);
  fail_if_err (err);

  result = gpgme_op_genkey_result (ctx);
  if (!result)
    {
      fprintf (stderr, "%s:%d: gpgme_op_genkey_result returns NULL\n",
	       __FILE__, __LINE__);
      exit (1);
    }

  printf ("Generated key: %s (%s)\n", result->fpr ? result->fpr : "none",
	  result->primary ? (result->sub ? "primary, sub" : "primary")
	  : (result->sub ? "sub" : "none"));

  if (result->fpr && strlen (result->fpr) != 40)
    {
      fprintf (stderr, "%s:%d: generated key has unexpected fingerprint\n",
	       __FILE__, __LINE__);
      exit (1);
    }
  if (!result->primary)
    {
      fprintf (stderr, "%s:%d: primary key was not generated\n",
	       __FILE__, __LINE__);
      exit (1);
    }
  if (!result->sub)
    {
      fprintf (stderr, "%s:%d: sub key was not generated\n",
	       __FILE__, __LINE__);
      exit (1);
    }

  /* Search just generated key. */
  gpgme_key_t key;
  err = gpgme_get_key (ctx,result->fpr,&key,1);
  fail_if_err (err);
  /* Delete just generated key. */
  err = gpgme_op_delete (ctx,key,1);
  fail_if_err (err);
  gpgme_key_unref (key);

  gpgme_release (ctx);
  return 0;
}
