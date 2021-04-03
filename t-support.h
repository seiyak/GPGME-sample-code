/* t-support.h - Helper routines for regression tests.
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

#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <locale.h>
#include <string.h>

#ifdef HAVE_W32_SYSTEM
#include <windows.h>
#endif

#include <gpgme.h>

#ifndef DIM
#define DIM(v)		     (sizeof(v)/sizeof((v)[0]))
#endif

#define fail_if_err(err)					\
  do								\
    {								\
      if (err)							\
        {							\
          fprintf (stderr, "%s:%d: %s: %s\n",			\
                   __FILE__, __LINE__, gpgme_strsource (err),	\
		   gpgme_strerror (err));			\
          exit (1);						\
        }							\
    }								\
  while (0)


static const char *
nonnull (const char *s)
{
  return s? s :"[none]";
}


void
print_data (gpgme_data_t dh)
{
#define BUF_SIZE 512
  char buf[BUF_SIZE + 1];
  int ret;
  
  ret = gpgme_data_seek (dh, 0, SEEK_SET);
  if (ret)
    fail_if_err (gpgme_err_code_from_errno (errno));
  while ((ret = gpgme_data_read (dh, buf, BUF_SIZE)) > 0)
    fwrite (buf, ret, 1, stdout);
  if (ret < 0)
    fail_if_err (gpgme_err_code_from_errno (errno));

  /* Reset read position to the beginning so that dh can be used as input
     for another operation after this method call. For example, dh is an
     output from encryption and also is used as an input for decryption.
     Otherwise GPG_ERR_NO_DATA is returned since this method moves the
     read position. */
  ret = gpgme_data_seek (dh, 0, SEEK_SET);
}


gpgme_error_t
passphrase_cb (void *opaque, const char *uid_hint, const char *passphrase_info,
	       int last_was_bad, int fd)
{
#ifdef HAVE_W32_SYSTEM
  DWORD written;
  WriteFile ((HANDLE) fd, "abc\n", 4, &written, 0);
#else
  int res;
  char *pass = "abc\n";
  int passlen = strlen (pass);
  int off = 0;

  do
    {
      res = write (fd, &pass[off], passlen - off);
      if (res > 0)
	off += res;
    }
  while (res > 0 && off != passlen);

  return off == passlen ? 0 : gpgme_error_from_errno (errno);
#endif

  return 0;
}


char *
make_filename (const char *fname)
{
  const char *srcdir = getenv ("srcdir");
  char *buf;

  if (!srcdir)
    srcdir = ".";
  buf = malloc (strlen(srcdir) + strlen(fname) + 2);
  if (!buf) 
    exit (8);
  strcpy (buf, srcdir);
  strcat (buf, "/");
  strcat (buf, fname);
  return buf;
}


void
init_gpgme (gpgme_protocol_t proto)
{
  gpgme_error_t err;

  gpgme_check_version (NULL);
  setlocale (LC_ALL, "");
  gpgme_set_locale (NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));
#ifndef HAVE_W32_SYSTEM
  gpgme_set_locale (NULL, LC_MESSAGES, setlocale (LC_MESSAGES, NULL));
#endif

  err = gpgme_engine_check_version (proto);
  fail_if_err (err);
}


void
print_import_result (gpgme_import_result_t r)
{
  gpgme_import_status_t st;

  for (st=r->imports; st; st = st->next)
    {
      printf ("  fpr: %s err: %d (%s) status:", nonnull (st->fpr),
              st->result, gpgme_strerror (st->result));
      if (st->status & GPGME_IMPORT_NEW)
        fputs (" new", stdout);
      if (st->status & GPGME_IMPORT_UID)
        fputs (" uid", stdout);
      if (st->status & GPGME_IMPORT_SIG)
        fputs (" sig", stdout);
      if (st->status & GPGME_IMPORT_SUBKEY)
        fputs (" subkey", stdout);
      if (st->status & GPGME_IMPORT_SECRET)
        fputs (" secret", stdout);
      putchar ('\n');
    }
  printf ("key import summary:\n"
          "        considered: %d\n"
          "        no user id: %d\n"
          "          imported: %d\n"
          "      imported_rsa: %d\n"
          "         unchanged: %d\n"
          "      new user ids: %d\n"
          "       new subkeys: %d\n"
          "    new signatures: %d\n"
          "   new revocations: %d\n"
          "       secret read: %d\n"
          "   secret imported: %d\n"
          "  secret unchanged: %d\n"
          "  skipped new keys: %d\n"
          "      not imported: %d\n",
          r->considered,
          r->no_user_id,
          r->imported,
          r->imported_rsa,
          r->unchanged,
          r->new_user_ids,
          r->new_sub_keys,
          r->new_signatures,
          r->new_revocations,
          r->secret_read,
          r->secret_imported,
          r->secret_unchanged,
          r->skipped_new_keys,
          r->not_imported);
}

gpgme_error_t
generate_keys (gpgme_ctx_t ctx,const char **parmss,int sz,char **fprs,
  void (*progress_meter) (void *hook, const char *what, int type, int current,
                          int total))
{
  gpgme_set_progress_cb (ctx, progress_meter, NULL);
  gpgme_error_t err;
  gpgme_genkey_result_t result;

  int i,len;
  for (i = 0; i < sz;i++)
    {
      err = gpgme_op_genkey (ctx, parmss[i], NULL, NULL);
      fail_if_err(err);

      if (!fprs)
        continue;

      result = gpgme_op_genkey_result(ctx);
      /* Finger print must be stored for later use. Otherwise,
         it will be invalid since gpgme_op_genkey() might be called
         multiple times. */
      if (!result->fpr)
        fprs[i] = NULL;
      else {
        len = strlen(result->fpr);
        fprs[i] = (char *)malloc(sizeof(char) * (len + 1));
        memcpy(fprs[i],result->fpr,len);
        fprs[i][len] = '\0';
      }
    }
  return err;
}

gpgme_error_t
generate_test_keys (gpgme_ctx_t ctx,int n,char **fprs,
  void (*progress_meter) (void *hook, const char *what, int type, int current,
                          int total))
{
  const char *parms1 = "<GnupgKeyParms format=\"internal\">\n"
    "Key-Type: RSA\n"
    "Key-Length: 2048\n"
    "Subkey-Type: RSA\n"
    "Subkey-Length: 2048\n"
    "Name-Real: Joe Tester\n"
    "Name-Comment: with stupid passphrase\n"
    "Name-Email: joe@foo.bar\n"
    "Expire-Date: 0\n"
    "Passphrase: abc\n"
    "</GnupgKeyParms>\n";

  const char *parms2 = "<GnupgKeyParms format=\"internal\">\n"
    "Key-Type: RSA\n"
    "Key-Length: 2048\n"
    "Subkey-Type: RSA\n"
    "Subkey-Length: 2048\n"
    "Name-Real: Joe Tester 2\n"
    "Name-Comment: with stupid passphrase 2\n"
    "Name-Email: joe2@foo.bar\n"
    "Expire-Date: 0\n"
    "Passphrase: abc\n"
    "</GnupgKeyParms>\n";

  const char *parms3 = "<GnupgKeyParms format=\"internal\">\n"
    "Key-Type: RSA\n"
    "Key-Length: 2048\n"
    "Subkey-Type: RSA\n"
    "Subkey-Length: 2048\n"
    "Name-Real: Joe Tester 3\n"
    "Name-Comment: with stupid passphrase 3\n"
    "Name-Email: joe2@foo.bar\n"
    "Expire-Date: 0\n"
    "Passphrase: abc\n"
    "</GnupgKeyParms>\n";

  switch (n){
    case 1:
    case 2:
    case 3:
      break;
    default:
      n = 3;
      break;
  }

  const char *parmss[n];
  switch (n){
    case 1:
      parmss[0] = parms1;
      break;
    case 2:
      parmss[0] = parms1;
      parmss[1] = parms2;
      break;
    case 3:
      parmss[0] = parms1;
      parmss[1] = parms2;
      parmss[2] = parms3;
      break;
    default:
      break;
  }
  return generate_keys (ctx,parmss,n,fprs,progress_meter);
}

gpgme_error_t
generate_test_key (gpgme_ctx_t ctx,
  void (*progress_meter) (void *hook, const char *what, int type, int current,
                          int total))
{
  return generate_test_keys (ctx,1,NULL,progress_meter);
}

gpgme_error_t
delete_test_key (gpgme_ctx_t ctx,gpgme_key_t key)
{
  gpgme_error_t err = gpgme_op_delete (ctx,key,1);
  gpgme_key_unref (key);
  return err;
}

void
check_sign_result (gpgme_key_t key, gpgme_sign_result_t result,
                   gpgme_sig_mode_t type,char *fpr)
{
  gpgme_key_sig_t sig = key->uids->signatures;
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
  if (result->signatures->pubkey_algo != sig->pubkey_algo)
    {
      fprintf (stderr, "Wrong pubkey algorithm reported: %i\n",
	       result->signatures->pubkey_algo);
      exit (1);
    }
   if (strcmp (fpr,result->signatures->fpr))
    {
      fprintf (stderr, "Wrong fingerprint reported: %s\n",
	       result->signatures->fpr);
      exit (1);
    }
}
