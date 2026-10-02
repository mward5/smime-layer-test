/* SPDX-License-Identifier: MIT */

/* Parse messages with Evolution's EMailParser, print the signature and
 * encryption results (validity pairs) it attaches to each part, and how
 * Evolution's security bar would show them.
 *
 * Run it through run.sh, which points HOME at a throwaway NSS database:
 * camel_init() always opens ~/.pki/nssdb, never the directory it is given.
 *
 * Usage: smime-layers [--html] message...
 *   --html  also print the security bar's HTML as Evolution renders it */

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <gtk/gtk.h>
#include <camel/camel.h>
#include <em-format/e-mail-formatter.h>
#include <em-format/e-mail-parser.h>
#include <em-format/e-mail-part-list.h>
#include <em-format/e-mail-part.h>

/* E_MAIL_PART_VALIDITY_OUTER; spelled out so this also builds without it */
#define VALIDITY_OUTER (1 << 6)

#define SECURE_BUTTON_MIME_TYPE "application/vnd.evolution.secure-button"

static const gchar *
sign_status_name (CamelCipherValiditySign status)
{
	switch (status) {
	case CAMEL_CIPHER_VALIDITY_SIGN_NONE: return "none";
	case CAMEL_CIPHER_VALIDITY_SIGN_GOOD: return "GOOD";
	case CAMEL_CIPHER_VALIDITY_SIGN_BAD: return "BAD";
	case CAMEL_CIPHER_VALIDITY_SIGN_UNKNOWN: return "UNKNOWN";
	case CAMEL_CIPHER_VALIDITY_SIGN_NEED_PUBLIC_KEY: return "NEED_PUBLIC_KEY";
	}
	return "?";
}

static const gchar *
encrypt_status_name (CamelCipherValidityEncrypt status)
{
	switch (status) {
	case CAMEL_CIPHER_VALIDITY_ENCRYPT_NONE: return "none";
	case CAMEL_CIPHER_VALIDITY_ENCRYPT_WEAK: return "weak";
	case CAMEL_CIPHER_VALIDITY_ENCRYPT_ENCRYPTED: return "encrypted";
	case CAMEL_CIPHER_VALIDITY_ENCRYPT_STRONG: return "strong";
	}
	return "?";
}

static void
print_flags (guint flags)
{
	const struct { guint bit; const gchar *name; } names[] = {
		{ E_MAIL_PART_VALIDITY_PGP, "PGP" },
		{ E_MAIL_PART_VALIDITY_SMIME, "SMIME" },
		{ E_MAIL_PART_VALIDITY_SIGNED, "SIGNED" },
		{ E_MAIL_PART_VALIDITY_ENCRYPTED, "ENCRYPTED" },
		{ E_MAIL_PART_VALIDITY_SENDER_SIGNER_MISMATCH, "MISMATCH" },
		{ E_MAIL_PART_VALIDITY_VERIFIED, "VERIFIED" },
		{ VALIDITY_OUTER, "OUTER" }
	};
	gboolean first = TRUE;
	guint ii;

	for (ii = 0; ii < G_N_ELEMENTS (names); ii++) {
		if (flags & names[ii].bit) {
			printf ("%s%s", first ? "" : "|", names[ii].name);
			first = FALSE;
		}
	}
}

/* The bar colours from Evolution's e-mail-formatter-secure-button.c */
static const gchar *
bar_colour_name (const gchar *html)
{
	if (strstr (html, "background:#87ba87"))
		return "green";
	if (strstr (html, "background:#ba8787"))
		return "red";
	if (strstr (html, "background:#e8d121"))
		return "yellow";

	return "plain";
}

/* The collapsed bar's text, with markup removed */
static gchar *
bar_summary_text (const gchar *html)
{
	const gchar *start, *end;
	GString *text;
	gboolean in_tag = FALSE;

	start = strstr (html, "<span style=\"vertical-align:middle;\">");
	if (!start)
		return g_strdup ("");

	start = strchr (start, '>') + 1;
	end = strstr (start, "</span>");
	if (!end)
		return g_strdup ("");

	text = g_string_new ("");
	for (; start < end; start++) {
		if (*start == '<')
			in_tag = TRUE;
		else if (*start == '>')
			in_tag = FALSE;
		else if (!in_tag)
			g_string_append_c (text, *start == '\n' ? ' ' : *start);
	}

	g_string_replace (text, "&lt;", "<", 0);
	g_string_replace (text, "&gt;", ">", 0);
	g_string_replace (text, "&amp;", "&", 0);
	g_strstrip (text->str);

	return g_string_free (text, FALSE);
}

static void
print_display (EMailFormatter *formatter,
               EMailPartList *part_list,
               EMailPart *part,
               gboolean show_html)
{
	EMailFormatterContext context = { part_list, E_MAIL_FORMATTER_MODE_NORMAL, 0, NULL };
	GOutputStream *out;
	const gchar *html, *table;

	out = g_memory_output_stream_new_resizable ();
	e_mail_formatter_format_as (formatter, &context, part, out, SECURE_BUTTON_MIME_TYPE, NULL);
	g_output_stream_write_all (out, "", 1, NULL, NULL, NULL);
	g_output_stream_close (out, NULL, NULL);
	html = g_memory_output_stream_get_data (G_MEMORY_OUTPUT_STREAM (out));

	/* One table per crypto system */
	for (table = strstr (html, "<table"); table; table = strstr (table + 1, "<table")) {
		const gchar *end = strstr (table, "</table>");
		gchar *one, *summary;

		one = end ? g_strndup (table, end - table) : g_strdup (table);
		summary = bar_summary_text (one);

		printf ("       display  %-6s details=%-6s \"%s\"\n", bar_colour_name (one),
			strstr (one, "Outer signature (over") ? "split" : "single", summary);

		if (show_html)
			printf ("       html     %s</table>\n", one);

		g_free (summary);
		g_free (one);
	}

	g_object_unref (out);
}

static void
print_message (EMailParser *parser,
               EMailFormatter *formatter,
               const gchar *filename,
               gboolean show_html)
{
	CamelStream *stream;
	CamelMimeMessage *message;
	EMailPartList *part_list;
	GQueue queue = G_QUEUE_INIT;
	GError *error = NULL;
	GList *link;

	stream = camel_stream_fs_new_with_name (filename, O_RDONLY, 0, &error);
	if (!stream) {
		g_printerr ("%s: %s\n", filename, error->message);
		g_clear_error (&error);
		return;
	}

	message = camel_mime_message_new ();
	if (!camel_data_wrapper_construct_from_stream_sync (CAMEL_DATA_WRAPPER (message), stream, NULL, &error)) {
		g_printerr ("%s: %s\n", filename, error->message);
		g_clear_error (&error);
		g_object_unref (message);
		g_object_unref (stream);
		return;
	}

	printf ("== %s\n", g_path_get_basename (filename));

	part_list = e_mail_parser_parse_sync (parser, NULL, filename, message, NULL);
	e_mail_part_list_queue_parts (part_list, NULL, &queue);

	for (link = g_queue_peek_head_link (&queue); link; link = g_list_next (link)) {
		EMailPart *part = link->data;
		GList *vlink;

		printf ("  part %-36s %-34s%s\n", e_mail_part_get_id (part),
			e_mail_part_get_mime_type (part) ? e_mail_part_get_mime_type (part) : "(none)",
			e_mail_part_get_is_attachment (part) ? "  [ATTACHMENT]" : "");

		for (vlink = g_queue_peek_head_link (&part->validities); vlink; vlink = g_list_next (vlink)) {
			EMailPartValidityPair *pair = vlink->data;
			GList *slink;

			printf ("       validity ");
			print_flags (pair->validity_type);
			printf ("  sign=%s encrypt=%s", sign_status_name (pair->validity->sign.status),
				encrypt_status_name (pair->validity->encrypt.status));

			for (slink = g_queue_peek_head_link (&pair->validity->sign.signers); slink; slink = g_list_next (slink)) {
				CamelCipherCertInfo *info = slink->data;

				printf ("  signer=%s", info->email ? info->email : info->name);
			}
			printf ("\n");
		}

		if (g_strcmp0 (e_mail_part_get_mime_type (part), SECURE_BUTTON_MIME_TYPE) == 0)
			print_display (formatter, part_list, part, show_html);
	}

	while (!g_queue_is_empty (&queue))
		g_object_unref (g_queue_pop_head (&queue));

	g_object_unref (part_list);
	g_object_unref (message);
	g_object_unref (stream);
}

gint
main (gint argc,
      gchar **argv)
{
	CamelSession *session;
	EMailParser *parser;
	EMailFormatter *formatter;
	gboolean show_html = FALSE;
	gchar *tmpdir;
	gint ii;

	/* The formatter asks GTK for icon sizes; no display is needed */
	gtk_init_check (&argc, &argv);

	if (camel_init (g_get_home_dir (), TRUE) != 0) {
		g_printerr ("camel_init failed\n");
		return 1;
	}

	tmpdir = g_dir_make_tmp ("smime-layers-XXXXXX", NULL);
	session = g_object_new (CAMEL_TYPE_SESSION,
		"user-data-dir", tmpdir,
		"user-cache-dir", tmpdir,
		NULL);
	parser = e_mail_parser_new (session);
	formatter = e_mail_formatter_new ();

	for (ii = 1; ii < argc; ii++) {
		if (g_strcmp0 (argv[ii], "--html") == 0)
			show_html = TRUE;
	}

	for (ii = 1; ii < argc; ii++) {
		if (g_strcmp0 (argv[ii], "--html") != 0)
			print_message (parser, formatter, argv[ii], show_html);
	}

	g_object_unref (formatter);
	g_object_unref (parser);
	g_object_unref (session);
	g_free (tmpdir);

	return 0;
}
