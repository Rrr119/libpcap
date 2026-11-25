/*
 * Copyright (c) 2026
 *	The Tcpdump Group and contributors.  All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <config.h>

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef _WIN32
  #include "getopt.h"
#else
  #include <unistd.h>
#endif

#include "pcap/funcattrs.h"
#include "portability.h"
#include "test-util.h"

#define MAX_CASES 64
#define MAX_LINE 65536

struct test_case {
	char *name;
	char *dlt_name;
	char *expr;
	int snaplen;
	int optimize;
};

static const char *program_name;

static void
PCAP_NORETURN_DEF
usage(FILE *f)
{
	fprintf(f, "%s, with %s\n", program_name, pcap_lib_version());
	fprintf(f, "Usage: %s <valid.tsv> <invalid.tsv> <valid.golden>\n",
	    program_name);
	fprintf(f, "	   (compile expressions and compare valid bytecode with the golden file)\n");
	fprintf(f, "  or:  %s -g <valid.tsv>\n", program_name);
	fprintf(f, "	   (print the valid bytecode golden file)\n");
	fprintf(f, "  or:  %s -h\n", program_name);
	exit(f == stdout ? EX_OK : EX_USAGE);
}

static char *
split_field(char **cursor)
{
	char *field = *cursor;
	char *tab;

	if (field == NULL)
		return NULL;
	tab = strchr(field, '\t');
	if (tab == NULL) {
		*cursor = NULL;
		return field;
	}
	*tab = '\0';
	*cursor = tab + 1;
	return field;
}

static int
parse_int(const char *name, const char *value, int *result)
{
	char *end;
	long n;

	errno = 0;
	n = strtol(value, &end, 0);
	if (errno != 0 || end == value || *end != '\0' ||
	    n < 0 || n > 262144) {
		fprintf(stderr, "%s: invalid integer '%s' in case '%s'\n",
		    program_name, value, name);
		return -1;
	}
	*result = (int)n;
	return 0;
}

static int
read_cases(const char *path, struct test_case *cases, int max_cases)
{
	FILE *f;
	char line[MAX_LINE];
	int count = 0;

	f = fopen(path, "r");
	if (f == NULL) {
		fprintf(stderr, "%s: fopen(%s): %s\n", program_name, path,
		    pcap_strerror(errno));
		return -1;
	}
	while (fgets(line, sizeof(line), f) != NULL) {
		char *cursor;
		char *fields[5];
		size_t len;
		int i;

		len = strlen(line);
		while (len != 0 &&
		    (line[len - 1] == '\n' || line[len - 1] == '\r'))
			line[--len] = '\0';
		if (len == 0 || line[0] == '#')
			continue;
		if (count == max_cases) {
			fprintf(stderr, "%s: too many cases in %s\n",
			    program_name, path);
			fclose(f);
			return -1;
		}

		cursor = line;
		for (i = 0; i < 5; i++)
			fields[i] = split_field(&cursor);
		if (cursor != NULL || fields[4] == NULL) {
			fprintf(stderr, "%s: malformed line in %s\n",
			    program_name, path);
			fclose(f);
			return -1;
		}

		cases[count].name = strdup(fields[0]);
		cases[count].dlt_name = strdup(fields[1]);
		cases[count].expr = strdup(strcmp(fields[4], "@empty@") == 0 ?
		    "" : fields[4]);
		if (cases[count].name == NULL ||
		    cases[count].dlt_name == NULL ||
		    cases[count].expr == NULL) {
			fprintf(stderr, "%s: out of memory\n", program_name);
			fclose(f);
			return -1;
		}
		if (parse_int(fields[0], fields[2],
		    &cases[count].snaplen) == -1 ||
		    parse_int(fields[0], fields[3],
		    &cases[count].optimize) == -1) {
			fclose(f);
			return -1;
		}
		if (cases[count].optimize != 0 && cases[count].optimize != 1) {
			fprintf(stderr, "%s: invalid optimize flag in case '%s'\n",
			    program_name, fields[0]);
			fclose(f);
			return -1;
		}
		count++;
	}
	fclose(f);
	return count;
}

static char *
hex_encode_insns(const struct bpf_insn *insns, unsigned len)
{
	static const char hex[] = "0123456789abcdef";
	char *result;
	size_t i, j = 0;

	result = malloc((size_t)len * 8 * 2 + 1);
	if (result == NULL)
		return NULL;
	for (i = 0; i < len; i++) {
		unsigned char bytes[8] = {
			(unsigned char)(insns[i].code >> 8),
			(unsigned char)insns[i].code,
			insns[i].jt,
			insns[i].jf,
			(unsigned char)(insns[i].k >> 24),
			(unsigned char)(insns[i].k >> 16),
			(unsigned char)(insns[i].k >> 8),
			(unsigned char)insns[i].k
		};
		size_t b;

		for (b = 0; b < sizeof(bytes); b++) {
			result[j++] = hex[bytes[b] >> 4];
			result[j++] = hex[bytes[b] & 0x0f];
		}
	}
	result[j] = '\0';
	return result;
}

static int
hex_nibble(const char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

/*
 * Decode the architecture-independent representation into struct bpf_insn
 * so the result can be compared with the generated program using memcmp().
 */
static int
hex_decode_insns(const char *hex, struct bpf_insn *insns, unsigned len)
{
	unsigned i;
	size_t n = strlen(hex);

	if (n != (size_t)len * 16)
		return -1;
	for (i = 0; i < len; i++) {
		unsigned char bytes[8];
		size_t b;

		for (b = 0; b < sizeof(bytes); b++) {
			int hi = hex_nibble(hex[(i * 8 + b) * 2]);
			int lo = hex_nibble(hex[(i * 8 + b) * 2 + 1]);

			if (hi < 0 || lo < 0)
				return -1;
			bytes[b] = (unsigned char)((hi << 4) | lo);
		}
		insns[i].code = (u_short)((bytes[0] << 8) | bytes[1]);
		insns[i].jt = bytes[2];
		insns[i].jf = bytes[3];
		insns[i].k = ((bpf_u_int32)bytes[4] << 24) |
		    ((bpf_u_int32)bytes[5] << 16) |
		    ((bpf_u_int32)bytes[6] << 8) |
		    bytes[7];
	}
	return 0;
}

static int
compile_case(const struct test_case *test, struct bpf_program *program,
    char *errbuf)
{
	int dlt;
	int rc;
	pcap_t *p;

	dlt = pcap_datalink_name_to_val(test->dlt_name);
	if (dlt == -1) {
		(void)snprintf(errbuf, PCAP_ERRBUF_SIZE,
		    "unknown data link type '%s'", test->dlt_name);
		return PCAP_ERROR;
	}
	p = pcap_open_dead(dlt, test->snaplen);
	if (p == NULL) {
		(void)snprintf(errbuf, PCAP_ERRBUF_SIZE,
		    "pcap_open_dead(%s, %d) failed", test->dlt_name,
		    test->snaplen);
		return PCAP_ERROR;
	}
	rc = pcap_compile(p, program, test->expr, test->optimize,
	    PCAP_NETMASK_UNKNOWN);
	if (rc != 0)
		(void)snprintf(errbuf, PCAP_ERRBUF_SIZE, "%s",
		    pcap_geterr(p));
	pcap_close(p);
	return rc;
}

static int
check_valid_cases(const struct test_case *cases, int count,
    const char *golden_path)
{
	FILE *golden;
	char line[MAX_LINE];
	int i;
	int passed = 0;

	golden = fopen(golden_path, "r");
	if (golden == NULL) {
		fprintf(stderr, "%s: fopen(%s): %s\n", program_name,
		    golden_path, pcap_strerror(errno));
		return -1;
	}
	for (i = 0; i < count; i++) {
		struct bpf_program program;
		char errbuf[PCAP_ERRBUF_SIZE];
		char *actual;
		char *name;
		char *expected;
		char *cursor;

		if (fgets(line, sizeof(line), golden) == NULL) {
			fprintf(stderr, "%s: golden file is too short\n",
			    program_name);
			fclose(golden);
			return -1;
		}
		name = line;
		cursor = name;
		if (split_field(&cursor) == NULL || cursor == NULL) {
			fprintf(stderr, "%s: malformed golden line %d\n",
			    program_name, i + 1);
			fclose(golden);
			return -1;
		}
		expected = cursor;
		expected[strcspn(expected, "\r\n")] = '\0';

		memset(&program, 0, sizeof(program));
		if (compile_case(&cases[i], &program, errbuf) != 0) {
			fprintf(stderr, "%s: valid case '%s' did not compile: %s\n",
			    program_name, cases[i].name, errbuf);
			fclose(golden);
			return -1;
		}
		if (strcmp(name, cases[i].name) != 0) {
			fprintf(stderr, "%s: golden case '%s' does not match '%s'\n",
			    program_name, name, cases[i].name);
			pcap_freecode(&program);
			fclose(golden);
			return -1;
		}
		actual = hex_encode_insns(program.bf_insns,
		    (unsigned)program.bf_len);
		if (actual == NULL) {
			fprintf(stderr, "%s: out of memory\n", program_name);
			pcap_freecode(&program);
			fclose(golden);
			return -1;
		}
		if (strcmp(actual, expected) != 0) {
			fprintf(stderr, "%s: case '%s' bytecode differs from the baseline\n",
			    program_name, cases[i].name);
			free(actual);
			pcap_freecode(&program);
			fclose(golden);
			return -1;
		}
		{
			struct bpf_insn *expected_insns = calloc(
			    (size_t)program.bf_len, sizeof(*expected_insns));

			if (expected_insns == NULL ||
			    hex_decode_insns(expected, expected_insns,
			    (unsigned)program.bf_len) == -1 ||
			    memcmp(program.bf_insns, expected_insns,
			    (size_t)program.bf_len *
			    sizeof(*program.bf_insns)) != 0) {
				fprintf(stderr, "%s: case '%s' bytecode differs from the baseline\n",
				    program_name, cases[i].name);
				free(expected_insns);
				free(actual);
				pcap_freecode(&program);
				fclose(golden);
				return -1;
			}
			free(expected_insns);
		}
		free(actual);
		pcap_freecode(&program);
		passed++;
	}
	fclose(golden);
	return passed;
}

static int
generate_valid_cases(const struct test_case *cases, int count)
{
	int i;

	for (i = 0; i < count; i++) {
		struct bpf_program program;
		char errbuf[PCAP_ERRBUF_SIZE];
		char *hex;

		memset(&program, 0, sizeof(program));
		if (compile_case(&cases[i], &program, errbuf) != 0) {
			fprintf(stderr, "%s: valid case '%s' did not compile: %s\n",
			    program_name, cases[i].name, errbuf);
			return -1;
		}
		hex = hex_encode_insns(program.bf_insns,
		    (unsigned)program.bf_len);
		if (hex == NULL) {
			fprintf(stderr, "%s: out of memory\n", program_name);
			pcap_freecode(&program);
			return -1;
		}
		printf("%s\t%s\n", cases[i].name, hex);
		free(hex);
		pcap_freecode(&program);
	}
	return count;
}

static int
check_invalid_cases(const struct test_case *cases, int count)
{
	int i;
	int passed = 0;

	for (i = 0; i < count; i++) {
		struct bpf_program program;
		char errbuf[PCAP_ERRBUF_SIZE];

		memset(&program, 0, sizeof(program));
		if (compile_case(&cases[i], &program, errbuf) == 0) {
			fprintf(stderr, "%s: invalid case '%s' compiled successfully\n",
			    program_name, cases[i].name);
			pcap_freecode(&program);
			return -1;
		}
		passed++;
	}
	return passed;
}

static void
free_cases(struct test_case *cases, int count)
{
	int i;

	for (i = 0; i < count; i++) {
		free(cases[i].name);
		free(cases[i].dlt_name);
		free(cases[i].expr);
	}
}

int
main(int argc, char **argv)
{
	struct test_case valid_cases[MAX_CASES];
	struct test_case invalid_cases[MAX_CASES];
	int generate = 0;
	int op;
	int valid_count;
	int invalid_count;
	int valid_passed;
	int invalid_passed;

	program_name = set_program_name(argv[0]);
	opterr = 0;
	while ((op = getopt(argc, argv, "gh")) != -1) {
		switch (op) {
		case 'g':
			generate = 1;
			break;
		case 'h':
			usage(stdout);
			/* NOTREACHED */
		default:
			usage(stderr);
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;

	if (generate) {
		if (argc != 1)
			usage(stderr);
		valid_count = read_cases(argv[0], valid_cases, MAX_CASES);
		if (valid_count < 0)
			error(EX_IOERR, "read_cases() failed");
		valid_passed = generate_valid_cases(valid_cases, valid_count);
		free_cases(valid_cases, valid_count);
		if (valid_passed < 0)
			error(EX_DATAERR, "generate_valid_cases() failed");
		exit(EX_OK);
	}

	if (argc != 3)
		usage(stderr);
	valid_count = read_cases(argv[0], valid_cases, MAX_CASES);
	if (valid_count < 0)
		error(EX_IOERR, "read_cases() failed");
	invalid_count = read_cases(argv[1], invalid_cases, MAX_CASES);
	if (invalid_count < 0)
		error(EX_IOERR, "read_cases() failed");

	valid_passed = check_valid_cases(valid_cases, valid_count, argv[2]);
	invalid_passed = check_invalid_cases(invalid_cases, invalid_count);
	free_cases(valid_cases, valid_count);
	free_cases(invalid_cases, invalid_count);
	if (valid_passed < 0 || invalid_passed < 0)
		error(EX_DATAERR, "filter validation failed");

	printf("filter validation: %d valid byte-identical, %d invalid rejected\n",
	    valid_passed, invalid_passed);
	exit(EX_OK);
}
