/*
 * Copyright (C) 2013 Alexey Galakhov <agalakhov@gmail.com>
 * Copyright (C) 2016 Alexei Gordeev <KP1533TM2@gmail.com>
 *
 * Licensed under the GNU General Public License Version 3
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "std.h"
#include "word.h"
#include "capt-command.h"
#include "capt-status.h"
#include "generic-ops.h"
#include "hiscoa-common.h"
#include "hiscoa-compress.h"
#include "paper.h"
#include "printer.h"

#include <stdlib.h>
#include <stdio.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

uint16_t job;

struct lbp2900_ops_s {
	struct printer_ops_s ops;

	const struct capt_status_s * (*get_status) (void);
	void (*wait_ready) (void);
};

static const struct capt_status_s *lbp2900_get_status(const struct printer_ops_s *ops)
{
	const struct lbp2900_ops_s *lops = container_of(ops, struct lbp2900_ops_s, ops);
	return lops->get_status();
}

static void lbp2900_wait_ready(const struct printer_ops_s *ops)
{
	const struct lbp2900_ops_s *lops = container_of(ops, struct lbp2900_ops_s, ops);
	lops->wait_ready();
}

/* Convert ASCII string to UTF-16LE, returns number of bytes written */
static size_t ascii_to_utf16le(uint8_t *dest, const char *src, size_t max_chars)
{
	size_t i;
	size_t len = strlen(src);
	if (len > max_chars) len = max_chars;
	for (i = 0; i < len; i++) {
		dest[i * 2] = (uint8_t)src[i];     /* Low byte */
		dest[i * 2 + 1] = 0x00;            /* High byte (ASCII = 0) */
	}
	return len * 2; /* Return byte count */
}

static void send_job_start(struct printer_state_s *state, uint8_t fg, uint16_t page)
{
	(void) page;
	const char *hostname = state->options.hostname;
	const char *username = state->options.username;
	const char *doc_name = state->options.doc_name;

	/* Calculate UTF-16LE string lengths in bytes */
	uint16_t ml = (uint16_t)(strlen(hostname) * 2);
	uint16_t ul = (uint16_t)(strlen(username) * 2);
	uint16_t nl = (uint16_t)(strlen(doc_name) * 2);

	time_t rawtime = time(NULL);
	const struct tm *tm = localtime(&rawtime);
	uint16_t year = (uint16_t)(1900 + tm->tm_year);
	uint8_t month = (uint8_t)(tm->tm_mon + 1);

	/* Buffer: 32 byte header + 40 bytes reserved + strings */
	size_t bufsize = 32 + 40 + ml + ul + nl;
	uint8_t *buf = malloc(bufsize);
	if (!buf) {
		fprintf(stderr, "ERROR: CAPT: Failed to allocate job setup buffer\n");
		return;
	}
	memset(buf, 0, bufsize);

	/* Build header (72 bytes) per USB capture analysis:
	 * [0-3]   = 00 00 00 00
	 * [4]     = phase flag: 0x01=has data, 0x00=cancel/cleanup
	 * [5-7]   = 00 00 00
	 * [8-9]   = hostname length (UTF-16LE bytes, LE16)
	 * [10-11] = username length
	 * [12-13] = docname length
	 * [14-15] = 00 00
	 * [16]    = job phase: 0x01=start, 0x04=cancel, 0x06=end
	 * [17]    = 0x01 (standard print)
	 * [18-19] = job ID (LE16)
	 * [20-21] = 0x01E0 (480, resolution-related)
	 * [22-23] = 0x01A4 (420, resolution-related)
	 * [24-25] = year (LE16, e.g. 2025)
	 * [26]    = month (1-12)
	 * [27]    = day
	 * [28]    = hour
	 * [29]    = minute
	 * [30]    = second
	 * [31-71] = zero padding
	 * [72+]   = UTF-16LE strings: hostname, username, docname
	 */
	buf[0] = 0x00; buf[1] = 0x00; buf[2] = 0x00; buf[3] = 0x00;
	buf[4] = (fg == 0x04) ? 0x00 : 0x01; /* phase flag: 1=has data, 0=cancel */
	buf[5] = 0x00; buf[6] = 0x00; buf[7] = 0x00;
	buf[8] = LO(ml); buf[9] = HI(ml);     /* Hostname length (UTF-16LE bytes) */
	buf[10] = LO(ul); buf[11] = HI(ul);   /* Username length */
	buf[12] = LO(nl); buf[13] = HI(nl);   /* Doc name length */
	buf[14] = 0x00; buf[15] = 0x00;
	buf[16] = fg; buf[17] = 0x01;
	buf[18] = LO(job); buf[19] = HI(job);
	buf[20] = 0xE0; buf[21] = 0x01;       /* 480 (0x01E0) - resolution related */
	buf[22] = 0xA4; buf[23] = 0x01;       /* 420 (0x01A4) - resolution related */
	buf[24] = LO(year); buf[25] = HI(year);
	buf[26] = month;
	buf[27] = (uint8_t)tm->tm_mday;
	buf[28] = (uint8_t)tm->tm_hour;
	buf[29] = (uint8_t)tm->tm_min;
	buf[30] = (uint8_t)tm->tm_sec;
	/* buf[31..71] = 0x00 (already zeroed by memset) */

	/* Reserved area (40 bytes) at offset 32, already zeroed */

	/* Write UTF-16LE strings at offset 72 */
	size_t offset = 72;
	ascii_to_utf16le(buf + offset, hostname, 32);
	offset += ml;
	ascii_to_utf16le(buf + offset, username, 32);
	offset += ul;
	ascii_to_utf16le(buf + offset, doc_name, 64);

	fprintf(stderr, "DEBUG: CAPT: Job setup - Host: %s, User: %s, Doc: %s\n",
		hostname, username, doc_name);

	capt_sendrecv(CAPT_JOB_SETUP, buf, bufsize, NULL, 0);
	free(buf);
}

/* JOB_BEGIN magic buffer is now built dynamically in lbp2900_job_prologue
 * to support retry (first byte = previous job_id for fg=2 retry).
 * Default pattern: 00 00 1E 00 00 00 00 00 */
static const uint8_t magicbuf_0[] = {
	0x00, 0x00, 0x1E, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t magicbuf_2[] = {
	0xEE, 0xDB, 0xEA, 0xAD, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* GPIO LED control buffers - from Windows driver USB capture */
static const uint8_t blinkonbuf[] = {
	/* Blink LED on (paper out, waiting for user) */
	0x00, 0x00, 0x01, 0x02, 0x01, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
};

static const uint8_t jambuf[] = {
	/* Paper jam LED pattern (byte[2]=0x06, byte[11]=0x01).
	 * From USB capture: 00 00 06 00 00 00 00 00 00 00 00 01
	 * Different from no-paper which has: byte[2-4]=01 02 01, byte[10]=01 */
	0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
};

static const uint8_t blinkoffbuf[] = {
	/* LED off (normal operation) */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};


static void lbp2900_job_prologue(struct printer_state_s *state)
{
	(void) state;
	uint8_t buf[8];
	size_t size;

	capt_sendrecv(CAPT_IDENT, NULL, 0, NULL, 0);
	sleep(1);
	capt_init_status();
	lbp2900_get_status(state->ops);

	/* JOB_BEGIN first byte carries previous job_id for retry (fg=2),
	 * or 0 for new job. USB captures show:
	 *   New job:   00 00 1E 00 00 00 00 00
	 *   Retry:     05 00 1E 00 00 00 00 00  (05 = previous job_id) */
	uint8_t magicbuf[8] = { 0x00, 0x00, 0x1E, 0x00, 0x00, 0x00, 0x00, 0x00 };
	if (state->is_retry)
		magicbuf[0] = LO(job);

	capt_sendrecv(CAPT_START_0, NULL, 0, NULL, 0);
	capt_sendrecv(CAPT_JOB_BEGIN, magicbuf, ARRAY_SIZE(magicbuf), buf, &size);
	job=WORD(buf[2], buf[3]);

	/* Use fg=2 for retry after error recovery, fg=1 for new job.
	 * USB captures show: initial job uses fg=1, retry after
	 * out-of-paper/jam recovery uses fg=2 in JOB_SETUP. */
	uint8_t fg = state->is_retry ? 2 : 1;
	send_job_start(state, fg, 0);
	lbp2900_wait_ready(state->ops);

	/* Send RESET(0x0000) after JOB_SETUP — seen in USB captures
	 * for most normal prints between JOB_SETUP and START_1 init */
	uint8_t dummy[2] = {0x00, 0x00};
	capt_sendrecv(CAPT_RESET, dummy, sizeof(dummy), NULL, 0);

	capt_sendrecv(CAPT_GPIO, blinkoffbuf, ARRAY_SIZE(blinkoffbuf), NULL, 0);
	lbp2900_wait_ready(state->ops);

	/* Clear retry flag after job setup */
	state->is_retry = false;
}

static void lbp3000_job_prologue(struct printer_state_s *state)
{
	(void) state;
	capt_sendrecv(CAPT_IDENT, NULL, 0, NULL, 0);
	sleep(1);
	capt_init_status();
	lbp2900_get_status(state->ops);

	capt_sendrecv(CAPT_START_0, NULL, 0, NULL, 0);
	capt_sendrecv(CAPT_JOB_BEGIN, magicbuf_0, ARRAY_SIZE(magicbuf_0), NULL, 0);
	/* LBP-3000 prints the very first printjob perfectly
	 * and then proceeds to hang at this (commented out)
	 * spot. That's the difference, or so it seems. */
/*	lbp2900_wait_ready(state->ops);	*/
	send_job_start(state, 1, 0);
	
	/* There's also that command, that apparently does something, and does something, 
	 * but it's there in the Wireshark logs. Response data == command data. */
	uint8_t dummy[2] = {0, 0};
	capt_sendrecv(CAPT_RESET, dummy, sizeof(dummy), NULL, 0);
	
	lbp2900_wait_ready(state->ops);
}

/* Determine paper size code from dimensions (paper_width x paper_height in 600dpi pixels) */
static uint8_t get_paper_size_code(unsigned width, unsigned height)
{
	/*
	 * Paper size codes from SPECS file + USB capture verification:
	 * 0x02 = A4        (4960 x 7014)  [confirmed by SPECS + capture]
	 * 0x0D = Letter    (5100 x 6600)  [confirmed by SPECS: "letter=0d"]
	 * 0x0C = Legal     (5078 x 8400)  [confirmed by capture: code 0x0C]
	 * 0x04 = Executive (4350 x 6300)
	 * 0x05 = A5        (3496 x 4960)
	 * 0x06 = B5        (4298 x 6070)
	 * 0x07 = Com10     (2474 x 5700)  envelope
	 * 0x08 = Monarch   (2324 x 4500)  envelope
	 * 0x09 = C5        (3826 x 5408)  envelope
	 * 0x0A = DL        (2598 x 5196)  envelope
	 * 0x0B = Index     (1800 x 2400)  3x5 card
	 * 0x13 = Manual    (custom)       [confirmed by capture]
	 *
	 * We use width to identify since it varies more between sizes
	 */
	if (width <= 1900)                          return 0x0B; /* Index Card 3x5 */
	if (width <= 2400)                          return 0x08; /* Monarch */
	if (width <= 2550)                          return 0x0A; /* DL Envelope */
	if (width <= 2600)                          return 0x07; /* Com10 */
	if (width <= 3600)                          return 0x05; /* A5 */
	if (width <= 3900)                          return 0x09; /* C5 Envelope */
	if (width <= 4350)                          return 0x06; /* B5 */
	if (width <= 4450)                          return 0x04; /* Executive */
	if (width <= 5000)                          return 0x02; /* A4 */
	if (height <= 6700)                         return 0x0D; /* Letter */
	return 0x0C; /* Legal */
}

static bool lbp2900_page_prologue(struct printer_state_s *state, const struct page_dims_s *dims)
{
	const struct capt_status_s *status;
	size_t s;
	uint8_t buf[16];

	uint8_t paper_type = state->options.paper_type; /* 0=Plain, 1=Heavy, 2=HeavyH, 3=PlainL, 4=ohp, 5=Envelope */
	if (paper_type > 5) paper_type = 0; /* default to Plain if invalid */
	uint8_t save = state->options.toner_save ? 0x01 : 0x00;
	uint8_t pt2 = 0x01;

	/* Toner density: 1=Lightest, 2=Light, 3=Normal, 4=Dark, 5=Darkest
	 * From USB captures: only byte[8] changes, bytes[9-11] stay 0x1F.
	 * Confirmed values: Lightest=0x00, Normal=0x1F, Darkest=0x3F */
	uint8_t density_level = state->options.toner_density;
	if (density_level < 1 || density_level > 5) density_level = 3; /* default to Normal */
	static const uint8_t density_map[] = { 0x1F, 0x00, 0x10, 0x1F, 0x2F, 0x3F };
	uint8_t density = density_map[density_level];

	/* When toner save is on, captures show byte[36] changes to 0x02 */
	if (save) pt2 = 0x02;

	/* Get paper size code based on page dimensions */
	uint8_t paper_code = get_paper_size_code(dims->paper_width, dims->paper_height);
	fprintf(stderr, "DEBUG: CAPT: Paper size code 0x%02X for %ux%u pixels\n",
		paper_code, dims->paper_width, dims->paper_height);

	/* Page counter: increments per page within job (0-based) */
	uint8_t page_counter = (state->ipage > 0) ? (uint8_t)(state->ipage - 1) : 0;

	/* Page parameters (40 bytes) - matched byte-for-byte to USB captures:
	 * [0-1]   page counter (LE16, 0-based per page in job)
	 * [2-3]   magic 0x312A
	 * [4-5]   paper size code (LE16)
	 * [6-7]   reserved (0x0000)
	 * [8]     toner density (0x00=Lightest, 0x1F=Normal, 0x3F=Darkest)
	 * [9-11]  always 0x1F 0x1F 0x1F
	 * [12]    paper type (0x00=Plain, 0x01=PlainL, 0x05=Envelope)
	 * [13-18] fixed: 0x11 0x04 0x00 0x01 0x01 0x02
	 * [19]    toner save (0x00=OFF, 0x01=ON)
	 * [20-25] fixed: 0x01 0x00 0x78 0x00 0x60 0x00
	 * [26-27] line size in bytes (LE16)
	 * [28-29] num lines (LE16)
	 * [30-31] paper width pixels (LE16)
	 * [32-33] paper height pixels (LE16)
	 * [34-35] reserved (0x0000)
	 * [36]    page type extra (0x01=normal, 0x02=tonerSave)
	 * [37-39] reserved (0x000000)
	 */
	uint8_t pageparms[] = {
		page_counter, 0x00, 0x31, 0x2A, paper_code, 0x00, 0x00, 0x00,
		density, 0x1F, 0x1F, 0x1F, paper_type, 0x11, 0x04, 0x00,
		0x01, 0x01, 0x02, save, 0x01, 0x00, 0x78, 0x00,
		0x60, 0x00,
		LO(dims->line_size), HI(dims->line_size), LO(dims->num_lines), HI(dims->num_lines),
		LO(dims->paper_width), HI(dims->paper_width),
		LO(dims->paper_height), HI(dims->paper_height),
		0x00, 0x00, pt2, 0x00, 0x00, 0x00,
	};

	(void) state;

	status = lbp2900_get_status(state->ops);
	if (FLAG(status, CAPT_FL_UNINIT1) || FLAG(status, CAPT_FL_UNINIT2)) {
		capt_sendrecv(CAPT_START_1, NULL, 0, NULL, 0);
		capt_sendrecv(CAPT_START_2, NULL, 0, NULL, 0);
		capt_sendrecv(CAPT_START_3, NULL, 0, NULL, 0);

		/* FIXME: wait for printer is free (could it be potentially dangerous or really mandatory?) */
		while ( ! FLAG(lbp2900_get_status(state->ops), ((4 << 16) | (1 << 0)) ) )
		  sleep(1);
		lbp2900_get_status(state->ops);


		lbp2900_wait_ready(state->ops);
		capt_sendrecv(CAPT_UPLOAD_2, magicbuf_2, ARRAY_SIZE(magicbuf_2), NULL, 0);
		lbp2900_wait_ready(state->ops);
	}

	while (1) {
		if (! FLAG(lbp2900_get_status(state->ops), CAPT_FL_BUFFERFULL))
			break;
		sleep(1);
	}

	capt_multi_begin(CAPT_SET_PARMS);
	capt_multi_add(CAPT_SET_PARM_PAGE, pageparms, sizeof(pageparms));
	s = hiscoa_format_params(buf, sizeof(buf), &hiscoa_default_params);
	capt_multi_add(CAPT_SET_PARM_HISCOA, buf, s);
	capt_multi_add(CAPT_SET_PARM_1, NULL, 0);
	capt_multi_add(CAPT_SET_PARM_2, NULL, 0);
	capt_multi_send();

	return true;
}

static bool lbp2900_page_epilogue(struct printer_state_s *state, const struct page_dims_s *dims)
{
	(void) dims;
	const struct capt_status_s *status;

	capt_send(CAPT_PRINT_DATA_END, NULL, 0);

	/* Wait until the page is received by printer before firing.
	 * USB captures show: PRINT_DATA_END → poll status → FIRE
	 * (no JOB_SETUP between DATA_END and FIRE) */
	while (1) {
	  sleep(1);
	  status = lbp2900_get_status(state->ops);
	  if (status->page_received == status->page_decoding)
	    break;
	}

	uint8_t buf[2] = { LO(status->page_decoding), HI(status->page_decoding) };
	capt_sendrecv(CAPT_FIRE, buf, 2, NULL, 0);
	lbp2900_wait_ready(state->ops);

	/* Track the last fired page for job-end JOB_SETUP */
	state->last_fired_page = status->page_decoding;

	while (1) {
		const struct capt_status_s *status = lbp2900_get_status(state->ops);
		/* Interesting. Using page_printing here results in shifted print */
		if (status->page_out == status->page_decoding)
			return true;
		/* Paper jam / cover open: s2 bit 14 (0x4000) + s4 bit 7 (0x0080)
		 * Seen in USB captures: s2 toggles 0100→4100 with s4 toggling 0→0080 */
		if (FLAG(status, CAPT_FL_PAPERJAM) || FLAG(status, CAPT_FL_JAMERR)) {
			fprintf(stderr, "DEBUG: CAPT: paper jam or cover open detected\n");
			return false;
		}
		/* No paper: original check via NOPAPER flags */
		if (FLAG(status, CAPT_FL_NOPAPER2) || FLAG(status, CAPT_FL_NOPAPER1)) {
			fprintf(stderr, "DEBUG: CAPT: no paper\n");
			if (FLAG(status, CAPT_FL_PRINTING) || FLAG(status, CAPT_FL_PROCESSING1))
				continue;
			return false;
		}
		sleep(1);
	}
}

static void lbp2900_job_epilogue(struct printer_state_s *state)
{
	uint8_t jbuf[2] = { LO(job), HI(job) };

	/* Wait for all pages to finish printing */
	while (1) {
		const struct capt_status_s *status = lbp2900_get_status(state->ops);
		if (status->page_completed == status->page_decoding)
			break;
		sleep(1);
	}

	/* Send final JOB_SETUP with fg=6 (end marker) before JOB_END.
	 * USB captures show this appears once at the end of the job,
	 * after all pages have been fired and completed. */
	send_job_start(state, 6, state->last_fired_page);
	lbp2900_wait_ready(state->ops);

	capt_sendrecv(CAPT_JOB_END, jbuf, 2, NULL, 0);
}

static void lbp2900_page_setup(struct printer_state_s *state,
		struct page_dims_s *dims,
		unsigned width, unsigned height)
{
	/*
	 * Raster dimensions per SPECS file + USB capture verification:
	 *   A4         4736 x 6776  (line_size=592)  [capture confirmed]
	 *   Letter     4864 x 6368  (line_size=608)  [SPECS]
	 *   Legal      4864 x 8162  (line_size=608)  [capture confirmed]
	 *   Executive  4128 x 6080  (line_size=516)
	 *   A5         3392 x 4736  (line_size=424)
	 *   B5         4096 x 5824  (line_size=512)
	 *   Index 3x5  1344 x 2528  (line_size=168)
	 *
	 * Paper width determines line_size:
	 *   width <= 4960 (A4/smaller) → 4736 pixels → 592 bytes
	 *   width > 4960 (Letter/Legal) → 4864 pixels → 608 bytes
	 *
	 * Max num_lines = paper_height - 238 pixel margin (10mm)
	 */
	unsigned max_raster_width;
	unsigned max_lines;

	(void) state;
	dims->band_size = 70;

	/* Select raster width based on paper width */
	if (dims->paper_width > 4960) {
		/* Letter, Legal, and wider sizes */
		max_raster_width = 4864;
	} else if (dims->paper_width > 4350) {
		/* A4 and B5 range */
		max_raster_width = 4736;
	} else if (dims->paper_width > 3600) {
		/* Executive range */
		max_raster_width = 4128;
	} else if (dims->paper_width > 2600) {
		/* A5 range */
		max_raster_width = 3392;
	} else if (dims->paper_width > 1900) {
		/* Envelope range */
		max_raster_width = 2400;
	} else {
		/* Index card range */
		max_raster_width = 1344;
	}

	dims->line_size = max_raster_width / 8;

	/* Max lines = paper height pixels minus ~238 pixel margin */
	if (dims->paper_height > 238)
		max_lines = dims->paper_height - 238;
	else
		max_lines = dims->paper_height;

	if (height > max_lines)
		dims->num_lines = max_lines;
	else
		dims->num_lines = height;

	/* Ensure width doesn't exceed raster width */
	if (width > max_raster_width)
		width = max_raster_width;
}

static void lbp2900_wait_user(struct printer_state_s *state)
{
	const struct capt_status_s *status;

	/* Determine error type and use appropriate GPIO LED pattern.
	 * From USB capture analysis:
	 *   Paper jam:  GPIO 00 00 06 00 00 00 00 00 00 00 00 01
	 *   No paper:   GPIO 00 00 01 02 01 00 00 00 00 00 01 00
	 * Both are followed by CAPT_RESET(0x0000) during error wait */
	status = lbp2900_get_status(state->ops);
	if (FLAG(status, CAPT_FL_PAPERJAM) || FLAG(status, CAPT_FL_JAMERR)) {
		fprintf(stderr, "DEBUG: CAPT: signaling paper jam via GPIO\n");
		capt_sendrecv(CAPT_GPIO, jambuf, ARRAY_SIZE(jambuf), NULL, 0);
	} else {
		fprintf(stderr, "DEBUG: CAPT: signaling no paper via GPIO\n");
		capt_sendrecv(CAPT_GPIO, blinkonbuf, ARRAY_SIZE(blinkonbuf), NULL, 0);
	}
	lbp2900_wait_ready(state->ops);

	/* Send CAPT_RESET(0x0000) - seen in USB captures during both
	 * paper jam and no-paper error recovery sequences */
	uint8_t dummy[2] = {0x00, 0x00};
	capt_sendrecv(CAPT_RESET, dummy, sizeof(dummy), NULL, 0);

	/* Wait for error to be cleared (paper loaded / jam fixed / cover closed).
	 * USB captures show: PAPERJAM (s2 bit 14) clears, goes through
	 * COVEROPEN (s2 bit 12) transitionally, then s2=0 when fully clear.
	 * For no-paper: nERROR (s2 bit 7) is the signal for button/ready. */
	while (1) {
		status = lbp2900_get_status(state->ops);
		/* Check if jam/cover error has cleared */
		if (!FLAG(status, CAPT_FL_PAPERJAM) && !FLAG(status, CAPT_FL_JAMERR)
		    && !FLAG(status, CAPT_FL_COVEROPEN)) {
			/* For jam recovery: s2 goes 4100→1000→0000 (all clear) */
			fprintf(stderr, "DEBUG: CAPT: error cleared\n");
			break;
		}
		if (FLAG(status, CAPT_FL_BUTTON)) {
			fprintf(stderr, "DEBUG: CAPT: button pressed\n");
		}
		if (FLAG(status, CAPT_FL_nERROR)) {
			fprintf(stderr, "DEBUG: CAPT: virtual button pressed\n");
			break;
		}
		sleep(1);
	}

	/* Turn off LED */
	capt_sendrecv(CAPT_GPIO, blinkoffbuf, ARRAY_SIZE(blinkoffbuf), NULL, 0);
	lbp2900_wait_ready(state->ops);

	/* Re-initialize printer after error recovery.
	 * USB captures show full re-init after GPIO_off:
	 *   START_1 → START_2 → START_3 → UPLOAD_2(DEADBEEF) */
	capt_sendrecv(CAPT_START_1, NULL, 0, NULL, 0);
	capt_sendrecv(CAPT_START_2, NULL, 0, NULL, 0);
	capt_sendrecv(CAPT_START_3, NULL, 0, NULL, 0);
	capt_sendrecv(CAPT_UPLOAD_2, magicbuf_2, ARRAY_SIZE(magicbuf_2), NULL, 0);
	lbp2900_wait_ready(state->ops);
}

static void lbp2900_cancel_job(struct printer_state_s *state)
{
	uint8_t jbuf[2] = { LO(job), HI(job) };

	/* USB capture shows cancel sequence:
	 * JOB_SETUP fg=4 (cancel) → START_2 → JOB_END
	 * fg=4 sets buf[4]=0x00 (no data flag) */
	fprintf(stderr, "DEBUG: CAPT: sending cancel (fg=4) to printer\n");
	send_job_start(state, 4, 0);
	lbp2900_wait_ready(state->ops);

	capt_sendrecv(CAPT_START_2, NULL, 0, NULL, 0);
	lbp2900_wait_ready(state->ops);

	capt_sendrecv(CAPT_JOB_END, jbuf, 2, NULL, 0);
}

static struct lbp2900_ops_s lbp2900_ops = {
	.ops = {
		.job_prologue = lbp2900_job_prologue,
		.job_epilogue = lbp2900_job_epilogue,
		.page_setup = lbp2900_page_setup,
		.page_prologue = lbp2900_page_prologue,
		.page_epilogue = lbp2900_page_epilogue,
		.compress_band = ops_compress_band_hiscoa,
		.send_band = ops_send_band_hiscoa,
		.wait_user = lbp2900_wait_user,
		.cancel_job = lbp2900_cancel_job,
	},
	.get_status = capt_get_xstatus,
	.wait_ready = capt_wait_ready,
};

static struct lbp2900_ops_s lbp3000_ops = {
	.ops = {
		.job_prologue = lbp3000_job_prologue,	/* different job prologue */
		.job_epilogue = lbp2900_job_epilogue,
		.page_setup = lbp2900_page_setup,
		.page_prologue = lbp2900_page_prologue,
		.page_epilogue = lbp2900_page_epilogue,
		.compress_band = ops_compress_band_hiscoa,
		.send_band = ops_send_band_hiscoa,
		.wait_user = lbp2900_wait_user,
		.cancel_job = lbp2900_cancel_job,
	},
	.get_status = capt_get_xstatus,
	.wait_ready = capt_wait_ready,
};

register_printer("LBP2900", lbp2900_ops.ops, WORKS);
register_printer("LBP3000", lbp3000_ops.ops, EXPERIMENTAL);

static struct lbp2900_ops_s lbp3010_ops = {
	.ops = {
		.job_prologue = lbp2900_job_prologue,
		.job_epilogue = lbp2900_job_epilogue,
		.page_setup = lbp2900_page_setup,
		.page_prologue = lbp2900_page_prologue,
		.page_epilogue = lbp2900_page_epilogue,
		.compress_band = ops_compress_band_hiscoa,
		.send_band = ops_send_band_hiscoa,
		.wait_user = lbp2900_wait_user,
		.cancel_job = lbp2900_cancel_job,
	},
	.get_status = capt_get_xstatus_only,
	.wait_ready = capt_wait_xready_only,
};

register_printer("LBP3010/LBP3018/LBP3050", lbp3010_ops.ops, EXPERIMENTAL);
