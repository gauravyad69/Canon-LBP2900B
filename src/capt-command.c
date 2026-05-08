/*
 * Copyright (C) 2013 Alexey Galakhov <agalakhov@gmail.com>
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

#define _DEFAULT_SOURCE  /* For usleep() */

#include "capt-command.h"

#include "std.h"
#include "word.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <cups/cups.h>
#include <cups/sidechannel.h>

#define CAPT_MAX_RETRIES 3
#define CAPT_RETRY_DELAY_MS 500
#define CAPT_RESPONSE_TIMEOUT_SEC 8
#define CAPT_DRAIN_HEADER_TIMEOUT_SEC 0.05

enum capt_read_result {
	CAPT_READ_OK = 1,
	CAPT_READ_TIMEOUT = 0,
	CAPT_READ_ERROR = -1,
};

static uint8_t capt_iobuf[0x10000];
static size_t  capt_iosize;

static void capt_debug_buf(const char *level, size_t size)
{
	size_t i;
	if (size > capt_iosize)
		size = capt_iosize;
	for (i = 0; i < size; ++i) {
		if (i != 0 && (i % 16) == 0)
			fprintf(stderr, "\n%s: CAPT:", level);
		fprintf(stderr, " %02X", capt_iobuf[i]);
	}
	if (size < capt_iosize)
		fprintf(stderr, "... (%u more)", (unsigned) (capt_iosize - size));
	fprintf(stderr, "\n");
}

static void capt_send_buf(void)
{
	const uint8_t *iopos = capt_iobuf;
	size_t iosize = capt_iosize;

	if (debug) {
		fprintf(stderr, "DEBUG: CAPT: send ");
		capt_debug_buf("DEBUG", 128);
	}

	while (iosize) {
		cups_sc_status_t status;
		uint8_t tmpbuf[128];
		size_t tmpsize = sizeof(tmpbuf);
		size_t sendsize = iosize;
		if (sendsize > 4096)
			sendsize = 4096;

		fwrite(iopos, 1, sendsize, stdout);
		iopos += sendsize;
		iosize -= sendsize;
		fflush(stdout);

		status = cupsSideChannelDoRequest(CUPS_SC_CMD_DRAIN_OUTPUT,
				(char *) tmpbuf, (int *) &tmpsize, 1.0);
		if (status != CUPS_SC_STATUS_OK) {
			if (status == CUPS_SC_STATUS_TIMEOUT) {
				/* Overcome race conditions in usb backend */
				if (debug)
					fprintf(stderr, "DEBUG: CAPT: output already empty, not drained\n");
			} else {
				fprintf(stderr, "ERROR: CAPT: no reply from backend, err=%i\n",
					(int) status);
				exit(0);
			}
		}
	}
}

static enum capt_read_result capt_read_exact(size_t offset, size_t expected,
		double timeout, int max_retries)
{
	ssize_t size;
	int retry = 0;
	size_t received = 0;

	if (offset + expected > sizeof(capt_iobuf)) {
		fprintf(stderr, "ALERT: bug in CAPT driver, input buffer overflow\n");
		exit(1);
	}

	while (received < expected) {
		if (debug) {
			fprintf(stderr, "DEBUG: CAPT: waiting for %u bytes\n",
				(unsigned) (expected - received));
		}
		size = cupsBackChannelRead((char *) capt_iobuf + offset + received,
			expected - received, timeout);

		if (size > 0) {
			received += (size_t) size;
			retry = 0;
			continue;
		}

		if (retry >= max_retries) {
			return (size == 0) ? CAPT_READ_TIMEOUT : CAPT_READ_ERROR;
		}
		retry += 1;
		if (debug) {
			if (size < 0)
				fprintf(stderr, "DEBUG: CAPT: read error (size=%zd), will retry\n", size);
			else
				fprintf(stderr, "DEBUG: CAPT: no data received, will retry\n");
		}
		usleep(CAPT_RETRY_DELAY_MS * 1000);
	}

	capt_iosize = offset + received;
	return CAPT_READ_OK;
}

static enum capt_read_result capt_recv_frame(uint16_t *cmd_out,
		double header_timeout, double body_timeout, int max_retries)
{
	enum capt_read_result ret;
	unsigned size;
	unsigned size_bcd;

	ret = capt_read_exact(0, 4, header_timeout, max_retries);
	if (ret != CAPT_READ_OK)
		return ret;

	size = WORD(capt_iobuf[2], capt_iobuf[3]);
	size_bcd = BCD(capt_iobuf[2], capt_iobuf[3]);
	if (size < 4 || size > sizeof(capt_iobuf)) {
		if (size_bcd >= 4 && size_bcd <= sizeof(capt_iobuf))
			size = size_bcd;
		else {
			fprintf(stderr, "ERROR: CAPT: bad reply size %u\n", (unsigned) size);
			return CAPT_READ_ERROR;
		}
	}

	if (size > 4) {
		ret = capt_read_exact(4, size - 4, body_timeout, max_retries);
		if (ret != CAPT_READ_OK)
			return ret;
	}

	capt_iosize = size;
	if (cmd_out)
		*cmd_out = WORD(capt_iobuf[0], capt_iobuf[1]);
	return CAPT_READ_OK;
}

static void capt_drain_pending(void)
{
	while (1) {
		uint16_t cmd;
		enum capt_read_result ret = capt_recv_frame(&cmd,
			CAPT_DRAIN_HEADER_TIMEOUT_SEC,
			CAPT_RESPONSE_TIMEOUT_SEC, 0);
		if (ret != CAPT_READ_OK)
			break;
		if (debug)
			fprintf(stderr, "DEBUG: CAPT: drained frame %04X (%u bytes)\n",
				cmd, (unsigned) capt_iosize);
	}
}

const char *capt_identify(void)
{
	while (1) {
		cups_sc_status_t status;
		capt_iosize = sizeof(capt_iobuf) - 1;
		status = cupsSideChannelDoRequest(CUPS_SC_CMD_GET_DEVICE_ID,
				(char *) capt_iobuf, (int *) &capt_iosize, 60.0);
		if (status != CUPS_SC_STATUS_OK) {
			fprintf(stderr, "ERROR: CAPT: unable to communicate with printer\n");
			exit(0);
		}
		capt_iobuf[capt_iosize] = '\0';
		fprintf(stderr, "DEBUG: CAPT: printer ID string %s\n", capt_iobuf);
		if (capt_iosize)
			return (const char*) capt_iobuf;
		sleep(1);
	}
}

static void capt_copy_cmd(uint16_t cmd, const void *buf, size_t size)
{
	if (capt_iosize + 4 + size > sizeof(capt_iobuf)) {
		fprintf(stderr, "ALERT: bug in CAPT driver, output buffer overflow\n");
		exit(1);
	}
	if (buf)
		memcpy(capt_iobuf + capt_iosize + 4, buf, size);
	else
		size = 0;
	capt_iobuf[capt_iosize + 0] = LO(cmd);
	capt_iobuf[capt_iosize + 1] = HI(cmd);
	capt_iobuf[capt_iosize + 2] = LO(size + 4);
	capt_iobuf[capt_iosize + 3] = HI(size + 4);
	capt_iosize += size + 4;
}

void capt_send(uint16_t cmd, const void *buf, size_t size)
{
	capt_iosize = 0;
	capt_copy_cmd(cmd, buf, size);
	capt_send_buf();
}

bool capt_sendrecv(uint16_t cmd, const void *buf, size_t size, void *reply, size_t *reply_size)
{
	int retry;

	for (retry = 0; retry <= CAPT_MAX_RETRIES; retry++) {
		time_t start;
		if (retry > 0) {
			fprintf(stderr, "DEBUG: CAPT: sendrecv retry %d/%d for cmd %04X\n",
				retry, CAPT_MAX_RETRIES, cmd);
			usleep(CAPT_RETRY_DELAY_MS * 1000);
		}

		capt_send(cmd, buf, size);
		start = time(NULL);
		while (1) {
			uint16_t rcmd;
			enum capt_read_result ret = capt_recv_frame(&rcmd,
				CAPT_RESPONSE_TIMEOUT_SEC,
				CAPT_RESPONSE_TIMEOUT_SEC,
				CAPT_MAX_RETRIES);
			if (ret != CAPT_READ_OK)
				break;

			if (rcmd == cmd) {
				if (debug) {
					fprintf(stderr, "DEBUG: CAPT: recv ");
					capt_debug_buf("DEBUG", capt_iosize);
				}
				if (reply) {
					size_t copysize = reply_size ? *reply_size : capt_iosize;
					if (copysize > capt_iosize)
						copysize = capt_iosize;
					memcpy(reply, capt_iobuf + 4, copysize);
				}
				if (reply_size)
					*reply_size = capt_iosize;
				capt_drain_pending();
				return true;
			}

			if (debug)
				fprintf(stderr, "DEBUG: CAPT: ignoring unsolicited frame %04X (%u bytes)\n",
					rcmd, (unsigned) capt_iosize);
			if ((time(NULL) - start) >= CAPT_RESPONSE_TIMEOUT_SEC)
				break;
		}
	}

	fprintf(stderr, "ERROR: CAPT: no reply from printer after %d retries for cmd %04X\n",
		CAPT_MAX_RETRIES, cmd);
	return false;
}

void capt_multi_begin(uint16_t cmd)
{
	capt_iobuf[0] = LO(cmd);
	capt_iobuf[1] = HI(cmd);
	capt_iosize = 4;
}

void capt_multi_add(uint16_t cmd, const void *buf, size_t size)
{
	capt_copy_cmd(cmd, buf, size);
}

void capt_multi_send(void)
{
	capt_iobuf[2] = LO(capt_iosize);
	capt_iobuf[3] = HI(capt_iosize);
	capt_send_buf();
}
