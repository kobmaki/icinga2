/******************************************************************************
 * Icinga 2                                                                   *
 * Copyright (C) 2012-2015 Icinga Development Team (http://www.icinga.org)    *
 *                                                                            *
 * This program is free software; you can redistribute it and/or              *
 * modify it under the terms of the GNU General Public License                *
 * as published by the Free Software Foundation; either version 2             *
 * of the License, or (at your option) any later version.                     *
 *                                                                            *
 * This program is distributed in the hope that it will be useful,            *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of             *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the              *
 * GNU General Public License for more details.                               *
 *                                                                            *
 * You should have received a copy of the GNU General Public License          *
 * along with this program; if not, write to the Free Software Foundation     *
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.             *
 ******************************************************************************/

#include "remote/base64.hpp"
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <sstream>

using namespace icinga;

String Base64::Encode(const String& data)
{
	BIO *bio64 = BIO_new(BIO_f_base64());
	BIO *bio = BIO_new(BIO_s_mem());
	bio = BIO_push(bio64, bio); //ties bio64 into bio

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //No newlines please

	BIO_write(bio, data.CStr(), data.GetLength());
	BIO_flush(bio);

	BUF_MEM *biobuf;
	BIO_get_mem_ptr(bio, &biobuf);
	BIO_set_close(bio, BIO_NOCLOSE); // BIO_free_all now leaves biobuf alone
	BIO_free_all(bio);

	String ret;

	//There has to be a more elegant way
	for (;;) {
		char chbuf[512];
		int p = BIO_read(bio, chbuf, 511);
		if (p <= 0)
			break;
		chbuf[p] = '\0';
		ret += String(chbuf);
	}

	return ret;
}

static int DecodeLen(const String& data)
{
	int dl = data.GetLength();

	if (data[dl - 1] != '=')
		return dl * 3 / 4;
	if (data[dl - 2] != '=')
		return dl * 3 / 4 - 1;
	return dl * 3 / 4 - 2;
}

String Base64::Decode(const String& data)
{
	BIO *bio64 = BIO_new(BIO_f_base64());

	char *inbuf = new char[data.GetLength()];
	inbuf = const_cast<char*>(data.CStr());

	BIO *bio = BIO_new_mem_buf(inbuf, data.GetLength());
	bio = BIO_push(bio64, bio); //ties bio64 into bio

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //No newlines please

	//TODO: Cool lambda magic
	char chbuf[DecodeLen(data)];
	BIO_read(bio, chbuf, data.GetLength());
	BIO_free_all(bio);
	delete[] inbuf;

	return String(chbuf);
}
