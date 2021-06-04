/*
 * Copyright 2010-2018 Adrian Thurston <thurston@colm.net>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <colm/debug.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include <colm/program.h>

const char *const colm_realm_names[REALMS] =
	// @NOTE: keep this in sync with 'main.cc': 'processArgs()' '-D' option
	{
		"BYTECODE",
		"PARSE",
		"MATCH",
		"COMPILE",
		"POOL",
		"PRINT",
		"INPUT",
		"SCAN",
	};

int _debug( struct colm_program *prg, long realm, const char *fmt, ... )
{
	int result = 0;
	if ( prg->active_realm & realm ) {
		/* Compute the index by shifting. */
		int ind = 0;
		while ( (realm & 0x1) != 0x1 ) {
			realm >>= 1;
			ind += 1;
		}

		fprintf( stderr, "%s: ", colm_realm_names[ind] );
		va_list args;
		va_start( args, fmt );
		result = vfprintf( stderr, fmt, args );
		va_end( args );
	}

	return result;
}

void fatal( const char *fmt, ... )
{
	va_list args;
	fprintf( stderr, "fatal: " );
	va_start( args, fmt );
	vfprintf( stderr, fmt, args );
	va_end( args );
	exit(1);
}

void message( const char *fmt, ... )
{
	va_list args;
	fprintf( stderr, "message: " );
	va_start( args, fmt );
	vfprintf( stderr, fmt, args );
	va_end( args );
}
