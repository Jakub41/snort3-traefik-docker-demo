/*
 * Copyright 2001-2018 Adrian Thurston <thurston@colm.net>
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

#ifndef _GVDOTGEN_H
#define _GVDOTGEN_H

#include <iostream>
#include "gendata.h"


class GraphvizDotGen : public RedBase
{
public:
	GraphvizDotGen( FsmGbl *id, FsmCtx *fsmCtx, FsmAp *fsm,
			std::string fsmName, int machineId, std::ostream &out )
	:
		RedBase(id, fsmCtx, fsm, fsmName, machineId),
		out(out)
	{}

	bool makeNameInst( std::string &res, NameInst *nameInst );
	void action( ActionTable *actionTable );
	void transAction( StateAp *fromState, TransData *trans );
	void key( Key key );
	void condSpec( CondSpace *condSpace, long condVals );
	void onChar( Key lowKey, Key highKey, CondSpace *condSpace, long condVals );
	void transList( StateAp *state );
	void write();
	void fromStateAction( StateAp *fromState );
	
	ostream &out;
};

#endif
