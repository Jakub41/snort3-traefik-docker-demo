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

#include "codegen.h"
#include "ragel.h"
#include "redfsm.h"
#include "gendata.h"
#include "parsedata.h"
#include <sstream>
#include <string>
#include <assert.h>
#include <iomanip>


using std::ostream;
using std::ostringstream;
using std::string;
using std::endl;
using std::istream;
using std::ifstream;
using std::ostream;
using std::ios;
using std::cin;
using std::endl;

std::ostream &operator<<( std::ostream &out, Variable &v )
{
	out << v.name;
	v.isReferenced = true;
	return out;
}

std::ostream &operator<<( std::ostream &out, GotoLabel &l )
{
	out << l.name;
	l.isReferenced = true;
	return out;
}

TableArray::TableArray( const char *name, CodeGen &codeGen )
:
	state(InitialState),
	name(name),
	width(0),
	isSigned(true),
	isChar(false),
	stringTables( codeGen.stringTables ),
	iall( codeGen.stringTables ? IALL_STRING : IALL_INTEGRAL ),
	values(0),

	/*
	 * Use zero for min and max because 
	 * we we null terminate every array.
	 */
	min(0),
	max(0),

	codeGen(codeGen),
	out(codeGen.out),
	ln(0),
	isReferenced(false),
	started(false)
{
	codeGen.arrayVector.append( this );
}

std::string TableArray::ref()
{
	isReferenced = true;
	return string("_") + codeGen.DATA_PREFIX() + name;
}

long long TableArray::size()
{
	return width * values;
}

void TableArray::startAnalyze()
{
}

void TableArray::valueAnalyze( long long v )
{
	values += 1;
	if ( v < min )
		min = v;
	if ( v > max )
		max = v;
}

void TableArray::finishAnalyze()
{
	if ( codeGen.backend == Direct ) {
		/* Calculate the type if it is not already set. */
		if ( type.empty() ) {
			if ( min >= S8BIT_MIN && max <= S8BIT_MAX ) {
				type = "signed char";
				width = sizeof(char);
			}
			else if ( min >= S16BIT_MIN && max <= S16BIT_MAX ) {
				type = "short";
				width = sizeof(short);
			}
			else if ( min >= S32BIT_MIN && max <= S32BIT_MAX ) {
				type = "int";
				width = sizeof(int);
			}
			else if ( min >= S64BIT_MAX && max <= S64BIT_MAX ) {
				type = "long";
				width = sizeof(long);
			}
			else  {
				type = "long long";
				width = sizeof(long long);
			}
		}
	}
	else {
		/* Calculate the type if it is not already set. */
		if ( type.empty() ) {
			if ( min >= S8BIT_MIN && max <= S8BIT_MAX ) {
				type = "s8";
				width = sizeof(char);
			}
			else if ( min >= S16BIT_MIN && max <= S16BIT_MAX ) {
				type = "s16";
				width = sizeof(short);
			}
			else if ( min >= S32BIT_MIN && max <= S32BIT_MAX ) {
				type = "s32";
				width = sizeof(int);
			}
			else if ( min >= S64BIT_MAX && max <= S64BIT_MAX ) {
				type = "s64";
				width = sizeof(long);
			}
			else  {
				type = "s128";
				width = sizeof(long long);
			}
		}
	}
}

void TableArray::startGenerate()
{
	if ( codeGen.backend == Direct ) {
		if ( stringTables ) {
			out << "static const char S_" << codeGen.DATA_PREFIX() << name <<
				"[] __attribute__((aligned (16))) = \n\t\"";
		}
		else {
			out << "static const " << type << " " << 
				"_" << codeGen.DATA_PREFIX() << name << 
				"[] = {\n\t";
		}
	}
	else {
		out << "array " << type << " " << 
			"_" << codeGen.DATA_PREFIX() << name << 
			"( " << min << ", " << max << " ) = { ";
	}
}

void TableArray::stringGenerate( long long value )
{
	char c; 
	short h;
	int i;
#if SIZEOF_INT != SIZEOF_LONG
	long l;
#endif
	unsigned char *p = 0;
	int n = 0;
	switch ( width ) {
		case sizeof( char ):
			c = value;
			p = (unsigned char *)&c;
			n = sizeof(char);
			break;
		case sizeof( short ):
			h = value;
			p = (unsigned char *)&h;
			n = sizeof(short);
			break;
		case sizeof( int ):
			i = value;
			p = (unsigned char *)&i;
			n = sizeof(int);
			break;
#if SIZEOF_INT != SIZEOF_LONG
		case sizeof( long ):
			l = value;
			p = (unsigned char *)&l;
			n = sizeof(long);
			break;
#endif
	}

	std::ios_base::fmtflags prevFlags = out.flags( std::ios::hex );
	int prevFill = out.fill( '0' );

	while ( n-- > 0 ) {
		out << '\\';
		out << 'x';
		out << std::setw(2) << (unsigned int) *p++;
	}

	out.flags( prevFlags );
	out.fill( prevFill );
}

void TableArray::valueGenerate( long long v )
{
	if ( codeGen.backend == Direct ) {
		if ( stringTables ) {
			stringGenerate( v );

			if ( ++ln % iall == 0 ) {
				out << "\"\n\t\"";
				ln = 0;
			}
		}
		else {
			if ( isChar )
				out << "c(" << v << ")";
			else if ( !isSigned )
				out << v << "u";
			else
				out << v;

			if ( ( ++ln % iall ) == 0 ) {
				out << ",\n\t";
				ln = 0;
			}
			else {
				out << ", ";
			}
		}
	}
	else {
		if ( isChar )
			out << "c(" << v << ")";
		else if ( !isSigned )
			out << "u(" << v << ")";
		else
			out << v;
		out << ", ";
	}
}

void TableArray::finishGenerate()
{
	if ( codeGen.backend == Direct ) {
		if ( stringTables ) {
	        out << "\";\nconst " << type << " *_" << codeGen.DATA_PREFIX() << name <<
	                " = (const " << type << "*) S_" << codeGen.DATA_PREFIX() << name << ";\n\n";

		}
		else {
			if ( isChar )
				out << "c(0)\n};\n\n";
			else if ( !isSigned )
				out << "0u\n};\n\n";
			else
				out << "0\n};\n\n";
		}
	}
	else {
		if ( isChar )
			out << "c(0) };\n\n";
		else if ( !isSigned )
			out << "u(0) };\n\n";
		else
			out << "0 };\n\n";
	}

	if ( codeGen.red->id->printStatistics ) {
		codeGen.red->id->stats() << name << "\t" << values << "\t" <<
			size() << "\t" << endl;
	}

	codeGen.tableData += size();
}

void TableArray::start()
{
	assert( !started );
	started = true;
	switch ( state ) {
		case InitialState:
			break;
		case AnalyzePass:
			startAnalyze();
			break;
		case GeneratePass:
			if ( isReferenced )
				startGenerate();
			break;
	}
}

void TableArray::value( long long v )
{
	assert( started );
	switch ( state ) {
		case InitialState:
			break;
		case AnalyzePass:
			valueAnalyze( v );
			break;
		case GeneratePass:
			if ( isReferenced )
				valueGenerate( v );
			break;
	}
}

void TableArray::finish()
{
	assert( started );
	started = false;
	switch ( state ) {
		case InitialState:
			break;
		case AnalyzePass:
			finishAnalyze();
			break;
		case GeneratePass:
			if ( isReferenced )
				finishGenerate();
			break;
	}
}

/* Init code gen with in parameters. */
CodeGen::CodeGen( const CodeGenArgs &args )
:
	CodeGenData( args ),
	cpc( "_cpc" ),
	pop_test( "_pop_test" ),
	new_recs( "new_recs" ),
	alt( "_alt" ),
	tableData( 0 ),
	backend( args.id->hostLang->backend ),
	stringTables( args.id->stringTables ),

	nfaTargs(         "nfa_targs",           *this ),
	nfaOffsets(       "nfa_offsets",         *this ),
	nfaPushActions(   "nfa_push_actions",    *this ),
	nfaPopTrans(      "nfa_pop_trans",       *this )
{
}

void CodeGen::statsSummary()
{
	if ( red->id->printStatistics )
		red->id->stats() << "table-data\t\t" << tableData << endl << endl;
}


string CodeGen::CAST( string type )
{
	if ( backend == Direct )
		return "(" + type + ")";
	else
		return "cast(" + type + ")";
}

/* Write out the fsm name. */
string CodeGen::FSM_NAME()
{
	return fsmName;
}

/* Emit the offset of the start state as a decimal integer. */
string CodeGen::START_STATE_ID()
{
	ostringstream ret;
	ret << redFsm->startState->id;
	return ret.str();
};


string CodeGen::ACCESS()
{
	ostringstream ret;
	if ( red->accessExpr != 0 ) {
		ret << OPEN_HOST_PLAIN();
		INLINE_LIST( ret, red->accessExpr, 0, false, false );
		ret << CLOSE_HOST_PLAIN();
		ret << ACCESS_OPER();
	}
	return ret.str();
}


string CodeGen::P()
{ 
	ostringstream ret;
	if ( red->pExpr == 0 )
		ret << "p";
	else {
		ret << OPEN_HOST_EXPR();
		INLINE_LIST( ret, red->pExpr, 0, false, false );
		ret << CLOSE_HOST_EXPR();
	}
	return ret.str();
}

string CodeGen::PE()
{
	ostringstream ret;
	if ( red->peExpr == 0 )
		ret << "pe";
	else {
		ret << OPEN_HOST_EXPR();
		INLINE_LIST( ret, red->peExpr, 0, false, false );
		ret << CLOSE_HOST_EXPR();
	}
	return ret.str();
}

string CodeGen::vEOF()
{
	ostringstream ret;
	if ( red->eofExpr == 0 )
		ret << "eof";
	else {
		ret << OPEN_HOST_EXPR();
		INLINE_LIST( ret, red->eofExpr, 0, false, false );
		ret << CLOSE_HOST_EXPR();
	}
	return ret.str();
}

string CodeGen::vCS()
{
	ostringstream ret;
	if ( red->csExpr == 0 )
		ret << ACCESS() << "cs";
	else {
		/* Emit the user supplied method of retrieving the key. */
		ret << OPEN_HOST_EXPR();
		INLINE_LIST( ret, red->csExpr, 0, false, false );
		ret << CLOSE_HOST_EXPR();
	}
	return ret.str();
}

string CodeGen::TOP()
{
	ostringstream ret;
	if ( red->topExpr == 0 )
		ret << ACCESS() + "top";
	else {
		ret << OPEN_HOST_EXPR();
		INLINE_LIST( ret, red->topExpr, 0, false, false );
		ret << CLOSE_HOST_EXPR();
	}
	return ret.str();
}

string CodeGen::STACK()
{
	ostringstream ret;
	if ( red->stackExpr == 0 )
		ret << ACCESS() + "stack";
	else {
		ret << OPEN_HOST_EXPR();
		INLINE_LIST( ret, red->stackExpr, 0, false, false );
		ret << CLOSE_HOST_EXPR();
	}
	return ret.str();
}

string CodeGen::ACT()
{
	ostringstream ret;
	if ( red->actExpr == 0 )
		ret << ACCESS() + "act";
	else {
		ret << OPEN_HOST_EXPR();
		INLINE_LIST( ret, red->actExpr, 0, false, false );
		ret << CLOSE_HOST_EXPR();
	}
	return ret.str();
}

string CodeGen::TOKSTART()
{
	ostringstream ret;
	if ( red->tokstartExpr == 0 )
		ret << ACCESS() + "ts";
	else {
		ret << OPEN_HOST_EXPR();
		INLINE_LIST( ret, red->tokstartExpr, 0, false, false );
		ret << CLOSE_HOST_EXPR();
	}
	return ret.str();
}

string CodeGen::TOKEND()
{
	ostringstream ret;
	if ( red->tokendExpr == 0 )
		ret << ACCESS() + "te";
	else {
		ret << OPEN_HOST_EXPR();
		INLINE_LIST( ret, red->tokendExpr, 0, false, false );
		ret << CLOSE_HOST_EXPR();
	}
	return ret.str();
}

string CodeGen::GET_KEY()
{
	ostringstream ret;
	if ( red->getKeyExpr != 0 ) { 
		/* Emit the user supplied method of retrieving the key. */
		ret << OPEN_HOST_EXPR();
		INLINE_LIST( ret, red->getKeyExpr, 0, false, false );
		ret << CLOSE_HOST_EXPR();
	}
	else {
		/* Expression for retrieving the key, use simple dereference. */
		ret << "( " << DEREF( "data", P() ) << ")";
	}
	return ret.str();
}

/* Write out a key from the fsm code gen. Depends on wether or not the key is
 * signed. */
string CodeGen::KEY( Key key )
{
	if ( backend == Direct ) {
		ostringstream ret;
		if ( alphType->isChar )
			ret << "c(" << (unsigned long) key.getVal() << ")";
		else if ( keyOps->isSigned || !keyOps->explicitUnsigned )
			ret << key.getVal();
		else
			ret << (unsigned long) key.getVal() << "u";
		return ret.str();
	}
	else {
		ostringstream ret;
		if ( alphType->isChar )
			ret << "c(" << (unsigned long) key.getVal() << ")";
		else if ( keyOps->isSigned || !keyOps->explicitUnsigned )
			ret << key.getVal();
		else
			ret << "u(" << (unsigned long) key.getVal() << ")";
		return ret.str();
	}
}

bool CodeGen::isAlphTypeSigned()
{
	return keyOps->isSigned;
}

void CodeGen::DECLARE( std::string type, Variable &var, std::string init )
{
	if ( var.isReferenced )
		out << type << " " << var.name << init << ";\n";
}

void CodeGen::EXEC( ostream &ret, GenInlineItem *item, int targState, int inFinish )
{
	/* The parser gives fexec two children. The double brackets are for D
	 * code. If the inline list is a single word it will get interpreted as a
	 * C-style cast by the D compiler. */
	ret << OPEN_GEN_BLOCK() << P() << " = ((";
	INLINE_LIST( ret, item->children, targState, inFinish, false );
	ret << "))-1;" << CLOSE_GEN_BLOCK() << "\n";
}

void CodeGen::LM_SWITCH( ostream &ret, GenInlineItem *item, 
		int targState, int inFinish, bool csForced )
{
	ret << 
		OPEN_GEN_BLOCK() << "switch( " << ACT() << " ) {\n";

	for ( GenInlineList::Iter lma = *item->children; lma.lte(); lma++ ) {
		/* Write the case label, the action and the case break. */
		if ( lma->lmId < 0 )
			ret << "	" << DEFAULT() << " {\n";
		else
			ret << "	" << CASE( STR(lma->lmId) ) << " {\n";

		/* Write the block and close it off. */
		INLINE_LIST( ret, lma->children, targState, inFinish, csForced );

		ret << CEND() << "\n}\n";
	}

	ret << 
		"	}" << CLOSE_GEN_BLOCK() << "\n"
		"\t";
}

void CodeGen::LM_EXEC( ostream &ret, GenInlineItem *item, int targState, int inFinish )
{
	/* The parser gives fexec two children. The double brackets are for D
	 * code. If the inline list is a single word it will get interpreted as a
	 * C-style cast by the D compiler. This should be in the D code generator. */
	ret << P() << " = ((";
	INLINE_LIST( ret, item->children, targState, inFinish, false );
	ret << "))-1;\n";
}

void CodeGen::SET_ACT( ostream &ret, GenInlineItem *item )
{
	ret << ACT() << " = " << item->lmId << ";";
}

void CodeGen::SET_TOKEND( ostream &ret, GenInlineItem *item )
{
	/* The tokend action sets tokend. */
	ret << TOKEND() << " = " << P();
	if ( item->offset != 0 ) 
		out << "+" << item->offset;
	out << ";";
}

void CodeGen::GET_TOKEND( ostream &ret, GenInlineItem *item )
{
	ret << TOKEND();
}

void CodeGen::INIT_TOKSTART( ostream &ret, GenInlineItem *item )
{
	ret << TOKSTART() << " = " << NIL() << ";";
}

void CodeGen::INIT_ACT( ostream &ret, GenInlineItem *item )
{
	ret << ACT() << " = 0;";
}

void CodeGen::SET_TOKSTART( ostream &ret, GenInlineItem *item )
{
	ret << TOKSTART() << " = " << P() << ";";
}

void CodeGen::HOST_STMT( ostream &ret, GenInlineItem *item, 
		int targState, bool inFinish, bool csForced )
{
	if ( item->children->length() > 0 ) {
		/* Write the block and close it off. */
		ret << OPEN_HOST_BLOCK( item->loc.fileName, item->loc.line );
		INLINE_LIST( ret, item->children, targState, inFinish, csForced );
		ret << CLOSE_HOST_BLOCK();
	}
}

#if 0
void CodeGen::LM_CASE( ostream &ret, GenInlineItem *item, 
		int targState, bool inFinish, bool csForced )
{
	if ( item->children->length() > 0 ) {
		/* Write the block and close it off. */
		INLINE_LIST( ret, item->children, targState, inFinish, csForced );
	}
}
#endif

void CodeGen::HOST_EXPR( ostream &ret, GenInlineItem *item, 
		int targState, bool inFinish, bool csForced )
{
	if ( item->children->length() > 0 ) {
		/* Write the block and close it off. */
		ret << OPEN_HOST_EXPR();
		INLINE_LIST( ret, item->children, targState, inFinish, csForced );
		ret << CLOSE_HOST_EXPR();
	}
}

void CodeGen::HOST_TEXT( ostream &ret, GenInlineItem *item, 
		int targState, bool inFinish, bool csForced )
{
	if ( item->children->length() > 0 ) {
		/* Write the block and close it off. */
		ret << OPEN_HOST_PLAIN();
		INLINE_LIST( ret, item->children, targState, inFinish, csForced );
		ret << CLOSE_HOST_PLAIN();
	}
}

void CodeGen::GEN_STMT( ostream &ret, GenInlineItem *item, 
		int targState, bool inFinish, bool csForced )
{
	if ( item->children->length() > 0 ) {
		/* Write the block and close it off. */
		ret << OPEN_GEN_BLOCK();
		INLINE_LIST( ret, item->children, targState, inFinish, csForced );
		ret << CLOSE_GEN_BLOCK();
	}
}

void CodeGen::GEN_EXPR( ostream &ret, GenInlineItem *item, 
		int targState, bool inFinish, bool csForced )
{
	if ( item->children->length() > 0 ) {
		/* Write the block and close it off. */
		ret << OPEN_GEN_EXPR();
		INLINE_LIST( ret, item->children, targState, inFinish, csForced );
		ret << CLOSE_GEN_EXPR();
	}
}

void CodeGen::INLINE_EXPR( ostream &ret, GenInlineList *inlineList )
{
	ret << OPEN_HOST_EXPR();
	INLINE_LIST( ret, inlineList, 0, false, false );
	ret << CLOSE_HOST_EXPR();
}

void CodeGen::INLINE_BLOCK( ostream &ret, GenInlineExpr *inlineExpr )
{
	out << OPEN_HOST_BLOCK( inlineExpr );
	INLINE_LIST( out, inlineExpr->inlineList, 0, false, false );
	out << CLOSE_HOST_BLOCK();
}

void CodeGen::INLINE_PLAIN( ostream &ret, GenInlineExpr *inlineExpr )
{

}

/* Write out an inline tree structure. Walks the list and possibly calls out
 * to virtual functions than handle language specific items in the tree. */
void CodeGen::INLINE_LIST( ostream &ret, GenInlineList *inlineList, 
		int targState, bool inFinish, bool csForced )
{
	for ( GenInlineList::Iter item = *inlineList; item.lte(); item++ ) {
		switch ( item->type ) {
		case GenInlineItem::Text:
			if ( backend == Direct )
				ret << item->data;
			else
				translatedHostData( ret, item->data );
			break;
		case GenInlineItem::Goto:
			GOTO( ret, item->targState->id, inFinish );
			break;
		case GenInlineItem::Call:
			CALL( ret, item->targState->id, targState, inFinish );
			break;
		case GenInlineItem::Ncall:
			NCALL( ret, item->targState->id, targState, inFinish );
			break;
		case GenInlineItem::Next:
			NEXT( ret, item->targState->id, inFinish );
			break;
		case GenInlineItem::Ret:
			RET( ret, inFinish );
			break;
		case GenInlineItem::Nret:
			NRET( ret, inFinish );
			break;
		case GenInlineItem::PChar:
			ret << P();
			break;
		case GenInlineItem::Char:
			ret << OPEN_GEN_EXPR() << GET_KEY() << CLOSE_GEN_EXPR();
			break;
		case GenInlineItem::Hold:
			ret << OPEN_GEN_BLOCK() << P() << " = " << P() << " - 1; " << CLOSE_GEN_BLOCK();
			break;
		case GenInlineItem::LmHold:
			ret << P() << " = " << P() << " - 1;";
			break;
		case GenInlineItem::NfaClear:
			ret << "nfa_len = 0; ";
			break;
		case GenInlineItem::Exec:
			EXEC( ret, item, targState, inFinish );
			break;
		case GenInlineItem::Curs:
			CURS( ret, inFinish );
			break;
		case GenInlineItem::Targs:
			TARGS( ret, inFinish, targState );
			break;
		case GenInlineItem::Entry:
			ret << item->targState->id;
			break;
		case GenInlineItem::GotoExpr:
			GOTO_EXPR( ret, item, inFinish );
			break;
		case GenInlineItem::CallExpr:
			CALL_EXPR( ret, item, targState, inFinish );
			break;
		case GenInlineItem::NcallExpr:
			NCALL_EXPR( ret, item, targState, inFinish );
			break;
		case GenInlineItem::NextExpr:
			NEXT_EXPR( ret, item, inFinish );
			break;
		case GenInlineItem::LmSwitch:
			LM_SWITCH( ret, item, targState, inFinish, csForced );
			break;
		case GenInlineItem::LmExec:
			LM_EXEC( ret, item, targState, inFinish );
			break;
		case GenInlineItem::LmCase:
			/* Not encountered here, in the lm switch. */
			break;
		case GenInlineItem::LmSetActId:
			SET_ACT( ret, item );
			break;
		case GenInlineItem::LmSetTokEnd:
			SET_TOKEND( ret, item );
			break;
		case GenInlineItem::LmGetTokEnd:
			GET_TOKEND( ret, item );
			break;
		case GenInlineItem::LmInitTokStart:
			INIT_TOKSTART( ret, item );
			break;
		case GenInlineItem::LmInitAct:
			INIT_ACT( ret, item );
			break;
		case GenInlineItem::LmSetTokStart:
			SET_TOKSTART( ret, item );
			break;
		case GenInlineItem::Break:
			BREAK( ret, targState, csForced );
			break;
		case GenInlineItem::Nbreak:
			NBREAK( ret, targState, csForced );
			break;
		case GenInlineItem::HostStmt:
			HOST_STMT( ret, item, targState, inFinish, csForced );
			break;
		case GenInlineItem::HostExpr:
			HOST_EXPR( ret, item, targState, inFinish, csForced );
			break;
		case GenInlineItem::HostText:
			HOST_TEXT( ret, item, targState, inFinish, csForced );
			break;
		case GenInlineItem::GenStmt:
			GEN_STMT( ret, item, targState, inFinish, csForced );
			break;
		case GenInlineItem::GenExpr:
			GEN_EXPR( ret, item, targState, inFinish, csForced );
			break;
		/* These should not be encountered. We handle these Nfa wraps at the top level. */
		case GenInlineItem::NfaWrapAction:
		case GenInlineItem::NfaWrapConds:
			break;
		}
	}
}

/* Write out paths in line directives. Escapes any special characters. */
string CodeGen::LDIR_PATH( char *path )
{
	ostringstream ret;
	for ( char *pc = path; *pc != 0; pc++ ) {
		if ( *pc == '\\' )
			ret << "\\\\";
		else
			ret << *pc;
	}
	return ret.str();
}

void CodeGen::ACTION( ostream &ret, GenAction *action, IlOpts opts )
{
	ret << '\t';
	ret << OPEN_HOST_BLOCK( action->loc.fileName, action->loc.line );
	INLINE_LIST( ret, action->inlineList, opts.targState, opts.inFinish, opts.csForced );
	ret << CLOSE_HOST_BLOCK();
	ret << "\n";
	genOutputLineDirective( ret );
}

void CodeGen::CONDITION( ostream &ret, GenAction *condition )
{
	ret << OPEN_HOST_EXPR( condition->loc.fileName, condition->loc.line );
	INLINE_LIST( ret, condition->inlineList, 0, false, false );
	ret << CLOSE_HOST_EXPR();
	ret << "\n";
	genOutputLineDirective( ret );
}

void CodeGen::NFA_CONDITION( ostream &ret, GenAction *condition, bool last )
{
	if ( condition->inlineList->length() == 1 &&
			condition->inlineList->head->type == 
			GenInlineItem::NfaWrapAction )
	{
		GenAction *action = condition->inlineList->head->wrappedAction;
		ACTION( out, action, IlOpts( 0, false, false ) );
	}
	else if ( condition->inlineList->length() == 1 &&
			condition->inlineList->head->type == 
			GenInlineItem::NfaWrapConds )
	{
		ret <<
			"	" << cpc << " = 0;\n";

		GenCondSpace *condSpace = condition->inlineList->head->condSpace;
		for ( GenCondSet::Iter csi = condSpace->condSet; csi.lte(); csi++ ) {
			ret <<
				"	if ( ";
			CONDITION( out, *csi );
			Size condValOffset = (1 << csi.pos());
			ret << " ) " << cpc << " += " << condValOffset << ";\n";
		}

		const CondKeySet &keys = condition->inlineList->head->condKeySet;
		if ( keys.length() > 0 ) {
			ret << pop_test << " = ";
			for ( CondKeySet::Iter cki = keys; cki.lte(); cki++ ) {
				ret << "" << cpc << " == " << *cki;
				if ( !cki.last() )
					ret << " || ";
			}
			ret << ";\n";
		}
		else {
			ret << pop_test << " = 0;\n";
		}

		if ( !last ) {
			ret <<
				"if ( !" << pop_test << " )\n"
				"	break;\n";
		}
	}
	else {
		ret << pop_test << " = ";
		CONDITION( ret, condition );
		ret << ";\n";

		if ( !last ) {
			ret <<
				"if ( !" << pop_test << " )\n"
				"	break;\n";
		}
	}
}

void CodeGen::NFA_POP_TEST_EXEC()
{
	out << 
		"		" << pop_test << " = 1;\n"
		"		switch ( nfa_bp[nfa_len].popTrans ) {\n";

	/* Loop the actions. */
	for ( GenActionTableMap::Iter redAct = redFsm->actionMap;
			redAct.lte(); redAct++ )
	{
		if ( redAct->numNfaPopTestRefs > 0 ) {
			/* Write the entry label. */
			out << "\t " << CASE( STR( redAct->actListId+1 ) ) << " {\n";

			/* Write each action in the list of action items. */
			for ( GenActionTable::Iter item = redAct->key; item.lte(); item++ )
				NFA_CONDITION( out, item->value, item.last() );

			out << CEND() << "\n}\n";
		}
	}

	out <<
		"		}\n"
		"\n";
}


string CodeGen::ERROR_STATE()
{
	ostringstream ret;
	if ( redFsm->errState != 0 )
		ret << redFsm->errState->id;
	else
		ret << "-1";
	return ret.str();
}

string CodeGen::FIRST_FINAL_STATE()
{
	ostringstream ret;
	if ( redFsm->firstFinState != 0 )
		ret << redFsm->firstFinState->id;
	else
		ret << redFsm->nextStateId;
	return ret.str();
}

void CodeGen::writeInit()
{
	out << "	{\n";

	if ( !noCS )
		out << "\t" << vCS() << " = " << CAST("int") << START() << ";\n";

	if ( redFsm->anyNfaStates() )
		out << "\t" << "nfa_len = 0;\n";
	
	/* If there are any calls, then the stack top needs initialization. */
	if ( redFsm->anyActionCalls() || redFsm->anyActionNcalls() ||
			redFsm->anyActionRets() || redFsm->anyActionNrets() )
	{
		out << "\t" << TOP() << " = 0;\n";
	}

	if ( red->hasLongestMatch ) {
		out << 
			"	" << TOKSTART() << " = " << NIL() << ";\n"
			"	" << TOKEND() << " = " << NIL() << ";\n";

		if ( redFsm->usingAct() ) {
			out << 
				"	" << ACT() << " = 0;\n";
		}
	}
	out << "	}\n";
}

string CodeGen::DATA_PREFIX()
{
	if ( !noPrefix )
		return FSM_NAME() + "_";
	return "";
}

/* Emit the alphabet data type. */
string CodeGen::ALPH_TYPE()
{
	string ret = alphType->data1;
	if ( alphType->data2 != 0 ) {
		ret += " ";
		ret += + alphType->data2;
	}
	return ret;
}

void CodeGen::VALUE( string type, string name, string value )
{
	if ( backend == Direct )
		out << "static const " << type << " " << name << " = " << value << ";\n";
	else
		out << "value " << type << " " << name << " = " << value << ";\n";
}

string CodeGen::STR( int v )
{
	ostringstream s;
	s << v;
	return s.str();
}

void CodeGen::STATE_IDS()
{
	if ( redFsm->startState != 0 )
		VALUE( "int",  START(), START_STATE_ID() );

	if ( !noFinal )
		VALUE( "int", FIRST_FINAL(), FIRST_FINAL_STATE() );

	if ( !noError )
		VALUE( "int", ERROR(), ERROR_STATE() );

	out << "\n";

	if ( red->entryPointNames.length() > 0 ) {
		for ( EntryNameVect::Iter en = red->entryPointNames; en.lte(); en++ ) {
			string name = DATA_PREFIX() + "en_" + *en;
			VALUE( "int", name, STR( red->entryPointIds[en.pos()] ) );
		}
		out << "\n";
	}
}

void CodeGen::writeStart()
{
	out << START_STATE_ID();
}

void CodeGen::writeFirstFinal()
{
	out << FIRST_FINAL_STATE();
}

void CodeGen::writeError()
{
	out << ERROR_STATE();
}

void CodeGen::writeExports()
{
	if ( red->exportList.length() > 0 ) {
		for ( ExportList::Iter ex = red->exportList; ex.lte(); ex++ ) {
			out << EXPORT( ALPH_TYPE(), 
				DATA_PREFIX() + "ex_" + ex->name, KEY(ex->key) ) << "\n";
		}
		out << "\n";
	}
}

void CodeGen::NFA_PUSH( std::string state )
{
	if ( redFsm->anyNfaStates() ) {
		out <<
			"	if ( " << ARR_REF( nfaOffsets ) << "[" << state << "] != 0 ) {\n"
			"		" << alt << " = 0; \n"
			"		" << new_recs << " = " << CAST("int") << ARR_REF( nfaTargs ) << "[" << CAST("int") <<
						ARR_REF( nfaOffsets ) << "[" << state << "]];\n";

		if ( red->nfaPrePushExpr != 0 ) {
			out << OPEN_HOST_BLOCK( red->nfaPrePushExpr );
			INLINE_LIST( out, red->nfaPrePushExpr->inlineList, 0, false, false );
			out << CLOSE_HOST_BLOCK();
			out << "\n";
			genOutputLineDirective( out );
		}

		out <<
			"		while ( " << alt << " < " << new_recs << " ) { \n";


		out <<
			"			nfa_bp[nfa_len].state = " << CAST("int") << ARR_REF( nfaTargs ) << "[" << CAST("int") <<
							ARR_REF( nfaOffsets ) << "[" << state << "] + 1 + " << alt << "];\n"
			"			nfa_bp[nfa_len].p = " << P() << ";\n";

		if ( redFsm->bAnyNfaPops ) {
			out <<
				"			nfa_bp[nfa_len].popTrans = " << ARR_REF( nfaPopTrans ) << "[" << CAST("long") <<
								ARR_REF( nfaOffsets ) << "[" << state << "] + 1 + " << alt << "];\n"
				"\n"
				;
		}

		if ( redFsm->bAnyNfaPushes ) {
			out <<
				"			switch ( " << ARR_REF( nfaPushActions ) << "[" << CAST("int") <<
								ARR_REF( nfaOffsets ) << "[" << state << "] + 1 + " << alt << "] ) {\n";

			/* Loop the actions. */
			for ( GenActionTableMap::Iter redAct = redFsm->actionMap;
					redAct.lte(); redAct++ )
			{
				if ( redAct->numNfaPushRefs > 0 ) {
					/* Write the entry label. */
					out << "\t " << CASE( STR( redAct->actListId+1 ) ) << " {\n";

					/* Write each action in the list of action items. */
					for ( GenActionTable::Iter item = redAct->key; item.lte(); item++ )
						ACTION( out, item->value, IlOpts( 0, false, false ) );

					out << "\n\t" << CEND() << "\n}\n";
				}
			}

			out <<
				"			}\n";
		}


		out <<
			"			nfa_len += 1;\n"
			"			" << alt << " += 1;\n"
			"		}\n"
			"	}\n"
			;
	}
}

void CodeGen::NFA_POST_POP()
{
	if ( red->nfaPostPopExpr != 0 ) {
		out << OPEN_HOST_BLOCK( red->nfaPostPopExpr );
		INLINE_LIST( out, red->nfaPostPopExpr->inlineList, 0, false, false );
		out << CLOSE_HOST_BLOCK();
	}
}
