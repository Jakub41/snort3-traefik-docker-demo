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

#ifndef _C_CODEGEN_H
#define _C_CODEGEN_H

#include <iostream>
#include <string>
#include <stdio.h>
#include "common.h"
#include "gendata.h"
#include "vector.h"
#include "idbase.h"

using std::string;
using std::ostream;

/* Integer array line length. */
//#define IALL 8

#define IALL_INTEGRAL 8
#define IALL_STRING 128


/* Forwards. */
struct RedFsmAp;
struct RedStateAp;
struct CodeGenData;
struct GenAction;
struct NameInst;
struct GenInlineItem;
struct GenInlineList;
struct RedAction;
struct FsmLongestMatch;
struct LongestMatchPart;

string itoa( int i );

struct Variable
{
	Variable( const char *name ) : name(name), isReferenced(false) {}

	const std::string ref() { isReferenced = true; return name; }

	const char *name;
	bool isReferenced;
};

struct GotoLabel
{
	GotoLabel( const char *name ) : name(name), isReferenced(false) {}

	const std::string ref() { isReferenced = true; return name; }

	const char *name;
	bool isReferenced;
};

std::ostream &operator<<( std::ostream &out, GotoLabel &l );
std::ostream &operator<<( std::ostream &out, Variable &v );

struct TableArray;
typedef Vector<TableArray*> ArrayVector;
class CodeGen;

struct TableArray
{
	enum State {
		InitialState = 1,
		AnalyzePass,
		GeneratePass
	};

	TableArray( const char *name, CodeGen &codeGen );

	void start();
	void startAnalyze();
	void startGenerate();

	void setType( std::string type, int width, bool isChar )
	{
		this->type = type;
		this->width = width;
		this->isChar = isChar;
	}

	std::string ref();

	void value( long long v );

	void valueAnalyze( long long v );
	void valueGenerate( long long v );
	void stringGenerate( long long value );

	void finish();
	void finishAnalyze();
	void finishGenerate();

	void setState( TableArray::State state )
		{ this->state = state; }

	long long size();

	State state;
	const char *name;
	std::string type;
	int width;
	bool isSigned;
	bool isChar;
	bool stringTables;
	int iall;
	long long values;
	long long min;
	long long max;
	CodeGen &codeGen;
	std::ostream &out;
	int ln;
	bool isReferenced;
	bool started;
};

struct IlOpts
{
	IlOpts( int targState, bool inFinish, bool csForced )
		: targState(targState), inFinish(inFinish), csForced(csForced) {}

	int targState;
	bool inFinish;
	bool csForced;
};


/*
 * class CodeGen
 */
class CodeGen : public CodeGenData
{
public:
	CodeGen( const CodeGenArgs &args );

	virtual ~CodeGen() {}

	virtual void writeInit();
	virtual void writeStart();
	virtual void writeFirstFinal();
	virtual void writeError();
	virtual void statsSummary();

protected:
	friend struct TableArray;
	typedef Vector<TableArray*> ArrayVector;
	ArrayVector arrayVector;

	Variable cpc;
	Variable pop_test;
	Variable new_recs;
	Variable alt;

	string FSM_NAME();
	string START_STATE_ID();
	void taActions();
	string KEY( Key key );
	string LDIR_PATH( char *path );

	void ACTION( ostream &ret, GenAction *action, IlOpts opts );
	void NFA_CONDITION( ostream &ret, GenAction *condition, bool last );
	void NFA_POP_TEST_EXEC();
	void CONDITION( ostream &ret, GenAction *condition );
	string ALPH_TYPE();

	bool isAlphTypeSigned();
	long long tableData;
	RagelBackend backend;
	bool stringTables;
	BackendFeature backendFeature;

	TableArray nfaTargs;
	TableArray nfaOffsets;
	TableArray nfaPushActions;
	TableArray nfaPopTrans;

	virtual string GET_KEY();

	string P();
	string PE();
	string vEOF();

	string ACCESS();
	string vCS();
	string STACK();
	string TOP();
	string TOKSTART();
	string TOKEND();
	string ACT();

	string DATA_PREFIX();
	string START() { return DATA_PREFIX() + "start"; }
	string ERROR() { return DATA_PREFIX() + "error"; }
	string FIRST_FINAL() { return DATA_PREFIX() + "first_final"; }

	/* Declare a variable only if referenced. */
	void DECLARE( std::string type, Variable &var, std::string init = "" );

	string CAST( string type );

	string ARR_TYPE( const TableArray &ta )
		{ return ta.type; }

	string ARR_REF( TableArray &ta )
		{ return ta.ref(); }

	void INLINE_EXPR( ostream &ret, GenInlineList *inlineList );
	void INLINE_BLOCK( ostream &ret, GenInlineExpr *inlineExpr );
	void INLINE_PLAIN( ostream &ret, GenInlineExpr *inlineExpr );

	void INLINE_LIST( ostream &ret, GenInlineList *inlineList,
			int targState, bool inFinish, bool csForced );
	virtual void GOTO( ostream &ret, int gotoDest, bool inFinish ) = 0;
	virtual void CALL( ostream &ret, int callDest, int targState, bool inFinish ) = 0;
	virtual void NCALL( ostream &ret, int callDest, int targState, bool inFinish ) = 0;
	virtual void NEXT( ostream &ret, int nextDest, bool inFinish ) = 0;
	virtual void GOTO_EXPR( ostream &ret, GenInlineItem *ilItem, bool inFinish ) = 0;
	virtual void NEXT_EXPR( ostream &ret, GenInlineItem *ilItem, bool inFinish ) = 0;
	virtual void CALL_EXPR( ostream &ret, GenInlineItem *ilItem,
			int targState, bool inFinish ) = 0;
	virtual void NCALL_EXPR( ostream &ret, GenInlineItem *ilItem,
			int targState, bool inFinish ) = 0;
	virtual void RET( ostream &ret, bool inFinish ) = 0;
	virtual void NRET( ostream &ret, bool inFinish ) = 0;
	virtual void BREAK( ostream &ret, int targState, bool csForced ) = 0;
	virtual void NBREAK( ostream &ret, int targState, bool csForced ) = 0;
	virtual void CURS( ostream &ret, bool inFinish ) = 0;
	virtual void TARGS( ostream &ret, bool inFinish, int targState ) = 0;
	void EXEC( ostream &ret, GenInlineItem *item, int targState, int inFinish );
	void LM_SWITCH( ostream &ret, GenInlineItem *item, int targState,
			int inFinish, bool csForced );
	void LM_EXEC( ostream &ret, GenInlineItem *item, int targState, int inFinish );
	void SET_ACT( ostream &ret, GenInlineItem *item );
	void INIT_TOKSTART( ostream &ret, GenInlineItem *item );
	void INIT_ACT( ostream &ret, GenInlineItem *item );
	void SET_TOKSTART( ostream &ret, GenInlineItem *item );
	void SET_TOKEND( ostream &ret, GenInlineItem *item );
	void GET_TOKEND( ostream &ret, GenInlineItem *item );

	void HOST_STMT( ostream &ret, GenInlineItem *item, int targState, bool inFinish, bool csForced );
	void HOST_EXPR( ostream &ret, GenInlineItem *item, int targState, bool inFinish, bool csForced );
	void HOST_TEXT( ostream &ret, GenInlineItem *item, int targState, bool inFinish, bool csForced );
	void GEN_STMT( ostream &ret, GenInlineItem *item, int targState, bool inFinish, bool csForced );
	void GEN_EXPR( ostream &ret, GenInlineItem *item, int targState, bool inFinish, bool csForced );

	void STATE_IDS();

	string ERROR_STATE();
	string FIRST_FINAL_STATE();

	string STR( int v );

	void VALUE( string type, string name, string value );

	string ACCESS_OPER()
		{ return backend == Direct ? "" : " -> "; }

	string OPEN_HOST_EXPR()
		{ return backend == Direct ? "(" : "host( \"-\", 1 ) ={"; }

	string OPEN_HOST_EXPR( string fileName, int line )
	{
		return backend == Direct ? "(" : "host( \"" + fileName + "\", " + STR(line) + " ) ={";
	}

	string CLOSE_HOST_EXPR()
		{ return backend == Direct ? ")" : "}="; }

	string OPEN_HOST_BLOCK( string fileName, int line )
	{
		if ( backend == Direct ) {
			std::stringstream ss;
			ss << "{\n" ;
			(*genLineDirective)( ss, lineDirectives, line, fileName.c_str() );
			return ss.str();
		}
		else {
			return "host( \"" + fileName + "\", " + STR(line) + " ) ${";
		}
	}

	string OPEN_HOST_BLOCK( GenInlineExpr *inlineExpr )
	{
		return OPEN_HOST_BLOCK( inlineExpr->loc.fileName, inlineExpr->loc.line );
	}

	string CLOSE_HOST_BLOCK()
		{ return backend == Direct ? "}\n" : "}$"; }

	string OPEN_HOST_PLAIN()
		{ return backend == Direct ? "" : "host( \"-\", 1 ) @{"; }

	string CLOSE_HOST_PLAIN()
		{ return backend == Direct ? "" : "}@"; }

	string OPEN_GEN_EXPR()
		{ return backend == Direct ? "(" : "={"; }

	string CLOSE_GEN_EXPR()
		{ return backend == Direct ? ")" : "}="; }

	string OPEN_GEN_BLOCK()
		{ return backend == Direct ? "{" : "${"; }

	string CLOSE_GEN_BLOCK()
		{ return backend == Direct ? "}" : "}$"; }

	string OPEN_GEN_PLAIN()
		{ return backend == Direct ? "" : "@{"; }

	string CLOSE_GEN_PLAIN()
		{ return backend == Direct ? "" : "}@"; }

	string INT()
		{ return "int"; }

	string UINT()
		{ return backend == Direct ? "unsigned int" : "uint"; }

	string INDEX( string type, string name )
	{
		if ( backend == Direct )
			return "const " + type + " *" + name;
		else
			return "index " + type + " " + name;
	}

	string INDEX( string type )
	{
		if ( backend == Direct )
			return "const " + type + " *";
		else
			return "index " + type + " ";
	}

	string LABEL( string name )
	{
		return name + ": ";
	}

	string EMIT_LABEL( GotoLabel label )
	{
		if ( label.isReferenced )
			return std::string(label.name) + ": {}\n";
		else
			return "";
	}

	string OFFSET( string arr, string off )
	{
		if ( backend == Direct )
			return "( " + arr + " + (" + off + "))";
		else
			return "offset( " + arr + ", " + off + " )";
	}

	string TRUE()
	{
		if ( backend == Direct )
			return "1";
		else
			return "TRUE";
	}

	string DEREF( string arr, string off )
	{
		if ( backend == Direct )
			return "(*( " + off + "))";
		else
			return "deref( " + arr + ", " + off + " )";
	}

	string CASE( string val )
	{
		if ( backend == Direct )
			return "case " + val + ": ";
		else
			return "case " + val;
	}

	string DEFAULT()
	{
		if ( backend == Direct )
			return "default:";
		else
			return "default";
	}

	string CEND( )
	{
		if ( backend == Direct )
			return " break; ";
		else
			return " ";
	}

	string FALLTHROUGH()
	{
		if ( backend == Direct )
			return " ";
		else
			return "fallthrough;";
	}

	string NIL()
	{
		if ( backend == Direct )
			return "0";
		else
			return "nil";
	}

	string EXPORT( string type, string name, string value )
	{
		if ( backend == Direct )
			return "#define " + name + " " + value;
		else
			return "export " + type + " " + name + " " + value + ";";
	}

	void NFA_POST_POP();
	virtual void NFA_PUSH( std::string );
	virtual void NFA_POP() = 0;
	virtual void LOCATE_TRANS() {}
	virtual void LOCATE_COND() {}
	virtual void EOF_TRANS() {}


	virtual void COND_EXEC( std::string expr ) {}
	virtual void COND_BIN_SEARCH( Variable &var, TableArray &keys, std::string ok, std::string error ) {}

public:
	virtual void writeExports();
};

#endif
