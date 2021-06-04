/*
 * Copyright 2014-2018 Adrian Thurston <thurston@colm.net>
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

#include "ragel.h"
#include "asm.h"
#include "redfsm.h"
#include "gendata.h"
#include "bstmap.h"
#include "ragel.h"
#include "redfsm.h"
#include "bstmap.h"
#include "gendata.h"
#include "parsedata.h"
#include <sstream>

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

extern int numSplitPartitions;
bool printStatistics = false;

/* Enables transition logging in the form that score-based state sorting can
 * processes. This bit of code is intended to increase locality and reduce
 * cache misses. Gains are minimal, 1-2%. */
// #define LOG_TRANS 1

void asmLineDirective( ostream &out, const char *fileName, int line )
{
	/* Write the preprocessor line info for to the input file. */
	out << "#line " << line  << " \"";
	for ( const char *pc = fileName; *pc != 0; pc++ ) {
		if ( *pc == '\\' )
			out << "\\\\";
		else
			out << *pc;
	}
	out << '"';

	out << '\n';
}

/* Init code gen with in parameters. */
AsmCodeGen::AsmCodeGen( const CodeGenArgs &args )
:
	CodeGenData( args ),
	nextLmSwitchLabel( 1 ),
	stackCS( false )
{
}

void AsmCodeGen::genAnalysis()
{
	/* For directly executable machines there is no required state
	 * ordering. Choose a depth-first ordering to increase the
	 * potential for fall-throughs. */
	redFsm->depthFirstOrdering();

	/* Choose default transitions and make the flat transitions by character class. */
	redFsm->chooseDefaultSpan();
	redFsm->makeFlatClass();
		
	/* If any errors have occured in the input file then don't write anything. */
	if ( red->id->errorCount > 0 )
		return;
	
	redFsm->setInTrans();

	/* Anlayze Machine will find the final action reference counts, among other
	 * things. We will use these in reporting the usage of fsm directives in
	 * action code. */
	red->analyzeMachine();
}

/* Write out the fsm name. */
string AsmCodeGen::FSM_NAME()
{
	return fsmName;
}

/* Emit the offset of the start state as a decimal integer. */
string AsmCodeGen::START_STATE_ID()
{
	ostringstream ret;
	ret << redFsm->startState->id;
	return ret.str();
};

string AsmCodeGen::ACCESS()
{
	ostringstream ret;
	if ( red->accessExpr != 0 )
		INLINE_LIST( ret, red->accessExpr, 0, false, false );
	return ret.str();
}


string AsmCodeGen::P()
{ 
	ostringstream ret;
	if ( red->pExpr == 0 )
		ret << "%r12";
	else {
		INLINE_LIST( ret, red->pExpr, 0, false, false );
	}
	return ret.str();
}

string AsmCodeGen::PE()
{
	ostringstream ret;
	if ( red->peExpr == 0 )
		ret << "%r13";
	else {
		INLINE_LIST( ret, red->peExpr, 0, false, false );
	}
	return ret.str();
}

string AsmCodeGen::vCS()
{
	ostringstream ret;
	if ( red->csExpr == 0 ) {
		if ( stackCS )
			ret << "-48(%rbp)";
		else
			ret << "%r11";
	}
	else {
		INLINE_LIST( ret, red->csExpr, 0, false, false );
	}
	return ret.str();
}

string AsmCodeGen::TOP()
{
	ostringstream ret;
	if ( red->topExpr == 0 )
		ret << "-64(%rbp)";
	else {
		ret << "(";
		INLINE_LIST( ret, red->topExpr, 0, false, false );
		ret << ")";
	}
	return ret.str();
}

string AsmCodeGen::NFA_STACK()
{
	return string( "-80(%rbp)" );
}

string AsmCodeGen::NFA_TOP()
{
	return string( "-88(%rbp)" );
}

string AsmCodeGen::NFA_SZ()
{
	return string( "-96(%rbp)" );
}

string AsmCodeGen::STACK()
{
	ostringstream ret;
	if ( red->stackExpr == 0 )
		ret << "-56(%rbp)";
	else {
		ret << "(";
		INLINE_LIST( ret, red->stackExpr, 0, false, false );
		ret << ")";
	}
	return ret.str();
}

string AsmCodeGen::vEOF()
{
	ostringstream ret;
	if ( red->eofExpr == 0 )
		ret << "-8(%rbp)";
	else {
		INLINE_LIST( ret, red->eofExpr, 0, false, false );
	}
	return ret.str();
}

string AsmCodeGen::TOKSTART()
{
	ostringstream ret;
	if ( red->tokstartExpr == 0 )
		ret << "-16(%rbp)";
	else {
		INLINE_LIST( ret, red->tokstartExpr, 0, false, false );
	}
	return ret.str();
}

string AsmCodeGen::TOKEND()
{
	ostringstream ret;
	if ( red->tokendExpr == 0 )
		ret << "-24(%rbp)";
	else {
		INLINE_LIST( ret, red->tokendExpr, 0, false, false );
	}
	return ret.str();
}

string AsmCodeGen::ACT()
{
	ostringstream ret;
	if ( red->actExpr == 0 )
		ret << "-32(%rbp)";
	else {
		INLINE_LIST( ret, red->actExpr, 0, false, false );
	}
	return ret.str();
}

string AsmCodeGen::NBREAK()
{
	return string("-33(%rbp)");
}

string AsmCodeGen::GET_KEY()
{
	ostringstream ret;
	if ( red->getKeyExpr != 0 ) { 
		/* Emit the user supplied method of retrieving the key. */
		ret << "(";
		INLINE_LIST( ret, red->getKeyExpr, 0, false, false );
		ret << ")";
	}
	else {
		/* Expression for retrieving the key, use simple dereference. */
		ret << "(" << P() << ")";
	}
	return ret.str();
}

string AsmCodeGen::COND_KEY( CondKey key )
{
	ostringstream ret;
	ret << "$" << key.getVal();
	return ret.str();
}


/* Write out a key from the fsm code gen. Depends on wether or not the key is
 * signed. */
string AsmCodeGen::KEY( Key key )
{
	ostringstream ret;
	ret << "$" << key.getVal();
	return ret.str();
}

bool AsmCodeGen::isAlphTypeSigned()
{
	return keyOps->isSigned;
}

void AsmCodeGen::EXEC( ostream &ret, GenInlineItem *item, int targState, int inFinish )
{
	/* The parser gives fexec two children. The double brackets are for D
	 * code. If the inline list is a single word it will get interpreted as a
	 * C-style cast by the D compiler. */

	ret <<
		"	subq	$1, ";
	INLINE_LIST( ret, item->children, targState, inFinish, false );
	ret <<
		"\n"
		"	movq	";
	INLINE_LIST( ret, item->children, targState, inFinish, false );
	ret << ", " << P() << "\n";
}

void AsmCodeGen::LM_SWITCH( ostream &ret, GenInlineItem *item, 
		int targState, int inFinish, bool csForced )
{
	long done = nextLmSwitchLabel++;

	ret << 
		"	movq	" << ACT() << ", %rax\n";

	for ( GenInlineList::Iter lma = *item->children; lma.lte(); lma++ ) {
		long l = nextLmSwitchLabel++;

		/* Write the case label, the action and the case break. */
		if ( lma->lmId < 0 ) {
		}
		else {
			ret <<
				"	cmpq	$" << lma->lmId << ", %rax\n"
				"	jne		" << LABEL( "lm_switch_next", l ) << "\n";
		}

		INLINE_LIST( ret, lma->children, targState, inFinish, csForced );

		ret <<
			"	jmp		" << LABEL( "lm_done", done ) << "\n"
			"" << LABEL( "lm_switch_next", l ) << ":\n";
	}

	ret << 
		"" << LABEL( "lm_done", done ) << ":\n";
}

void AsmCodeGen::SET_ACT( ostream &ret, GenInlineItem *item )
{
	ret <<
		"	movq	$" << item->lmId << ", " << ACT() << "\n";
}

void AsmCodeGen::SET_TOKEND( ostream &ret, GenInlineItem *item )
{
	/* Sets tokend, there may be an offset. */
	ret <<
		"	movq	" << P() << ", %rax\n";

	if ( item->offset != 0 ) {
		out <<
			"	addq	$" << item->offset << ", %rax\n";
	}

	out <<
		"	movq	%rax, " << TOKEND() << "\n";
}

void AsmCodeGen::GET_TOKEND( ostream &ret, GenInlineItem *item )
{
	ret <<
		"	movq	" << TOKEND() << ", " << "%rax\n";
}

void AsmCodeGen::INIT_TOKSTART( ostream &ret, GenInlineItem *item )
{
	ret <<
		"	movq	$0, " << TOKSTART() << "\n";
}

void AsmCodeGen::INIT_ACT( ostream &ret, GenInlineItem *item )
{
	ret <<
		"	movq	$0, " << ACT() << "\n";
}

void AsmCodeGen::SET_TOKSTART( ostream &ret, GenInlineItem *item )
{
	ret <<
		"	movq	" << P() << ", " << TOKSTART() << "\n";
}

void AsmCodeGen::HOST_STMT( ostream &ret, GenInlineItem *item, 
		int targState, bool inFinish, bool csForced )
{
	if ( item->children->length() > 0 ) {
		/* Write the block and close it off. */
		INLINE_LIST( ret, item->children, targState, inFinish, csForced );
	}
}

void AsmCodeGen::HOST_EXPR( ostream &ret, GenInlineItem *item, 
		int targState, bool inFinish, bool csForced )
{
	if ( item->children->length() > 0 ) {
		/* Write the block and close it off. */
		INLINE_LIST( ret, item->children, targState, inFinish, csForced );
	}
}

void AsmCodeGen::HOST_TEXT( ostream &ret, GenInlineItem *item, 
		int targState, bool inFinish, bool csForced )
{
	if ( item->children->length() > 0 ) {
		/* Write the block and close it off. */
		INLINE_LIST( ret, item->children, targState, inFinish, csForced );
	}
}

void AsmCodeGen::GEN_STMT( ostream &ret, GenInlineItem *item, 
		int targState, bool inFinish, bool csForced )
{
	if ( item->children->length() > 0 ) {
		/* Write the block and close it off. */
		INLINE_LIST( ret, item->children, targState, inFinish, csForced );
	}
}

void AsmCodeGen::GEN_EXPR( ostream &ret, GenInlineItem *item, 
		int targState, bool inFinish, bool csForced )
{
	if ( item->children->length() > 0 ) {
		/* Write the block and close it off. */
		INLINE_LIST( ret, item->children, targState, inFinish, csForced );
	}
}

void AsmCodeGen::LM_EXEC( ostream &ret, GenInlineItem *item, int targState, int inFinish )
{
	/* The parser gives fexec two children. The double brackets are for D code.
	 * If the inline list is a single word it will get interpreted as a C-style
	 * cast by the D compiler. This should be in the D code generator. */
	INLINE_LIST( ret, item->children, targState, inFinish, false );

	ret <<
		"	movq	%rax, " << P() << "\n"
		"	subq	$1, " << P() << "\n";
}

void AsmCodeGen::NBREAK( ostream &ret, int targState, bool csForced )
{
	outLabelUsed = true;
	ret << 
		"	addq	$1, " << P() << "\n";

	if ( !csForced ) {
		ret <<
			"	movq	$" << targState << ", " << vCS() << "\n";
	}

	ret <<
		"	movb	$1, " << NBREAK() << "\n"
		"	jmp		" << LABEL( "pop" ) << "\n";
}

/* Write out an inline tree structure. Walks the list and possibly calls out
 * to virtual functions than handle language specific items in the tree. */
void AsmCodeGen::INLINE_LIST( ostream &ret, GenInlineList *inlineList, 
		int targState, bool inFinish, bool csForced )
{
	for ( GenInlineList::Iter item = *inlineList; item.lte(); item++ ) {
		switch ( item->type ) {
		case GenInlineItem::Text:
			ret << item->data;
			break;
		case GenInlineItem::Goto:
			GOTO( ret, item->targState->id, inFinish );
			break;
		case GenInlineItem::Call:
			CALL( ret, item->targState->id, targState, inFinish );
			break;
		case GenInlineItem::Next:
			NEXT( ret, item->targState->id, inFinish );
			break;
		case GenInlineItem::Ret:
			RET( ret, inFinish );
			break;
		case GenInlineItem::PChar:
			ret << P();
			break;
		case GenInlineItem::Char:
			ret << GET_KEY();
			break;
		case GenInlineItem::Hold:
			ret <<
				"	subq	$1, " << P() << "\n";
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
		case GenInlineItem::NextExpr:
			NEXT_EXPR( ret, item, inFinish );
			break;
		case GenInlineItem::LmSwitch:
			LM_SWITCH( ret, item, targState, inFinish, csForced );
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
		/* Stubbed. */
		case GenInlineItem::Ncall:
			NCALL( ret, item->targState->id, targState, inFinish );
			break;
		case GenInlineItem::NcallExpr:
			NCALL_EXPR( ret, item, targState, inFinish );
			break;
		case GenInlineItem::Nret:
			NRET( ret, inFinish );
			break;
		case GenInlineItem::Nbreak:
			NBREAK( ret, targState, csForced );
			break;
		case GenInlineItem::LmCase:
			break;

		case GenInlineItem::LmExec:
			LM_EXEC( ret, item, targState, inFinish );
			break;

		case GenInlineItem::LmHold:
			ret <<
				"	subq	$1, " << P() << "\n";
			break;
		case GenInlineItem::NfaClear:
			ret <<
				"	movq	$0, " << NFA_TOP() << "\n";
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
		/* Handled at the top level. */
		case GenInlineItem::NfaWrapAction:
		case GenInlineItem::NfaWrapConds:
			break;
		}
	}
}
/* Write out paths in line directives. Escapes any special characters. */
string AsmCodeGen::LDIR_PATH( char *path )
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

void AsmCodeGen::ACTION( ostream &ret, GenAction *action, int targState, 
		bool inFinish, bool csForced )
{
	/* Write the preprocessor line info for going into the source file. */
	asmLineDirective( ret, action->loc.fileName, action->loc.line );

	/* Write the block and close it off. */
	INLINE_LIST( ret, action->inlineList, targState, inFinish, csForced );
}

void AsmCodeGen::CONDITION( ostream &ret, GenAction *condition )
{
	ret << "\n";
	asmLineDirective( ret, condition->loc.fileName, condition->loc.line );
	INLINE_LIST( ret, condition->inlineList, 0, false, false );
}

bool singleItem( GenAction *action, GenInlineItem::Type type )
{
	return action->inlineList->length() == 1 &&
			action->inlineList->head->type == type;
}

void AsmCodeGen::NFA_CONDITION( ostream &ret, GenAction *condition, bool last )
{
	if ( singleItem( condition, GenInlineItem::NfaWrapAction ) )
	{
		GenAction *action = condition->inlineList->head->wrappedAction;
		ACTION( out, action, 0, false, false );
	}
	else if ( singleItem( condition, GenInlineItem::NfaWrapConds ) )
	{
		GenCondSpace *condSpace = condition->inlineList->head->condSpace;
		const CondKeySet &condKeySet = condition->inlineList->head->condKeySet;

		out << "	movq	$0, %r9\n";
		for ( GenCondSet::Iter csi = condSpace->condSet; csi.lte(); csi++ ) {
			out <<
				"	pushq	%r9\n";

			CONDITION( out, *csi );
			out << 
				"\n"
				"	test	%eax, %eax\n"
				"	setne   %cl\n"
				"	movsbq	%cl, %rcx\n"
				"	salq	$" << csi.pos() << ", %rcx\n"
				"	popq	%r9\n"
				"	addq	%rcx, %r9\n";
		}

		for ( int c = 0; c < condKeySet.length(); c++ ) {
			CondKey key = condKeySet[c];
			out <<
				"	cmpq	" << COND_KEY( key ) << ", %r9\n"
				"	je		102f\n";
		}

		out <<
			"	jmp	" << LABEL( "pop_fail" ) << "\n"
			"102:\n";
	}
	else {
		CONDITION( ret, condition );
		out <<
			"	test	%eax, %eax\n"
			"	jz		" << LABEL( "pop_fail" ) << "\n";
	}
}

string AsmCodeGen::ERROR_STATE()
{
	ostringstream ret;
	if ( redFsm->errState != 0 )
		ret << redFsm->errState->id;
	else
		ret << "-1";
	return ret.str();
}

string AsmCodeGen::FIRST_FINAL_STATE()
{
	ostringstream ret;
	if ( redFsm->firstFinState != 0 )
		ret << redFsm->firstFinState->id;
	else
		ret << redFsm->nextStateId;
	return ret.str();
}

void AsmCodeGen::writeInit()
{
	if ( !noCS ) {
		/* Don't use vCS here. vCS may assumes CS needs to be on the stack.
		 * Just use the interface register. */
		out <<
			"	movq	$" << redFsm->startState->id << ", %r11\n";
	}

	if ( redFsm->anyNfaStates() ) {
		out <<
			"	movq	$0, " << NFA_TOP() << "\n";
	}
	
	/* If there are any calls, then the stack top needs initialization. */
	if ( redFsm->anyActionCalls() || redFsm->anyActionRets() ) {
		out <<
			"	movq	$0, " << TOP() << "\n";
	}

	if ( red->hasLongestMatch ) {
		out << 
			"	movq	$0, " << TOKSTART() << "\n"
			"	movq	$0, " << TOKEND() << "\n"
			"	movq	$0, " << ACT() << "\n";
	}
}

string AsmCodeGen::DATA_PREFIX()
{
	if ( !noPrefix )
		return FSM_NAME() + "_";
	return "";
}

/* Emit the alphabet data type. */
string AsmCodeGen::ALPH_TYPE()
{
	string ret = alphType->data1;
	if ( alphType->data2 != 0 ) {
		ret += " ";
		ret += + alphType->data2;
	}
	return ret;
}

void AsmCodeGen::STATIC_CONST_INT( const string &name, const string &value )
{
	out <<
		"	.align	8\n"
		"	.type	" << name << ", @object\n"
		"	.size	" << name << ", 8\n" <<
		name << ":\n"
		"	.long	" << value << "\n";
}

void AsmCodeGen::STATE_IDS()
{
	if ( redFsm->startState != 0 )
		STATIC_CONST_INT( START(), START_STATE_ID() );

	if ( !noFinal )
		STATIC_CONST_INT( FIRST_FINAL(), FIRST_FINAL_STATE() );

	if ( !noError )
		STATIC_CONST_INT( ERROR(), ERROR_STATE() );

	out << "\n";

	if ( red->entryPointNames.length() > 0 ) {
		for ( EntryNameVect::Iter en = red->entryPointNames; en.lte(); en++ ) {
			ostringstream ret;
			ret << redFsm->startState->id;

			STATIC_CONST_INT( string( DATA_PREFIX() + "en_" + *en ),
					ret.str() );
		}
		out << "\n";
	}
}

void AsmCodeGen::writeStart()
{
	out << START_STATE_ID();
}

void AsmCodeGen::writeFirstFinal()
{
	out << FIRST_FINAL_STATE();
}

void AsmCodeGen::writeError()
{
	out << ERROR_STATE();
}

string AsmCodeGen::PTR_CONST()
{
	return "const ";
}

string AsmCodeGen::PTR_CONST_END()
{
	return "";
}

std::ostream &AsmCodeGen::OPEN_ARRAY( string type, string name )
{
	out << "static const " << type << " " << name << "[] = {\n";
	return out;
}

std::ostream &AsmCodeGen::CLOSE_ARRAY()
{
	return out << "};\n";
}

std::ostream &AsmCodeGen::STATIC_VAR( string type, string name )
{
	out << "static const " << type << " " << name;
	return out;
}

string AsmCodeGen::UINT( )
{
	return "unsigned int";
}

string AsmCodeGen::ARR_OFF( string ptr, string offset )
{
	return ptr + " + " + offset;
}

string AsmCodeGen::CAST( string type )
{
	return "(" + type + ")";
}

string AsmCodeGen::NULL_ITEM()
{
	return "0";
}

string AsmCodeGen::POINTER()
{
	return " *";
}

std::ostream &AsmCodeGen::SWITCH_DEFAULT()
{
	return out;
}

string AsmCodeGen::CTRL_FLOW()
{
	return "";
}

void AsmCodeGen::writeExports()
{
	if ( red->exportList.length() > 0 ) {
		for ( ExportList::Iter ex = red->exportList; ex.lte(); ex++ ) {
			out << "#define " << DATA_PREFIX() << "ex_" << ex->name << " " << 
					KEY(ex->key) << "\n";
		}
		out << "\n";
	}
}

string AsmCodeGen::LABEL( const char *type, long i )
{
	std::stringstream s;
	s << ".L" << red->machineId << "_" << type << "_" << i;
	return s.str();
}

string AsmCodeGen::LABEL( const char *name )
{
	std::stringstream s;
	s << ".L" << red->machineId << "_" << name;
	return s.str();
}

void AsmCodeGen::emitSingleIfElseIf( RedStateAp *state )
{
	/* Load up the singles. */
	int numSingles = state->outSingle.length();
	RedTransEl *data = state->outSingle.data;

	/* Write out the single indices. */
	for ( int j = 0; j < numSingles; j++ ) {
		out <<
			"	cmpb	" << KEY( data[j].lowKey ) << ", %r10b\n"
			"	je	" << TRANS_GOTO_TARG( data[j].value ) << "\n";
	}
}

void AsmCodeGen::emitSingleJumpTable( RedStateAp *state, string def )
{
	int numSingles = state->outSingle.length();
	RedTransEl *data = state->outSingle.data;

	long long low = data[0].lowKey.getVal();
	long long high = data[numSingles-1].lowKey.getVal();

	if ( def.size() == 0 )
		def = LABEL( "sjf", state->id );

	out <<
		"	movzbq	%r10b, %rax\n"
		"	subq	$" << low << ", %rax\n"
		"	cmpq	$" << (high - low) << ", %rax\n"
		"	ja		" << def << "\n"
		"	leaq	" << LABEL( "sjt", state->id ) << "(%rip), %rcx\n"
		"	movslq  (%rcx,%rax,4), %rdx\n"
		"	addq	%rcx, %rdx\n"
		"	jmp     *%rdx\n"
		"	.section .rodata\n"
		"	.align 4\n"
		<< LABEL( "sjt", state->id ) << ":\n";

	for ( long long j = 0; j < numSingles; j++ ) {
		/* Fill in gap between prev and this. */
		if ( j > 0 ) {
			long long span = keyOps->span( data[j-1].lowKey, data[j].lowKey ) - 2;
			for ( long long k = 0; k < span; k++ ) {
				out << "	.long	" << def << " - " <<
						LABEL( "sjt", state->id ) << "\n";
			}
		}

		out << "	.long	" << TRANS_GOTO_TARG( data[j].value ) << " - " <<
				LABEL( "sjt", state->id ) << "\n";
	}

	out <<
		"	.text\n"
		"" << LABEL( "sjf", state->id ) << ":\n";
}


void AsmCodeGen::emitRangeBSearch( RedStateAp *state, int low, int high )
{
	static int nl = 1;

	/* Get the mid position, staying on the lower end of the range. */
	int mid = (low + high) >> 1;
	RedTransEl *data = state->outRange.data;

	/* Determine if we need to look higher or lower. */
	bool anyLower = mid > low;
	bool anyHigher = mid < high;

	/* Determine if the keys at mid are the limits of the alphabet. */
	bool limitLow = keyOps->eq( data[mid].lowKey, keyOps->minKey );
	bool limitHigh = keyOps->eq( data[mid].highKey, keyOps->maxKey );
	
//	string nf = TRANS_GOTO_TARG( state->defTrans );

	/* For some reason the hop is faster and results in smaller code. Not sure
	 * why. */
	string nf = LABEL( "nf", state->id );

	if ( anyLower && anyHigher ) {
		int l1 = nl++;
		string targ = TRANS_GOTO_TARG( data[mid].value );

		/* Can go lower and higher than mid. */
		out <<
			"	cmpb	" << KEY( data[mid].lowKey ) << ", %r10b\n"
			"	jge	" << LABEL( "nl", l1 ) << "\n";
			
		
		emitRangeBSearch( state, low, mid-1 );

		out <<
			LABEL( "nl", l1 ) << ":\n";

		if ( !keyOps->eq( data[mid].lowKey, data[mid].highKey ) ) {
			out <<
				"	cmpb	" << KEY ( data[mid].highKey ) << ", %r10b\n";
		}

		out <<
			"	jle	" << targ << "\n";

		emitRangeBSearch( state, mid+1, high );
	}
	else if ( anyLower && !anyHigher ) {

		string targ;
		if ( limitHigh )
			targ = TRANS_GOTO_TARG( data[mid].value );
		else
			targ = LABEL( "nl",  nl++ );

		/* Can go lower than mid but not higher. */

		out <<
			"	cmpb	" << KEY( data[mid].lowKey ) << ", %r10b\n"
			"	jge	" << targ << "\n";

		emitRangeBSearch( state, low, mid-1 );

		/* If the higher is the highest in the alphabet then there is no sense
		 * testing it. */
		if ( !limitHigh ) {

			out <<
				targ << ":\n";

			if ( ! keyOps->eq( data[mid].lowKey, data[mid].highKey ) ) {
				out <<
					"	cmpb	" << KEY ( data[mid].highKey ) << ", %r10b\n";
			}

			out <<
				"	jg	" << nf << "\n";

			TRANS_GOTO( data[mid].value );
		}
	}
	else if ( !anyLower && anyHigher ) {
		string targ;
		if ( limitLow )
			targ = TRANS_GOTO_TARG( data[mid].value );
		else
			targ = LABEL( "nl", nl++ );

		/* Can go higher than mid but not lower. */

		out <<
			"	cmpb	" << KEY( data[mid].highKey ) << ", %r10b\n"
			"	jle	" << targ << "\n";

		emitRangeBSearch( state, mid+1, high );

		/* If the lower end is the lowest in the alphabet then there is no
		 * sense testing it. */
		if ( !limitLow ) {

			out <<
				targ << ":\n";

			if ( !keyOps->eq( data[mid].lowKey, data[mid].highKey ) ) {
				out <<
					"	cmpb	" << KEY( data[mid].lowKey ) << ", %r10b\n";
			}

			out <<
				"	jl	" << nf << "\n";

			TRANS_GOTO( data[mid].value );
		}
	}
	else {
		/* Cannot go higher or lower than mid. It's mid or bust. What
		 * tests to do depends on limits of alphabet. */
		if ( !limitLow && !limitHigh ) {

			if ( !keyOps->eq( data[mid].lowKey, data[mid].highKey ) ) {
				out <<
					"	cmpb	" << KEY( data[mid].lowKey ) << ", %r10b\n"
					"	jl	" << nf << "\n"
					"	cmpb	" << KEY( data[mid].highKey ) << ", %r10b\n"
					"	jg	" << nf << "\n";
			}
			else {
				out <<
					"	cmpb	" << KEY( data[mid].lowKey ) << ", %r10b\n"
					"	jne	" << nf << "\n";
			}

			TRANS_GOTO( data[mid].value );
		}
		else if ( limitLow && !limitHigh ) {

			out <<
				"	cmpb	" << KEY( data[mid].highKey ) << ", %r10b\n"
				"	jg	" << nf << "\n";

			TRANS_GOTO( data[mid].value );
		}
		else if ( !limitLow && limitHigh ) {

			out <<
				"	cmpb	" << KEY( data[mid].lowKey ) << ", %r10b\n"
				"	jl	" << nf << "\n";

			TRANS_GOTO( data[mid].value );
		}
		else {
			/* Both high and low are at the limit. No tests to do. */
			TRANS_GOTO( data[mid].value );
		}
	}
}

void AsmCodeGen::emitCharClassIfElseIf( RedStateAp *st )
{
	long long span = st->high - st->low + 1;
	for ( long long pos = 0; pos < span; pos++ ) {
		out <<
			"	cmpb	" << KEY( st->low + pos ) << ", %r10b\n"
			"	je	" << TRANS_GOTO_TARG( st->transList[pos] ) << "\n";
	}
}

void AsmCodeGen::emitCharClassJumpTable( RedStateAp *st, string def )
{
	long long low = st->low;
	long long high = st->high;

	if ( def.size() == 0 )
		def = LABEL( "ccf", st->id );

	out <<
		"	movzbq	%r10b, %rax\n"
		"	subq	$" << low << ", %rax\n"
		"	cmpq	$" << (high - low) << ", %rax\n"
		"	ja		" << def << "\n"
		"	leaq	" << LABEL( "cct", st->id ) << "(%rip), %rcx\n"
		"	movslq  (%rcx,%rax,4), %rdx\n"
		"	addq	%rcx, %rdx\n"
		"	jmp     *%rdx\n"
		"	.section .rodata\n"
		"	.align 4\n"
		<< LABEL( "cct", st->id ) << ":\n";

	long long span = st->high - st->low + 1;
	for ( long long pos = 0; pos < span; pos++ ) {
		out << "	.long	" << TRANS_GOTO_TARG( st->transList[pos] ) << " - " <<
				LABEL( "cct", st->id ) << "\n";
	}

	out <<
		"	.text\n"
		"" << LABEL( "ccf", st->id ) << ":\n";
}

void AsmCodeGen::NFA_PUSH( RedStateAp *st )
{
	if ( st->nfaTargs != 0 && st->nfaTargs->length() > 0 ) {
		if ( red->nfaPrePushExpr != 0 ) {
			out << "	movq    $" << st->nfaTargs->length() << ", %rdi\n";
			INLINE_LIST( out, red->nfaPrePushExpr->inlineList, 0, false, false );
		}

		for ( RedNfaTargs::Iter t = *st->nfaTargs; t.lte(); t++ ) {
			out <<
				"	movq	" << NFA_STACK() << ", %rax\n"
				"	movq	" << NFA_TOP() << ", %rcx\n"
				"	imulq	$24, %rcx\n"
				"	movq    $" << t->state->id << ", 0(%rax,%rcx,)\n"
				"	movq	" << P() << ", 8(%rax,%rcx,)\n";

			out <<
				"	# pop action id " << t->id << "\n"
				"	movq	$" << t->id << ", 16(%rax,%rcx,)\n";

			if ( t->push ) {
				for ( GenActionTable::Iter item = t->push->key; item.lte(); item++ ) {
					ACTION( out, item->value, st->id, false,
							t->push->anyNextStmt() );
					out << "\n";
				}
			}

			out <<
				"	movq	" << NFA_TOP() << ", %rcx\n"
				"	addq	$1, %rcx\n"
				"	movq	%rcx, " << NFA_TOP() << "\n";
		}
	}
}

void AsmCodeGen::STATE_GOTOS()
{
	bool eof = redFsm->anyEofActivity() || redFsm->anyNfaStates();

	for ( RedStateList::Iter st = redFsm->stateList; st.lte(); st++ ) {
		/* Writing code above state gotos. */
		IN_TRANS_ACTIONS( st );

		if ( st->labelNeeded ) 
			out << LABEL( "st", st->id ) << ":\n";


		/* need to do this if the transition is an eof transition, or if the action
		 * contains fexec. Otherwise, no need. */
		if ( eof ) {
			out <<
				"	cmpq	" << P() << ", " << vEOF() << "\n";

			if ( st->isFinal )
				out << "	je		" << LABEL( "out", st->id ) << "\n";
			else
				out << "	je		" << LABEL( "pop", st->id ) << "\n";
		}

		if ( st->toStateAction != 0 ) {
			/* Remember that we wrote an action. Write every action in the list. */
			for ( GenActionTable::Iter item = st->toStateAction->key; item.lte(); item++ ) {
				ACTION( out, item->value, st->id, false, 
						st->toStateAction->anyNextStmt() );
				out << "\n";
			}
		}

		if ( st == redFsm->errState ) {
			out << LABEL( "en", st->id ) << ":\n";

			/* Break out here. */
			outLabelUsed = true;

			out << 
				"	movq	$" << st->id << ", " << vCS() << "\n"
				"	jmp		" << LABEL( "pop" ) << "\n";
		}
		else {
			/* Advance and test buffer pos. */
			if ( st->labelNeeded ) {
				out <<
					"	addq	$1, " << P() << "\n";

			}

			/* This is the entry label for starting a run. */
			out << LABEL( "en", st->id ) << ":\n";

			if ( !noEnd ) {
				if ( eof ) {
					out <<
						"	cmpq	" << P() << ", " << PE() << "\n"
						"	jne	" << LABEL( "nope", st->id ) << "\n" <<
						"	cmpq	" << P() << ", " << vEOF() << "\n"
						"	jne	" << LABEL( "out", st->id ) << "\n" <<
						LABEL( "nope", st->id ) << ":\n";
				}
				else {
					out <<
						"	cmpq	" << P() << ", " << PE() << "\n"
						"	je	" << LABEL( "out", st->id ) << "\n";
				}
			}

			NFA_PUSH( st );

			if ( st->fromStateAction != 0 ) {
				/* Remember that we wrote an action. Write every action in the list. */
				for ( GenActionTable::Iter item = st->fromStateAction->key;
						item.lte(); item++ )
				{
					ACTION( out, item->value, st->id, false,
							st->fromStateAction->anyNextStmt() );
					out << "\n";
				}
			}

			if ( !noEnd && eof ) {
				out <<
					"	cmpq	" << P() << ", " << vEOF() << "\n"
					"	jne	" << LABEL( "neofd", st->id ) << "\n";

				if ( st->eofTrans != 0 )
					TRANS_GOTO( st->eofTrans );
				else {
					if ( st->isFinal || !redFsm->anyNfaStates() )
						out << "jmp " << LABEL( "out", st->id ) << "\n";
					else
						out << "jmp " << LABEL( "pop", st->id ) << "\n";
				}

				out <<
					"	jmp	" << LABEL( "deofd", st->id ) << "\n";

				out << LABEL( "neofd", st->id ) << ":\n";
			}

			/* Record the prev state if necessary. */
			if ( st->anyRegCurStateRef() ) {
				out <<
					"	movq	$" << st->id << ", -72(%rbp)\n";
			}


#ifdef LOG_TRANS
			out <<
				"	movzbl	(" << P() << "), %r10d\n"
				"	movq	$" << machineId << ", %rdi\n"
				"	movq	$" << st->id << ", %rsi\n"
				"	movslq	%r10d, %rdx\n"
				"	call	" << LABEL( "log_trans" ) << "\n"
				;
#endif

			/* Load *p. */
			if ( st->transList != 0 ) {
				long lowKey = redFsm->lowKey.getVal();
				long highKey = redFsm->highKey.getVal();

				out <<
					"	movzbl	(" << P() << "), %r10d\n"
					"	cmpl	$" << lowKey << ", %r10d\n"
					"	jl		" << LABEL( "nf", st->id ) << "\n"
					"	cmpl	$" << highKey << ", %r10d\n"
					"	jg		" << LABEL( "nf", st->id ) << "\n"
					"	subl	" << KEY( lowKey ) << ", %r10d\n"
					"	leaq	" << LABEL( "char_class" ) << "(%rip), %rcx\n"
					"	movslq	%r10d, %rax\n"
					"	movb	(%rcx, %rax), %r10b\n"
				;


				long len = ( st->high - st->low + 1 );

				if ( len < 8 )
					emitCharClassIfElseIf( st );
				else {
					string def;
					if ( st->outRange.length() == 0 )
						def = TRANS_GOTO_TARG( st->defTrans );
					emitCharClassJumpTable( st, def );
				}
			}

			/* Write the default transition. */
			out << LABEL( "nf", st->id ) << ":\n";
			TRANS_GOTO( st->defTrans );

			if ( !noEnd && eof ) {
				out << LABEL( "deofd", st->id) << ":\n";
			}
		}
	}
}

unsigned int AsmCodeGen::TO_STATE_ACTION( RedStateAp *state )
{
	int act = 0;
	if ( state->toStateAction != 0 )
		act = state->toStateAction->location+1;
	return act;
}

unsigned int AsmCodeGen::FROM_STATE_ACTION( RedStateAp *state )
{
	int act = 0;
	if ( state->fromStateAction != 0 )
		act = state->fromStateAction->location+1;
	return act;
}

unsigned int AsmCodeGen::EOF_ACTION( RedStateAp *state )
{
	int act = 0;
	if ( state->eofAction != 0 )
		act = state->eofAction->location+1;
	return act;
}

bool AsmCodeGen::useAgainLabel()
{
	return redFsm->anyActionRets() || 
			redFsm->anyActionByValControl() ||
			redFsm->anyRegNextStmt();
}

void AsmCodeGen::GOTO( ostream &ret, int gotoDest, bool inFinish )
{
	ret <<
		"	jmp		" << LABEL( "st", gotoDest ) << "\n";
}

void AsmCodeGen::CALL( ostream &ret, int callDest, int targState, bool inFinish )
{
	if ( red->prePushExpr != 0 )
		INLINE_LIST( ret, red->prePushExpr->inlineList, 0, false, false );

	ret <<
		"	movq	" << STACK() << ", %rax\n"
		"	movq	" << TOP() << ", %rcx\n"
		"	movq	$" << targState << ", (%rax, %rcx, 8)\n"
		"	addq	$1, %rcx\n"
		"	movq	%rcx, " << TOP() << "\n"
	;

	ret <<
		"	jmp		" << LABEL( "st", callDest ) << "\n";
	;
}

void AsmCodeGen::CALL_EXPR( ostream &ret, GenInlineItem *ilItem, int targState, bool inFinish )
{
	if ( red->prePushExpr != 0 )
		INLINE_LIST( ret, red->prePushExpr->inlineList, 0, false, false );

	ret <<
		"\n"
		"	movq	";
	INLINE_LIST( ret, ilItem->children, 0, inFinish, false );
	ret << ", %rdx\n"
		"\n"
		"	movq	" << STACK() << ", %rax\n"
		"	movq	" << TOP() << ", %rcx\n"
		"	movq	$" << targState << ", (%rax, %rcx, 8)\n"
		"	addq	$1, %rcx\n"
		"	movq	%rcx, " << TOP() << "\n"
		"	movq	%rdx, " << vCS() << "\n"
	;

	ret <<
		"	jmp		" << LABEL( "again" ) << "\n";
}

void AsmCodeGen::RET( ostream &ret, bool inFinish )
{
	ret <<
		"	movq	" << STACK() << ", %rax\n"
		"	movq	" << TOP() << ", %rcx\n"
		"	subq	$1, %rcx\n"
		"	movq	(%rax, %rcx, 8), %rax\n"
		"	movq	%rax, " << vCS() << "\n"
		"	movq	%rcx, " << TOP() << "\n";

	if ( red->postPopExpr != 0 )
		INLINE_LIST( ret, red->postPopExpr->inlineList, 0, false, false );

	ret <<
		"	jmp		" << LABEL("again") << "\n";
}

void AsmCodeGen::GOTO_EXPR( ostream &ret, GenInlineItem *ilItem, bool inFinish )
{
	ret << "	movq	";
	INLINE_LIST( ret, ilItem->children, 0, inFinish, false );
	ret << ", " << vCS() << "\n";

	ret <<
		"	jmp		" << LABEL("again") << "\n";
}

void AsmCodeGen::NEXT( ostream &ret, int nextDest, bool inFinish )
{
	ret <<
		"	movq	$" << nextDest << ", " << vCS() << "\n";
}

void AsmCodeGen::NEXT_EXPR( ostream &ret, GenInlineItem *ilItem, bool inFinish )
{
	ret << "	movq	";
	INLINE_LIST( ret, ilItem->children, 0, inFinish, false );
	ret << ", " << vCS() << "\n";
}

void AsmCodeGen::NCALL( ostream &ret, int callDest, int targState, bool inFinish )
{
	if ( red->prePushExpr != 0 )
		INLINE_LIST( ret, red->prePushExpr->inlineList, 0, false, false );

	ret <<
		"	movq	" << STACK() << ", %rax\n"
		"	movq	" << TOP() << ", %rcx\n"
		"	movq	$" << targState << ", (%rax, %rcx, 8)\n"
		"	addq	$1, %rcx\n"
		"	movq	%rcx, " << TOP() << "\n"
		"	movq	$" << callDest << ", " << vCS() << "\n";
}

void AsmCodeGen::NCALL_EXPR( ostream &ret, GenInlineItem *ilItem,
		int targState, bool inFinish )
{
	if ( red->prePushExpr != 0 )
		INLINE_LIST( ret, red->prePushExpr->inlineList, 0, false, false );

	ret <<
		"\n"
		"	movq	";
	INLINE_LIST( ret, ilItem->children, 0, inFinish, false );
	ret << ", %rdx\n"
		"\n"
		"	movq	" << STACK() << ", %rax\n"
		"	movq	" << TOP() << ", %rcx\n"
		"	movq	$" << targState << ", (%rax, %rcx, 8)\n"
		"	addq	$1, %rcx\n"
		"	movq	%rcx, " << TOP() << "\n"
		"	movq	%rdx, " << vCS() << "\n";
}

void AsmCodeGen::NRET( ostream &ret, bool inFinish )
{
	ret <<
		"	movq	" << STACK() << ", %rax\n"
		"	movq	" << TOP() << ", %rcx\n"
		"	subq	$1, %rcx\n"
		"	movq	(%rax, %rcx, 8), %rax\n"
		"	movq	%rax, " << vCS() << "\n"
		"	movq	%rcx, " << TOP() << "\n";

	if ( red->postPopExpr != 0 )
		INLINE_LIST( ret, red->postPopExpr->inlineList, 0, false, false );
}

void AsmCodeGen::CURS( ostream &ret, bool inFinish )
{
	ret <<
		"	movq	-72(%rbp), %rax\n";
}

void AsmCodeGen::TARGS( ostream &ret, bool inFinish, int targState )
{
	ret <<
		"	movq	$" << targState << ", %rax\n";
}

void AsmCodeGen::BREAK( ostream &ret, int targState, bool csForced )
{
	outLabelUsed = true;
	ret << "{" << P() << "++; ";
	if ( !csForced ) 
		ret << vCS() << " = " << targState << "; ";
	ret << CTRL_FLOW() << "goto _out;}";
}

bool AsmCodeGen::IN_TRANS_ACTIONS( RedStateAp *state )
{
	bool anyWritten = false;

	/* Emit any transitions that have actions and that go to this state. */
	for ( int it = 0; it < state->numInCondTests; it++ ) {
		/* Write the label for the transition so it can be jumped to. */
		RedTransAp *trans = state->inCondTests[it];
		out << LABEL( "ctr", trans->id ) << ":\n";

		if ( trans->condSpace->condSet.length() == 1 ) {
			RedCondPair *tp, *fp;
			if ( trans->numConds() == 1 ) {
				/* The single condition is either false or true, errCond is the
				 * opposite. */
				if ( trans->outCondKey(0) == 0 ) {
					fp = trans->outCond(0);
					tp = trans->errCond();
				}
				else {
					tp = trans->outCond(0);
					fp = trans->errCond();
				}
			}
			else {
				/* Full list, goes false, then true. */
				fp = trans->outCond(0);
				tp = trans->outCond(1);
			}
			
			GenCondSet::Iter csi = trans->condSpace->condSet;
			CONDITION( out, *csi );

			out <<
				"	test	%eax, %eax\n"
				"	je		" << TRANS_GOTO_TARG( fp ) << "\n"
				"	jmp		" << TRANS_GOTO_TARG( tp ) << "\n";
		}
		else {
			out << "	movq	$0, %r9\n";

			for ( GenCondSet::Iter csi = trans->condSpace->condSet; csi.lte(); csi++ ) {
				out <<
					"	pushq	%r9\n";

				CONDITION( out, *csi );
				out << 
					"\n"
					"	test	%eax, %eax\n"
					"	setne   %cl\n"
					"	movsbq	%cl, %rcx\n"
					"	salq	$" << csi.pos() << ", %rcx\n"
					"	popq	%r9\n"
					"	addq	%rcx, %r9\n";
			}

			for ( int c = 0; c < trans->numConds(); c++ ) {
				CondKey key = trans->outCondKey( c );
				RedCondPair *pair = trans->outCond( c );
				out <<
					"	cmpq	" << COND_KEY( key ) << ", %r9\n"
					"	je	" << TRANS_GOTO_TARG( pair ) << "\n";

			}

			RedCondPair *err = trans->errCond();
			if ( err != 0 ) {
				out <<
					"	jmp	" << TRANS_GOTO_TARG( err ) << "\n";
			}
		}
	}

	/* Emit any transitions that have actions and that go to this state. */
	for ( int it = 0; it < state->numInConds; it++ ) {
		RedCondPair *pair = state->inConds[it];
		if ( pair->action != 0 /* && pair->labelNeeded */ ) {
			/* Remember that we wrote an action so we know to write the
			 * line directive for going back to the output. */
			anyWritten = true;

			/* Write the label for the transition so it can be jumped to. */
			out << LABEL( "tr", pair->id ) << ":\n";

			/* If the action contains a next, then we must preload the current
			 * state since the action may or may not set it. */
			if ( pair->action->anyNextStmt() ) {
				out <<
					"	movq	$" << pair->targ->id << ", " << vCS() << "\n";
			}

			if ( redFsm->anyRegNbreak() ) {
				out <<
					"	movb	$0, " << NBREAK() << "\n";
			}

			/* Write each action in the list. */
			for ( GenActionTable::Iter item = pair->action->key; item.lte(); item++ ) {
				ACTION( out, item->value, pair->targ->id, false, 
						pair->action->anyNextStmt() );
				out << "\n";
			}

			if ( redFsm->anyRegNbreak() ) {
				out <<
					"	cmpb	$0, " << NBREAK() << "\n"
					"	jne		" << LABEL( "pop" ) << "\n";
				outLabelUsed = true;
			}
				

			/* If the action contains a next then we need to reload, otherwise
			 * jump directly to the target state. */
			if ( pair->action->anyNextStmt() )
				out << "	jmp " << LABEL( "again" ) << "\n";
			else
				out << "	jmp " << LABEL( "st", pair->targ->id ) << "\n";
		}
	}

	return anyWritten;
}

std::string AsmCodeGen::TRANS_GOTO_TARG( RedCondPair *pair )
{
	std::stringstream s;
	if ( pair->action != 0 ) {
		/* Go to the transition which will go to the state. */
		s << LABEL( "tr", pair->id );
	}
	else {
		/* Go directly to the target state. */
		s << LABEL( "st", pair->targ->id );
	}
	return s.str();
}

std::string AsmCodeGen::TRANS_GOTO_TARG( RedTransAp *trans )
{
	if ( trans->condSpace != 0 ) {
		/* Need to jump to the trans since there are conditions. */
		return LABEL( "ctr", trans->id );
	}
	else {
		return TRANS_GOTO_TARG( &trans->p );
	}
}

/* Emit the goto to take for a given transition. */
std::ostream &AsmCodeGen::TRANS_GOTO( RedTransAp *trans )
{
	out << "	jmp	" << TRANS_GOTO_TARG( trans ) << "\n";
	return out;
}

std::ostream &AsmCodeGen::EXIT_STATES()
{
	for ( RedStateList::Iter st = redFsm->stateList; st.lte(); st++ ) {
		out << 
			LABEL( "out", st->id ) << ":\n"
			"	movq	$" << st->id << ", " << vCS() << "\n"
			"	jmp		" << LABEL( "out" ) << "\n";

		out << 
			LABEL( "pop", st->id ) << ":\n"
			"	movq	$" << st->id << ", " << vCS() << "\n"
			"	jmp		" << LABEL( "pop" ) << "\n";
	}
	return out;
}

std::ostream &AsmCodeGen::AGAIN_CASES()
{
	/* Jump into the machine based on the current state. */
	out <<
		"	leaq	" << LABEL( "again_jmp" ) << "(%rip), %rcx\n";

	if ( stackCS ) {
		out <<
			"	movq	" << vCS() << ", %r11\n";
	}

	out <<
		"	movq	(%rcx,%r11,8), %rcx\n"
		"	jmp		*%rcx\n"
		"	.section .rodata\n"
		"	.align 8\n"
		<< LABEL( "again_jmp" ) << ":\n";

	for ( int stId = 0; stId < redFsm->stateList.length(); stId++ ) {
		out <<
			"	.quad	" << LABEL( "st", stId ) << "\n";
	}

	out <<
		"	.text\n";

	return out;
}

std::ostream &AsmCodeGen::ENTRY_CASES()
{
	out <<
		"	movq	(%rcx,%r11,8), %rcx\n"
		"	jmp		*%rcx\n"
		"	.section .rodata\n"
		"	.align 8\n"
		<< LABEL( "entry_jmp" ) << ":\n";

	for ( int stId = 0; stId < redFsm->stateList.length(); stId++ ) {
		out <<
			"	.quad	" << LABEL( "en", stId ) << "\n";
	}

	out <<
		"	.text\n";
	return out;
}


std::ostream &AsmCodeGen::FINISH_CASES()
{
	/* The current state is in %rax. */
	/*long done = */ nextLmSwitchLabel++;

	for ( RedStateList::Iter st = redFsm->stateList; st.lte(); st++ ) {
		if ( st->eofTrans != 0 ) {
			out <<
				"	cmpq	$" << st->id << ", %rax\n"
				"	jne		" << LABEL( "fc", st->id ) << "\n";

			if ( st->fromStateAction != 0 ) {
				/* Remember that we wrote an action. Write every action in the list. */
				for ( GenActionTable::Iter item = st->fromStateAction->key;
						item.lte(); item++ )
				{
					ACTION( out, item->value, st->id, false,
							st->fromStateAction->anyNextStmt() );
					out << "\n";
				}
			}
				
			out <<
				"	jmp		" << TRANS_GOTO_TARG( st->eofTrans ) << "\n" <<
				LABEL( "fc", st->id ) << ":\n";
		}
	}

	return out;
}

void AsmCodeGen::setLabelsNeeded( GenInlineList *inlineList )
{
	for ( GenInlineList::Iter item = *inlineList; item.lte(); item++ ) {
		switch ( item->type ) {
		case GenInlineItem::Goto: case GenInlineItem::Call: {
			/* Mark the target as needing a label. */
			item->targState->labelNeeded = true;
			break;
		}
		default: break;
		}

		if ( item->children != 0 )
			setLabelsNeeded( item->children );
	}
}

void AsmCodeGen::setLabelsNeeded( RedCondPair *pair )
{
	/* If there is no action with a next statement, then the label will be
	 * needed. */
	if ( pair->action == 0 || !pair->action->anyNextStmt() )
		pair->targ->labelNeeded = true;

	/* Need labels for states that have goto or calls in action code
	 * invoked on characters (ie, not from out action code). */
	if ( pair->action != 0 ) {
		/* Loop the actions. */
		for ( GenActionTable::Iter act = pair->action->key; act.lte(); act++ ) {
			/* Get the action and walk it's tree. */
			setLabelsNeeded( act->value->inlineList );
		}
	}
}

/* Set up labelNeeded flag for each state. */
void AsmCodeGen::setLabelsNeeded()
{
	/* If we use the _again label, then we the _again switch, which uses all
	 * labels. */
	if ( useAgainLabel() ) {
		for ( RedStateList::Iter st = redFsm->stateList; st.lte(); st++ )
			st->labelNeeded = true;
	}
	else {
		/* Do not use all labels by default, init all labelNeeded vars to false. */
		for ( RedStateList::Iter st = redFsm->stateList; st.lte(); st++ )
			st->labelNeeded = false;

		for ( TransApSet::Iter trans = redFsm->transSet; trans.lte(); trans++ ) {
			if ( trans->condSpace == 0 )
				setLabelsNeeded( &trans->p );
		}

		for ( CondApSet::Iter cond = redFsm->condSet; cond.lte(); cond++ )
			setLabelsNeeded( &cond->p );

		for ( RedStateList::Iter st = redFsm->stateList; st.lte(); st++ ) {
			if ( st->eofAction != 0 ) {
				for ( GenActionTable::Iter item = st->eofAction->key; item.lte(); item++ )
					setLabelsNeeded( item->value->inlineList );
			}
		}
	}

	if ( !noEnd ) {
		for ( RedStateList::Iter st = redFsm->stateList; st.lte(); st++ )
			st->outNeeded = st->labelNeeded;
	}
}

void AsmCodeGen::writeData()
{
	STATE_IDS();

	long long maxSpan = keyOps->span( redFsm->lowKey, redFsm->highKey );

	out <<
		"	.type	" << LABEL( "char_class" ) << ", @object\n" <<
		LABEL( "char_class" ) << ":\n";

	for ( long long pos = 0; pos < maxSpan; pos++ ) {
		out <<
			"	.byte " << redFsm->classMap[pos] << "\n";
	}
	
#ifdef LOG_TRANS
	out <<
		LABEL( "fmt_log_trans" ) << ":\n"
		"	.string \"%i %i %i\\n\"\n";
#endif
}

void AsmCodeGen::setNfaIds()
{
	long nextId = 1;
	for ( RedStateList::Iter st = redFsm->stateList; st.lte(); st++ ) {
		if ( st->nfaTargs != 0 ) {
			for ( RedNfaTargs::Iter targ = *st->nfaTargs; targ.lte(); targ++ ) {
				targ->id = nextId;
				nextId += 1;
			}
		}
	}
}

void AsmCodeGen::writeExec()
{
	/* Must set labels immediately before writing because we may depend on the
	 * noend write option. */
	setLabelsNeeded();
	testEofUsed = false;
	outLabelUsed = false;

	setNfaIds();

	/* If there are eof actions then we need to run code after exporting the
	 * final state to vCS. Since the interface register is calee-save, we need
	 * it to live on the stack. */
	stackCS = redFsm->anyEofActivity();

	/*
	 * This code needs 88 bytes of stack (offset 0 from %rbp).
	 *
	 * cv : %r9   -- caller-save, used internally, condition char, undefined in
	 *               conditions and actions, can use
	 *
	 * pc : %r10b -- caller-save, used internally, undefined in conditions
	 *               actions, can use
	 *
	 * cs : %r11  -- caller-save, written by write init, read and
	 *               written by exec, undefined in conditions and actions
	 *
	 * p  : %r12  -- callee-save, interface, persistent
	 *
	 * pe : %r13  -- callee-save, interface, persistent
	 *
	 * eof:        -8(%rbp)
	 *
	 * ts:        -16(%rbp)
	 *
	 * te:        -24(%rbp)
	 *
	 * act:       -32(%rbp)
	 *
	 * _nbreak:   -40(%rbp)
	 *
	 * stackCS:   -48(%rbp)
	 *
	 * stack:     -56(%rbp)
	 * top:       -64(%rbp)
	 *
	 * _ps:       -72(%rbp)
	 *
	 * nfa_stack  -80(%rbp)
	 * nfa_top    -88(%rbp)
	 * nfa_sz     -96(%rbp)
	 */

	if ( redFsm->anyRegCurStateRef() ) {
		out <<
			"	movq	$0, -72(%rbp)\n";
	}

	if ( stackCS ) {
		/* Only need a persistent cs in the case of eof actions when exiting the
		 * block. Where CS lives is a matter of performance though, so we should
		 * only do this if necessary. */
		out <<
			"	movq	%r11, " << vCS() << "\n";
	}

	if ( useAgainLabel() ) {
		out << 
			"	jmp		" << LABEL( "resume" ) << "\n"
			<< LABEL( "again" ) << ":\n";

		AGAIN_CASES();
	}

	if ( useAgainLabel() || redFsm->anyNfaStates() )
		out << LABEL( "resume" ) << ":\n";

	/* Jump into the machine based on the current state. */
	out <<
		"	leaq	" << LABEL( "entry_jmp" ) << "(%rip), %rcx\n";

	if ( stackCS ) {
		out <<
			"	movq	" << vCS() << ", %r11\n";
	}

	ENTRY_CASES();

	STATE_GOTOS();

	EXIT_STATES();

	out << LABEL( "pop" ) << ":\n";

	if ( redFsm->anyNfaStates() ) {
		out <<
			"	movq    " << NFA_TOP() << ", %rcx\n"
			"	cmpq	$0, %rcx\n"
			"	je		" << LABEL( "nfa_stack_empty" ) << "\n"
			"	movq    " << NFA_TOP() << ", %rcx\n"
			"	subq	$1, %rcx\n"
			"	movq	%rcx, " << NFA_TOP() << "\n"
			"	movq	" << NFA_STACK() << ", %rax\n"
			"	imulq	$24, %rcx\n"
			"	movq    0(%rax,%rcx,), %r11\n"
			"	movq	8(%rax,%rcx,), " << P() << "\n"
			"	movq	%r11, " << vCS() << "\n"
			;

		if ( redFsm->bAnyNfaPops ) {
			out <<
				"	movq	%r11, %r14\n"
				"	movq	16(%rax,%rcx,), %rax\n";

			for ( RedStateList::Iter st = redFsm->stateList; st.lte(); st++ ) {
				if ( st->nfaTargs != 0 ) {
					for ( RedNfaTargs::Iter targ = *st->nfaTargs; targ.lte(); targ++ ) {

							/* Write the entry label. */
							out <<
								"   # pop action select\n"
								"	cmp		$" << targ->id << ", %rax\n"
								"	jne		100f\n";

							if ( targ->popTest != 0 ) {
								/* Write each action in the list of action items. */
								for ( GenActionTable::Iter item = targ->popTest->key; item.lte(); item++ )
									NFA_CONDITION( out, item->value, item.last() );
							}

							out <<
								"	jmp		101f\n"
								"100:\n";

					}
				}
			}

			out <<
				"101:\n"
				"	movq	%r14, %r11\n";
		}

		out <<
			"	jmp		" << LABEL( "resume" ) << "\n" <<
			LABEL( "pop_fail" ) << ":\n"
			"	movq	$" << ERROR_STATE() << ", " << vCS() << "\n"
			"	jmp		" << LABEL( "resume" ) << "\n" <<
			LABEL( "nfa_stack_empty" ) << ":\n";
	}

	if ( stackCS ) {
		out <<
			"	movq	" << vCS() << ", %r11\n";
	}

	out <<
		"# WRITE EXEC END\n";

	out << LABEL( "out" ) << ":\n";

	if ( stackCS ) {
		out <<
			"	movq	" << vCS() << ", %r11\n";
	}

#ifdef LOG_TRANS
	out <<
		"	jmp " << LABEL( "skip" ) << "\n" <<
		LABEL( "log_trans" ) << ":\n"
		"	movq    %rdx, %rcx\n"
		"	movq    %rsi, %rdx\n"
		"	movq    %rdi, %rsi\n"
		"	movq	" << LABEL( "fmt_log_trans" ) << "@GOTPCREL(%rip), %rdi\n"
		"	movq    $0, %rax\n"
		"	call    printf@PLT\n"
		"	ret\n" <<
		LABEL( "skip" ) << ":\n"
		"\n";
#endif
}
