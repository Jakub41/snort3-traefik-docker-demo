/*
 * Copyright 2006-2018 Adrian Thurston <thurston@colm.net>
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

#include "consinit.h"

#include <iostream>

using std::cout;
using std::cerr;
using std::endl;

LexTerm *rangeTerm( const char *low, const char *high )
{
	Literal *lowLit = Literal::cons( internal, String( low ), Literal::LitString );
	Literal *highLit = Literal::cons( internal, String( high ), Literal::LitString );
	Range *range = Range::cons( lowLit, highLit );
	LexFactor *factor = LexFactor::cons( range );
	LexFactorNeg *factorNeg = LexFactorNeg::cons( factor );
	LexFactorRep *factorRep = LexFactorRep::cons( factorNeg );
	LexFactorAug *factorAug = LexFactorAug::cons( factorRep );
	LexTerm *term = LexTerm::cons( factorAug );
	return term;
}

LexFactorNeg *litFactorNeg( const char *str )
{
	Literal *lit = Literal::cons( internal, String( str ), Literal::LitString );
	LexFactor *factor = LexFactor::cons( lit );
	LexFactorNeg *factorNeg = LexFactorNeg::cons( factor );
	return factorNeg;
}

LexFactorAug *litFactorAug( const char *str )
{
	Literal *lit = Literal::cons( internal, String( str ), Literal::LitString );
	LexFactor *factor = LexFactor::cons( lit );
	LexFactorNeg *factorNeg = LexFactorNeg::cons( factor );
	LexFactorRep *factorRep = LexFactorRep::cons( factorNeg );
	LexFactorAug *factorAug = LexFactorAug::cons( factorRep );
	return factorAug;
}

LexTerm *litTerm( const char *str )
{
	Literal *lit = Literal::cons( internal, String( str ), Literal::LitString );
	LexFactor *factor = LexFactor::cons( lit );
	LexFactorNeg *factorNeg = LexFactorNeg::cons( factor );
	LexFactorRep *factorRep = LexFactorRep::cons( factorNeg );
	LexFactorAug *factorAug = LexFactorAug::cons( factorRep );
	LexTerm *term = LexTerm::cons( factorAug );
	return term;
}

LexExpression *litExpr( const char *str )
{
	LexTerm *term = litTerm( str );
	LexExpression *expr = LexExpression::cons( term );
	return expr;
}

LexExpression *orExpr( LexTerm *term1, LexTerm *term2 )
{
	LexExpression *expr1 = LexExpression::cons( term1 );
	return LexExpression::cons( expr1, term2, LexExpression::OrType );
}

LexExpression *orExpr( LexTerm *term1, LexTerm *term2, LexTerm *term3 )
{
	LexExpression *expr1 = LexExpression::cons( term1 );
	LexExpression *expr2 = LexExpression::cons( expr1, term2, LexExpression::OrType );
	LexExpression *expr3 = LexExpression::cons( expr2, term3, LexExpression::OrType );
	return expr3;
}

LexExpression *orExpr( LexTerm *term1, LexTerm *term2, LexTerm *term3, LexTerm *term4 )
{
	LexExpression *expr1 = LexExpression::cons( term1 );
	LexExpression *expr2 = LexExpression::cons( expr1, term2, LexExpression::OrType );
	LexExpression *expr3 = LexExpression::cons( expr2, term3, LexExpression::OrType );
	LexExpression *expr4 = LexExpression::cons( expr3, term4, LexExpression::OrType );
	return expr4;
}

LexExpression *orExpr( LexTerm *term1, LexTerm *term2, LexTerm *term3,
		LexTerm *term4, LexTerm *term5, LexTerm *term6 )
{
	LexExpression *expr1 = LexExpression::cons( term1 );
	LexExpression *expr2 = LexExpression::cons( expr1, term2, LexExpression::OrType );
	LexExpression *expr3 = LexExpression::cons( expr2, term3, LexExpression::OrType );
	LexExpression *expr4 = LexExpression::cons( expr3, term4, LexExpression::OrType );
	return expr4;
}

LexFactorAug *starFactorAug( LexExpression *expr )
{
	LexJoin *join = LexJoin::cons( expr );
	LexFactor *factor = LexFactor::cons( join );
	LexFactorNeg *factorNeg = LexFactorNeg::cons( factor );
	LexFactorRep *factorRep = LexFactorRep::cons( factorNeg );
	LexFactorRep *staredRep = LexFactorRep::cons( internal,
			factorRep, 0, 0, LexFactorRep::StarType );
	LexFactorAug *factorAug = LexFactorAug::cons( staredRep );
	return factorAug;
}

LexFactorAug *starFactorAug( LexTerm *term )
{
	LexExpression *expr = LexExpression::cons( term );
	return starFactorAug( expr );
}

LexFactorAug *starFactorAug( LexFactorAug *factorAug )
{
	LexTerm *term = LexTerm::cons( factorAug );
	return starFactorAug( term );
}

LexFactorAug *plusFactorAug( LexExpression *expr )
{
	LexJoin *join = LexJoin::cons( expr );
	LexFactor *factor = LexFactor::cons( join );
	LexFactorNeg *factorNeg = LexFactorNeg::cons( factor );
	LexFactorRep *factorRep = LexFactorRep::cons( factorNeg );
	LexFactorRep *staredRep = LexFactorRep::cons( internal, factorRep, 0, 0, LexFactorRep::PlusType );
	LexFactorAug *factorAug = LexFactorAug::cons( staredRep );
	return factorAug;
}

LexTerm *concatTerm( LexFactorAug *fa1, LexFactorAug *fa2 )
{
	LexTerm *term1 = LexTerm::cons( fa1 );
	LexTerm *term2 = LexTerm::cons( term1, fa2, LexTerm::ConcatType );
	return term2;
}

LexTerm *concatTerm( LexFactorAug *fa1, LexFactorAug *fa2, LexFactorAug *fa3 )
{
	LexTerm *term1 = LexTerm::cons( fa1 );
	LexTerm *term2 = LexTerm::cons( term1, fa2, LexTerm::ConcatType );
	LexTerm *term3 = LexTerm::cons( term2, fa3, LexTerm::ConcatType );
	return term3;
}

LexFactorAug *parensFactorAug( LexExpression *expr )
{
	LexJoin *join = LexJoin::cons( expr );
	LexFactor *factor = LexFactor::cons( join );
	LexFactorNeg *factorNeg = LexFactorNeg::cons( factor );
	LexFactorRep *factorRep = LexFactorRep::cons( factorNeg );
	LexFactorAug *factorAug = LexFactorAug::cons( factorRep );
	return factorAug;
}

LexFactorNeg *parensFactorNeg( LexExpression *expr )
{
	LexJoin *join = LexJoin::cons( expr );
	LexFactor *factor = LexFactor::cons( join );
	LexFactorNeg *factorNeg = LexFactorNeg::cons( factor );
	return factorNeg;
}

LexFactorAug *parensFactorAug( LexTerm *term )
{
	LexExpression *expr = LexExpression::cons( term );
	LexJoin *join = LexJoin::cons( expr );
	LexFactor *factor = LexFactor::cons( join );
	LexFactorNeg *factorNeg = LexFactorNeg::cons( factor );
	LexFactorRep *factorRep = LexFactorRep::cons( factorNeg );
	LexFactorAug *factorAug = LexFactorAug::cons( factorRep );
	return factorAug;
}

LexFactorAug *charNegFactorAug( LexExpression *expr )
{
	LexFactorNeg *factorNeg = parensFactorNeg( expr );
	LexFactorNeg *charNeg = LexFactorNeg::cons( factorNeg, LexFactorNeg::CharNegateType );
	LexFactorRep *factorRep = LexFactorRep::cons( charNeg );
	LexFactorAug *factorAug = LexFactorAug::cons( factorRep );
	return factorAug;
}

LexTerm *charNegTerm( LexExpression *expr )
{
	LexFactorAug *factorAug = charNegFactorAug( expr );
	LexTerm *term = LexTerm::cons( factorAug );
	return term;
}

LexTerm *parensTerm( LexExpression *expr )
{
	LexFactorAug *factorAug = parensFactorAug( expr );
	return LexTerm::cons( factorAug );
}

void ConsInit::wsIgnore()
{
	ObjectDef *objectDef = ObjectDef::cons( ObjectDef::UserType, String(), pd->nextObjectId++ ); 

	LexTerm *r1 = litTerm( "' '" );
	LexTerm *r2 = litTerm( "'\t'" );
	LexTerm *r3 = litTerm( "'\v'" );
	LexTerm *r4 = litTerm( "'\n'" );
	LexTerm *r5 = litTerm( "'\r'" );
	LexTerm *r6 = litTerm( "'\f'" );

	LexExpression *whitespace = orExpr( r1, r2, r3, r4, r5, r6 );
	LexFactorAug *whitespaceRep = plusFactorAug( whitespace );

	LexTerm *term = LexTerm::cons( whitespaceRep );
	LexExpression *expr = LexExpression::cons( term );
	LexJoin *join = LexJoin::cons( expr );

	defineToken( internal, String(), join, objectDef, 0, true, false, false );
}

void ConsInit::commentIgnore()
{
	ObjectDef *objectDef = ObjectDef::cons( ObjectDef::UserType, String(), pd->nextObjectId++ ); 

	LexFactorAug *pound = litFactorAug( "'#'" );
	LexExpression *newline = litExpr( "'\\n'" );

	LexFactorAug *commChars = charNegFactorAug( newline );
	LexFactorAug *restOfLine = starFactorAug( commChars );

	LexFactorAug *termNewline = litFactorAug( "'\\n'" );

	LexTerm *concat = concatTerm( pound, restOfLine, termNewline );
	LexExpression *expr = LexExpression::cons( concat );

	LexJoin *join = LexJoin::cons( expr );

	defineToken( internal, String(), join, objectDef, 0, true, false, false );
}

void ConsInit::idToken()
{
	String hello( "id" );

	ObjectDef *objectDef = ObjectDef::cons( ObjectDef::UserType, hello, pd->nextObjectId++ ); 

	LexTerm *r1 = rangeTerm( "'a'", "'z'" );
	LexTerm *r2 = rangeTerm( "'A'", "'Z'" );
	LexTerm *r3 = litTerm( "'_'" );
	LexFactorAug *first = parensFactorAug( orExpr( r1, r2, r3 ) ); 

	LexTerm *r4 = rangeTerm( "'a'", "'z'" );
	LexTerm *r5 = rangeTerm( "'A'", "'Z'" );
	LexTerm *r6 = litTerm( "'_'" );
	LexTerm *r7 = rangeTerm( "'0'", "'9'" );
	LexExpression *second = orExpr( r4, r5, r6, r7 );
	LexFactorAug *secondStar = starFactorAug( second );

	LexTerm *concat = concatTerm( first, secondStar );

	LexExpression *expr = LexExpression::cons( concat );
	LexJoin *join = LexJoin::cons( expr );

	defineToken( internal, hello, join, objectDef, 0, false, false, false );
}

void ConsInit::literalToken()
{
	String hello( "literal" );

	ObjectDef *objectDef = ObjectDef::cons( ObjectDef::UserType, hello, pd->nextObjectId++ ); 

	LexFactorAug *r1 = litFactorAug( "'\\''" );

	/* [^'\\] */
	LexExpression *singleQuoteBackSlash = orExpr( 
		litTerm( "'\\''" ),
		litTerm( "'\\\\'" ) );

	LexTerm *freeChars = charNegTerm( singleQuoteBackSlash );

	/* '\\' any */
	LexFactorAug *backSlash = litFactorAug( "'\\\\'" );
	LexExpression *any = LexExpression::cons( BT_Any );
	LexTerm *escape = concatTerm( backSlash, parensFactorAug( any ) );

	/* Union and repeat. */
	LexExpression *charOrEscape = orExpr( freeChars, escape );
	LexFactorAug *r2 = starFactorAug( charOrEscape );

	LexFactorAug *r3 = litFactorAug( "'\''" );

	LexTerm *concat = concatTerm( r1, r2, r3 );
	LexExpression *expr = LexExpression::cons( concat );
	LexJoin *join = LexJoin::cons( expr );

	defineToken( internal, hello, join, objectDef, 0, false, false, false );
}

void ConsInit::keyword( const String &name, const String &lit )
{
	ObjectDef *objectDef = ObjectDef::cons( ObjectDef::UserType, name, pd->nextObjectId++ ); 
	LexTerm *term = litTerm( lit );
	LexExpression *expr = LexExpression::cons( term );
	LexJoin *join = LexJoin::cons( expr );
	defineToken( internal, name, join, objectDef, 0, false, false, false );
}

void ConsInit::keyword( const String &kw )
{
	literalDef( internal, kw, false, false );
}

ProdEl *ConsInit::prodRefName( const String &name )
{
	ProdEl *prodEl = prodElName( internal, name,
			NamespaceQual::cons( curNspace() ), 0,
			RepeatNone, false );
	return prodEl;
}

ProdEl *ConsInit::prodRefName( const String &capture, const String &name )
{
	ObjectField *captureField = ObjectField::cons( internal,
			ObjectField::RhsNameType, 0, capture );
	ProdEl *prodEl = prodElName( internal, name,
			NamespaceQual::cons( curNspace() ), captureField,
			RepeatNone, false );
	return prodEl;
}

ProdEl *ConsInit::prodRefNameLeftRepeat( const String &name )
{
	ProdEl *prodEl = prodElName( internal, name,
			NamespaceQual::cons( curNspace() ), 0,
			RepeatLeftRepeat, false );
	return prodEl;
}

ProdEl *ConsInit::prodRefNameLeftRepeat( const String &capture, const String &name )
{
	ObjectField *captureField = ObjectField::cons( internal,
			ObjectField::RhsNameType, 0, capture );
	ProdEl *prodEl = prodElName( internal, name,
			NamespaceQual::cons( curNspace() ), captureField,
			RepeatLeftRepeat, false );
	return prodEl;
}

ProdEl *ConsInit::prodRefLit( const String &lit )
{
	ProdEl *prodEl = prodElLiteral( internal, lit, 
			NamespaceQual::cons( curNspace() ), 0,
			RepeatNone, false );
	return prodEl;
}

Production *ConsInit::production()
{
	ProdElList *prodElList = new ProdElList;
	return BaseParser::production( internal, prodElList, String(), false, 0, 0 );
}

Production *ConsInit::production( ProdEl *prodEl1 )
{
	ProdElList *prodElList = new ProdElList;
	appendProdEl( prodElList, prodEl1 );
	return BaseParser::production( internal, prodElList, String(), false, 0, 0 );
}

Production *ConsInit::production( ProdEl *prodEl1, ProdEl *prodEl2 )
{
	ProdElList *prodElList = new ProdElList;
	appendProdEl( prodElList, prodEl1 );
	appendProdEl( prodElList, prodEl2 );
	return BaseParser::production( internal, prodElList, String(), false, 0, 0 );
}

Production *ConsInit::production( ProdEl *prodEl1, ProdEl *prodEl2,
		ProdEl *prodEl3 )
{
	ProdElList *prodElList = new ProdElList;
	appendProdEl( prodElList, prodEl1 );
	appendProdEl( prodElList, prodEl2 );
	appendProdEl( prodElList, prodEl3 );
	return BaseParser::production( internal, prodElList, String(), false, 0, 0 );
}

Production *ConsInit::production( ProdEl *prodEl1, ProdEl *prodEl2,
		ProdEl *prodEl3, ProdEl *prodEl4 )
{
	ProdElList *prodElList = new ProdElList;
	appendProdEl( prodElList, prodEl1 );
	appendProdEl( prodElList, prodEl2 );
	appendProdEl( prodElList, prodEl3 );
	appendProdEl( prodElList, prodEl4 );
	return BaseParser::production( internal, prodElList, String(), false, 0, 0 );
}

Production *ConsInit::production( ProdEl *prodEl1, ProdEl *prodEl2,
		ProdEl *prodEl3, ProdEl *prodEl4, ProdEl *prodEl5 )
{
	ProdElList *prodElList = new ProdElList;
	appendProdEl( prodElList, prodEl1 );
	appendProdEl( prodElList, prodEl2 );
	appendProdEl( prodElList, prodEl3 );
	appendProdEl( prodElList, prodEl4 );
	appendProdEl( prodElList, prodEl5 );
	return BaseParser::production( internal, prodElList, String(), false, 0, 0 );
}

Production *ConsInit::production( ProdEl *prodEl1, ProdEl *prodEl2,
		ProdEl *prodEl3, ProdEl *prodEl4, ProdEl *prodEl5,
		ProdEl *prodEl6, ProdEl *prodEl7 )
{
	ProdElList *prodElList = new ProdElList;
	appendProdEl( prodElList, prodEl1 );
	appendProdEl( prodElList, prodEl2 );
	appendProdEl( prodElList, prodEl3 );
	appendProdEl( prodElList, prodEl4 );
	appendProdEl( prodElList, prodEl5 );
	appendProdEl( prodElList, prodEl6 );
	appendProdEl( prodElList, prodEl7 );
	return BaseParser::production( internal, prodElList, String(), false, 0, 0 );
}

void ConsInit::definition( const String &name, Production *prod1, Production *prod2,
		Production *prod3, Production *prod4 )
{
	LelProdList *prodList = new LelProdList;
	prodAppend( prodList, prod1 );
	prodAppend( prodList, prod2 );
	prodAppend( prodList, prod3 );
	prodAppend( prodList, prod4 );

	NtDef *ntDef = NtDef::cons( name, curNspace(), curStruct(), false );
	ObjectDef *objectDef = ObjectDef::cons( ObjectDef::UserType,
			name, pd->nextObjectId++ ); 
	cflDef( ntDef, objectDef, prodList );
}

void ConsInit::definition( const String &name, Production *prod1,
		Production *prod2, Production *prod3 )
{
	LelProdList *prodList = new LelProdList;
	prodAppend( prodList, prod1 );
	prodAppend( prodList, prod2 );
	prodAppend( prodList, prod3 );

	NtDef *ntDef = NtDef::cons( name, curNspace(), curStruct(), false );
	ObjectDef *objectDef = ObjectDef::cons( ObjectDef::UserType,
			name, pd->nextObjectId++ ); 
	cflDef( ntDef, objectDef, prodList );
}

void ConsInit::definition( const String &name, Production *prod1, Production *prod2 )
{
	LelProdList *prodList = new LelProdList;
	prodAppend( prodList, prod1 );
	prodAppend( prodList, prod2 );

	NtDef *ntDef = NtDef::cons( name, curNspace(), curStruct(), false );
	ObjectDef *objectDef = ObjectDef::cons( ObjectDef::UserType,
			name, pd->nextObjectId++ ); 
	cflDef( ntDef, objectDef, prodList );
}

void ConsInit::definition( const String &name, Production *prod )
{
	LelProdList *prodList = new LelProdList;
	prodAppend( prodList, prod );

	NtDef *ntDef = NtDef::cons( name, curNspace(), curStruct(), false );
	ObjectDef *objectDef = ObjectDef::cons( ObjectDef::UserType,
			name, pd->nextObjectId++ ); 
	cflDef( ntDef, objectDef, prodList );
}

void ConsInit::lexFactor()
{
	ProdEl *prodEl1 = prodRefName( "Literal", "literal" );
	Production *prod1 = production( prodEl1 );

	ProdEl *prodEl8 = prodRefName( "Id", "id" );
	Production *prod4 = production( prodEl8 );

	ProdEl *prodEl2 = prodRefLit( "'('" );
	ProdEl *prodEl3 = prodRefName( "Expr", "lex_expr" );
	ProdEl *prodEl4 = prodRefLit( "')'" );
	Production *prod2 = production( prodEl2, prodEl3, prodEl4 );

	ProdEl *prodEl5 = prodRefName( "Low", "literal" );
	ProdEl *prodEl6 = prodRefLit( "'..'" );
	ProdEl *prodEl7 = prodRefName( "High", "literal" );
	Production *prod3 = production( prodEl5, prodEl6, prodEl7 );

	definition( "lex_factor", prod1, prod2, prod3, prod4 );
}

void ConsInit::lexFactorNeg()
{
	ProdEl *prodEl1 = prodRefLit( "'^'" );
	ProdEl *prodEl2 = prodRefName( "FactorNeg", "lex_factor_neg" );
	Production *prod1 = production( prodEl1, prodEl2 );
	
	ProdEl *prodEl3 = prodRefName( "Factor", "lex_factor" );
	Production *prod2 = production( prodEl3 );

	definition( "lex_factor_neg", prod1, prod2 );
}

void ConsInit::lexFactorRep()
{
	ProdEl *prodEl1 = prodRefName( "FactorRep", "lex_factor_rep" );
	ProdEl *prodEl2 = prodRefName( "Star", "STAR" );
	Production *prod1 = production( prodEl1, prodEl2 );

	ProdEl *prodEl3 = prodRefName( "FactorRep", "lex_factor_rep" );
	ProdEl *prodEl4 = prodRefName( "Plus", "PLUS" );
	Production *prod2 = production( prodEl3, prodEl4 );
	
	ProdEl *prodEl5 = prodRefName( "FactorNeg", "lex_factor_neg" );
	Production *prod3 = production( prodEl5 );

	definition( "lex_factor_rep", prod1, prod2, prod3 );
}

void ConsInit::lexTerm()
{
	ProdEl *prodEl1 = prodRefName( "Term", "lex_term" );
	ProdEl *prodEl2 = prodRefName( "Dot", "DOT" );
	ProdEl *prodEl3 = prodRefName( "FactorRep", "lex_factor_rep" );
	Production *prod1 = production( prodEl1, prodEl2, prodEl3 );

	ProdEl *prodEl4 = prodRefName( "Term", "lex_term" );
	ProdEl *prodEl5 = prodRefName( "ColonLt", "COLON_LT" );
	ProdEl *prodEl6 = prodRefName( "FactorRep", "lex_factor_rep" );
	Production *prod2 = production( prodEl4, prodEl5, prodEl6 );
	
	ProdEl *prodEl7 = prodRefName( "FactorRep", "lex_factor_rep" );
	Production *prod3 = production( prodEl7 );

	definition( "lex_term", prod1, prod2, prod3 );
}

void ConsInit::lexExpr()
{
	ProdEl *prodEl1 = prodRefName( "Expr", "lex_expr" );
	ProdEl *prodEl2 = prodRefLit( "'|'" );
	ProdEl *prodEl3 = prodRefName( "Term", "lex_term" );
	Production *prod1 = production( prodEl1, prodEl2, prodEl3 );
	
	ProdEl *prodEl4 = prodRefName( "Term", "lex_term" );
	Production *prod2 = production( prodEl4 );

	definition( "lex_expr", prod1, prod2 );
}

void ConsInit::token()
{
	ProdEl *prodEl1 = prodRefLit( "'token'" );
	ProdEl *prodEl2 = prodRefName( "Id", "id" );
	ProdEl *prodEl3 = prodRefName( "LeftNi", "opt_ni" );
	ProdEl *prodEl4 = prodRefLit( "'/'" );
	ProdEl *prodEl5 = prodRefName( "Expr", "lex_expr" );
	ProdEl *prodEl6 = prodRefLit( "'/'" );
	ProdEl *prodEl7 = prodRefName( "RightNi", "opt_ni" );
	Production *prod1 = production( prodEl1, prodEl2, prodEl3,
			prodEl4, prodEl5, prodEl6, prodEl7 );
	definition( "token_def", prod1 );
}

void ConsInit::ignore()
{
	ProdEl *prodEl1 = prodRefLit( "'ignore'" );
	ProdEl *prodEl2 = prodRefLit( "'/'" );
	ProdEl *prodEl3 = prodRefName( "Expr", "lex_expr" );
	ProdEl *prodEl4 = prodRefLit( "'/'" );
	Production *prod1 = production( prodEl1, prodEl2, prodEl3, prodEl4 );
	definition( "ignore_def", prod1 );
}

void ConsInit::tokenList()
{
	ProdEl *prodEl1 = prodRefName( "TokenList", "token_list" );
	ProdEl *prodEl2 = prodRefName( "TokenDef", "token_def" );
	Production *prod1 = production( prodEl1, prodEl2 );

	ProdEl *prodEl3 = prodRefName( "TokenList", "token_list" );
	ProdEl *prodEl4 = prodRefName( "IgnoreDef", "ignore_def" );
	Production *prod2 = production( prodEl3, prodEl4 );

	Production *prod3 = production();

	definition( "token_list",  prod1, prod2, prod3 );
}

Production *ConsInit::prodLex()
{
	ProdEl *prodEl1 = prodRefLit( "'lex'" );
	ProdEl *prodEl2 = prodRefName( "TokenList", "token_list" );
	ProdEl *prodEl3 = prodRefLit( "'end'" );

	return production( prodEl1, prodEl2, prodEl3 );
}

void ConsInit::optProdElName()
{
	ProdEl *prodEl1 = prodRefName( "Name", "id" );
	ProdEl *prodEl2 = prodRefLit( "':'" );
	Production *prod1 = production( prodEl1, prodEl2 );
	
	Production *prod2 = production();

	definition( "opt_prod_el_name",  prod1, prod2 );
}

void ConsInit::optNi()
{
	ProdEl *prodEl1 = prodRefLit( "'-'" );
	ProdEl *prodEl2 = prodRefName( "Ni", "NI" );
	Production *prod1 = production( prodEl1, prodEl2 );

	Production *prod2 = production();

	definition( "opt_ni",  prod1, prod2 );
}

void ConsInit::optRepeat()
{
	ProdEl *prodEl1 = prodRefName( "Star", "STAR" );
	Production *prod1 = production( prodEl1 );

	ProdEl *prodEl2 = prodRefName( "LeftStar", "LEFT_STAR" );
	Production *prod2 = production( prodEl2 );

	Production *prod3 = production();

	definition( "opt_prod_repeat",  prod1, prod2, prod3 );
}

void ConsInit::prodEl()
{
	ProdEl *prodEl1 = prodRefName( "OptName", "opt_prod_el_name" );
	ProdEl *prodEl2 = prodRefName( "Id", "id" );
	ProdEl *prodEl3 = prodRefName( "OptRepeat", "opt_prod_repeat" );
	Production *prod1 = production( prodEl1, prodEl2, prodEl3 );

	definition( "prod_el",  prod1 );
}

void ConsInit::prodElList()
{
	ProdEl *prodEl1 = prodRefName( "ProdElList", "prod_el_list" );
	ProdEl *prodEl2 = prodRefName( "ProdEl", "prod_el" );
	Production *prod1 = production( prodEl1, prodEl2 );

	Production *prod2 = production();

	definition( "prod_el_list",  prod1, prod2 );
}

void ConsInit::optCommit()
{
	ProdEl *prodEl1 = prodRefName( "Commit", "COMMIT" );
	Production *prod1 = production( prodEl1 );

	Production *prod2 = production();

	definition( "opt_commit",  prod1, prod2 );
}

void ConsInit::optProdName()
{
	ProdEl *prodEl1 = prodRefLit( "':'" );
	ProdEl *prodEl2 = prodRefName( "Name", "id" );
	Production *prod1 = production( prodEl1, prodEl2 );
	
	Production *prod2 = production();

	definition( "opt_prod_name",  prod1, prod2 );
}

void ConsInit::prodVarDef()
{
	ProdEl *prodEl1 = prodRefName( "Name", "id" );
	ProdEl *prodEl2 = prodRefLit( "':'" );
	ProdEl *prodEl3 = prodRefName( "Type", "id" );
	Production *prod1 = production( prodEl1, prodEl2, prodEl3 );

	definition( "prod_var_def", prod1 );
}

/* The prod var list we provide in a basic form, just "id: id." We won't make
 * use of them in bootstrap0 or bootstrap1, They are ignored in the loader for
 * bootstrap1. We want to use them in bootstrap2 during the rewrite stage. */
void ConsInit::prodVarList()
{
	ProdEl *prodEl1 = prodRefName( "VarDefList", "prod_var_list" );
	ProdEl *prodEl2 = prodRefName( "VarDef", "prod_var_def" );
	Production *prod1 = production( prodEl1, prodEl2 );

	Production *prod2 = production();

	definition( "prod_var_list",  prod1, prod2 );
}

void ConsInit::prod()
{
	ProdEl *prodEl1 = prodRefLit( "'['" );
	ProdEl *prodEl2 = prodRefName( "ProdElList", "prod_el_list" );
	ProdEl *prodEl3 = prodRefLit( "']'" );
	ProdEl *prodEl4 = prodRefName( "OptName", "opt_prod_name" );
	ProdEl *prodEl5 = prodRefName( "OptCommit", "opt_commit" );
	Production *prod1 = production( prodEl1, prodEl2, prodEl3, prodEl4, prodEl5 );

	definition( "prod",  prod1 );
}

void ConsInit::prodList()
{
	ProdEl *prodEl1 = prodRefName( "ProdList", "prod_list" );
	ProdEl *prodEl2 = prodRefLit( "'|'" );
	ProdEl *prodEl3 = prodRefName( "Prod", "prod" );
	Production *prod1 = production( prodEl1, prodEl2, prodEl3 );

	ProdEl *prodEl4 = prodRefName( "Prod", "prod" );
	Production *prod2 = production( prodEl4 );

	definition( "prod_list",  prod1, prod2 );
}

Production *ConsInit::prodProd()
{
	ProdEl *prodEl1 = prodRefLit( "'def'" );
	ProdEl *prodEl2 = prodRefName( "DefId", "id" );
	ProdEl *prodEl3 = prodRefName( "ProdVarList", "prod_var_list" );
	ProdEl *prodEl4 = prodRefName( "ProdList", "prod_list" );

	return production( prodEl1, prodEl2, prodEl3, prodEl4 );
}

void ConsInit::item()
{
	Production *prod1 = prodLex();
	Production *prod2 = prodProd();
	definition( "item",  prod1, prod2 );
}

void ConsInit::startProd()
{
	ProdEl *prodEl1 = prodRefNameLeftRepeat( "ItemList", "item" );
	Production *prod1 = production( prodEl1 );

	definition( "start",  prod1 );
}

void ConsInit::parseInput( StmtList *stmtList )
{
	/* Pop argv, this yields the file name . */
	CallArgVect *popArgs = new CallArgVect;
	QualItemVect *popQual = new QualItemVect;
	popQual->append( QualItem( QualItem::Arrow, internal, String( "argv" ) ) );

	LangVarRef *popRef = LangVarRef::cons( internal,
			curNspace(), 0, curLocalFrame()->rootScope,
			NamespaceQual::cons( curNspace() ), popQual, String("pop") );
	LangExpr *pop = LangExpr::cons( LangTerm::cons( InputLoc(), popRef, popArgs ) );

	TypeRef *typeRef = TypeRef::cons( internal, pd->uniqueTypeStr );
	ObjectField *objField = ObjectField::cons( internal,
			ObjectField::UserLocalType, typeRef, "A" );

	LangStmt *stmt = varDef( objField, pop, LangStmt::AssignType );
	stmtList->append( stmt );

	/* Construct a literal string 'r', for second arg to open. */
	ConsItem *modeConsItem = ConsItem::cons( internal,
			ConsItem::InputText, String("r") );
	ConsItemList *modeCons = new ConsItemList;
	modeCons->append( modeConsItem );
	LangExpr *modeExpr = LangExpr::cons( LangTerm::cons( internal, modeCons ) );

	/* Reference A->value */
	QualItemVect *qual = new QualItemVect;
	LangVarRef *varRef = LangVarRef::cons( internal, curNspace(), 0,
			curLocalFrame()->rootScope, NamespaceQual::cons( curNspace() ),
			qual, String("A") );
	LangExpr *Avalue = LangExpr::cons( LangTerm::cons( internal,
			LangTerm::VarRefType, varRef ) );
	
	/* Call open. */
	QualItemVect *openQual = new QualItemVect;
	LangVarRef *openRef = LangVarRef::cons( internal,
			0, 0, curLocalFrame()->rootScope,
			NamespaceQual::cons( curNspace() ), openQual, String("open") );
	CallArgVect *openArgs = new CallArgVect;
	openArgs->append( new CallArg(Avalue) );
	openArgs->append( new CallArg(modeExpr) );
	LangExpr *open = LangExpr::cons( LangTerm::cons( InputLoc(), openRef, openArgs ) );

	/* Construct a list containing the open stream. */
	ConsItem *consItem = ConsItem::cons( internal, ConsItem::ExprType, open, ConsItem::TrimDefault );
	ConsItemList *list = ConsItemList::cons( consItem );

	/* Will capture the parser to "P" */
	objField = ObjectField::cons( internal,
			ObjectField::UserLocalType, 0, String("P") );

	/* Parse the "start" def. */
	NamespaceQual *nspaceQual = NamespaceQual::cons( curNspace() );
	typeRef = TypeRef::cons( internal, nspaceQual,
			String("start"), RepeatNone );

	/* Parse the above list. */
	LangExpr *parseExpr = parseCmd( internal, false, false, objField,
			typeRef, 0, list, true, false, false, "" );
	LangStmt *parseStmt = LangStmt::cons( internal, LangStmt::ExprType, parseExpr );
	stmtList->append( parseStmt );
}

void ConsInit::exportTree( StmtList *stmtList )
{
	/* reference P */
	QualItemVect *qual = new QualItemVect;
	LangVarRef *varRef = LangVarRef::cons( internal, curNspace(), 0,
			curLocalFrame()->rootScope, NamespaceQual::cons( curNspace() ), qual, String("P") );
	LangExpr *expr = LangExpr::cons( LangTerm::cons( internal,
			LangTerm::VarRefType, varRef ) );

	/* Assign P to ColmTree */
	NamespaceQual *nspaceQual = NamespaceQual::cons( curNspace() );
	TypeRef *typeRef = TypeRef::cons( internal, nspaceQual, String("start"), RepeatNone );
	ObjectField *program = ObjectField::cons( internal,
			ObjectField::StructFieldType, typeRef, String("ColmTree") );
	LangStmt *programExport = exportStmt( program, LangStmt::AssignType, expr );
	stmtList->append( programExport );
}

void ConsInit::go( long activeRealm )
{
	ConsInit::init();

	StmtList *stmtList = new StmtList;

	/* The token region */
	pushRegionSet( internal );

	wsIgnore();
	commentIgnore();

	keyword( "'def'" );
	keyword( "'lex'" );
	keyword( "'end'" );
	keyword( "'token'" );
	keyword( "'ignore'" );
	keyword( "NI", "'ni'" );
	keyword( "COMMIT", "'commit'" );

	idToken();
	literalToken();

	keyword( "STAR", "'*'");
	keyword( "PLUS", "'+'");
	keyword( "LEFT_STAR", "'<*'");
	keyword( "'['" );
	keyword( "']'" );
	keyword( "'|'" );
	keyword( "'/'" );
	keyword( "':'" );
	keyword( "DOT", "'.'" );
	keyword( "COLON_LT", "':>'" );
	keyword( "'('" );
	keyword( "')'" );
	keyword( "'..'" );
	keyword( "'^'" );
	keyword( "'-'" );

	popRegionSet();

	lexFactor();
	lexFactorNeg();
	lexFactorRep();
	lexTerm();
	lexExpr();

	optNi();
	optRepeat();
	optProdElName();
	prodEl();
	prodElList();
	optCommit();
	optProdName();
	prodVarDef();
	prodVarList();
	prod();
	prodList();
	ignore();
	token();
	tokenList();
	item();
	startProd();

	parseInput( stmtList );
	exportTree( stmtList );

	pd->rootCodeBlock = CodeBlock::cons( stmtList, 0 );
}
