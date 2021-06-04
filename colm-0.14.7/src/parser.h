/*
 * Copyright 2013-2018 Adrian Thurston <thurston@colm.net>
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

#ifndef _COLM_PARSER_H
#define _COLM_PARSER_H

#include <iostream>

#include <avltree.h>

#include "compiler.h"
#include "parser.h"

#define PROPERTY_REDUCE_FIRST 0x1

struct BaseParser
{
	BaseParser( Compiler *pd )
		: pd(pd), enterRl(false)
	{}

	virtual ~BaseParser() {}

	Compiler *pd;

	RegionSetVect regionStack;
	NamespaceVect namespaceStack;
	ReductionVect reductionStack;
	StructStack structStack;
	ObjectDef *localFrameTop;
	NameScope *scopeTop;

	bool enterRl;

	bool insideRegion()
		{ return regionStack.length() > 0; }

	StructDef *curStruct()
		{ return structStack.length() == 0 ? 0 : structStack.top(); }

	Namespace *curNspace()
		{ return namespaceStack.top(); }
	
	NameScope *curScope()
		{ return scopeTop; }
	
	ObjectDef *curLocalFrame()
		{ return localFrameTop; }
	
	Reduction *curReduction()
		{ return reductionStack.top(); }

	/* Lexical feedback. */

	void listElDef( String name );
	void mapElDef( String name, TypeRef *keyType );

	void argvDecl();
	void init();
	void addRegularDef( const InputLoc &loc, Namespace *nspace, 
			const String &name, LexJoin *join );
	TokenRegion *createRegion( const InputLoc &loc, RegionImpl *impl );
	Namespace *createRootNamespace();
	Namespace *createNamespace( const InputLoc &loc, const String &name );
	void pushRegionSet( const InputLoc &loc );
	void popRegionSet();
	void addProduction( const InputLoc &loc, const String &name, 
			ProdElList *prodElList, bool commit,
			CodeBlock *redBlock, LangEl *predOf );
	void addArgvList();
	void addStdsList();
	LexJoin *literalJoin( const InputLoc &loc, const String &data );

	Reduction *createReduction( const InputLoc loc, const String &name );

	void defineToken( const InputLoc &loc, String name, LexJoin *join,
			ObjectDef *objectDef, CodeBlock *transBlock,
			bool ignore, bool noPreIgnore, bool noPostIgnore );

	void zeroDef( const InputLoc &loc, const String &name );
	void literalDef( const InputLoc &loc, const String &data,
			bool noPreIgnore, bool noPostIgnore );

	ObjectDef *blockOpen();
	void blockClose();

	void inHostDef( const String &hostCall, ObjectDef *localFrame,
			ParameterList *paramList, TypeRef *typeRef,
			const String &name, bool exprt );
	void functionDef( StmtList *stmtList, ObjectDef *localFrame,
			ParameterList *paramList, TypeRef *typeRef,
			const String &name, bool exprt );

	void iterDef( StmtList *stmtList, ObjectDef *localFrame,
			ParameterList *paramList, const String &name );
	LangStmt *globalDef( ObjectField *objField, LangExpr *expr,
			LangStmt::Type assignType );
	void cflDef( NtDef *ntDef, ObjectDef *objectDef, LelProdList *defList );
	ReOrBlock *lexRegularExprData( ReOrBlock *reOrBlock, ReOrItem *reOrItem );

	int lexFactorRepNum( const InputLoc &loc, const String &data );
	LexFactor *lexRlFactorName( const String &data, const InputLoc &loc );
	LexFactorAug *lexFactorLabel( const InputLoc &loc, const String &data,
			LexFactorAug *factorAug );
	LexJoin *lexOptJoin( LexJoin *join, LexJoin *context );
	LangExpr *send( const InputLoc &loc, LangVarRef *varRef,
			ConsItemList *list, bool eof );
	LangExpr *sendTree( const InputLoc &loc, LangVarRef *varRef,
			ConsItemList *list, bool eof );
	LangExpr *parseCmd( const InputLoc &loc, bool tree, bool stop, ObjectField *objField,
			TypeRef *typeRef, FieldInitVect *fieldInitVect, ConsItemList *list,
			bool used, bool reduce, bool read, const String &reducer );
	PatternItemList *consPatternEl( LangVarRef *varRef, PatternItemList *list );
	PatternItemList *patternElNamed( const InputLoc &loc, LangVarRef *varRef,
			NamespaceQual *nspaceQual, const String &data, RepeatType repeatType );
	PatternItemList *patternElType( const InputLoc &loc, LangVarRef *varRef,
			NamespaceQual *nspaceQual, const String &data, RepeatType repeatType );
	PatternItemList *patListConcat( PatternItemList *list1, PatternItemList *list2 );
	ConsItemList *consListConcat( ConsItemList *list1, ConsItemList *list2 );
	LangStmt *forScope( const InputLoc &loc, const String &data,
			NameScope *scope, TypeRef *typeRef, IterCall *iterCall, StmtList *stmtList );
	void preEof( const InputLoc &loc, StmtList *stmtList, ObjectDef *localFrame );

	ProdEl *prodElName( const InputLoc &loc, const String &data,
			NamespaceQual *nspaceQual, ObjectField *objField, RepeatType repeatType,
			bool commit );
	ProdEl *prodElLiteral( const InputLoc &loc, const String &data,
			NamespaceQual *nspaceQual, ObjectField *objField, RepeatType repeatType,
			bool commit );
	ConsItemList *consElLiteral( const InputLoc &loc, TypeRef *consTypeRef,
			const String &data, NamespaceQual *nspaceQual );
	Production *production( const InputLoc &loc, ProdElList *prodElList,
			String name, bool commit, CodeBlock *codeBlock, LangEl *predOf );
	void objVarDef( ObjectDef *objectDef, ObjectField *objField );
	LelProdList *prodAppend( LelProdList *defList, Production *definition );

	LangExpr *construct( const InputLoc &loc, ObjectField *objField,
			ConsItemList *list, TypeRef *typeRef, FieldInitVect *fieldInitVect );
	LangExpr *match( const InputLoc &loc, LangVarRef *varRef,
			PatternItemList *list );
	LangExpr *prodCompare( const InputLoc &loc, LangVarRef *varRef,
			const String &prod, LangExpr *matchExpr );
	LangStmt *varDef( ObjectField *objField,
			LangExpr *expr, LangStmt::Type assignType );
	LangStmt *exportStmt( ObjectField *objField, LangStmt::Type assignType, LangExpr *expr );


	LangExpr *require( const InputLoc &loc, LangVarRef *varRef, PatternItemList *list );
	void structVarDef( const InputLoc &loc, ObjectField *objField );
	void structHead( const InputLoc &loc, Namespace *inNspace,
			const String &data, ObjectDef::Type objectType );
	StmtList *appendStatement( StmtList *stmtList, LangStmt *stmt );
	ParameterList *appendParam( ParameterList *paramList, ObjectField *objField );
	ObjectField *addParam( const InputLoc &loc,
			ObjectField::Type type, TypeRef *typeRef, const String &name );
	PredDecl *predTokenName( const InputLoc &loc, NamespaceQual *qual, const String &data );
	PredDecl *predTokenLit( const InputLoc &loc, const String &data,
			NamespaceQual *nspaceQual );
	void alias( const InputLoc &loc, const String &data, TypeRef *typeRef );
	void precedenceStmt( PredType predType, PredDeclList *predDeclList );
	ProdElList *appendProdEl( ProdElList *prodElList, ProdEl *prodEl );

	void pushScope();
	void popScope();

	virtual void go( long activeRealm ) = 0;

	BstSet<String, ColmCmpStr> genericElDefined;

	NamespaceQual *emptyNspaceQual()
	{
		return NamespaceQual::cons( curNspace() );
	}

};

#endif /* _COLM_PARSER_H */

