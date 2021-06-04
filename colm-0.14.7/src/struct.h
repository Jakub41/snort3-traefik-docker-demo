/*
 * Copyright 2016-2018 Adrian Thurston <thurston@colm.net>
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

#ifndef _COLM_STRUCT_H
#define _COLM_STRUCT_H

#if defined(__cplusplus)
extern "C" {
#endif

typedef void (*colm_destructor_t)( struct colm_program *prg,
		tree_t **sp, struct colm_struct *s );

struct colm_struct
{
	short id;
	struct colm_struct *prev, *next;
};

/* Must overlay colm_struct. */
struct colm_inbuilt
{
	short id;
	struct colm_struct *prev, *next;
	colm_destructor_t destructor;
};

/* Must overlay colm_inbuilt. */
typedef struct colm_parser
{
	short id;
	struct colm_struct *prev, *next;
	colm_destructor_t destructor;

	struct pda_run *pda_run;
	struct colm_input *input;
	tree_t *result;
} parser_t;

/* Must overlay colm_inbuilt. */
typedef struct colm_input
{
	short id;
	struct colm_struct *prev, *next;
	colm_destructor_t destructor;

	struct input_impl *impl;
} input_t;

/* Must overlay colm_inbuilt. */
typedef struct colm_stream
{
	short id;
	struct colm_struct *prev, *next;
	colm_destructor_t destructor;

	struct stream_impl *impl;
} stream_t;

#define COLM_LIST_EL_SIZE 2
typedef struct colm_list_el
{
	struct colm_list_el *list_next;
	struct colm_list_el *list_prev;
} list_el_t;

/* Must overlay colm_inbuilt. */
typedef struct colm_list
{
	short id;
	struct colm_struct *prev, *next;
	colm_destructor_t destructor;

	list_el_t *head, *tail;
	long list_len;
	struct generic_info *generic_info;
} list_t;

typedef struct colm_map_el
{
	tree_t *key;

	struct colm_map_el *left, *right, *parent;
	long height;

	struct colm_map_el *next, *prev;
} map_el_t;

#define COLM_MAP_EL_SIZE ( sizeof(colm_map_el) / sizeof(void*) )

typedef struct colm_map
{
	short id;
	struct colm_struct *prev, *next;
	colm_destructor_t destructor;

	struct colm_map_el *head, *tail, *root;
	long tree_size;
	struct generic_info *generic_info;
} map_t;

struct colm_struct *colm_struct_new_size( struct colm_program *prg, int size );
struct colm_struct *colm_struct_new( struct colm_program *prg, int id );
void colm_struct_add( struct colm_program *prg, struct colm_struct *item );
void colm_struct_delete( struct colm_program *prg, struct colm_tree **sp,
		struct colm_struct *el );

struct colm_struct *colm_struct_inbuilt( struct colm_program *prg, int size,
		colm_destructor_t destructor );

#define colm_struct_get_field( obj, type, field ) \
	(type)(((void**)(((struct colm_struct*)obj)+1))[field])

#define colm_struct_set_field( obj, type, field, val ) \
	((type*)(((struct colm_struct*)obj)+1))[field] = val

#define colm_struct_get_addr( obj, type, field ) \
	(type)(&(((void **)(((struct colm_struct*)obj)+1))[field]))

#define colm_struct_container( el, field ) \
	((void*)el) - (field * sizeof(void*)) - sizeof(struct colm_struct)

#define colm_generic_el_container( prg, el, genId ) \
	colm_struct_container( el, prg->rtd->generic_info[genId].el_offset )

#define colm_struct_to_list_el( prg, obj, genId ) \
	colm_struct_get_addr( obj, list_el_t*, prg->rtd->generic_info[genId].el_offset )

#define colm_struct_to_map_el( prg, obj, genId ) \
	colm_struct_get_addr( obj, map_el_t*, prg->rtd->generic_info[genId].el_offset )

parser_t *colm_parser_new( program_t *prg, struct generic_info *gi, int stop_id, int reducer );
input_t *colm_input_new( struct colm_program *prg );
stream_t *colm_stream_new_struct( struct colm_program *prg );

list_t *colm_list_new( struct colm_program *prg );
struct colm_struct *colm_list_get( struct colm_program *prg, list_t *list,
		word_t gen_id, word_t field );
struct colm_struct *colm_list_el_get( struct colm_program *prg,
		list_el_t *list_el, word_t gen_id, word_t field );
list_el_t *colm_list_detach_head( list_t *list );
list_el_t *colm_list_detach_tail( list_t *list );
long colm_list_length( list_t *list );

map_t *colm_map_new( struct colm_program *prg );
struct colm_struct *colm_map_el_get( struct colm_program *prg,
		map_el_t *map_el, word_t gen_id, word_t field );
struct colm_struct *colm_map_get( struct colm_program *prg, map_t *map,
		word_t gen_id, word_t field );

struct colm_struct *colm_construct_generic( struct colm_program *prg, long generic_id, int stop_id );
struct colm_struct *colm_construct_reducer( struct colm_program *prg, long generic_id, int reducer_id );
struct input_impl *input_to_impl( input_t *ptr );
struct stream_impl *stream_to_impl( stream_t *ptr );

#if defined(__cplusplus)
}
#endif

#endif /* _COLM_STRUCT_H */

