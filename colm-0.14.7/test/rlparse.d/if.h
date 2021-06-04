#ifndef _EXPORTS_H
#define _EXPORTS_H

#include <colm/colm.h>
#include <colm/tree.h>
#include <colm/colmex.h>
#include <string>

struct _notoken;
struct ptr;
struct str;
struct il;
struct any;
struct select;
struct c_select;
struct ruby_select;
struct ocaml_select;
struct crack_select;
struct selectt;
struct c_select_section;
struct ruby_select_section;
struct ocaml_select_section;
struct crack_select_section;
struct start;
struct import_val;
struct import;
namespace srlex { struct _literal_0003; }
namespace srlex { struct _literal_0005; }
namespace srlex { struct _literal_0007; }
namespace srlex { struct _ignore_0001; }
namespace srlex { struct word; }
namespace ragel { struct _literal_0015; }
namespace ragel { struct _literal_001b; }
namespace ragel { struct _literal_001d; }
namespace ragel { struct _literal_001f; }
namespace ragel { struct _literal_0021; }
namespace ragel { struct _literal_0023; }
namespace ragel { struct _literal_0025; }
namespace ragel { struct _literal_0027; }
namespace ragel { struct _literal_0029; }
namespace ragel { struct _literal_002b; }
namespace ragel { struct _literal_002d; }
namespace ragel { struct _literal_002f; }
namespace ragel { struct _literal_0031; }
namespace ragel { struct _literal_0033; }
namespace ragel { struct _literal_0035; }
namespace ragel { struct _literal_0037; }
namespace ragel { struct _literal_0039; }
namespace ragel { struct _literal_003b; }
namespace ragel { struct _literal_003d; }
namespace ragel { struct _literal_003f; }
namespace ragel { struct _literal_0041; }
namespace ragel { struct _literal_0043; }
namespace ragel { struct _literal_0045; }
namespace ragel { struct _literal_0047; }
namespace ragel { struct _literal_0049; }
namespace ragel { struct _literal_004b; }
namespace ragel { struct _literal_004d; }
namespace ragel { struct _literal_004f; }
namespace ragel { struct _literal_0051; }
namespace ragel { struct _literal_0053; }
namespace ragel { struct _literal_0055; }
namespace ragel { struct _literal_0057; }
namespace ragel { struct _literal_0059; }
namespace ragel { struct _literal_005b; }
namespace ragel { struct _literal_005d; }
namespace ragel { struct _literal_005f; }
namespace ragel { struct _literal_0061; }
namespace ragel { struct _literal_0063; }
namespace ragel { struct _literal_0065; }
namespace ragel { struct _literal_0067; }
namespace ragel { struct _literal_0069; }
namespace ragel { struct _literal_006b; }
namespace ragel { struct _literal_006d; }
namespace ragel { struct _literal_006f; }
namespace ragel { struct _literal_0071; }
namespace ragel { struct _literal_0073; }
namespace ragel { struct _literal_0075; }
namespace ragel { struct _literal_0077; }
namespace ragel { struct _literal_0079; }
namespace ragel { struct _literal_007b; }
namespace ragel { struct _literal_007d; }
namespace ragel { struct _literal_007f; }
namespace ragel { struct _literal_0081; }
namespace ragel { struct _literal_0083; }
namespace ragel { struct _literal_0085; }
namespace ragel { struct _literal_0087; }
namespace ragel { struct _literal_0089; }
namespace ragel { struct _literal_008b; }
namespace ragel { struct _literal_008d; }
namespace ragel { struct _literal_008f; }
namespace ragel { struct _literal_0091; }
namespace ragel { struct _literal_0093; }
namespace ragel { struct _literal_0095; }
namespace ragel { struct _literal_0097; }
namespace ragel { struct _literal_0099; }
namespace ragel { struct _literal_009b; }
namespace ragel { struct _literal_009d; }
namespace ragel { struct _literal_009f; }
namespace ragel { struct _literal_00a1; }
namespace ragel { struct _literal_00a3; }
namespace ragel { struct _literal_00a5; }
namespace ragel { struct _literal_00a7; }
namespace ragel { struct _literal_00a9; }
namespace ragel { struct _literal_00ab; }
namespace ragel { struct _literal_00ad; }
namespace ragel { struct _literal_00af; }
namespace ragel { struct _literal_00b1; }
namespace ragel { struct _literal_00b3; }
namespace ragel { struct _literal_00b5; }
namespace ragel { struct _literal_00b7; }
namespace ragel { struct _literal_00b9; }
namespace ragel { struct _literal_00bb; }
namespace ragel { struct _literal_00bd; }
namespace ragel { struct _literal_00bf; }
namespace ragel { struct _literal_00c1; }
namespace ragel { struct _literal_00c3; }
namespace ragel { struct _literal_00c5; }
namespace ragel { struct _literal_00c7; }
namespace ragel { struct _literal_00c9; }
namespace ragel { struct _literal_00cb; }
namespace ragel { struct _literal_00cd; }
namespace ragel { struct _literal_00cf; }
namespace ragel { struct _literal_00d1; }
namespace ragel { struct _literal_00d3; }
namespace ragel { struct _literal_00d5; }
namespace ragel { struct _literal_00d7; }
namespace ragel { struct _literal_00d9; }
namespace ragel { struct _literal_00db; }
namespace ragel { struct _ignore_0017; }
namespace ragel { struct _ignore_0019; }
namespace ragel { struct string; }
namespace ragel { struct lex_regex_open; }
namespace ragel { struct lex_sqopen_pos; }
namespace ragel { struct lex_sqopen_neg; }
namespace ragel { struct word; }
namespace ragel { struct uint; }
namespace ragel { struct hex; }
namespace ragel { struct re_dot; }
namespace ragel { struct re_star; }
namespace ragel { struct re_char; }
namespace ragel { struct re_close; }
namespace ragel { struct re_sqopen_pos; }
namespace ragel { struct re_sqopen_neg; }
namespace ragel { struct re_or_dash; }
namespace ragel { struct re_or_char; }
namespace ragel { struct re_or_sqclose; }
namespace ragel { struct _inline_expr_reparse; }
namespace ragel { struct variable_name; }
namespace ragel { struct inline_expr_reparse; }
namespace ragel { struct join; }
namespace ragel { struct expression; }
namespace ragel { struct expression_op_list; }
namespace ragel { struct expression_op; }
namespace ragel { struct expr_left; }
namespace ragel { struct term; }
namespace ragel { struct term_left; }
namespace ragel { struct term_op_list_short; }
namespace ragel { struct term_op; }
namespace ragel { struct factor_label; }
namespace ragel { struct factor_ep; }
namespace ragel { struct epsilon_target; }
namespace ragel { struct action_expr; }
namespace ragel { struct action_block; }
namespace ragel { struct action_arg_list; }
namespace ragel { struct opt_action_arg_list; }
namespace ragel { struct named_action_ref; }
namespace ragel { struct action_ref; }
namespace ragel { struct priority_name; }
namespace ragel { struct error_name; }
namespace ragel { struct priority_aug; }
namespace ragel { struct aug_base; }
namespace ragel { struct aug_cond; }
namespace ragel { struct aug_to_state; }
namespace ragel { struct aug_from_state; }
namespace ragel { struct aug_eof; }
namespace ragel { struct aug_gbl_error; }
namespace ragel { struct aug_local_error; }
namespace ragel { struct factor_aug; }
namespace ragel { struct factor_rep; }
namespace ragel { struct factor_rep_op_list; }
namespace ragel { struct factor_rep_op; }
namespace ragel { struct factor_rep_num; }
namespace ragel { struct factor_neg; }
namespace ragel { struct opt_max_arg; }
namespace ragel { struct nfastar; }
namespace ragel { struct colon_cond; }
namespace ragel { struct factor; }
namespace ragel { struct regex; }
namespace ragel { struct reg_item_rep_list; }
namespace ragel { struct reg_item_rep; }
namespace ragel { struct reg_item; }
namespace ragel { struct reg_or_data; }
namespace ragel { struct reg_or_char; }
namespace ragel { struct range_lit; }
namespace ragel { struct alphabet_num; }
namespace ragel { struct lm_act; }
namespace ragel { struct opt_lm_act; }
namespace ragel { struct lm_stmt; }
namespace ragel { struct lm_stmt_list; }
namespace ragel { struct lm; }
namespace ragel { struct action_param; }
namespace ragel { struct action_param_list; }
namespace ragel { struct opt_action_param_list; }
namespace ragel { struct action_params; }
namespace ragel { struct action_spec; }
namespace ragel { struct def_name; }
namespace ragel { struct assignment; }
namespace ragel { struct instantiation; }
namespace ragel { struct nfa_expr; }
namespace ragel { struct nfa_round_spec; }
namespace ragel { struct nfa_round_list; }
namespace ragel { struct nfa_rounds; }
namespace ragel { struct nfa_union; }
namespace ragel { struct alphtype_type; }
namespace ragel { struct include_spec; }
namespace ragel { struct opt_export; }
namespace ragel { struct write_arg; }
namespace ragel { struct machine_name; }
namespace ragel { struct statement; }
namespace ragel { struct opt_machine_name; }
namespace ragel { struct ragel_start; }
namespace c_inline { struct _literal_0101; }
namespace c_inline { struct _literal_0103; }
namespace c_inline { struct _literal_0105; }
namespace c_inline { struct _literal_0107; }
namespace c_inline { struct _literal_0109; }
namespace c_inline { struct _literal_010b; }
namespace c_inline { struct _literal_010d; }
namespace c_inline { struct _literal_010f; }
namespace c_inline { struct _literal_0111; }
namespace c_inline { struct _literal_0113; }
namespace c_inline { struct _literal_0115; }
namespace c_inline { struct _literal_0117; }
namespace c_inline { struct _literal_0119; }
namespace c_inline { struct _literal_011b; }
namespace c_inline { struct _literal_011d; }
namespace c_inline { struct _literal_012b; }
namespace c_inline { struct _literal_012d; }
namespace c_inline { struct _literal_012f; }
namespace c_inline { struct _literal_0131; }
namespace c_inline { struct _literal_0133; }
namespace c_inline { struct _literal_0135; }
namespace c_inline { struct _literal_0137; }
namespace c_inline { struct _literal_0139; }
namespace c_inline { struct ident; }
namespace c_inline { struct number; }
namespace c_inline { struct hex_number; }
namespace c_inline { struct comment; }
namespace c_inline { struct string; }
namespace c_inline { struct whitespace; }
namespace c_inline { struct var_ref; }
namespace c_inline { struct c_any; }
namespace c_inline { struct inline_expr; }
namespace c_inline { struct expr_item_list; }
namespace c_inline { struct expr_item; }
namespace c_inline { struct expr_any; }
namespace c_inline { struct expr_symbol; }
namespace c_inline { struct expr_interpret; }
namespace c_inline { struct state_ref; }
namespace c_inline { struct opt_name_sep; }
namespace c_inline { struct state_ref_names; }
namespace c_inline { struct inline_block; }
namespace c_inline { struct block_item_list; }
namespace c_inline { struct block_item; }
namespace c_inline { struct block_symbol; }
namespace c_inline { struct block_interpret; }
namespace c_host { struct _literal_013f; }
namespace c_host { struct slr; }
namespace c_host { struct ident; }
namespace c_host { struct number; }
namespace c_host { struct hex_number; }
namespace c_host { struct comment; }
namespace c_host { struct string; }
namespace c_host { struct whitespace; }
namespace c_host { struct c_any; }
namespace c_host { struct tok; }
namespace c_host { struct section; }
namespace ocaml_inline { struct _literal_0151; }
namespace ocaml_inline { struct _literal_0153; }
namespace ocaml_inline { struct _literal_0155; }
namespace ocaml_inline { struct _literal_0157; }
namespace ocaml_inline { struct _literal_0159; }
namespace ocaml_inline { struct _literal_015b; }
namespace ocaml_inline { struct _literal_015d; }
namespace ocaml_inline { struct _literal_015f; }
namespace ocaml_inline { struct _literal_0161; }
namespace ocaml_inline { struct _literal_0163; }
namespace ocaml_inline { struct _literal_0165; }
namespace ocaml_inline { struct _literal_0167; }
namespace ocaml_inline { struct _literal_0169; }
namespace ocaml_inline { struct _literal_016b; }
namespace ocaml_inline { struct _literal_016d; }
namespace ocaml_inline { struct _literal_017b; }
namespace ocaml_inline { struct _literal_017d; }
namespace ocaml_inline { struct _literal_017f; }
namespace ocaml_inline { struct _literal_0181; }
namespace ocaml_inline { struct _literal_0183; }
namespace ocaml_inline { struct _literal_0185; }
namespace ocaml_inline { struct _literal_0187; }
namespace ocaml_inline { struct _literal_0189; }
namespace ocaml_inline { struct ident; }
namespace ocaml_inline { struct number; }
namespace ocaml_inline { struct hex_number; }
namespace ocaml_inline { struct comment; }
namespace ocaml_inline { struct string; }
namespace ocaml_inline { struct whitespace; }
namespace ocaml_inline { struct c_any; }
namespace ocaml_inline { struct inline_expr; }
namespace ocaml_inline { struct expr_item; }
namespace ocaml_inline { struct expr_any; }
namespace ocaml_inline { struct expr_symbol; }
namespace ocaml_inline { struct expr_interpret; }
namespace ocaml_inline { struct state_ref; }
namespace ocaml_inline { struct opt_name_sep; }
namespace ocaml_inline { struct state_ref_names; }
namespace ocaml_inline { struct inline_block; }
namespace ocaml_inline { struct block_item; }
namespace ocaml_inline { struct block_symbol; }
namespace ocaml_inline { struct block_interpret; }
namespace ocaml_host { struct _literal_018d; }
namespace ocaml_host { struct slr; }
namespace ocaml_host { struct ident; }
namespace ocaml_host { struct number; }
namespace ocaml_host { struct hex_number; }
namespace ocaml_host { struct comment; }
namespace ocaml_host { struct string; }
namespace ocaml_host { struct whitespace; }
namespace ocaml_host { struct ocaml_any; }
namespace ocaml_host { struct tok; }
namespace ocaml_host { struct section; }
namespace ruby_inline { struct _literal_019f; }
namespace ruby_inline { struct _literal_01a1; }
namespace ruby_inline { struct _literal_01a3; }
namespace ruby_inline { struct _literal_01a5; }
namespace ruby_inline { struct _literal_01a7; }
namespace ruby_inline { struct _literal_01a9; }
namespace ruby_inline { struct _literal_01ab; }
namespace ruby_inline { struct _literal_01ad; }
namespace ruby_inline { struct _literal_01af; }
namespace ruby_inline { struct _literal_01b1; }
namespace ruby_inline { struct _literal_01b3; }
namespace ruby_inline { struct _literal_01b5; }
namespace ruby_inline { struct _literal_01b7; }
namespace ruby_inline { struct _literal_01b9; }
namespace ruby_inline { struct _literal_01bb; }
namespace ruby_inline { struct _literal_01c9; }
namespace ruby_inline { struct _literal_01cb; }
namespace ruby_inline { struct _literal_01cd; }
namespace ruby_inline { struct _literal_01cf; }
namespace ruby_inline { struct _literal_01d1; }
namespace ruby_inline { struct _literal_01d3; }
namespace ruby_inline { struct _literal_01d5; }
namespace ruby_inline { struct _literal_01d7; }
namespace ruby_inline { struct ident; }
namespace ruby_inline { struct number; }
namespace ruby_inline { struct hex_number; }
namespace ruby_inline { struct comment; }
namespace ruby_inline { struct string; }
namespace ruby_inline { struct whitespace; }
namespace ruby_inline { struct ruby_any; }
namespace ruby_inline { struct inline_expr; }
namespace ruby_inline { struct expr_item; }
namespace ruby_inline { struct expr_any; }
namespace ruby_inline { struct expr_symbol; }
namespace ruby_inline { struct expr_interpret; }
namespace ruby_inline { struct state_ref; }
namespace ruby_inline { struct opt_name_sep; }
namespace ruby_inline { struct state_ref_names; }
namespace ruby_inline { struct inline_block; }
namespace ruby_inline { struct block_item; }
namespace ruby_inline { struct block_symbol; }
namespace ruby_inline { struct block_interpret; }
namespace ruby_host { struct _literal_01db; }
namespace ruby_host { struct slr; }
namespace ruby_host { struct ident; }
namespace ruby_host { struct number; }
namespace ruby_host { struct hex_number; }
namespace ruby_host { struct comment; }
namespace ruby_host { struct string; }
namespace ruby_host { struct whitespace; }
namespace ruby_host { struct ruby_any; }
namespace ruby_host { struct tok; }
namespace ruby_host { struct section; }
namespace crack_inline { struct _literal_01ed; }
namespace crack_inline { struct _literal_01ef; }
namespace crack_inline { struct _literal_01f1; }
namespace crack_inline { struct _literal_01f3; }
namespace crack_inline { struct _literal_01f5; }
namespace crack_inline { struct _literal_01f7; }
namespace crack_inline { struct _literal_01f9; }
namespace crack_inline { struct _literal_01fb; }
namespace crack_inline { struct _literal_01fd; }
namespace crack_inline { struct _literal_01ff; }
namespace crack_inline { struct _literal_0201; }
namespace crack_inline { struct _literal_0203; }
namespace crack_inline { struct _literal_0205; }
namespace crack_inline { struct _literal_0207; }
namespace crack_inline { struct _literal_0209; }
namespace crack_inline { struct _literal_0217; }
namespace crack_inline { struct _literal_0219; }
namespace crack_inline { struct _literal_021b; }
namespace crack_inline { struct _literal_021d; }
namespace crack_inline { struct _literal_021f; }
namespace crack_inline { struct _literal_0221; }
namespace crack_inline { struct _literal_0223; }
namespace crack_inline { struct _literal_0225; }
namespace crack_inline { struct ident; }
namespace crack_inline { struct number; }
namespace crack_inline { struct hex_number; }
namespace crack_inline { struct comment; }
namespace crack_inline { struct string; }
namespace crack_inline { struct whitespace; }
namespace crack_inline { struct c_any; }
namespace crack_inline { struct inline_expr; }
namespace crack_inline { struct expr_item; }
namespace crack_inline { struct expr_any; }
namespace crack_inline { struct expr_symbol; }
namespace crack_inline { struct expr_interpret; }
namespace crack_inline { struct state_ref; }
namespace crack_inline { struct opt_name_sep; }
namespace crack_inline { struct state_ref_names; }
namespace crack_inline { struct inline_block; }
namespace crack_inline { struct block_item; }
namespace crack_inline { struct block_symbol; }
namespace crack_inline { struct block_interpret; }
namespace crack_host { struct _literal_0229; }
namespace crack_host { struct slr; }
namespace crack_host { struct ident; }
namespace crack_host { struct number; }
namespace crack_host { struct hex_number; }
namespace crack_host { struct comment; }
namespace crack_host { struct string; }
namespace crack_host { struct whitespace; }
namespace crack_host { struct c_any; }
namespace crack_host { struct tok; }
namespace crack_host { struct section; }
struct _ign_0x55b47a1dd850;
struct _ign_0x55b47a1e12c0;
struct _ign_0x55b47a1e1500;
struct _ign_0x55b47a20ad10;
struct _ign_0x55b47a20af50;
struct _ign_0x55b47a210010;
struct _ign_0x55b47a212460;
struct _ign_0x55b47a1ae370;
struct _ign_0x55b47a1d2560;
struct _ign_0x55b47a1b42a0;
struct _ign_0x55b47a3a95d0;
struct _ign_0x55b47a38f0a0;
struct _ign_0x55b47a416030;
struct _ign_0x55b47a38e100;
struct _ign_0x55b47a369d40;
struct _ign_0x55b47a1b30f0;
struct __0x55b47a1e1360_DEF_PAT_1;
struct __0x55b47a20adb0_DEF_PAT_2;
struct __0x55b47a20de10_DEF_PAT_3;
struct __0x55b47a211d40_DEF_PAT_4;
struct __0x55b47a212500_DEF_PAT_5;
struct __0x55b47a1ae5f0_DEF_PAT_6;
struct __0x55b47a1d2600_DEF_PAT_7;
struct __0x55b47a1b4520_DEF_PAT_8;
struct __0x55b47a3a9670_DEF_PAT_9;
struct __0x55b47a38f320_DEF_PAT_10;
struct __0x55b47a4160d0_DEF_PAT_11;
struct __0x55b47a38e380_DEF_PAT_12;
struct __0x55b47a369de0_DEF_PAT_13;
struct __0x55b47a17d690_DEF_PAT_14;
struct _repeat_import;
namespace c_host { struct _repeat_section; }
namespace ruby_host { struct _repeat_section; }
namespace ocaml_host { struct _repeat_section; }
namespace ragel { struct _repeat_write_arg; }
namespace ragel { struct _repeat_statement; }
namespace c_inline { struct _opt_whitespace; }
namespace ocaml_inline { struct _repeat_expr_item; }
namespace ocaml_inline { struct _repeat_block_item; }
namespace ocaml_inline { struct _opt_whitespace; }
namespace ruby_inline { struct _repeat_expr_item; }
namespace ruby_inline { struct _repeat_block_item; }
namespace ruby_inline { struct _opt_whitespace; }
namespace crack_inline { struct _repeat_expr_item; }
namespace crack_inline { struct _repeat_block_item; }
namespace crack_inline { struct _opt_whitespace; }
namespace crack_host { struct _repeat_section; }
struct _T_any;
struct _T_start;
struct _T_import_val;
struct _T_import;
namespace ragel { struct _T_inline_expr_reparse; }
namespace ragel { struct _T_join; }
namespace ragel { struct _T_expression; }
namespace ragel { struct _T_expression_op_list; }
namespace ragel { struct _T_expression_op; }
namespace ragel { struct _T_expr_left; }
namespace ragel { struct _T_term; }
namespace ragel { struct _T_term_left; }
namespace ragel { struct _T_term_op_list_short; }
namespace ragel { struct _T_term_op; }
namespace ragel { struct _T_factor_label; }
namespace ragel { struct _T_factor_ep; }
namespace ragel { struct _T_epsilon_target; }
namespace ragel { struct _T_action_expr; }
namespace ragel { struct _T_action_block; }
namespace ragel { struct _T_action_arg_list; }
namespace ragel { struct _T_opt_action_arg_list; }
namespace ragel { struct _T_named_action_ref; }
namespace ragel { struct _T_action_ref; }
namespace ragel { struct _T_priority_name; }
namespace ragel { struct _T_error_name; }
namespace ragel { struct _T_priority_aug; }
namespace ragel { struct _T_aug_base; }
namespace ragel { struct _T_aug_cond; }
namespace ragel { struct _T_aug_to_state; }
namespace ragel { struct _T_aug_from_state; }
namespace ragel { struct _T_aug_eof; }
namespace ragel { struct _T_aug_gbl_error; }
namespace ragel { struct _T_aug_local_error; }
namespace ragel { struct _T_factor_aug; }
namespace ragel { struct _T_factor_rep; }
namespace ragel { struct _T_factor_rep_op_list; }
namespace ragel { struct _T_factor_rep_op; }
namespace ragel { struct _T_factor_rep_num; }
namespace ragel { struct _T_factor_neg; }
namespace ragel { struct _T_opt_max_arg; }
namespace ragel { struct _T_nfastar; }
namespace ragel { struct _T_colon_cond; }
namespace ragel { struct _T_factor; }
namespace ragel { struct _T_regex; }
namespace ragel { struct _T_reg_item_rep_list; }
namespace ragel { struct _T_reg_item_rep; }
namespace ragel { struct _T_reg_item; }
namespace ragel { struct _T_reg_or_data; }
namespace ragel { struct _T_reg_or_char; }
namespace ragel { struct _T_range_lit; }
namespace ragel { struct _T_alphabet_num; }
namespace ragel { struct _T_lm_act; }
namespace ragel { struct _T_opt_lm_act; }
namespace ragel { struct _T_lm_stmt; }
namespace ragel { struct _T_lm_stmt_list; }
namespace ragel { struct _T_lm; }
namespace ragel { struct _T_action_param; }
namespace ragel { struct _T_action_param_list; }
namespace ragel { struct _T_opt_action_param_list; }
namespace ragel { struct _T_action_params; }
namespace ragel { struct _T_action_spec; }
namespace ragel { struct _T_def_name; }
namespace ragel { struct _T_assignment; }
namespace ragel { struct _T_instantiation; }
namespace ragel { struct _T_nfa_expr; }
namespace ragel { struct _T_nfa_round_spec; }
namespace ragel { struct _T_nfa_round_list; }
namespace ragel { struct _T_nfa_rounds; }
namespace ragel { struct _T_nfa_union; }
namespace ragel { struct _T_alphtype_type; }
namespace ragel { struct _T_include_spec; }
namespace ragel { struct _T_opt_export; }
namespace ragel { struct _T_write_arg; }
namespace ragel { struct _T_machine_name; }
namespace ragel { struct _T_statement; }
namespace ragel { struct _T_opt_machine_name; }
namespace ragel { struct _T_ragel_start; }
namespace c_inline { struct _T_inline_expr; }
namespace c_inline { struct _T_expr_item_list; }
namespace c_inline { struct _T_expr_item; }
namespace c_inline { struct _T_expr_any; }
namespace c_inline { struct _T_expr_symbol; }
namespace c_inline { struct _T_expr_interpret; }
namespace c_inline { struct _T_state_ref; }
namespace c_inline { struct _T_opt_name_sep; }
namespace c_inline { struct _T_state_ref_names; }
namespace c_inline { struct _T_inline_block; }
namespace c_inline { struct _T_block_item_list; }
namespace c_inline { struct _T_block_item; }
namespace c_inline { struct _T_block_symbol; }
namespace c_inline { struct _T_block_interpret; }
namespace c_host { struct _T_tok; }
namespace c_host { struct _T_section; }
namespace ocaml_inline { struct _T_inline_expr; }
namespace ocaml_inline { struct _T_expr_item; }
namespace ocaml_inline { struct _T_expr_any; }
namespace ocaml_inline { struct _T_expr_symbol; }
namespace ocaml_inline { struct _T_expr_interpret; }
namespace ocaml_inline { struct _T_state_ref; }
namespace ocaml_inline { struct _T_opt_name_sep; }
namespace ocaml_inline { struct _T_state_ref_names; }
namespace ocaml_inline { struct _T_inline_block; }
namespace ocaml_inline { struct _T_block_item; }
namespace ocaml_inline { struct _T_block_symbol; }
namespace ocaml_inline { struct _T_block_interpret; }
namespace ocaml_host { struct _T_tok; }
namespace ocaml_host { struct _T_section; }
namespace ruby_inline { struct _T_inline_expr; }
namespace ruby_inline { struct _T_expr_item; }
namespace ruby_inline { struct _T_expr_any; }
namespace ruby_inline { struct _T_expr_symbol; }
namespace ruby_inline { struct _T_expr_interpret; }
namespace ruby_inline { struct _T_state_ref; }
namespace ruby_inline { struct _T_opt_name_sep; }
namespace ruby_inline { struct _T_state_ref_names; }
namespace ruby_inline { struct _T_inline_block; }
namespace ruby_inline { struct _T_block_item; }
namespace ruby_inline { struct _T_block_symbol; }
namespace ruby_inline { struct _T_block_interpret; }
namespace ruby_host { struct _T_tok; }
namespace ruby_host { struct _T_section; }
namespace crack_inline { struct _T_inline_expr; }
namespace crack_inline { struct _T_expr_item; }
namespace crack_inline { struct _T_expr_any; }
namespace crack_inline { struct _T_expr_symbol; }
namespace crack_inline { struct _T_expr_interpret; }
namespace crack_inline { struct _T_state_ref; }
namespace crack_inline { struct _T_opt_name_sep; }
namespace crack_inline { struct _T_state_ref_names; }
namespace crack_inline { struct _T_inline_block; }
namespace crack_inline { struct _T_block_item; }
namespace crack_inline { struct _T_block_symbol; }
namespace crack_inline { struct _T_block_interpret; }
namespace crack_host { struct _T_tok; }
namespace crack_host { struct _T_section; }
struct _T__repeat_import;
namespace c_host { struct _T__repeat_section; }
namespace ruby_host { struct _T__repeat_section; }
namespace ocaml_host { struct _T__repeat_section; }
namespace ragel { struct _T__repeat_write_arg; }
namespace ragel { struct _T__repeat_statement; }
namespace c_inline { struct _T__opt_whitespace; }
namespace ocaml_inline { struct _T__repeat_expr_item; }
namespace ocaml_inline { struct _T__repeat_block_item; }
namespace ocaml_inline { struct _T__opt_whitespace; }
namespace ruby_inline { struct _T__repeat_expr_item; }
namespace ruby_inline { struct _T__repeat_block_item; }
namespace ruby_inline { struct _T__opt_whitespace; }
namespace crack_inline { struct _T__repeat_expr_item; }
namespace crack_inline { struct _T__repeat_block_item; }
namespace crack_inline { struct _T__opt_whitespace; }
namespace crack_host { struct _T__repeat_section; }
struct _root;
struct _notoken
	: public ExportTree
{
	static const int ID = 1103;
	_notoken( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
};
struct ptr
	: public ExportTree
{
	static const int ID = 1;
	ptr( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
};
struct str
	: public ExportTree
{
	static const int ID = 2;
	str( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
};
struct il
	: public ExportTree
{
	static const int ID = 3;
	il( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
};
struct any
	: public ExportTree
{
	static const int ID = 1104;
	any( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
};
struct select
	: public ExportTree
{
	static const int ID = 4;
	select( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
};
struct c_select
	: public ExportTree
{
	static const int ID = 5;
	c_select( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
};
struct ruby_select
	: public ExportTree
{
	static const int ID = 6;
	ruby_select( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
};
struct ocaml_select
	: public ExportTree
{
	static const int ID = 7;
	ocaml_select( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
};
struct crack_select
	: public ExportTree
{
	static const int ID = 8;
	crack_select( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
};
struct selectt
	: public ExportTree
{
	static const int ID = 9;
	selectt( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
};
struct c_select_section
	: public ExportTree
{
	static const int ID = 10;
	c_select_section( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
};
struct ruby_select_section
	: public ExportTree
{
	static const int ID = 11;
	ruby_select_section( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
};
struct ocaml_select_section
	: public ExportTree
{
	static const int ID = 12;
	ocaml_select_section( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
};
struct crack_select_section
	: public ExportTree
{
	static const int ID = 13;
	crack_select_section( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
};
struct start
	: public ExportTree
{
	static const int ID = 1105;
	start( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::c_select_section c_select_section();
	::c_host::_repeat_section SectionList();
	::ruby_select_section ruby_select_section();
	::ruby_host::_repeat_section RSectionList();
	::ocaml_select_section ocaml_select_section();
	::ocaml_host::_repeat_section OSectionList();
	::crack_select_section crack_select_section();
};
struct import_val
	: public ExportTree
{
	static const int ID = 1106;
	import_val( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::c_host::number number();
	::c_host::string string();
	enum prod_name {
		Number = 0,
		String = 1,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
};
struct import
	: public ExportTree
{
	static const int ID = 1107;
	import( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::c_host::ident Name();
	::import_val Val();
};
namespace srlex { struct _literal_0003
	: public ExportTree
{
	static const int ID = 14;
	_literal_0003( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace srlex { struct _literal_0005
	: public ExportTree
{
	static const int ID = 15;
	_literal_0005( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace srlex { struct _literal_0007
	: public ExportTree
{
	static const int ID = 16;
	_literal_0007( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace srlex { struct _ignore_0001
	: public ExportTree
{
	static const int ID = 17;
	_ignore_0001( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace srlex { struct word
	: public ExportTree
{
	static const int ID = 18;
	word( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_0015
	: public ExportTree
{
	static const int ID = 19;
	_literal_0015( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_001b
	: public ExportTree
{
	static const int ID = 20;
	_literal_001b( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_001d
	: public ExportTree
{
	static const int ID = 21;
	_literal_001d( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_001f
	: public ExportTree
{
	static const int ID = 22;
	_literal_001f( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_0021
	: public ExportTree
{
	static const int ID = 23;
	_literal_0021( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_0023
	: public ExportTree
{
	static const int ID = 24;
	_literal_0023( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_0025
	: public ExportTree
{
	static const int ID = 25;
	_literal_0025( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_0027
	: public ExportTree
{
	static const int ID = 26;
	_literal_0027( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_0029
	: public ExportTree
{
	static const int ID = 27;
	_literal_0029( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_002b
	: public ExportTree
{
	static const int ID = 28;
	_literal_002b( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_002d
	: public ExportTree
{
	static const int ID = 29;
	_literal_002d( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_002f
	: public ExportTree
{
	static const int ID = 30;
	_literal_002f( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_0031
	: public ExportTree
{
	static const int ID = 31;
	_literal_0031( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_0033
	: public ExportTree
{
	static const int ID = 32;
	_literal_0033( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_0035
	: public ExportTree
{
	static const int ID = 33;
	_literal_0035( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_0037
	: public ExportTree
{
	static const int ID = 34;
	_literal_0037( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_0039
	: public ExportTree
{
	static const int ID = 35;
	_literal_0039( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_003b
	: public ExportTree
{
	static const int ID = 36;
	_literal_003b( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_003d
	: public ExportTree
{
	static const int ID = 37;
	_literal_003d( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_003f
	: public ExportTree
{
	static const int ID = 38;
	_literal_003f( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_0041
	: public ExportTree
{
	static const int ID = 39;
	_literal_0041( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_0043
	: public ExportTree
{
	static const int ID = 40;
	_literal_0043( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_0045
	: public ExportTree
{
	static const int ID = 41;
	_literal_0045( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_0047
	: public ExportTree
{
	static const int ID = 42;
	_literal_0047( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_0049
	: public ExportTree
{
	static const int ID = 43;
	_literal_0049( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_004b
	: public ExportTree
{
	static const int ID = 44;
	_literal_004b( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_004d
	: public ExportTree
{
	static const int ID = 45;
	_literal_004d( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_004f
	: public ExportTree
{
	static const int ID = 46;
	_literal_004f( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_0051
	: public ExportTree
{
	static const int ID = 47;
	_literal_0051( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_0053
	: public ExportTree
{
	static const int ID = 48;
	_literal_0053( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_0055
	: public ExportTree
{
	static const int ID = 49;
	_literal_0055( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_0057
	: public ExportTree
{
	static const int ID = 50;
	_literal_0057( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_0059
	: public ExportTree
{
	static const int ID = 51;
	_literal_0059( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_005b
	: public ExportTree
{
	static const int ID = 52;
	_literal_005b( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_005d
	: public ExportTree
{
	static const int ID = 53;
	_literal_005d( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_005f
	: public ExportTree
{
	static const int ID = 54;
	_literal_005f( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_0061
	: public ExportTree
{
	static const int ID = 55;
	_literal_0061( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_0063
	: public ExportTree
{
	static const int ID = 56;
	_literal_0063( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_0065
	: public ExportTree
{
	static const int ID = 57;
	_literal_0065( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_0067
	: public ExportTree
{
	static const int ID = 58;
	_literal_0067( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_0069
	: public ExportTree
{
	static const int ID = 59;
	_literal_0069( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_006b
	: public ExportTree
{
	static const int ID = 60;
	_literal_006b( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_006d
	: public ExportTree
{
	static const int ID = 61;
	_literal_006d( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_006f
	: public ExportTree
{
	static const int ID = 62;
	_literal_006f( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_0071
	: public ExportTree
{
	static const int ID = 63;
	_literal_0071( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_0073
	: public ExportTree
{
	static const int ID = 64;
	_literal_0073( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_0075
	: public ExportTree
{
	static const int ID = 65;
	_literal_0075( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_0077
	: public ExportTree
{
	static const int ID = 66;
	_literal_0077( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_0079
	: public ExportTree
{
	static const int ID = 67;
	_literal_0079( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_007b
	: public ExportTree
{
	static const int ID = 68;
	_literal_007b( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_007d
	: public ExportTree
{
	static const int ID = 69;
	_literal_007d( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_007f
	: public ExportTree
{
	static const int ID = 70;
	_literal_007f( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_0081
	: public ExportTree
{
	static const int ID = 71;
	_literal_0081( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_0083
	: public ExportTree
{
	static const int ID = 72;
	_literal_0083( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_0085
	: public ExportTree
{
	static const int ID = 73;
	_literal_0085( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_0087
	: public ExportTree
{
	static const int ID = 74;
	_literal_0087( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_0089
	: public ExportTree
{
	static const int ID = 75;
	_literal_0089( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_008b
	: public ExportTree
{
	static const int ID = 76;
	_literal_008b( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_008d
	: public ExportTree
{
	static const int ID = 77;
	_literal_008d( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_008f
	: public ExportTree
{
	static const int ID = 78;
	_literal_008f( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_0091
	: public ExportTree
{
	static const int ID = 79;
	_literal_0091( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_0093
	: public ExportTree
{
	static const int ID = 80;
	_literal_0093( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_0095
	: public ExportTree
{
	static const int ID = 81;
	_literal_0095( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_0097
	: public ExportTree
{
	static const int ID = 82;
	_literal_0097( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_0099
	: public ExportTree
{
	static const int ID = 83;
	_literal_0099( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_009b
	: public ExportTree
{
	static const int ID = 84;
	_literal_009b( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_009d
	: public ExportTree
{
	static const int ID = 85;
	_literal_009d( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_009f
	: public ExportTree
{
	static const int ID = 86;
	_literal_009f( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_00a1
	: public ExportTree
{
	static const int ID = 87;
	_literal_00a1( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_00a3
	: public ExportTree
{
	static const int ID = 88;
	_literal_00a3( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_00a5
	: public ExportTree
{
	static const int ID = 89;
	_literal_00a5( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_00a7
	: public ExportTree
{
	static const int ID = 90;
	_literal_00a7( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_00a9
	: public ExportTree
{
	static const int ID = 91;
	_literal_00a9( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_00ab
	: public ExportTree
{
	static const int ID = 92;
	_literal_00ab( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_00ad
	: public ExportTree
{
	static const int ID = 93;
	_literal_00ad( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_00af
	: public ExportTree
{
	static const int ID = 94;
	_literal_00af( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_00b1
	: public ExportTree
{
	static const int ID = 95;
	_literal_00b1( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_00b3
	: public ExportTree
{
	static const int ID = 96;
	_literal_00b3( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_00b5
	: public ExportTree
{
	static const int ID = 97;
	_literal_00b5( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_00b7
	: public ExportTree
{
	static const int ID = 98;
	_literal_00b7( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_00b9
	: public ExportTree
{
	static const int ID = 99;
	_literal_00b9( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_00bb
	: public ExportTree
{
	static const int ID = 100;
	_literal_00bb( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_00bd
	: public ExportTree
{
	static const int ID = 101;
	_literal_00bd( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_00bf
	: public ExportTree
{
	static const int ID = 102;
	_literal_00bf( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_00c1
	: public ExportTree
{
	static const int ID = 103;
	_literal_00c1( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_00c3
	: public ExportTree
{
	static const int ID = 104;
	_literal_00c3( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_00c5
	: public ExportTree
{
	static const int ID = 105;
	_literal_00c5( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_00c7
	: public ExportTree
{
	static const int ID = 106;
	_literal_00c7( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_00c9
	: public ExportTree
{
	static const int ID = 107;
	_literal_00c9( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_00cb
	: public ExportTree
{
	static const int ID = 108;
	_literal_00cb( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_00cd
	: public ExportTree
{
	static const int ID = 109;
	_literal_00cd( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_00cf
	: public ExportTree
{
	static const int ID = 110;
	_literal_00cf( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_00d1
	: public ExportTree
{
	static const int ID = 111;
	_literal_00d1( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_00d3
	: public ExportTree
{
	static const int ID = 112;
	_literal_00d3( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_00d5
	: public ExportTree
{
	static const int ID = 113;
	_literal_00d5( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_00d7
	: public ExportTree
{
	static const int ID = 114;
	_literal_00d7( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_00d9
	: public ExportTree
{
	static const int ID = 115;
	_literal_00d9( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _literal_00db
	: public ExportTree
{
	static const int ID = 116;
	_literal_00db( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _ignore_0017
	: public ExportTree
{
	static const int ID = 117;
	_ignore_0017( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _ignore_0019
	: public ExportTree
{
	static const int ID = 118;
	_ignore_0019( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct string
	: public ExportTree
{
	static const int ID = 119;
	string( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct lex_regex_open
	: public ExportTree
{
	static const int ID = 120;
	lex_regex_open( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct lex_sqopen_pos
	: public ExportTree
{
	static const int ID = 121;
	lex_sqopen_pos( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct lex_sqopen_neg
	: public ExportTree
{
	static const int ID = 122;
	lex_sqopen_neg( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct word
	: public ExportTree
{
	static const int ID = 123;
	word( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct uint
	: public ExportTree
{
	static const int ID = 124;
	uint( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct hex
	: public ExportTree
{
	static const int ID = 125;
	hex( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct re_dot
	: public ExportTree
{
	static const int ID = 126;
	re_dot( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct re_star
	: public ExportTree
{
	static const int ID = 127;
	re_star( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct re_char
	: public ExportTree
{
	static const int ID = 128;
	re_char( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct re_close
	: public ExportTree
{
	static const int ID = 129;
	re_close( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct re_sqopen_pos
	: public ExportTree
{
	static const int ID = 130;
	re_sqopen_pos( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct re_sqopen_neg
	: public ExportTree
{
	static const int ID = 131;
	re_sqopen_neg( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct re_or_dash
	: public ExportTree
{
	static const int ID = 132;
	re_or_dash( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct re_or_char
	: public ExportTree
{
	static const int ID = 133;
	re_or_char( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct re_or_sqclose
	: public ExportTree
{
	static const int ID = 134;
	re_or_sqclose( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _inline_expr_reparse
	: public ExportTree
{
	static const int ID = 135;
	_inline_expr_reparse( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct variable_name
	: public ExportTree
{
	static const int ID = 136;
	variable_name( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct inline_expr_reparse
	: public ExportTree
{
	static const int ID = 1108;
	inline_expr_reparse( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::_inline_expr_reparse _inline_expr_reparse();
	::ragel::action_expr action_expr();
	enum prod_name {
		Reparse = 0,
		ActionExpr = 1,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct join
	: public ExportTree
{
	static const int ID = 1109;
	join( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::join _join();
	::ragel::expression expression();
	enum prod_name {
		Rec = 0,
		Base = 1,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct expression
	: public ExportTree
{
	static const int ID = 1110;
	expression( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::expr_left expr_left();
	::ragel::expression_op_list expression_op_list();
	enum prod_name {
		Expression = 0,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct expression_op_list
	: public ExportTree
{
	static const int ID = 1111;
	expression_op_list( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::expression_op expression_op();
	::ragel::expression_op_list _expression_op_list();
	enum prod_name {
		Op = 0,
		Empty = 1,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct expression_op
	: public ExportTree
{
	static const int ID = 1112;
	expression_op( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::term term();
	enum prod_name {
		Or = 0,
		And = 1,
		Sub = 2,
		Ssub = 3,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct expr_left
	: public ExportTree
{
	static const int ID = 1113;
	expr_left( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::term term();
	enum prod_name {
		Term = 0,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct term
	: public ExportTree
{
	static const int ID = 1114;
	term( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::term_left term_left();
	::ragel::term_op_list_short term_op_list_short();
	enum prod_name {
		Term = 0,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct term_left
	: public ExportTree
{
	static const int ID = 1115;
	term_left( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::factor_label factor_label();
	enum prod_name {
		FactorLabel = 0,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct term_op_list_short
	: public ExportTree
{
	static const int ID = 1116;
	term_op_list_short( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::term_op term_op();
	::ragel::term_op_list_short _term_op_list_short();
	enum prod_name {
		Empty = 0,
		Terms = 1,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct term_op
	: public ExportTree
{
	static const int ID = 1117;
	term_op( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::factor_label factor_label();
	enum prod_name {
		None = 0,
		Dot = 1,
		ColonLt = 2,
		ColonLtLt = 3,
		GtColon = 4,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct factor_label
	: public ExportTree
{
	static const int ID = 1118;
	factor_label( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::word word();
	::ragel::factor_label _factor_label();
	::ragel::factor_ep factor_ep();
	enum prod_name {
		Label = 0,
		Ep = 1,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct factor_ep
	: public ExportTree
{
	static const int ID = 1119;
	factor_ep( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::factor_aug factor_aug();
	::ragel::epsilon_target epsilon_target();
	enum prod_name {
		Epsilon = 0,
		Base = 1,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct epsilon_target
	: public ExportTree
{
	static const int ID = 1120;
	epsilon_target( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::epsilon_target _epsilon_target();
	::ragel::word word();
	enum prod_name {
		Rec = 0,
		Base = 1,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct action_expr
	: public ExportTree
{
	static const int ID = 1121;
	action_expr( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::c_select c_select();
	::c_inline::inline_expr CInlineExpr();
	::ruby_select ruby_select();
	::ruby_inline::inline_expr RubyInlineExpr();
	::ocaml_select ocaml_select();
	::ocaml_inline::inline_expr OCamlInlineExpr();
	::crack_select crack_select();
	::crack_inline::inline_expr CrackInlineExpr();
	enum prod_name {
		C = 0,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct action_block
	: public ExportTree
{
	static const int ID = 1122;
	action_block( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::c_select c_select();
	::c_inline::inline_block CInlineBlock();
	::ruby_select ruby_select();
	::ruby_inline::inline_block RubyInlineBlock();
	::ocaml_select ocaml_select();
	::ocaml_inline::inline_block OCamlInlineBlock();
	::crack_select crack_select();
	::crack_inline::inline_block CrackInlineBlock();
	enum prod_name {
		C = 0,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct action_arg_list
	: public ExportTree
{
	static const int ID = 1123;
	action_arg_list( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::action_arg_list _action_arg_list();
	::ragel::action_ref action_ref();
	enum prod_name {
		Rec = 0,
		Base = 1,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct opt_action_arg_list
	: public ExportTree
{
	static const int ID = 1124;
	opt_action_arg_list( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::action_arg_list action_arg_list();
	enum prod_name {
		List = 0,
		Empty = 1,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct named_action_ref
	: public ExportTree
{
	static const int ID = 1125;
	named_action_ref( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::word word();
	::ragel::opt_action_arg_list opt_action_arg_list();
	enum prod_name {
		Plain = 0,
		Args = 1,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct action_ref
	: public ExportTree
{
	static const int ID = 1126;
	action_ref( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::named_action_ref named_action_ref();
	::ragel::action_block action_block();
	enum prod_name {
		NamedRef = 0,
		ParenNamed = 1,
		Block = 2,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct priority_name
	: public ExportTree
{
	static const int ID = 1127;
	priority_name( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::word word();
	enum prod_name {
		Word = 0,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct error_name
	: public ExportTree
{
	static const int ID = 1128;
	error_name( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::word word();
	enum prod_name {
		Word = 0,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct priority_aug
	: public ExportTree
{
	static const int ID = 1129;
	priority_aug( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::uint uint();
	enum prod_name {
		NoSign = 0,
		Plus = 1,
		Minus = 2,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct aug_base
	: public ExportTree
{
	static const int ID = 1130;
	aug_base( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	enum prod_name {
		Finish = 0,
		Enter = 1,
		Leave = 2,
		All = 3,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct aug_cond
	: public ExportTree
{
	static const int ID = 1131;
	aug_cond( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	enum prod_name {
		Start1 = 0,
		All1 = 1,
		Leave1 = 2,
		Start2 = 3,
		All2 = 4,
		Leave2 = 5,
		Start3 = 6,
		All3 = 7,
		Leave3 = 8,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct aug_to_state
	: public ExportTree
{
	static const int ID = 1132;
	aug_to_state( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	enum prod_name {
		Start1 = 0,
		NotStart1 = 1,
		All1 = 2,
		Final1 = 3,
		NotFinal1 = 4,
		Middle1 = 5,
		Start2 = 6,
		NotStart2 = 7,
		All2 = 8,
		Final2 = 9,
		NotFinal2 = 10,
		Middle2 = 11,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct aug_from_state
	: public ExportTree
{
	static const int ID = 1133;
	aug_from_state( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	enum prod_name {
		Start1 = 0,
		NotStart1 = 1,
		All1 = 2,
		Final1 = 3,
		NotFinal1 = 4,
		Middle1 = 5,
		Start2 = 6,
		NotStart2 = 7,
		All2 = 8,
		Final2 = 9,
		NotFinal2 = 10,
		Middle2 = 11,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct aug_eof
	: public ExportTree
{
	static const int ID = 1134;
	aug_eof( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	enum prod_name {
		Start1 = 0,
		NotStart1 = 1,
		All1 = 2,
		Final1 = 3,
		NotFinal1 = 4,
		Middle1 = 5,
		Start2 = 6,
		NotStart2 = 7,
		All2 = 8,
		Final2 = 9,
		NotFinal2 = 10,
		Middle2 = 11,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct aug_gbl_error
	: public ExportTree
{
	static const int ID = 1135;
	aug_gbl_error( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	enum prod_name {
		Start1 = 0,
		NotStart1 = 1,
		All1 = 2,
		Final1 = 3,
		NotFinal1 = 4,
		Middle1 = 5,
		Start2 = 6,
		NotStart2 = 7,
		All2 = 8,
		Final2 = 9,
		NotFinal2 = 10,
		Middle2 = 11,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct aug_local_error
	: public ExportTree
{
	static const int ID = 1136;
	aug_local_error( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	enum prod_name {
		Start1 = 0,
		NotStart1 = 1,
		All1 = 2,
		Final1 = 3,
		NotFinal1 = 4,
		Middle1 = 5,
		Start2 = 6,
		NotStart2 = 7,
		All2 = 8,
		Final2 = 9,
		NotFinal2 = 10,
		Middle2 = 11,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct factor_aug
	: public ExportTree
{
	static const int ID = 1137;
	factor_aug( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::factor_aug _factor_aug();
	::ragel::aug_base aug_base();
	::ragel::action_ref action_ref();
	::ragel::priority_aug priority_aug();
	::ragel::priority_name priority_name();
	::ragel::aug_cond aug_cond();
	::ragel::aug_to_state aug_to_state();
	::ragel::aug_from_state aug_from_state();
	::ragel::aug_eof aug_eof();
	::ragel::aug_gbl_error aug_gbl_error();
	::ragel::aug_local_error aug_local_error();
	::ragel::error_name error_name();
	::ragel::factor_rep factor_rep();
	enum prod_name {
		ActionRef = 0,
		PriorEmbed = 1,
		NamedPriorEmbed = 2,
		CondEmbed = 3,
		NegCondEmbed = 4,
		ToStateAction = 5,
		FromStateAction = 6,
		EofAction = 7,
		GblErrorAction = 8,
		LocalErrorDef = 9,
		LocalErrorName = 10,
		Base = 11,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct factor_rep
	: public ExportTree
{
	static const int ID = 1138;
	factor_rep( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::factor_neg factor_neg();
	::ragel::factor_rep_op_list factor_rep_op_list();
	enum prod_name {
		Op = 0,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct factor_rep_op_list
	: public ExportTree
{
	static const int ID = 1139;
	factor_rep_op_list( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::factor_rep_op factor_rep_op();
	::ragel::factor_rep_op_list _factor_rep_op_list();
	enum prod_name {
		Rec = 0,
		Base = 1,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct factor_rep_op
	: public ExportTree
{
	static const int ID = 1140;
	factor_rep_op( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::factor_rep_num factor_rep_num();
	::ragel::factor_rep_num LowRep();
	::ragel::factor_rep_num HighRep();
	enum prod_name {
		Star = 0,
		StarStar = 1,
		Optional = 2,
		Plus = 3,
		ExactRep = 4,
		MaxRep = 5,
		MinRep = 6,
		RangeRep = 7,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct factor_rep_num
	: public ExportTree
{
	static const int ID = 1141;
	factor_rep_num( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::uint uint();
	enum prod_name {
		RepNum = 0,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct factor_neg
	: public ExportTree
{
	static const int ID = 1142;
	factor_neg( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::factor_neg _factor_neg();
	::ragel::factor factor();
	enum prod_name {
		Bang = 0,
		Caret = 1,
		Base = 2,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct opt_max_arg
	: public ExportTree
{
	static const int ID = 1143;
	opt_max_arg( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::action_ref action_ref();
	enum prod_name {
		Action = 0,
		Empty = 1,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct nfastar
	: public ExportTree
{
	static const int ID = 1144;
	nfastar( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct colon_cond
	: public ExportTree
{
	static const int ID = 1145;
	colon_cond( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	enum prod_name {
		Cond = 0,
		CondStar = 1,
		CondPlus = 2,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct factor
	: public ExportTree
{
	static const int ID = 1146;
	factor( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::alphabet_num alphabet_num();
	::ragel::word word();
	::ragel::string string();
	::ragel::lex_sqopen_pos lex_sqopen_pos();
	::ragel::reg_or_data reg_or_data();
	::ragel::re_or_sqclose re_or_sqclose();
	::ragel::lex_sqopen_neg lex_sqopen_neg();
	::ragel::lex_regex_open lex_regex_open();
	::ragel::regex regex();
	::ragel::re_close re_close();
	::ragel::range_lit RL1();
	::ragel::range_lit RL2();
	::ragel::nfastar nfastar();
	::ragel::expression expression();
	::ragel::action_ref Push();
	::ragel::action_ref Pop();
	::ragel::action_ref Init();
	::ragel::action_ref Stay();
	::ragel::action_ref Repeat();
	::ragel::action_ref Exit();
	::ragel::colon_cond colon_cond();
	::ragel::action_ref Inc();
	::ragel::action_ref Min();
	::ragel::opt_max_arg OptMax();
	::ragel::join join();
	enum prod_name {
		AlphabetNum = 0,
		Word = 1,
		String = 2,
		PosOrBlock = 3,
		NegOrBlock = 4,
		Regex = 5,
		Range = 6,
		RangeIndep = 7,
		Nfa = 8,
		Cond = 9,
		Join = 10,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct regex
	: public ExportTree
{
	static const int ID = 1147;
	regex( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::reg_item_rep_list reg_item_rep_list();
	enum prod_name {
		List = 0,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct reg_item_rep_list
	: public ExportTree
{
	static const int ID = 1148;
	reg_item_rep_list( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::reg_item_rep_list _reg_item_rep_list();
	::ragel::reg_item_rep reg_item_rep();
	enum prod_name {
		Rec = 0,
		Base = 1,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct reg_item_rep
	: public ExportTree
{
	static const int ID = 1149;
	reg_item_rep( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::reg_item reg_item();
	::ragel::re_star re_star();
	enum prod_name {
		Star = 0,
		Base = 1,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct reg_item
	: public ExportTree
{
	static const int ID = 1150;
	reg_item( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::re_sqopen_pos re_sqopen_pos();
	::ragel::reg_or_data reg_or_data();
	::ragel::re_or_sqclose re_or_sqclose();
	::ragel::re_sqopen_neg re_sqopen_neg();
	::ragel::re_dot re_dot();
	::ragel::re_char re_char();
	enum prod_name {
		PosOrBlock = 0,
		NegOrBlock = 1,
		Dot = 2,
		Char = 3,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct reg_or_data
	: public ExportTree
{
	static const int ID = 1151;
	reg_or_data( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::reg_or_data _reg_or_data();
	::ragel::reg_or_char reg_or_char();
	enum prod_name {
		Data = 0,
		Base = 1,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct reg_or_char
	: public ExportTree
{
	static const int ID = 1152;
	reg_or_char( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::re_or_char re_or_char();
	::ragel::re_or_char Low();
	::ragel::re_or_dash re_or_dash();
	::ragel::re_or_char High();
	enum prod_name {
		Char = 0,
		Range = 1,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct range_lit
	: public ExportTree
{
	static const int ID = 1153;
	range_lit( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::string string();
	::ragel::alphabet_num alphabet_num();
	enum prod_name {
		String = 0,
		AN = 1,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct alphabet_num
	: public ExportTree
{
	static const int ID = 1154;
	alphabet_num( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::uint uint();
	::ragel::hex hex();
	enum prod_name {
		Uint = 0,
		Neg = 1,
		Hex = 2,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct lm_act
	: public ExportTree
{
	static const int ID = 1155;
	lm_act( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::action_ref action_ref();
	::ragel::action_block action_block();
	enum prod_name {
		ActionRef = 0,
		ActionBlock = 1,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct opt_lm_act
	: public ExportTree
{
	static const int ID = 1156;
	opt_lm_act( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::lm_act lm_act();
	enum prod_name {
		Act = 0,
		Empty = 1,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct lm_stmt
	: public ExportTree
{
	static const int ID = 1157;
	lm_stmt( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::join join();
	::ragel::opt_lm_act opt_lm_act();
	::ragel::assignment assignment();
	::ragel::action_spec action_spec();
	enum prod_name {
		LmStmt = 0,
		Assignment = 1,
		ActionSpec = 2,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct lm_stmt_list
	: public ExportTree
{
	static const int ID = 1158;
	lm_stmt_list( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::lm_stmt_list _lm_stmt_list();
	::ragel::lm_stmt lm_stmt();
	enum prod_name {
		Rec = 0,
		Base = 1,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct lm
	: public ExportTree
{
	static const int ID = 1159;
	lm( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::join join();
	::ragel::lm_stmt_list lm_stmt_list();
	enum prod_name {
		Join = 0,
		Lm = 1,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct action_param
	: public ExportTree
{
	static const int ID = 1160;
	action_param( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::word word();
	enum prod_name {
		Word = 0,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct action_param_list
	: public ExportTree
{
	static const int ID = 1161;
	action_param_list( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::action_param_list _action_param_list();
	::ragel::action_param action_param();
	enum prod_name {
		Rec = 0,
		Base = 1,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct opt_action_param_list
	: public ExportTree
{
	static const int ID = 1162;
	opt_action_param_list( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::action_param_list action_param_list();
	enum prod_name {
		List = 0,
		Empty = 1,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct action_params
	: public ExportTree
{
	static const int ID = 1163;
	action_params( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::opt_action_param_list opt_action_param_list();
	enum prod_name {
		List = 0,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct action_spec
	: public ExportTree
{
	static const int ID = 1164;
	action_spec( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::word word();
	::ragel::action_params action_params();
	::ragel::action_block action_block();
	enum prod_name {
		ActionSpecParams = 0,
		ActionSpec = 1,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct def_name
	: public ExportTree
{
	static const int ID = 1165;
	def_name( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::word word();
	enum prod_name {
		Word = 0,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct assignment
	: public ExportTree
{
	static const int ID = 1166;
	assignment( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::opt_export opt_export();
	::ragel::def_name def_name();
	::ragel::join join();
	enum prod_name {
		Assignment = 0,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct instantiation
	: public ExportTree
{
	static const int ID = 1167;
	instantiation( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::opt_export opt_export();
	::ragel::def_name def_name();
	::ragel::lm lm();
	enum prod_name {
		Instantiation = 0,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct nfa_expr
	: public ExportTree
{
	static const int ID = 1168;
	nfa_expr( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::nfa_expr _nfa_expr();
	::ragel::term term();
	enum prod_name {
		Union = 0,
		Base = 1,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct nfa_round_spec
	: public ExportTree
{
	static const int ID = 1169;
	nfa_round_spec( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::uint Depth();
	::ragel::uint Group();
	enum prod_name {
		Spec = 0,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct nfa_round_list
	: public ExportTree
{
	static const int ID = 1170;
	nfa_round_list( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::nfa_round_list _nfa_round_list();
	::ragel::nfa_round_spec nfa_round_spec();
	enum prod_name {
		Recurse = 0,
		Base = 1,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct nfa_rounds
	: public ExportTree
{
	static const int ID = 1171;
	nfa_rounds( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::nfa_round_list nfa_round_list();
	enum prod_name {
		Rounds = 0,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct nfa_union
	: public ExportTree
{
	static const int ID = 1172;
	nfa_union( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::def_name def_name();
	::ragel::nfa_rounds nfa_rounds();
	::ragel::nfa_expr nfa_expr();
	enum prod_name {
		NfaUnion = 0,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct alphtype_type
	: public ExportTree
{
	static const int ID = 1173;
	alphtype_type( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::word W1();
	::ragel::word W2();
	enum prod_name {
		One = 0,
		Two = 1,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct include_spec
	: public ExportTree
{
	static const int ID = 1174;
	include_spec( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::word word();
	::ragel::string string();
	enum prod_name {
		Machine = 0,
		File = 1,
		MachineFile = 2,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct opt_export
	: public ExportTree
{
	static const int ID = 1175;
	opt_export( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	enum prod_name {
		Export = 0,
		Base = 1,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct write_arg
	: public ExportTree
{
	static const int ID = 1176;
	write_arg( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::word word();
	enum prod_name {
		Word = 0,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct machine_name
	: public ExportTree
{
	static const int ID = 1177;
	machine_name( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::word word();
	enum prod_name {
		MachineName = 0,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct statement
	: public ExportTree
{
	static const int ID = 1178;
	statement( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::assignment assignment();
	::ragel::instantiation instantiation();
	::ragel::nfa_union nfa_union();
	::ragel::action_spec action_spec();
	::ragel::action_block action_block();
	::ragel::variable_name variable_name();
	::ragel::inline_expr_reparse inline_expr_reparse();
	::ragel::alphtype_type alphtype_type();
	::ragel::word Cmd();
	::ragel::_repeat_write_arg ArgList();
	::ragel::string string();
	::ragel::include_spec include_spec();
	enum prod_name {
		Assignment = 0,
		Instantiation = 1,
		NfaUnion = 2,
		ActionSpec = 3,
		PrePush = 4,
		PostPop = 5,
		Variable = 6,
		AlphType = 7,
		Access = 8,
		Write = 9,
		GetKey = 10,
		Import = 11,
		Include = 12,
		NfaPrePush = 13,
		NfaPostPop = 14,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct opt_machine_name
	: public ExportTree
{
	static const int ID = 1179;
	opt_machine_name( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::machine_name machine_name();
	enum prod_name {
		MachineName = 0,
		Empty = 1,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ragel { struct ragel_start
	: public ExportTree
{
	static const int ID = 1180;
	ragel_start( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::opt_machine_name opt_machine_name();
	::ragel::_repeat_statement _repeat_statement();
}; }
namespace c_inline { struct _literal_0101
	: public ExportTree
{
	static const int ID = 137;
	_literal_0101( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace c_inline { struct _literal_0103
	: public ExportTree
{
	static const int ID = 138;
	_literal_0103( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace c_inline { struct _literal_0105
	: public ExportTree
{
	static const int ID = 139;
	_literal_0105( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace c_inline { struct _literal_0107
	: public ExportTree
{
	static const int ID = 140;
	_literal_0107( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace c_inline { struct _literal_0109
	: public ExportTree
{
	static const int ID = 141;
	_literal_0109( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace c_inline { struct _literal_010b
	: public ExportTree
{
	static const int ID = 142;
	_literal_010b( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace c_inline { struct _literal_010d
	: public ExportTree
{
	static const int ID = 143;
	_literal_010d( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace c_inline { struct _literal_010f
	: public ExportTree
{
	static const int ID = 144;
	_literal_010f( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace c_inline { struct _literal_0111
	: public ExportTree
{
	static const int ID = 145;
	_literal_0111( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace c_inline { struct _literal_0113
	: public ExportTree
{
	static const int ID = 146;
	_literal_0113( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace c_inline { struct _literal_0115
	: public ExportTree
{
	static const int ID = 147;
	_literal_0115( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace c_inline { struct _literal_0117
	: public ExportTree
{
	static const int ID = 148;
	_literal_0117( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace c_inline { struct _literal_0119
	: public ExportTree
{
	static const int ID = 149;
	_literal_0119( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace c_inline { struct _literal_011b
	: public ExportTree
{
	static const int ID = 150;
	_literal_011b( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace c_inline { struct _literal_011d
	: public ExportTree
{
	static const int ID = 151;
	_literal_011d( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace c_inline { struct _literal_012b
	: public ExportTree
{
	static const int ID = 152;
	_literal_012b( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace c_inline { struct _literal_012d
	: public ExportTree
{
	static const int ID = 153;
	_literal_012d( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace c_inline { struct _literal_012f
	: public ExportTree
{
	static const int ID = 154;
	_literal_012f( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace c_inline { struct _literal_0131
	: public ExportTree
{
	static const int ID = 155;
	_literal_0131( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace c_inline { struct _literal_0133
	: public ExportTree
{
	static const int ID = 156;
	_literal_0133( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace c_inline { struct _literal_0135
	: public ExportTree
{
	static const int ID = 157;
	_literal_0135( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace c_inline { struct _literal_0137
	: public ExportTree
{
	static const int ID = 158;
	_literal_0137( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace c_inline { struct _literal_0139
	: public ExportTree
{
	static const int ID = 159;
	_literal_0139( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace c_inline { struct ident
	: public ExportTree
{
	static const int ID = 160;
	ident( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace c_inline { struct number
	: public ExportTree
{
	static const int ID = 161;
	number( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace c_inline { struct hex_number
	: public ExportTree
{
	static const int ID = 162;
	hex_number( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace c_inline { struct comment
	: public ExportTree
{
	static const int ID = 163;
	comment( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace c_inline { struct string
	: public ExportTree
{
	static const int ID = 164;
	string( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace c_inline { struct whitespace
	: public ExportTree
{
	static const int ID = 165;
	whitespace( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace c_inline { struct var_ref
	: public ExportTree
{
	static const int ID = 166;
	var_ref( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace c_inline { struct c_any
	: public ExportTree
{
	static const int ID = 167;
	c_any( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace c_inline { struct inline_expr
	: public ExportTree
{
	static const int ID = 1181;
	inline_expr( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::c_inline::expr_item_list expr_item_list();
	enum prod_name {
		List = 0,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace c_inline { struct expr_item_list
	: public ExportTree
{
	static const int ID = 1182;
	expr_item_list( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::c_inline::expr_item_list _expr_item_list();
	::c_inline::expr_item expr_item();
	enum prod_name {
		Rec = 0,
		Empty = 1,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace c_inline { struct expr_item
	: public ExportTree
{
	static const int ID = 1183;
	expr_item( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::c_inline::expr_any expr_any();
	::c_inline::expr_symbol expr_symbol();
	::c_inline::expr_interpret expr_interpret();
	enum prod_name {
		ExprAny = 0,
		ExprSymbol = 1,
		ExprInterpret = 2,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace c_inline { struct expr_any
	: public ExportTree
{
	static const int ID = 1184;
	expr_any( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::c_inline::whitespace whitespace();
	::c_inline::comment comment();
	::c_inline::string string();
	::c_inline::number number();
	::c_inline::hex_number hex_number();
	::c_inline::ident ident();
	::c_inline::c_any c_any();
	enum prod_name {
		WS = 0,
		Comment = 1,
		String = 2,
		Number = 3,
		Hex = 4,
		Ident = 5,
		Any = 6,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace c_inline { struct expr_symbol
	: public ExportTree
{
	static const int ID = 1185;
	expr_symbol( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	enum prod_name {
		Comma = 0,
		Open = 1,
		Close = 2,
		Star = 3,
		DoubleColon = 4,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace c_inline { struct expr_interpret
	: public ExportTree
{
	static const int ID = 1186;
	expr_interpret( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::c_inline::state_ref state_ref();
	::c_inline::var_ref var_ref();
	enum prod_name {
		Fpc = 0,
		Fc = 1,
		Fcurs = 2,
		Ftargs = 3,
		Fentry = 4,
		VarRef = 5,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace c_inline { struct state_ref
	: public ExportTree
{
	static const int ID = 1187;
	state_ref( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::c_inline::opt_name_sep opt_name_sep();
	::c_inline::state_ref_names state_ref_names();
	enum prod_name {
		Ref = 0,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace c_inline { struct opt_name_sep
	: public ExportTree
{
	static const int ID = 1188;
	opt_name_sep( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	enum prod_name {
		ColonColon = 0,
		Empty = 1,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace c_inline { struct state_ref_names
	: public ExportTree
{
	static const int ID = 1189;
	state_ref_names( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::c_inline::state_ref_names _state_ref_names();
	::srlex::word word();
	enum prod_name {
		Rec = 0,
		Base = 1,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace c_inline { struct inline_block
	: public ExportTree
{
	static const int ID = 1190;
	inline_block( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::c_inline::block_item_list block_item_list();
	enum prod_name {
		List = 0,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace c_inline { struct block_item_list
	: public ExportTree
{
	static const int ID = 1191;
	block_item_list( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::c_inline::block_item block_item();
	::c_inline::block_item_list _block_item_list();
	enum prod_name {
		Rec = 0,
		Base = 1,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace c_inline { struct block_item
	: public ExportTree
{
	static const int ID = 1192;
	block_item( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::c_inline::expr_any expr_any();
	::c_inline::block_symbol block_symbol();
	::c_inline::block_interpret block_interpret();
	::c_inline::inline_block inline_block();
	enum prod_name {
		ExprAny = 0,
		BlockSymbol = 1,
		BlockInterpret = 2,
		RecBlock = 3,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace c_inline { struct block_symbol
	: public ExportTree
{
	static const int ID = 1193;
	block_symbol( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	enum prod_name {
		B1 = 0,
		B2 = 1,
		B3 = 2,
		B4 = 3,
		B5 = 4,
		B6 = 5,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace c_inline { struct block_interpret
	: public ExportTree
{
	static const int ID = 1194;
	block_interpret( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::c_inline::expr_interpret expr_interpret();
	::c_inline::_opt_whitespace _opt_whitespace();
	::c_inline::inline_expr inline_expr();
	::c_inline::state_ref state_ref();
	enum prod_name {
		ExprInterpret = 0,
		Fhold = 1,
		FgotoExpr = 2,
		FnextExpr = 3,
		FcallExpr = 4,
		FncallExpr = 5,
		Fexec = 6,
		FgotoSr = 7,
		FnextSr = 8,
		FcallSr = 9,
		FncallSr = 10,
		Fret = 11,
		Fnret = 12,
		Fbreak = 13,
		Fnbreak = 14,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace c_host { struct _literal_013f
	: public ExportTree
{
	static const int ID = 168;
	_literal_013f( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace c_host { struct slr
	: public ExportTree
{
	static const int ID = 169;
	slr( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace c_host { struct ident
	: public ExportTree
{
	static const int ID = 170;
	ident( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace c_host { struct number
	: public ExportTree
{
	static const int ID = 171;
	number( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace c_host { struct hex_number
	: public ExportTree
{
	static const int ID = 172;
	hex_number( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace c_host { struct comment
	: public ExportTree
{
	static const int ID = 173;
	comment( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace c_host { struct string
	: public ExportTree
{
	static const int ID = 174;
	string( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace c_host { struct whitespace
	: public ExportTree
{
	static const int ID = 175;
	whitespace( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace c_host { struct c_any
	: public ExportTree
{
	static const int ID = 176;
	c_any( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace c_host { struct tok
	: public ExportTree
{
	static const int ID = 1195;
	tok( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::c_host::ident ident();
	::c_host::number number();
	::c_host::hex_number hex_number();
	::c_host::comment comment();
	::c_host::string string();
	::c_host::whitespace whitespace();
	::c_host::c_any c_any();
	enum prod_name {
		Ident = 0,
		Number = 1,
		HexNumber = 2,
		Comment = 3,
		String = 4,
		Whitespace = 5,
		Any = 6,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace c_host { struct section
	: public ExportTree
{
	static const int ID = 1196;
	section( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::ragel_start ragel_start();
	::c_host::tok tok();
	enum prod_name {
		MultiLine = 0,
		Tok = 1,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ocaml_inline { struct _literal_0151
	: public ExportTree
{
	static const int ID = 177;
	_literal_0151( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ocaml_inline { struct _literal_0153
	: public ExportTree
{
	static const int ID = 178;
	_literal_0153( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ocaml_inline { struct _literal_0155
	: public ExportTree
{
	static const int ID = 179;
	_literal_0155( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ocaml_inline { struct _literal_0157
	: public ExportTree
{
	static const int ID = 180;
	_literal_0157( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ocaml_inline { struct _literal_0159
	: public ExportTree
{
	static const int ID = 181;
	_literal_0159( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ocaml_inline { struct _literal_015b
	: public ExportTree
{
	static const int ID = 182;
	_literal_015b( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ocaml_inline { struct _literal_015d
	: public ExportTree
{
	static const int ID = 183;
	_literal_015d( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ocaml_inline { struct _literal_015f
	: public ExportTree
{
	static const int ID = 184;
	_literal_015f( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ocaml_inline { struct _literal_0161
	: public ExportTree
{
	static const int ID = 185;
	_literal_0161( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ocaml_inline { struct _literal_0163
	: public ExportTree
{
	static const int ID = 186;
	_literal_0163( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ocaml_inline { struct _literal_0165
	: public ExportTree
{
	static const int ID = 187;
	_literal_0165( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ocaml_inline { struct _literal_0167
	: public ExportTree
{
	static const int ID = 188;
	_literal_0167( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ocaml_inline { struct _literal_0169
	: public ExportTree
{
	static const int ID = 189;
	_literal_0169( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ocaml_inline { struct _literal_016b
	: public ExportTree
{
	static const int ID = 190;
	_literal_016b( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ocaml_inline { struct _literal_016d
	: public ExportTree
{
	static const int ID = 191;
	_literal_016d( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ocaml_inline { struct _literal_017b
	: public ExportTree
{
	static const int ID = 192;
	_literal_017b( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ocaml_inline { struct _literal_017d
	: public ExportTree
{
	static const int ID = 193;
	_literal_017d( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ocaml_inline { struct _literal_017f
	: public ExportTree
{
	static const int ID = 194;
	_literal_017f( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ocaml_inline { struct _literal_0181
	: public ExportTree
{
	static const int ID = 195;
	_literal_0181( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ocaml_inline { struct _literal_0183
	: public ExportTree
{
	static const int ID = 196;
	_literal_0183( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ocaml_inline { struct _literal_0185
	: public ExportTree
{
	static const int ID = 197;
	_literal_0185( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ocaml_inline { struct _literal_0187
	: public ExportTree
{
	static const int ID = 198;
	_literal_0187( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ocaml_inline { struct _literal_0189
	: public ExportTree
{
	static const int ID = 199;
	_literal_0189( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ocaml_inline { struct ident
	: public ExportTree
{
	static const int ID = 200;
	ident( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ocaml_inline { struct number
	: public ExportTree
{
	static const int ID = 201;
	number( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ocaml_inline { struct hex_number
	: public ExportTree
{
	static const int ID = 202;
	hex_number( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ocaml_inline { struct comment
	: public ExportTree
{
	static const int ID = 203;
	comment( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ocaml_inline { struct string
	: public ExportTree
{
	static const int ID = 204;
	string( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ocaml_inline { struct whitespace
	: public ExportTree
{
	static const int ID = 205;
	whitespace( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ocaml_inline { struct c_any
	: public ExportTree
{
	static const int ID = 206;
	c_any( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ocaml_inline { struct inline_expr
	: public ExportTree
{
	static const int ID = 1197;
	inline_expr( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ocaml_inline::_repeat_expr_item _repeat_expr_item();
}; }
namespace ocaml_inline { struct expr_item
	: public ExportTree
{
	static const int ID = 1198;
	expr_item( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ocaml_inline::expr_any expr_any();
	::ocaml_inline::expr_symbol expr_symbol();
	::ocaml_inline::expr_interpret expr_interpret();
	enum prod_name {
		ExprAny = 0,
		ExprSymbol = 1,
		ExprInterpret = 2,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ocaml_inline { struct expr_any
	: public ExportTree
{
	static const int ID = 1199;
	expr_any( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ocaml_inline::whitespace whitespace();
	::ocaml_inline::comment comment();
	::ocaml_inline::string string();
	::ocaml_inline::number number();
	::ocaml_inline::hex_number hex_number();
	::ocaml_inline::ident ident();
	::ocaml_inline::c_any c_any();
}; }
namespace ocaml_inline { struct expr_symbol
	: public ExportTree
{
	static const int ID = 1200;
	expr_symbol( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ocaml_inline { struct expr_interpret
	: public ExportTree
{
	static const int ID = 1201;
	expr_interpret( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ocaml_inline::state_ref state_ref();
	enum prod_name {
		Fpc = 0,
		Fc = 1,
		Fcurs = 2,
		Ftargs = 3,
		Fentry = 4,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ocaml_inline { struct state_ref
	: public ExportTree
{
	static const int ID = 1202;
	state_ref( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ocaml_inline::opt_name_sep opt_name_sep();
	::ocaml_inline::state_ref_names state_ref_names();
}; }
namespace ocaml_inline { struct opt_name_sep
	: public ExportTree
{
	static const int ID = 1203;
	opt_name_sep( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	enum prod_name {
		ColonColon = 0,
		Empty = 1,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ocaml_inline { struct state_ref_names
	: public ExportTree
{
	static const int ID = 1204;
	state_ref_names( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ocaml_inline::state_ref_names _state_ref_names();
	::srlex::word word();
	enum prod_name {
		Rec = 0,
		Base = 1,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ocaml_inline { struct inline_block
	: public ExportTree
{
	static const int ID = 1205;
	inline_block( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ocaml_inline::_repeat_block_item _repeat_block_item();
}; }
namespace ocaml_inline { struct block_item
	: public ExportTree
{
	static const int ID = 1206;
	block_item( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ocaml_inline::expr_any expr_any();
	::ocaml_inline::block_symbol block_symbol();
	::ocaml_inline::block_interpret block_interpret();
	::ocaml_inline::inline_block inline_block();
	enum prod_name {
		ExprAny = 0,
		BlockSymbol = 1,
		BlockInterpret = 2,
		RecBlock = 3,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ocaml_inline { struct block_symbol
	: public ExportTree
{
	static const int ID = 1207;
	block_symbol( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ocaml_inline { struct block_interpret
	: public ExportTree
{
	static const int ID = 1208;
	block_interpret( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ocaml_inline::expr_interpret expr_interpret();
	::ocaml_inline::_opt_whitespace _opt_whitespace();
	::ocaml_inline::inline_expr inline_expr();
	::ocaml_inline::state_ref state_ref();
	enum prod_name {
		ExprInterpret = 0,
		Fhold = 1,
		FgotoExpr = 2,
		FnextExpr = 3,
		FcallExpr = 4,
		FncallExpr = 5,
		Fexec = 6,
		FgotoSr = 7,
		FnextSr = 8,
		FcallSr = 9,
		FncallSr = 10,
		Fret = 11,
		Fnret = 12,
		Fbreak = 13,
		Fnbreak = 14,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ocaml_host { struct _literal_018d
	: public ExportTree
{
	static const int ID = 207;
	_literal_018d( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ocaml_host { struct slr
	: public ExportTree
{
	static const int ID = 208;
	slr( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ocaml_host { struct ident
	: public ExportTree
{
	static const int ID = 209;
	ident( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ocaml_host { struct number
	: public ExportTree
{
	static const int ID = 210;
	number( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ocaml_host { struct hex_number
	: public ExportTree
{
	static const int ID = 211;
	hex_number( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ocaml_host { struct comment
	: public ExportTree
{
	static const int ID = 212;
	comment( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ocaml_host { struct string
	: public ExportTree
{
	static const int ID = 213;
	string( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ocaml_host { struct whitespace
	: public ExportTree
{
	static const int ID = 214;
	whitespace( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ocaml_host { struct ocaml_any
	: public ExportTree
{
	static const int ID = 215;
	ocaml_any( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ocaml_host { struct tok
	: public ExportTree
{
	static const int ID = 1209;
	tok( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ocaml_host::ident ident();
	::ocaml_host::number number();
	::ocaml_host::hex_number hex_number();
	::ocaml_host::comment comment();
	::ocaml_host::string string();
	::ocaml_host::whitespace whitespace();
	::ocaml_host::ocaml_any ocaml_any();
}; }
namespace ocaml_host { struct section
	: public ExportTree
{
	static const int ID = 1210;
	section( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::ragel_start ragel_start();
	::ocaml_host::tok tok();
	enum prod_name {
		MultiLine = 0,
		Tok = 1,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ruby_inline { struct _literal_019f
	: public ExportTree
{
	static const int ID = 216;
	_literal_019f( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ruby_inline { struct _literal_01a1
	: public ExportTree
{
	static const int ID = 217;
	_literal_01a1( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ruby_inline { struct _literal_01a3
	: public ExportTree
{
	static const int ID = 218;
	_literal_01a3( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ruby_inline { struct _literal_01a5
	: public ExportTree
{
	static const int ID = 219;
	_literal_01a5( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ruby_inline { struct _literal_01a7
	: public ExportTree
{
	static const int ID = 220;
	_literal_01a7( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ruby_inline { struct _literal_01a9
	: public ExportTree
{
	static const int ID = 221;
	_literal_01a9( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ruby_inline { struct _literal_01ab
	: public ExportTree
{
	static const int ID = 222;
	_literal_01ab( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ruby_inline { struct _literal_01ad
	: public ExportTree
{
	static const int ID = 223;
	_literal_01ad( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ruby_inline { struct _literal_01af
	: public ExportTree
{
	static const int ID = 224;
	_literal_01af( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ruby_inline { struct _literal_01b1
	: public ExportTree
{
	static const int ID = 225;
	_literal_01b1( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ruby_inline { struct _literal_01b3
	: public ExportTree
{
	static const int ID = 226;
	_literal_01b3( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ruby_inline { struct _literal_01b5
	: public ExportTree
{
	static const int ID = 227;
	_literal_01b5( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ruby_inline { struct _literal_01b7
	: public ExportTree
{
	static const int ID = 228;
	_literal_01b7( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ruby_inline { struct _literal_01b9
	: public ExportTree
{
	static const int ID = 229;
	_literal_01b9( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ruby_inline { struct _literal_01bb
	: public ExportTree
{
	static const int ID = 230;
	_literal_01bb( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ruby_inline { struct _literal_01c9
	: public ExportTree
{
	static const int ID = 231;
	_literal_01c9( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ruby_inline { struct _literal_01cb
	: public ExportTree
{
	static const int ID = 232;
	_literal_01cb( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ruby_inline { struct _literal_01cd
	: public ExportTree
{
	static const int ID = 233;
	_literal_01cd( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ruby_inline { struct _literal_01cf
	: public ExportTree
{
	static const int ID = 234;
	_literal_01cf( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ruby_inline { struct _literal_01d1
	: public ExportTree
{
	static const int ID = 235;
	_literal_01d1( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ruby_inline { struct _literal_01d3
	: public ExportTree
{
	static const int ID = 236;
	_literal_01d3( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ruby_inline { struct _literal_01d5
	: public ExportTree
{
	static const int ID = 237;
	_literal_01d5( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ruby_inline { struct _literal_01d7
	: public ExportTree
{
	static const int ID = 238;
	_literal_01d7( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ruby_inline { struct ident
	: public ExportTree
{
	static const int ID = 239;
	ident( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ruby_inline { struct number
	: public ExportTree
{
	static const int ID = 240;
	number( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ruby_inline { struct hex_number
	: public ExportTree
{
	static const int ID = 241;
	hex_number( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ruby_inline { struct comment
	: public ExportTree
{
	static const int ID = 242;
	comment( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ruby_inline { struct string
	: public ExportTree
{
	static const int ID = 243;
	string( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ruby_inline { struct whitespace
	: public ExportTree
{
	static const int ID = 244;
	whitespace( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ruby_inline { struct ruby_any
	: public ExportTree
{
	static const int ID = 245;
	ruby_any( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ruby_inline { struct inline_expr
	: public ExportTree
{
	static const int ID = 1211;
	inline_expr( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ruby_inline::_repeat_expr_item _repeat_expr_item();
}; }
namespace ruby_inline { struct expr_item
	: public ExportTree
{
	static const int ID = 1212;
	expr_item( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ruby_inline::expr_any expr_any();
	::ruby_inline::expr_symbol expr_symbol();
	::ruby_inline::expr_interpret expr_interpret();
	enum prod_name {
		ExprAny = 0,
		ExprSymbol = 1,
		ExprInterpret = 2,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ruby_inline { struct expr_any
	: public ExportTree
{
	static const int ID = 1213;
	expr_any( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ruby_inline::whitespace whitespace();
	::ruby_inline::comment comment();
	::ruby_inline::string string();
	::ruby_inline::number number();
	::ruby_inline::hex_number hex_number();
	::ruby_inline::ident ident();
	::ruby_inline::ruby_any ruby_any();
}; }
namespace ruby_inline { struct expr_symbol
	: public ExportTree
{
	static const int ID = 1214;
	expr_symbol( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ruby_inline { struct expr_interpret
	: public ExportTree
{
	static const int ID = 1215;
	expr_interpret( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ruby_inline::state_ref state_ref();
	enum prod_name {
		Fpc = 0,
		Fc = 1,
		Fcurs = 2,
		Ftargs = 3,
		Fentry = 4,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ruby_inline { struct state_ref
	: public ExportTree
{
	static const int ID = 1216;
	state_ref( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ruby_inline::opt_name_sep opt_name_sep();
	::ruby_inline::state_ref_names state_ref_names();
}; }
namespace ruby_inline { struct opt_name_sep
	: public ExportTree
{
	static const int ID = 1217;
	opt_name_sep( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	enum prod_name {
		ColonColon = 0,
		Empty = 1,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ruby_inline { struct state_ref_names
	: public ExportTree
{
	static const int ID = 1218;
	state_ref_names( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ruby_inline::state_ref_names _state_ref_names();
	::srlex::word word();
	enum prod_name {
		Rec = 0,
		Base = 1,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ruby_inline { struct inline_block
	: public ExportTree
{
	static const int ID = 1219;
	inline_block( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ruby_inline::_repeat_block_item _repeat_block_item();
}; }
namespace ruby_inline { struct block_item
	: public ExportTree
{
	static const int ID = 1220;
	block_item( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ruby_inline::expr_any expr_any();
	::ruby_inline::block_symbol block_symbol();
	::ruby_inline::block_interpret block_interpret();
	::ruby_inline::inline_block inline_block();
	enum prod_name {
		ExprAny = 0,
		BlockSymbol = 1,
		BlockInterpret = 2,
		RecBlock = 3,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ruby_inline { struct block_symbol
	: public ExportTree
{
	static const int ID = 1221;
	block_symbol( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ruby_inline { struct block_interpret
	: public ExportTree
{
	static const int ID = 1222;
	block_interpret( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ruby_inline::expr_interpret expr_interpret();
	::ruby_inline::_opt_whitespace _opt_whitespace();
	::ruby_inline::inline_expr inline_expr();
	::ruby_inline::state_ref state_ref();
	enum prod_name {
		ExprInterpret = 0,
		Fhold = 1,
		FgotoExpr = 2,
		FnextExpr = 3,
		FcallExpr = 4,
		FncallExpr = 5,
		Fexec = 6,
		FgotoSr = 7,
		FnextSr = 8,
		FcallSr = 9,
		FncallSr = 10,
		Fret = 11,
		Fnret = 12,
		Fbreak = 13,
		Fnbreak = 14,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace ruby_host { struct _literal_01db
	: public ExportTree
{
	static const int ID = 246;
	_literal_01db( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ruby_host { struct slr
	: public ExportTree
{
	static const int ID = 247;
	slr( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ruby_host { struct ident
	: public ExportTree
{
	static const int ID = 248;
	ident( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ruby_host { struct number
	: public ExportTree
{
	static const int ID = 249;
	number( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ruby_host { struct hex_number
	: public ExportTree
{
	static const int ID = 250;
	hex_number( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ruby_host { struct comment
	: public ExportTree
{
	static const int ID = 251;
	comment( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ruby_host { struct string
	: public ExportTree
{
	static const int ID = 252;
	string( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ruby_host { struct whitespace
	: public ExportTree
{
	static const int ID = 253;
	whitespace( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ruby_host { struct ruby_any
	: public ExportTree
{
	static const int ID = 254;
	ruby_any( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ruby_host { struct tok
	: public ExportTree
{
	static const int ID = 1223;
	tok( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ruby_host::ident ident();
	::ruby_host::number number();
	::ruby_host::hex_number hex_number();
	::ruby_host::comment comment();
	::ruby_host::string string();
	::ruby_host::whitespace whitespace();
	::ruby_host::ruby_any ruby_any();
}; }
namespace ruby_host { struct section
	: public ExportTree
{
	static const int ID = 1224;
	section( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::ragel_start ragel_start();
	::ruby_host::tok tok();
	enum prod_name {
		MultiLine = 0,
		Tok = 1,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace crack_inline { struct _literal_01ed
	: public ExportTree
{
	static const int ID = 255;
	_literal_01ed( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace crack_inline { struct _literal_01ef
	: public ExportTree
{
	static const int ID = 256;
	_literal_01ef( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace crack_inline { struct _literal_01f1
	: public ExportTree
{
	static const int ID = 257;
	_literal_01f1( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace crack_inline { struct _literal_01f3
	: public ExportTree
{
	static const int ID = 258;
	_literal_01f3( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace crack_inline { struct _literal_01f5
	: public ExportTree
{
	static const int ID = 259;
	_literal_01f5( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace crack_inline { struct _literal_01f7
	: public ExportTree
{
	static const int ID = 260;
	_literal_01f7( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace crack_inline { struct _literal_01f9
	: public ExportTree
{
	static const int ID = 261;
	_literal_01f9( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace crack_inline { struct _literal_01fb
	: public ExportTree
{
	static const int ID = 262;
	_literal_01fb( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace crack_inline { struct _literal_01fd
	: public ExportTree
{
	static const int ID = 263;
	_literal_01fd( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace crack_inline { struct _literal_01ff
	: public ExportTree
{
	static const int ID = 264;
	_literal_01ff( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace crack_inline { struct _literal_0201
	: public ExportTree
{
	static const int ID = 265;
	_literal_0201( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace crack_inline { struct _literal_0203
	: public ExportTree
{
	static const int ID = 266;
	_literal_0203( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace crack_inline { struct _literal_0205
	: public ExportTree
{
	static const int ID = 267;
	_literal_0205( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace crack_inline { struct _literal_0207
	: public ExportTree
{
	static const int ID = 268;
	_literal_0207( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace crack_inline { struct _literal_0209
	: public ExportTree
{
	static const int ID = 269;
	_literal_0209( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace crack_inline { struct _literal_0217
	: public ExportTree
{
	static const int ID = 270;
	_literal_0217( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace crack_inline { struct _literal_0219
	: public ExportTree
{
	static const int ID = 271;
	_literal_0219( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace crack_inline { struct _literal_021b
	: public ExportTree
{
	static const int ID = 272;
	_literal_021b( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace crack_inline { struct _literal_021d
	: public ExportTree
{
	static const int ID = 273;
	_literal_021d( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace crack_inline { struct _literal_021f
	: public ExportTree
{
	static const int ID = 274;
	_literal_021f( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace crack_inline { struct _literal_0221
	: public ExportTree
{
	static const int ID = 275;
	_literal_0221( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace crack_inline { struct _literal_0223
	: public ExportTree
{
	static const int ID = 276;
	_literal_0223( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace crack_inline { struct _literal_0225
	: public ExportTree
{
	static const int ID = 277;
	_literal_0225( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace crack_inline { struct ident
	: public ExportTree
{
	static const int ID = 278;
	ident( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace crack_inline { struct number
	: public ExportTree
{
	static const int ID = 279;
	number( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace crack_inline { struct hex_number
	: public ExportTree
{
	static const int ID = 280;
	hex_number( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace crack_inline { struct comment
	: public ExportTree
{
	static const int ID = 281;
	comment( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace crack_inline { struct string
	: public ExportTree
{
	static const int ID = 282;
	string( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace crack_inline { struct whitespace
	: public ExportTree
{
	static const int ID = 283;
	whitespace( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace crack_inline { struct c_any
	: public ExportTree
{
	static const int ID = 284;
	c_any( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace crack_inline { struct inline_expr
	: public ExportTree
{
	static const int ID = 1225;
	inline_expr( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::crack_inline::_repeat_expr_item _repeat_expr_item();
}; }
namespace crack_inline { struct expr_item
	: public ExportTree
{
	static const int ID = 1226;
	expr_item( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::crack_inline::expr_any expr_any();
	::crack_inline::expr_symbol expr_symbol();
	::crack_inline::expr_interpret expr_interpret();
	enum prod_name {
		ExprAny = 0,
		ExprSymbol = 1,
		ExprInterpret = 2,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace crack_inline { struct expr_any
	: public ExportTree
{
	static const int ID = 1227;
	expr_any( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::crack_inline::whitespace whitespace();
	::crack_inline::comment comment();
	::crack_inline::string string();
	::crack_inline::number number();
	::crack_inline::hex_number hex_number();
	::crack_inline::ident ident();
	::crack_inline::c_any c_any();
}; }
namespace crack_inline { struct expr_symbol
	: public ExportTree
{
	static const int ID = 1228;
	expr_symbol( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace crack_inline { struct expr_interpret
	: public ExportTree
{
	static const int ID = 1229;
	expr_interpret( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::crack_inline::state_ref state_ref();
	enum prod_name {
		Fpc = 0,
		Fc = 1,
		Fcurs = 2,
		Ftargs = 3,
		Fentry = 4,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace crack_inline { struct state_ref
	: public ExportTree
{
	static const int ID = 1230;
	state_ref( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::crack_inline::opt_name_sep opt_name_sep();
	::crack_inline::state_ref_names state_ref_names();
}; }
namespace crack_inline { struct opt_name_sep
	: public ExportTree
{
	static const int ID = 1231;
	opt_name_sep( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	enum prod_name {
		ColonColon = 0,
		Empty = 1,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace crack_inline { struct state_ref_names
	: public ExportTree
{
	static const int ID = 1232;
	state_ref_names( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::crack_inline::state_ref_names _state_ref_names();
	::srlex::word word();
	enum prod_name {
		Rec = 0,
		Base = 1,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace crack_inline { struct inline_block
	: public ExportTree
{
	static const int ID = 1233;
	inline_block( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::crack_inline::_repeat_block_item _repeat_block_item();
}; }
namespace crack_inline { struct block_item
	: public ExportTree
{
	static const int ID = 1234;
	block_item( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::crack_inline::expr_any expr_any();
	::crack_inline::block_symbol block_symbol();
	::crack_inline::block_interpret block_interpret();
	::crack_inline::inline_block inline_block();
	enum prod_name {
		ExprAny = 0,
		BlockSymbol = 1,
		BlockInterpret = 2,
		RecBlock = 3,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace crack_inline { struct block_symbol
	: public ExportTree
{
	static const int ID = 1235;
	block_symbol( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace crack_inline { struct block_interpret
	: public ExportTree
{
	static const int ID = 1236;
	block_interpret( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::crack_inline::expr_interpret expr_interpret();
	::crack_inline::_opt_whitespace _opt_whitespace();
	::crack_inline::inline_expr inline_expr();
	::crack_inline::state_ref state_ref();
	enum prod_name {
		ExprInterpret = 0,
		Fhold = 1,
		FgotoExpr = 2,
		FnextExpr = 3,
		FcallExpr = 4,
		FncallExpr = 5,
		Fexec = 6,
		FgotoSr = 7,
		FnextSr = 8,
		FcallSr = 9,
		FncallSr = 10,
		Fret = 11,
		Fnret = 12,
		Fbreak = 13,
		Fnbreak = 14,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
namespace crack_host { struct _literal_0229
	: public ExportTree
{
	static const int ID = 285;
	_literal_0229( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace crack_host { struct slr
	: public ExportTree
{
	static const int ID = 286;
	slr( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace crack_host { struct ident
	: public ExportTree
{
	static const int ID = 287;
	ident( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace crack_host { struct number
	: public ExportTree
{
	static const int ID = 288;
	number( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace crack_host { struct hex_number
	: public ExportTree
{
	static const int ID = 289;
	hex_number( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace crack_host { struct comment
	: public ExportTree
{
	static const int ID = 290;
	comment( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace crack_host { struct string
	: public ExportTree
{
	static const int ID = 291;
	string( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace crack_host { struct whitespace
	: public ExportTree
{
	static const int ID = 292;
	whitespace( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace crack_host { struct c_any
	: public ExportTree
{
	static const int ID = 293;
	c_any( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace crack_host { struct tok
	: public ExportTree
{
	static const int ID = 1237;
	tok( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::crack_host::ident ident();
	::crack_host::number number();
	::crack_host::hex_number hex_number();
	::crack_host::comment comment();
	::crack_host::string string();
	::crack_host::whitespace whitespace();
	::crack_host::c_any c_any();
}; }
namespace crack_host { struct section
	: public ExportTree
{
	static const int ID = 1238;
	section( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::ragel_start ragel_start();
	::crack_host::tok tok();
	enum prod_name {
		MultiLine = 0,
		Tok = 1,
	};
	enum prod_name prodName() { return (enum prod_name)__tree->prod_num; }
}; }
struct _ign_0x55b47a1dd850
	: public ExportTree
{
	static const int ID = 294;
	_ign_0x55b47a1dd850( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
};
struct _ign_0x55b47a1e12c0
	: public ExportTree
{
	static const int ID = 295;
	_ign_0x55b47a1e12c0( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
};
struct _ign_0x55b47a1e1500
	: public ExportTree
{
	static const int ID = 296;
	_ign_0x55b47a1e1500( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
};
struct _ign_0x55b47a20ad10
	: public ExportTree
{
	static const int ID = 297;
	_ign_0x55b47a20ad10( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
};
struct _ign_0x55b47a20af50
	: public ExportTree
{
	static const int ID = 298;
	_ign_0x55b47a20af50( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
};
struct _ign_0x55b47a210010
	: public ExportTree
{
	static const int ID = 299;
	_ign_0x55b47a210010( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
};
struct _ign_0x55b47a212460
	: public ExportTree
{
	static const int ID = 300;
	_ign_0x55b47a212460( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
};
struct _ign_0x55b47a1ae370
	: public ExportTree
{
	static const int ID = 301;
	_ign_0x55b47a1ae370( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
};
struct _ign_0x55b47a1d2560
	: public ExportTree
{
	static const int ID = 302;
	_ign_0x55b47a1d2560( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
};
struct _ign_0x55b47a1b42a0
	: public ExportTree
{
	static const int ID = 303;
	_ign_0x55b47a1b42a0( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
};
struct _ign_0x55b47a3a95d0
	: public ExportTree
{
	static const int ID = 304;
	_ign_0x55b47a3a95d0( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
};
struct _ign_0x55b47a38f0a0
	: public ExportTree
{
	static const int ID = 305;
	_ign_0x55b47a38f0a0( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
};
struct _ign_0x55b47a416030
	: public ExportTree
{
	static const int ID = 306;
	_ign_0x55b47a416030( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
};
struct _ign_0x55b47a38e100
	: public ExportTree
{
	static const int ID = 307;
	_ign_0x55b47a38e100( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
};
struct _ign_0x55b47a369d40
	: public ExportTree
{
	static const int ID = 308;
	_ign_0x55b47a369d40( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
};
struct _ign_0x55b47a1b30f0
	: public ExportTree
{
	static const int ID = 309;
	_ign_0x55b47a1b30f0( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
};
struct __0x55b47a1e1360_DEF_PAT_1
	: public ExportTree
{
	static const int ID = 310;
	__0x55b47a1e1360_DEF_PAT_1( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
};
struct __0x55b47a20adb0_DEF_PAT_2
	: public ExportTree
{
	static const int ID = 311;
	__0x55b47a20adb0_DEF_PAT_2( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
};
struct __0x55b47a20de10_DEF_PAT_3
	: public ExportTree
{
	static const int ID = 312;
	__0x55b47a20de10_DEF_PAT_3( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
};
struct __0x55b47a211d40_DEF_PAT_4
	: public ExportTree
{
	static const int ID = 313;
	__0x55b47a211d40_DEF_PAT_4( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
};
struct __0x55b47a212500_DEF_PAT_5
	: public ExportTree
{
	static const int ID = 314;
	__0x55b47a212500_DEF_PAT_5( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
};
struct __0x55b47a1ae5f0_DEF_PAT_6
	: public ExportTree
{
	static const int ID = 315;
	__0x55b47a1ae5f0_DEF_PAT_6( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
};
struct __0x55b47a1d2600_DEF_PAT_7
	: public ExportTree
{
	static const int ID = 316;
	__0x55b47a1d2600_DEF_PAT_7( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
};
struct __0x55b47a1b4520_DEF_PAT_8
	: public ExportTree
{
	static const int ID = 317;
	__0x55b47a1b4520_DEF_PAT_8( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
};
struct __0x55b47a3a9670_DEF_PAT_9
	: public ExportTree
{
	static const int ID = 318;
	__0x55b47a3a9670_DEF_PAT_9( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
};
struct __0x55b47a38f320_DEF_PAT_10
	: public ExportTree
{
	static const int ID = 319;
	__0x55b47a38f320_DEF_PAT_10( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
};
struct __0x55b47a4160d0_DEF_PAT_11
	: public ExportTree
{
	static const int ID = 320;
	__0x55b47a4160d0_DEF_PAT_11( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
};
struct __0x55b47a38e380_DEF_PAT_12
	: public ExportTree
{
	static const int ID = 321;
	__0x55b47a38e380_DEF_PAT_12( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
};
struct __0x55b47a369de0_DEF_PAT_13
	: public ExportTree
{
	static const int ID = 322;
	__0x55b47a369de0_DEF_PAT_13( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
};
struct __0x55b47a17d690_DEF_PAT_14
	: public ExportTree
{
	static const int ID = 323;
	__0x55b47a17d690_DEF_PAT_14( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
};
struct _repeat_import
	: public ExportTree
{
	static const int ID = 1239;
	_repeat_import( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
};
namespace c_host { struct _repeat_section
	: public ExportTree
{
	static const int ID = 1240;
	_repeat_section( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ruby_host { struct _repeat_section
	: public ExportTree
{
	static const int ID = 1241;
	_repeat_section( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ocaml_host { struct _repeat_section
	: public ExportTree
{
	static const int ID = 1242;
	_repeat_section( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _repeat_write_arg
	: public ExportTree
{
	static const int ID = 1243;
	_repeat_write_arg( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _repeat_statement
	: public ExportTree
{
	static const int ID = 1244;
	_repeat_statement( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace c_inline { struct _opt_whitespace
	: public ExportTree
{
	static const int ID = 1245;
	_opt_whitespace( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ocaml_inline { struct _repeat_expr_item
	: public ExportTree
{
	static const int ID = 1246;
	_repeat_expr_item( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ocaml_inline { struct _repeat_block_item
	: public ExportTree
{
	static const int ID = 1247;
	_repeat_block_item( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ocaml_inline { struct _opt_whitespace
	: public ExportTree
{
	static const int ID = 1248;
	_opt_whitespace( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ruby_inline { struct _repeat_expr_item
	: public ExportTree
{
	static const int ID = 1249;
	_repeat_expr_item( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ruby_inline { struct _repeat_block_item
	: public ExportTree
{
	static const int ID = 1250;
	_repeat_block_item( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ruby_inline { struct _opt_whitespace
	: public ExportTree
{
	static const int ID = 1251;
	_opt_whitespace( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace crack_inline { struct _repeat_expr_item
	: public ExportTree
{
	static const int ID = 1252;
	_repeat_expr_item( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace crack_inline { struct _repeat_block_item
	: public ExportTree
{
	static const int ID = 1253;
	_repeat_block_item( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace crack_inline { struct _opt_whitespace
	: public ExportTree
{
	static const int ID = 1254;
	_opt_whitespace( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace crack_host { struct _repeat_section
	: public ExportTree
{
	static const int ID = 1255;
	_repeat_section( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
struct _T_any
	: public ExportTree
{
	static const int ID = 324;
	_T_any( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
};
struct _T_start
	: public ExportTree
{
	static const int ID = 325;
	_T_start( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::c_select_section c_select_section();
	::c_host::_repeat_section SectionList();
	::ruby_select_section ruby_select_section();
	::ruby_host::_repeat_section RSectionList();
	::ocaml_select_section ocaml_select_section();
	::ocaml_host::_repeat_section OSectionList();
	::crack_select_section crack_select_section();
};
struct _T_import_val
	: public ExportTree
{
	static const int ID = 326;
	_T_import_val( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::c_host::number number();
	::c_host::string string();
};
struct _T_import
	: public ExportTree
{
	static const int ID = 327;
	_T_import( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::c_host::ident Name();
	::import_val Val();
};
namespace ragel { struct _T_inline_expr_reparse
	: public ExportTree
{
	static const int ID = 328;
	_T_inline_expr_reparse( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::_inline_expr_reparse _inline_expr_reparse();
	::ragel::action_expr action_expr();
}; }
namespace ragel { struct _T_join
	: public ExportTree
{
	static const int ID = 329;
	_T_join( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::join _join();
	::ragel::expression expression();
}; }
namespace ragel { struct _T_expression
	: public ExportTree
{
	static const int ID = 330;
	_T_expression( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::expr_left expr_left();
	::ragel::expression_op_list expression_op_list();
}; }
namespace ragel { struct _T_expression_op_list
	: public ExportTree
{
	static const int ID = 331;
	_T_expression_op_list( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::expression_op expression_op();
	::ragel::expression_op_list _expression_op_list();
}; }
namespace ragel { struct _T_expression_op
	: public ExportTree
{
	static const int ID = 332;
	_T_expression_op( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::term term();
}; }
namespace ragel { struct _T_expr_left
	: public ExportTree
{
	static const int ID = 333;
	_T_expr_left( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::term term();
}; }
namespace ragel { struct _T_term
	: public ExportTree
{
	static const int ID = 334;
	_T_term( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::term_left term_left();
	::ragel::term_op_list_short term_op_list_short();
}; }
namespace ragel { struct _T_term_left
	: public ExportTree
{
	static const int ID = 335;
	_T_term_left( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::factor_label factor_label();
}; }
namespace ragel { struct _T_term_op_list_short
	: public ExportTree
{
	static const int ID = 336;
	_T_term_op_list_short( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::term_op term_op();
	::ragel::term_op_list_short _term_op_list_short();
}; }
namespace ragel { struct _T_term_op
	: public ExportTree
{
	static const int ID = 337;
	_T_term_op( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::factor_label factor_label();
}; }
namespace ragel { struct _T_factor_label
	: public ExportTree
{
	static const int ID = 338;
	_T_factor_label( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::word word();
	::ragel::factor_label _factor_label();
	::ragel::factor_ep factor_ep();
}; }
namespace ragel { struct _T_factor_ep
	: public ExportTree
{
	static const int ID = 339;
	_T_factor_ep( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::factor_aug factor_aug();
	::ragel::epsilon_target epsilon_target();
}; }
namespace ragel { struct _T_epsilon_target
	: public ExportTree
{
	static const int ID = 340;
	_T_epsilon_target( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::epsilon_target _epsilon_target();
	::ragel::word word();
}; }
namespace ragel { struct _T_action_expr
	: public ExportTree
{
	static const int ID = 341;
	_T_action_expr( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::c_select c_select();
	::c_inline::inline_expr CInlineExpr();
	::ruby_select ruby_select();
	::ruby_inline::inline_expr RubyInlineExpr();
	::ocaml_select ocaml_select();
	::ocaml_inline::inline_expr OCamlInlineExpr();
	::crack_select crack_select();
	::crack_inline::inline_expr CrackInlineExpr();
}; }
namespace ragel { struct _T_action_block
	: public ExportTree
{
	static const int ID = 342;
	_T_action_block( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::c_select c_select();
	::c_inline::inline_block CInlineBlock();
	::ruby_select ruby_select();
	::ruby_inline::inline_block RubyInlineBlock();
	::ocaml_select ocaml_select();
	::ocaml_inline::inline_block OCamlInlineBlock();
	::crack_select crack_select();
	::crack_inline::inline_block CrackInlineBlock();
}; }
namespace ragel { struct _T_action_arg_list
	: public ExportTree
{
	static const int ID = 343;
	_T_action_arg_list( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::action_arg_list _action_arg_list();
	::ragel::action_ref action_ref();
}; }
namespace ragel { struct _T_opt_action_arg_list
	: public ExportTree
{
	static const int ID = 344;
	_T_opt_action_arg_list( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::action_arg_list action_arg_list();
}; }
namespace ragel { struct _T_named_action_ref
	: public ExportTree
{
	static const int ID = 345;
	_T_named_action_ref( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::word word();
	::ragel::opt_action_arg_list opt_action_arg_list();
}; }
namespace ragel { struct _T_action_ref
	: public ExportTree
{
	static const int ID = 346;
	_T_action_ref( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::named_action_ref named_action_ref();
	::ragel::action_block action_block();
}; }
namespace ragel { struct _T_priority_name
	: public ExportTree
{
	static const int ID = 347;
	_T_priority_name( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::word word();
}; }
namespace ragel { struct _T_error_name
	: public ExportTree
{
	static const int ID = 348;
	_T_error_name( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::word word();
}; }
namespace ragel { struct _T_priority_aug
	: public ExportTree
{
	static const int ID = 349;
	_T_priority_aug( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::uint uint();
}; }
namespace ragel { struct _T_aug_base
	: public ExportTree
{
	static const int ID = 350;
	_T_aug_base( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _T_aug_cond
	: public ExportTree
{
	static const int ID = 351;
	_T_aug_cond( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _T_aug_to_state
	: public ExportTree
{
	static const int ID = 352;
	_T_aug_to_state( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _T_aug_from_state
	: public ExportTree
{
	static const int ID = 353;
	_T_aug_from_state( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _T_aug_eof
	: public ExportTree
{
	static const int ID = 354;
	_T_aug_eof( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _T_aug_gbl_error
	: public ExportTree
{
	static const int ID = 355;
	_T_aug_gbl_error( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _T_aug_local_error
	: public ExportTree
{
	static const int ID = 356;
	_T_aug_local_error( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _T_factor_aug
	: public ExportTree
{
	static const int ID = 357;
	_T_factor_aug( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::factor_aug _factor_aug();
	::ragel::aug_base aug_base();
	::ragel::action_ref action_ref();
	::ragel::priority_aug priority_aug();
	::ragel::priority_name priority_name();
	::ragel::aug_cond aug_cond();
	::ragel::aug_to_state aug_to_state();
	::ragel::aug_from_state aug_from_state();
	::ragel::aug_eof aug_eof();
	::ragel::aug_gbl_error aug_gbl_error();
	::ragel::aug_local_error aug_local_error();
	::ragel::error_name error_name();
	::ragel::factor_rep factor_rep();
}; }
namespace ragel { struct _T_factor_rep
	: public ExportTree
{
	static const int ID = 358;
	_T_factor_rep( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::factor_neg factor_neg();
	::ragel::factor_rep_op_list factor_rep_op_list();
}; }
namespace ragel { struct _T_factor_rep_op_list
	: public ExportTree
{
	static const int ID = 359;
	_T_factor_rep_op_list( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::factor_rep_op factor_rep_op();
	::ragel::factor_rep_op_list _factor_rep_op_list();
}; }
namespace ragel { struct _T_factor_rep_op
	: public ExportTree
{
	static const int ID = 360;
	_T_factor_rep_op( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::factor_rep_num factor_rep_num();
	::ragel::factor_rep_num LowRep();
	::ragel::factor_rep_num HighRep();
}; }
namespace ragel { struct _T_factor_rep_num
	: public ExportTree
{
	static const int ID = 361;
	_T_factor_rep_num( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::uint uint();
}; }
namespace ragel { struct _T_factor_neg
	: public ExportTree
{
	static const int ID = 362;
	_T_factor_neg( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::factor_neg _factor_neg();
	::ragel::factor factor();
}; }
namespace ragel { struct _T_opt_max_arg
	: public ExportTree
{
	static const int ID = 363;
	_T_opt_max_arg( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::action_ref action_ref();
}; }
namespace ragel { struct _T_nfastar
	: public ExportTree
{
	static const int ID = 364;
	_T_nfastar( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _T_colon_cond
	: public ExportTree
{
	static const int ID = 365;
	_T_colon_cond( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _T_factor
	: public ExportTree
{
	static const int ID = 366;
	_T_factor( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::alphabet_num alphabet_num();
	::ragel::word word();
	::ragel::string string();
	::ragel::lex_sqopen_pos lex_sqopen_pos();
	::ragel::reg_or_data reg_or_data();
	::ragel::re_or_sqclose re_or_sqclose();
	::ragel::lex_sqopen_neg lex_sqopen_neg();
	::ragel::lex_regex_open lex_regex_open();
	::ragel::regex regex();
	::ragel::re_close re_close();
	::ragel::range_lit RL1();
	::ragel::range_lit RL2();
	::ragel::nfastar nfastar();
	::ragel::expression expression();
	::ragel::action_ref Push();
	::ragel::action_ref Pop();
	::ragel::action_ref Init();
	::ragel::action_ref Stay();
	::ragel::action_ref Repeat();
	::ragel::action_ref Exit();
	::ragel::colon_cond colon_cond();
	::ragel::action_ref Inc();
	::ragel::action_ref Min();
	::ragel::opt_max_arg OptMax();
	::ragel::join join();
}; }
namespace ragel { struct _T_regex
	: public ExportTree
{
	static const int ID = 367;
	_T_regex( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::reg_item_rep_list reg_item_rep_list();
}; }
namespace ragel { struct _T_reg_item_rep_list
	: public ExportTree
{
	static const int ID = 368;
	_T_reg_item_rep_list( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::reg_item_rep_list _reg_item_rep_list();
	::ragel::reg_item_rep reg_item_rep();
}; }
namespace ragel { struct _T_reg_item_rep
	: public ExportTree
{
	static const int ID = 369;
	_T_reg_item_rep( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::reg_item reg_item();
	::ragel::re_star re_star();
}; }
namespace ragel { struct _T_reg_item
	: public ExportTree
{
	static const int ID = 370;
	_T_reg_item( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::re_sqopen_pos re_sqopen_pos();
	::ragel::reg_or_data reg_or_data();
	::ragel::re_or_sqclose re_or_sqclose();
	::ragel::re_sqopen_neg re_sqopen_neg();
	::ragel::re_dot re_dot();
	::ragel::re_char re_char();
}; }
namespace ragel { struct _T_reg_or_data
	: public ExportTree
{
	static const int ID = 371;
	_T_reg_or_data( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::reg_or_data _reg_or_data();
	::ragel::reg_or_char reg_or_char();
}; }
namespace ragel { struct _T_reg_or_char
	: public ExportTree
{
	static const int ID = 372;
	_T_reg_or_char( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::re_or_char re_or_char();
	::ragel::re_or_char Low();
	::ragel::re_or_dash re_or_dash();
	::ragel::re_or_char High();
}; }
namespace ragel { struct _T_range_lit
	: public ExportTree
{
	static const int ID = 373;
	_T_range_lit( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::string string();
	::ragel::alphabet_num alphabet_num();
}; }
namespace ragel { struct _T_alphabet_num
	: public ExportTree
{
	static const int ID = 374;
	_T_alphabet_num( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::uint uint();
	::ragel::hex hex();
}; }
namespace ragel { struct _T_lm_act
	: public ExportTree
{
	static const int ID = 375;
	_T_lm_act( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::action_ref action_ref();
	::ragel::action_block action_block();
}; }
namespace ragel { struct _T_opt_lm_act
	: public ExportTree
{
	static const int ID = 376;
	_T_opt_lm_act( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::lm_act lm_act();
}; }
namespace ragel { struct _T_lm_stmt
	: public ExportTree
{
	static const int ID = 377;
	_T_lm_stmt( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::join join();
	::ragel::opt_lm_act opt_lm_act();
	::ragel::assignment assignment();
	::ragel::action_spec action_spec();
}; }
namespace ragel { struct _T_lm_stmt_list
	: public ExportTree
{
	static const int ID = 378;
	_T_lm_stmt_list( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::lm_stmt_list _lm_stmt_list();
	::ragel::lm_stmt lm_stmt();
}; }
namespace ragel { struct _T_lm
	: public ExportTree
{
	static const int ID = 379;
	_T_lm( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::join join();
	::ragel::lm_stmt_list lm_stmt_list();
}; }
namespace ragel { struct _T_action_param
	: public ExportTree
{
	static const int ID = 380;
	_T_action_param( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::word word();
}; }
namespace ragel { struct _T_action_param_list
	: public ExportTree
{
	static const int ID = 381;
	_T_action_param_list( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::action_param_list _action_param_list();
	::ragel::action_param action_param();
}; }
namespace ragel { struct _T_opt_action_param_list
	: public ExportTree
{
	static const int ID = 382;
	_T_opt_action_param_list( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::action_param_list action_param_list();
}; }
namespace ragel { struct _T_action_params
	: public ExportTree
{
	static const int ID = 383;
	_T_action_params( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::opt_action_param_list opt_action_param_list();
}; }
namespace ragel { struct _T_action_spec
	: public ExportTree
{
	static const int ID = 384;
	_T_action_spec( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::word word();
	::ragel::action_params action_params();
	::ragel::action_block action_block();
}; }
namespace ragel { struct _T_def_name
	: public ExportTree
{
	static const int ID = 385;
	_T_def_name( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::word word();
}; }
namespace ragel { struct _T_assignment
	: public ExportTree
{
	static const int ID = 386;
	_T_assignment( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::opt_export opt_export();
	::ragel::def_name def_name();
	::ragel::join join();
}; }
namespace ragel { struct _T_instantiation
	: public ExportTree
{
	static const int ID = 387;
	_T_instantiation( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::opt_export opt_export();
	::ragel::def_name def_name();
	::ragel::lm lm();
}; }
namespace ragel { struct _T_nfa_expr
	: public ExportTree
{
	static const int ID = 388;
	_T_nfa_expr( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::nfa_expr _nfa_expr();
	::ragel::term term();
}; }
namespace ragel { struct _T_nfa_round_spec
	: public ExportTree
{
	static const int ID = 389;
	_T_nfa_round_spec( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::uint Depth();
	::ragel::uint Group();
}; }
namespace ragel { struct _T_nfa_round_list
	: public ExportTree
{
	static const int ID = 390;
	_T_nfa_round_list( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::nfa_round_list _nfa_round_list();
	::ragel::nfa_round_spec nfa_round_spec();
}; }
namespace ragel { struct _T_nfa_rounds
	: public ExportTree
{
	static const int ID = 391;
	_T_nfa_rounds( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::nfa_round_list nfa_round_list();
}; }
namespace ragel { struct _T_nfa_union
	: public ExportTree
{
	static const int ID = 392;
	_T_nfa_union( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::def_name def_name();
	::ragel::nfa_rounds nfa_rounds();
	::ragel::nfa_expr nfa_expr();
}; }
namespace ragel { struct _T_alphtype_type
	: public ExportTree
{
	static const int ID = 393;
	_T_alphtype_type( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::word W1();
	::ragel::word W2();
}; }
namespace ragel { struct _T_include_spec
	: public ExportTree
{
	static const int ID = 394;
	_T_include_spec( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::word word();
	::ragel::string string();
}; }
namespace ragel { struct _T_opt_export
	: public ExportTree
{
	static const int ID = 395;
	_T_opt_export( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _T_write_arg
	: public ExportTree
{
	static const int ID = 396;
	_T_write_arg( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::word word();
}; }
namespace ragel { struct _T_machine_name
	: public ExportTree
{
	static const int ID = 397;
	_T_machine_name( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::word word();
}; }
namespace ragel { struct _T_statement
	: public ExportTree
{
	static const int ID = 398;
	_T_statement( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::assignment assignment();
	::ragel::instantiation instantiation();
	::ragel::nfa_union nfa_union();
	::ragel::action_spec action_spec();
	::ragel::action_block action_block();
	::ragel::variable_name variable_name();
	::ragel::inline_expr_reparse inline_expr_reparse();
	::ragel::alphtype_type alphtype_type();
	::ragel::word Cmd();
	::ragel::_repeat_write_arg ArgList();
	::ragel::string string();
	::ragel::include_spec include_spec();
}; }
namespace ragel { struct _T_opt_machine_name
	: public ExportTree
{
	static const int ID = 399;
	_T_opt_machine_name( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::machine_name machine_name();
}; }
namespace ragel { struct _T_ragel_start
	: public ExportTree
{
	static const int ID = 400;
	_T_ragel_start( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::opt_machine_name opt_machine_name();
	::ragel::_repeat_statement _repeat_statement();
}; }
namespace c_inline { struct _T_inline_expr
	: public ExportTree
{
	static const int ID = 401;
	_T_inline_expr( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::c_inline::expr_item_list expr_item_list();
}; }
namespace c_inline { struct _T_expr_item_list
	: public ExportTree
{
	static const int ID = 402;
	_T_expr_item_list( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::c_inline::expr_item_list _expr_item_list();
	::c_inline::expr_item expr_item();
}; }
namespace c_inline { struct _T_expr_item
	: public ExportTree
{
	static const int ID = 403;
	_T_expr_item( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::c_inline::expr_any expr_any();
	::c_inline::expr_symbol expr_symbol();
	::c_inline::expr_interpret expr_interpret();
}; }
namespace c_inline { struct _T_expr_any
	: public ExportTree
{
	static const int ID = 404;
	_T_expr_any( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::c_inline::whitespace whitespace();
	::c_inline::comment comment();
	::c_inline::string string();
	::c_inline::number number();
	::c_inline::hex_number hex_number();
	::c_inline::ident ident();
	::c_inline::c_any c_any();
}; }
namespace c_inline { struct _T_expr_symbol
	: public ExportTree
{
	static const int ID = 405;
	_T_expr_symbol( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace c_inline { struct _T_expr_interpret
	: public ExportTree
{
	static const int ID = 406;
	_T_expr_interpret( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::c_inline::state_ref state_ref();
	::c_inline::var_ref var_ref();
}; }
namespace c_inline { struct _T_state_ref
	: public ExportTree
{
	static const int ID = 407;
	_T_state_ref( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::c_inline::opt_name_sep opt_name_sep();
	::c_inline::state_ref_names state_ref_names();
}; }
namespace c_inline { struct _T_opt_name_sep
	: public ExportTree
{
	static const int ID = 408;
	_T_opt_name_sep( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace c_inline { struct _T_state_ref_names
	: public ExportTree
{
	static const int ID = 409;
	_T_state_ref_names( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::c_inline::state_ref_names _state_ref_names();
	::srlex::word word();
}; }
namespace c_inline { struct _T_inline_block
	: public ExportTree
{
	static const int ID = 410;
	_T_inline_block( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::c_inline::block_item_list block_item_list();
}; }
namespace c_inline { struct _T_block_item_list
	: public ExportTree
{
	static const int ID = 411;
	_T_block_item_list( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::c_inline::block_item block_item();
	::c_inline::block_item_list _block_item_list();
}; }
namespace c_inline { struct _T_block_item
	: public ExportTree
{
	static const int ID = 412;
	_T_block_item( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::c_inline::expr_any expr_any();
	::c_inline::block_symbol block_symbol();
	::c_inline::block_interpret block_interpret();
	::c_inline::inline_block inline_block();
}; }
namespace c_inline { struct _T_block_symbol
	: public ExportTree
{
	static const int ID = 413;
	_T_block_symbol( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace c_inline { struct _T_block_interpret
	: public ExportTree
{
	static const int ID = 414;
	_T_block_interpret( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::c_inline::expr_interpret expr_interpret();
	::c_inline::_opt_whitespace _opt_whitespace();
	::c_inline::inline_expr inline_expr();
	::c_inline::state_ref state_ref();
}; }
namespace c_host { struct _T_tok
	: public ExportTree
{
	static const int ID = 415;
	_T_tok( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::c_host::ident ident();
	::c_host::number number();
	::c_host::hex_number hex_number();
	::c_host::comment comment();
	::c_host::string string();
	::c_host::whitespace whitespace();
	::c_host::c_any c_any();
}; }
namespace c_host { struct _T_section
	: public ExportTree
{
	static const int ID = 416;
	_T_section( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::ragel_start ragel_start();
	::c_host::tok tok();
}; }
namespace ocaml_inline { struct _T_inline_expr
	: public ExportTree
{
	static const int ID = 417;
	_T_inline_expr( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ocaml_inline::_repeat_expr_item _repeat_expr_item();
}; }
namespace ocaml_inline { struct _T_expr_item
	: public ExportTree
{
	static const int ID = 418;
	_T_expr_item( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ocaml_inline::expr_any expr_any();
	::ocaml_inline::expr_symbol expr_symbol();
	::ocaml_inline::expr_interpret expr_interpret();
}; }
namespace ocaml_inline { struct _T_expr_any
	: public ExportTree
{
	static const int ID = 419;
	_T_expr_any( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ocaml_inline::whitespace whitespace();
	::ocaml_inline::comment comment();
	::ocaml_inline::string string();
	::ocaml_inline::number number();
	::ocaml_inline::hex_number hex_number();
	::ocaml_inline::ident ident();
	::ocaml_inline::c_any c_any();
}; }
namespace ocaml_inline { struct _T_expr_symbol
	: public ExportTree
{
	static const int ID = 420;
	_T_expr_symbol( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ocaml_inline { struct _T_expr_interpret
	: public ExportTree
{
	static const int ID = 421;
	_T_expr_interpret( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ocaml_inline::state_ref state_ref();
}; }
namespace ocaml_inline { struct _T_state_ref
	: public ExportTree
{
	static const int ID = 422;
	_T_state_ref( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ocaml_inline::opt_name_sep opt_name_sep();
	::ocaml_inline::state_ref_names state_ref_names();
}; }
namespace ocaml_inline { struct _T_opt_name_sep
	: public ExportTree
{
	static const int ID = 423;
	_T_opt_name_sep( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ocaml_inline { struct _T_state_ref_names
	: public ExportTree
{
	static const int ID = 424;
	_T_state_ref_names( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ocaml_inline::state_ref_names _state_ref_names();
	::srlex::word word();
}; }
namespace ocaml_inline { struct _T_inline_block
	: public ExportTree
{
	static const int ID = 425;
	_T_inline_block( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ocaml_inline::_repeat_block_item _repeat_block_item();
}; }
namespace ocaml_inline { struct _T_block_item
	: public ExportTree
{
	static const int ID = 426;
	_T_block_item( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ocaml_inline::expr_any expr_any();
	::ocaml_inline::block_symbol block_symbol();
	::ocaml_inline::block_interpret block_interpret();
	::ocaml_inline::inline_block inline_block();
}; }
namespace ocaml_inline { struct _T_block_symbol
	: public ExportTree
{
	static const int ID = 427;
	_T_block_symbol( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ocaml_inline { struct _T_block_interpret
	: public ExportTree
{
	static const int ID = 428;
	_T_block_interpret( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ocaml_inline::expr_interpret expr_interpret();
	::ocaml_inline::_opt_whitespace _opt_whitespace();
	::ocaml_inline::inline_expr inline_expr();
	::ocaml_inline::state_ref state_ref();
}; }
namespace ocaml_host { struct _T_tok
	: public ExportTree
{
	static const int ID = 429;
	_T_tok( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ocaml_host::ident ident();
	::ocaml_host::number number();
	::ocaml_host::hex_number hex_number();
	::ocaml_host::comment comment();
	::ocaml_host::string string();
	::ocaml_host::whitespace whitespace();
	::ocaml_host::ocaml_any ocaml_any();
}; }
namespace ocaml_host { struct _T_section
	: public ExportTree
{
	static const int ID = 430;
	_T_section( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::ragel_start ragel_start();
	::ocaml_host::tok tok();
}; }
namespace ruby_inline { struct _T_inline_expr
	: public ExportTree
{
	static const int ID = 431;
	_T_inline_expr( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ruby_inline::_repeat_expr_item _repeat_expr_item();
}; }
namespace ruby_inline { struct _T_expr_item
	: public ExportTree
{
	static const int ID = 432;
	_T_expr_item( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ruby_inline::expr_any expr_any();
	::ruby_inline::expr_symbol expr_symbol();
	::ruby_inline::expr_interpret expr_interpret();
}; }
namespace ruby_inline { struct _T_expr_any
	: public ExportTree
{
	static const int ID = 433;
	_T_expr_any( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ruby_inline::whitespace whitespace();
	::ruby_inline::comment comment();
	::ruby_inline::string string();
	::ruby_inline::number number();
	::ruby_inline::hex_number hex_number();
	::ruby_inline::ident ident();
	::ruby_inline::ruby_any ruby_any();
}; }
namespace ruby_inline { struct _T_expr_symbol
	: public ExportTree
{
	static const int ID = 434;
	_T_expr_symbol( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ruby_inline { struct _T_expr_interpret
	: public ExportTree
{
	static const int ID = 435;
	_T_expr_interpret( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ruby_inline::state_ref state_ref();
}; }
namespace ruby_inline { struct _T_state_ref
	: public ExportTree
{
	static const int ID = 436;
	_T_state_ref( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ruby_inline::opt_name_sep opt_name_sep();
	::ruby_inline::state_ref_names state_ref_names();
}; }
namespace ruby_inline { struct _T_opt_name_sep
	: public ExportTree
{
	static const int ID = 437;
	_T_opt_name_sep( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ruby_inline { struct _T_state_ref_names
	: public ExportTree
{
	static const int ID = 438;
	_T_state_ref_names( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ruby_inline::state_ref_names _state_ref_names();
	::srlex::word word();
}; }
namespace ruby_inline { struct _T_inline_block
	: public ExportTree
{
	static const int ID = 439;
	_T_inline_block( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ruby_inline::_repeat_block_item _repeat_block_item();
}; }
namespace ruby_inline { struct _T_block_item
	: public ExportTree
{
	static const int ID = 440;
	_T_block_item( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ruby_inline::expr_any expr_any();
	::ruby_inline::block_symbol block_symbol();
	::ruby_inline::block_interpret block_interpret();
	::ruby_inline::inline_block inline_block();
}; }
namespace ruby_inline { struct _T_block_symbol
	: public ExportTree
{
	static const int ID = 441;
	_T_block_symbol( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ruby_inline { struct _T_block_interpret
	: public ExportTree
{
	static const int ID = 442;
	_T_block_interpret( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ruby_inline::expr_interpret expr_interpret();
	::ruby_inline::_opt_whitespace _opt_whitespace();
	::ruby_inline::inline_expr inline_expr();
	::ruby_inline::state_ref state_ref();
}; }
namespace ruby_host { struct _T_tok
	: public ExportTree
{
	static const int ID = 443;
	_T_tok( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ruby_host::ident ident();
	::ruby_host::number number();
	::ruby_host::hex_number hex_number();
	::ruby_host::comment comment();
	::ruby_host::string string();
	::ruby_host::whitespace whitespace();
	::ruby_host::ruby_any ruby_any();
}; }
namespace ruby_host { struct _T_section
	: public ExportTree
{
	static const int ID = 444;
	_T_section( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::ragel_start ragel_start();
	::ruby_host::tok tok();
}; }
namespace crack_inline { struct _T_inline_expr
	: public ExportTree
{
	static const int ID = 445;
	_T_inline_expr( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::crack_inline::_repeat_expr_item _repeat_expr_item();
}; }
namespace crack_inline { struct _T_expr_item
	: public ExportTree
{
	static const int ID = 446;
	_T_expr_item( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::crack_inline::expr_any expr_any();
	::crack_inline::expr_symbol expr_symbol();
	::crack_inline::expr_interpret expr_interpret();
}; }
namespace crack_inline { struct _T_expr_any
	: public ExportTree
{
	static const int ID = 447;
	_T_expr_any( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::crack_inline::whitespace whitespace();
	::crack_inline::comment comment();
	::crack_inline::string string();
	::crack_inline::number number();
	::crack_inline::hex_number hex_number();
	::crack_inline::ident ident();
	::crack_inline::c_any c_any();
}; }
namespace crack_inline { struct _T_expr_symbol
	: public ExportTree
{
	static const int ID = 448;
	_T_expr_symbol( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace crack_inline { struct _T_expr_interpret
	: public ExportTree
{
	static const int ID = 449;
	_T_expr_interpret( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::crack_inline::state_ref state_ref();
}; }
namespace crack_inline { struct _T_state_ref
	: public ExportTree
{
	static const int ID = 450;
	_T_state_ref( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::crack_inline::opt_name_sep opt_name_sep();
	::crack_inline::state_ref_names state_ref_names();
}; }
namespace crack_inline { struct _T_opt_name_sep
	: public ExportTree
{
	static const int ID = 451;
	_T_opt_name_sep( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace crack_inline { struct _T_state_ref_names
	: public ExportTree
{
	static const int ID = 452;
	_T_state_ref_names( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::crack_inline::state_ref_names _state_ref_names();
	::srlex::word word();
}; }
namespace crack_inline { struct _T_inline_block
	: public ExportTree
{
	static const int ID = 453;
	_T_inline_block( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::crack_inline::_repeat_block_item _repeat_block_item();
}; }
namespace crack_inline { struct _T_block_item
	: public ExportTree
{
	static const int ID = 454;
	_T_block_item( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::crack_inline::expr_any expr_any();
	::crack_inline::block_symbol block_symbol();
	::crack_inline::block_interpret block_interpret();
	::crack_inline::inline_block inline_block();
}; }
namespace crack_inline { struct _T_block_symbol
	: public ExportTree
{
	static const int ID = 455;
	_T_block_symbol( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace crack_inline { struct _T_block_interpret
	: public ExportTree
{
	static const int ID = 456;
	_T_block_interpret( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::crack_inline::expr_interpret expr_interpret();
	::crack_inline::_opt_whitespace _opt_whitespace();
	::crack_inline::inline_expr inline_expr();
	::crack_inline::state_ref state_ref();
}; }
namespace crack_host { struct _T_tok
	: public ExportTree
{
	static const int ID = 457;
	_T_tok( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::crack_host::ident ident();
	::crack_host::number number();
	::crack_host::hex_number hex_number();
	::crack_host::comment comment();
	::crack_host::string string();
	::crack_host::whitespace whitespace();
	::crack_host::c_any c_any();
}; }
namespace crack_host { struct _T_section
	: public ExportTree
{
	static const int ID = 458;
	_T_section( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
	::ragel::ragel_start ragel_start();
	::crack_host::tok tok();
}; }
struct _T__repeat_import
	: public ExportTree
{
	static const int ID = 459;
	_T__repeat_import( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
};
namespace c_host { struct _T__repeat_section
	: public ExportTree
{
	static const int ID = 460;
	_T__repeat_section( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ruby_host { struct _T__repeat_section
	: public ExportTree
{
	static const int ID = 461;
	_T__repeat_section( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ocaml_host { struct _T__repeat_section
	: public ExportTree
{
	static const int ID = 462;
	_T__repeat_section( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _T__repeat_write_arg
	: public ExportTree
{
	static const int ID = 463;
	_T__repeat_write_arg( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ragel { struct _T__repeat_statement
	: public ExportTree
{
	static const int ID = 464;
	_T__repeat_statement( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace c_inline { struct _T__opt_whitespace
	: public ExportTree
{
	static const int ID = 465;
	_T__opt_whitespace( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ocaml_inline { struct _T__repeat_expr_item
	: public ExportTree
{
	static const int ID = 466;
	_T__repeat_expr_item( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ocaml_inline { struct _T__repeat_block_item
	: public ExportTree
{
	static const int ID = 467;
	_T__repeat_block_item( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ocaml_inline { struct _T__opt_whitespace
	: public ExportTree
{
	static const int ID = 468;
	_T__opt_whitespace( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ruby_inline { struct _T__repeat_expr_item
	: public ExportTree
{
	static const int ID = 469;
	_T__repeat_expr_item( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ruby_inline { struct _T__repeat_block_item
	: public ExportTree
{
	static const int ID = 470;
	_T__repeat_block_item( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace ruby_inline { struct _T__opt_whitespace
	: public ExportTree
{
	static const int ID = 471;
	_T__opt_whitespace( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace crack_inline { struct _T__repeat_expr_item
	: public ExportTree
{
	static const int ID = 472;
	_T__repeat_expr_item( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace crack_inline { struct _T__repeat_block_item
	: public ExportTree
{
	static const int ID = 473;
	_T__repeat_block_item( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace crack_inline { struct _T__opt_whitespace
	: public ExportTree
{
	static const int ID = 474;
	_T__opt_whitespace( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
namespace crack_host { struct _T__repeat_section
	: public ExportTree
{
	static const int ID = 475;
	_T__repeat_section( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
}; }
struct _root
	: public ExportTree
{
	static const int ID = 1256;
	_root( colm_program *prg, colm_tree *tree ) : ExportTree( prg, tree ) {
}
};
::start RagelTree( colm_program *prg );
::str RagelError( colm_program *prg );
::_repeat_import RagelImport( colm_program *prg );

#endif
