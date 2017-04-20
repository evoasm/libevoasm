/* vim: set filetype=c: */
/* AUTOGENERATED FILE, DO NOT EDIT */

/*
 * Copyright (C) 2016 Julian Aron Prenner <jap@polyadic.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


#pragma once

#include "evoasm-util.h"

typedef struct {
  uint64_t addr_size : 1;
  uint64_t disp_set : 1;
  uint64_t force_disp32 : 1;
  uint64_t force_long_vex : 1;
  uint64_t force_rex : 1;
  uint64_t force_sib : 1;
  uint64_t lock : 1;
  uint64_t reg0_high_byte : 1;
  uint64_t reg0_set : 1;
  uint64_t reg1_high_byte : 1;
  uint64_t reg1_set : 1;
  uint64_t reg_base_set : 1;
  uint64_t reg_index_set : 1;
  uint64_t rex_b : 1;
  uint64_t rex_r : 1;
  uint64_t rex_w : 1;
  uint64_t rex_x : 1;
  uint64_t vex_l : 1;
  uint64_t scale : 2;
  uint64_t legacy_prefix_order : 3;
  uint64_t modrm_reg : 3;
  uint64_t vex_v : 4;
  uint64_t reg0 : 6;
  uint64_t reg1 : 6;
  uint64_t reg2 : 6;
  uint64_t reg3 : 6;
  uint64_t reg_base : 6;
  uint64_t reg_index : 6;
  evoasm_packed(union {
    int8_t imm1 : 8;
    int32_t disp : 32;
  });
  evoasm_packed(union {
    int64_t imm0 : 64;
    int64_t moffs : 64;
    int64_t rel : 64;
  });
} evoasm_x64_params_t;

typedef struct {
  uint64_t reg0_high_byte : 1;
  uint64_t reg0_set : 1;
  uint64_t reg1_high_byte : 1;
  uint64_t reg1_set : 1;
  uint64_t reg0 : 6;
  uint64_t reg1 : 6;
  uint64_t reg2 : 6;
  uint64_t reg3 : 6;
  evoasm_packed(union {
    int32_t imm0 : 32;
    int32_t rel : 32;
  });
} evoasm_x64_basic_params_t;

static inline void evoasm_x64_params_set_(evoasm_x64_params_t * params, evoasm_x64_param_id_t param, int64_t param_val) {
  switch(param) {
    case EVOASM_X64_PARAM_REG0:
      params->reg0 = (uint64_t) (((uint64_t) param_val) & 0x3f);
      params->reg0_set = true;
      break;
    case EVOASM_X64_PARAM_REG1:
      params->reg1 = (uint64_t) (((uint64_t) param_val) & 0x3f);
      params->reg1_set = true;
      break;
    case EVOASM_X64_PARAM_REG2:
      params->reg2 = (uint64_t) (((uint64_t) param_val) & 0x3f);
      break;
    case EVOASM_X64_PARAM_REG3:
      params->reg3 = (uint64_t) (((uint64_t) param_val) & 0x3f);
      break;
    case EVOASM_X64_PARAM_IMM0:
      params->imm0 = (int64_t) (((uint64_t) param_val) & 0xffffffffffffffff);
      break;
    case EVOASM_X64_PARAM_FORCE_REX:
      params->force_rex = (uint64_t) (((uint64_t) param_val) & 0x1);
      break;
    case EVOASM_X64_PARAM_REX_R:
      params->rex_r = (uint64_t) (((uint64_t) param_val) & 0x1);
      break;
    case EVOASM_X64_PARAM_REX_X:
      params->rex_x = (uint64_t) (((uint64_t) param_val) & 0x1);
      break;
    case EVOASM_X64_PARAM_REX_B:
      params->rex_b = (uint64_t) (((uint64_t) param_val) & 0x1);
      break;
    case EVOASM_X64_PARAM_LEGACY_PREFIX_ORDER:
      params->legacy_prefix_order = (uint64_t) (((uint64_t) param_val) & 0x7);
      break;
    case EVOASM_X64_PARAM_LOCK:
      params->lock = (uint64_t) (((uint64_t) param_val) & 0x1);
      break;
    case EVOASM_X64_PARAM_ADDR_SIZE:
      params->addr_size = (uint64_t) (((uint64_t) param_val) & 0x1);
      break;
    case EVOASM_X64_PARAM_REG_BASE:
      params->reg_base = (uint64_t) (((uint64_t) param_val) & 0x3f);
      params->reg_base_set = true;
      break;
    case EVOASM_X64_PARAM_REG_INDEX:
      params->reg_index = (uint64_t) (((uint64_t) param_val) & 0x3f);
      params->reg_index_set = true;
      break;
    case EVOASM_X64_PARAM_REX_W:
      params->rex_w = (uint64_t) (((uint64_t) param_val) & 0x1);
      break;
    case EVOASM_X64_PARAM_DISP:
      params->disp = (int32_t) (((uint64_t) param_val) & 0xffffffff);
      params->disp_set = true;
      break;
    case EVOASM_X64_PARAM_SCALE:
      params->scale = (uint64_t) (((uint64_t) param_val) & 0x3);
      break;
    case EVOASM_X64_PARAM_FORCE_SIB:
      params->force_sib = (uint64_t) (((uint64_t) param_val) & 0x1);
      break;
    case EVOASM_X64_PARAM_FORCE_DISP32:
      params->force_disp32 = (uint64_t) (((uint64_t) param_val) & 0x1);
      break;
    case EVOASM_X64_PARAM_REG0_HIGH_BYTE:
      params->reg0_high_byte = (uint64_t) (((uint64_t) param_val) & 0x1);
      break;
    case EVOASM_X64_PARAM_REG1_HIGH_BYTE:
      params->reg1_high_byte = (uint64_t) (((uint64_t) param_val) & 0x1);
      break;
    case EVOASM_X64_PARAM_FORCE_LONG_VEX:
      params->force_long_vex = (uint64_t) (((uint64_t) param_val) & 0x1);
      break;
    case EVOASM_X64_PARAM_REL:
      params->rel = (int64_t) (((uint64_t) param_val) & 0xffffffffffffffff);
      break;
    case EVOASM_X64_PARAM_IMM1:
      params->imm1 = (int8_t) (((uint64_t) param_val) & 0xff);
      break;
    case EVOASM_X64_PARAM_MOFFS:
      params->moffs = (int64_t) (((uint64_t) param_val) & 0xffffffffffffffff);
      break;
    case EVOASM_X64_PARAM_VEX_L:
      params->vex_l = (uint64_t) (((uint64_t) param_val) & 0x1);
      break;
    case EVOASM_X64_PARAM_MODRM_REG:
      params->modrm_reg = (uint64_t) (((uint64_t) param_val) & 0x7);
      break;
    case EVOASM_X64_PARAM_VEX_V:
      params->vex_v = (uint64_t) (((uint64_t) param_val) & 0xf);
      break;
    default:
      evoasm_assert_not_reached();
  }
}

static inline void evoasm_x64_basic_params_set_(evoasm_x64_basic_params_t * params, evoasm_x64_basic_param_id_t param, int64_t param_val) {
  switch(param) {
    case EVOASM_X64_BASIC_PARAM_REG0:
      params->reg0 = (uint64_t) (((uint64_t) param_val) & 0x3f);
      params->reg0_set = true;
      break;
    case EVOASM_X64_BASIC_PARAM_REG1:
      params->reg1 = (uint64_t) (((uint64_t) param_val) & 0x3f);
      params->reg1_set = true;
      break;
    case EVOASM_X64_BASIC_PARAM_REG2:
      params->reg2 = (uint64_t) (((uint64_t) param_val) & 0x3f);
      break;
    case EVOASM_X64_BASIC_PARAM_REG3:
      params->reg3 = (uint64_t) (((uint64_t) param_val) & 0x3f);
      break;
    case EVOASM_X64_BASIC_PARAM_IMM0:
      params->imm0 = (int32_t) (((uint64_t) param_val) & 0xffffffff);
      break;
    case EVOASM_X64_BASIC_PARAM_REG0_HIGH_BYTE:
      params->reg0_high_byte = (uint64_t) (((uint64_t) param_val) & 0x1);
      break;
    case EVOASM_X64_BASIC_PARAM_REG1_HIGH_BYTE:
      params->reg1_high_byte = (uint64_t) (((uint64_t) param_val) & 0x1);
      break;
    case EVOASM_X64_BASIC_PARAM_REL:
      params->rel = (int32_t) (((uint64_t) param_val) & 0xffffffff);
      break;
    default:
      evoasm_assert_not_reached();
  }
}
static inline int64_t evoasm_x64_params_get_(evoasm_x64_params_t * params, evoasm_x64_param_id_t param) {
  switch(param) {
    case EVOASM_X64_PARAM_REG0:
      return (int64_t) params->reg0;
    case EVOASM_X64_PARAM_REG1:
      return (int64_t) params->reg1;
    case EVOASM_X64_PARAM_REG2:
      return (int64_t) params->reg2;
    case EVOASM_X64_PARAM_REG3:
      return (int64_t) params->reg3;
    case EVOASM_X64_PARAM_IMM0:
      return (int64_t) params->imm0;
    case EVOASM_X64_PARAM_FORCE_REX:
      return (int64_t) params->force_rex;
    case EVOASM_X64_PARAM_REX_R:
      return (int64_t) params->rex_r;
    case EVOASM_X64_PARAM_REX_X:
      return (int64_t) params->rex_x;
    case EVOASM_X64_PARAM_REX_B:
      return (int64_t) params->rex_b;
    case EVOASM_X64_PARAM_LEGACY_PREFIX_ORDER:
      return (int64_t) params->legacy_prefix_order;
    case EVOASM_X64_PARAM_LOCK:
      return (int64_t) params->lock;
    case EVOASM_X64_PARAM_ADDR_SIZE:
      return (int64_t) params->addr_size;
    case EVOASM_X64_PARAM_REG_BASE:
      return (int64_t) params->reg_base;
    case EVOASM_X64_PARAM_REG_INDEX:
      return (int64_t) params->reg_index;
    case EVOASM_X64_PARAM_REX_W:
      return (int64_t) params->rex_w;
    case EVOASM_X64_PARAM_DISP:
      return (int64_t) params->disp;
    case EVOASM_X64_PARAM_SCALE:
      return (int64_t) params->scale;
    case EVOASM_X64_PARAM_FORCE_SIB:
      return (int64_t) params->force_sib;
    case EVOASM_X64_PARAM_FORCE_DISP32:
      return (int64_t) params->force_disp32;
    case EVOASM_X64_PARAM_REG0_HIGH_BYTE:
      return (int64_t) params->reg0_high_byte;
    case EVOASM_X64_PARAM_REG1_HIGH_BYTE:
      return (int64_t) params->reg1_high_byte;
    case EVOASM_X64_PARAM_FORCE_LONG_VEX:
      return (int64_t) params->force_long_vex;
    case EVOASM_X64_PARAM_REL:
      return (int64_t) params->rel;
    case EVOASM_X64_PARAM_IMM1:
      return (int64_t) params->imm1;
    case EVOASM_X64_PARAM_MOFFS:
      return (int64_t) params->moffs;
    case EVOASM_X64_PARAM_VEX_L:
      return (int64_t) params->vex_l;
    case EVOASM_X64_PARAM_MODRM_REG:
      return (int64_t) params->modrm_reg;
    case EVOASM_X64_PARAM_VEX_V:
      return (int64_t) params->vex_v;
    default:
      evoasm_assert_not_reached();
  }
}

static inline int64_t evoasm_x64_basic_params_get_(evoasm_x64_basic_params_t * params, evoasm_x64_basic_param_id_t param) {
  switch(param) {
    case EVOASM_X64_BASIC_PARAM_REG0:
      return (int64_t) params->reg0;
    case EVOASM_X64_BASIC_PARAM_REG1:
      return (int64_t) params->reg1;
    case EVOASM_X64_BASIC_PARAM_REG2:
      return (int64_t) params->reg2;
    case EVOASM_X64_BASIC_PARAM_REG3:
      return (int64_t) params->reg3;
    case EVOASM_X64_BASIC_PARAM_IMM0:
      return (int64_t) params->imm0;
    case EVOASM_X64_BASIC_PARAM_REG0_HIGH_BYTE:
      return (int64_t) params->reg0_high_byte;
    case EVOASM_X64_BASIC_PARAM_REG1_HIGH_BYTE:
      return (int64_t) params->reg1_high_byte;
    case EVOASM_X64_BASIC_PARAM_REL:
      return (int64_t) params->rel;
    default:
      evoasm_assert_not_reached();
  }
}
static inline void evoasm_x64_params_unset_(evoasm_x64_params_t * params, evoasm_x64_param_id_t param) {
  switch(param) {
    case EVOASM_X64_PARAM_REG0:
      params->reg0 = 0;
      params->reg0_set = false;
      break;
    case EVOASM_X64_PARAM_REG1:
      params->reg1 = 0;
      params->reg1_set = false;
      break;
    case EVOASM_X64_PARAM_REG2:
      params->reg2 = 0;
      break;
    case EVOASM_X64_PARAM_REG3:
      params->reg3 = 0;
      break;
    case EVOASM_X64_PARAM_IMM0:
      params->imm0 = 0;
      break;
    case EVOASM_X64_PARAM_FORCE_REX:
      params->force_rex = 0;
      break;
    case EVOASM_X64_PARAM_REX_R:
      params->rex_r = 0;
      break;
    case EVOASM_X64_PARAM_REX_X:
      params->rex_x = 0;
      break;
    case EVOASM_X64_PARAM_REX_B:
      params->rex_b = 0;
      break;
    case EVOASM_X64_PARAM_LEGACY_PREFIX_ORDER:
      params->legacy_prefix_order = 0;
      break;
    case EVOASM_X64_PARAM_LOCK:
      params->lock = 0;
      break;
    case EVOASM_X64_PARAM_ADDR_SIZE:
      params->addr_size = 0;
      break;
    case EVOASM_X64_PARAM_REG_BASE:
      params->reg_base = 0;
      params->reg_base_set = false;
      break;
    case EVOASM_X64_PARAM_REG_INDEX:
      params->reg_index = 0;
      params->reg_index_set = false;
      break;
    case EVOASM_X64_PARAM_REX_W:
      params->rex_w = 0;
      break;
    case EVOASM_X64_PARAM_DISP:
      params->disp = 0;
      params->disp_set = false;
      break;
    case EVOASM_X64_PARAM_SCALE:
      params->scale = 0;
      break;
    case EVOASM_X64_PARAM_FORCE_SIB:
      params->force_sib = 0;
      break;
    case EVOASM_X64_PARAM_FORCE_DISP32:
      params->force_disp32 = 0;
      break;
    case EVOASM_X64_PARAM_REG0_HIGH_BYTE:
      params->reg0_high_byte = 0;
      break;
    case EVOASM_X64_PARAM_REG1_HIGH_BYTE:
      params->reg1_high_byte = 0;
      break;
    case EVOASM_X64_PARAM_FORCE_LONG_VEX:
      params->force_long_vex = 0;
      break;
    case EVOASM_X64_PARAM_REL:
      params->rel = 0;
      break;
    case EVOASM_X64_PARAM_IMM1:
      params->imm1 = 0;
      break;
    case EVOASM_X64_PARAM_MOFFS:
      params->moffs = 0;
      break;
    case EVOASM_X64_PARAM_VEX_L:
      params->vex_l = 0;
      break;
    case EVOASM_X64_PARAM_MODRM_REG:
      params->modrm_reg = 0;
      break;
    case EVOASM_X64_PARAM_VEX_V:
      params->vex_v = 0;
      break;
    default:
      evoasm_assert_not_reached();
  }
}

static inline void evoasm_x64_basic_params_unset_(evoasm_x64_basic_params_t * params, evoasm_x64_basic_param_id_t param) {
  switch(param) {
    case EVOASM_X64_BASIC_PARAM_REG0:
      params->reg0 = 0;
      params->reg0_set = false;
      break;
    case EVOASM_X64_BASIC_PARAM_REG1:
      params->reg1 = 0;
      params->reg1_set = false;
      break;
    case EVOASM_X64_BASIC_PARAM_REG2:
      params->reg2 = 0;
      break;
    case EVOASM_X64_BASIC_PARAM_REG3:
      params->reg3 = 0;
      break;
    case EVOASM_X64_BASIC_PARAM_IMM0:
      params->imm0 = 0;
      break;
    case EVOASM_X64_BASIC_PARAM_REG0_HIGH_BYTE:
      params->reg0_high_byte = 0;
      break;
    case EVOASM_X64_BASIC_PARAM_REG1_HIGH_BYTE:
      params->reg1_high_byte = 0;
      break;
    case EVOASM_X64_BASIC_PARAM_REL:
      params->rel = 0;
      break;
    default:
      evoasm_assert_not_reached();
  }
}
static inline evoasm_x64_param_type_t evoasm_x64_param_get_type_(evoasm_x64_param_id_t param) {
  switch(param) {
    case EVOASM_X64_PARAM_REG0:
      return EVOASM_X64_PARAM_TYPE_REG;
    case EVOASM_X64_PARAM_REG1:
      return EVOASM_X64_PARAM_TYPE_REG;
    case EVOASM_X64_PARAM_REG2:
      return EVOASM_X64_PARAM_TYPE_REG;
    case EVOASM_X64_PARAM_REG3:
      return EVOASM_X64_PARAM_TYPE_REG;
    case EVOASM_X64_PARAM_IMM0:
      return EVOASM_X64_PARAM_TYPE_INT64;
    case EVOASM_X64_PARAM_FORCE_REX:
      return EVOASM_X64_PARAM_TYPE_BOOL;
    case EVOASM_X64_PARAM_REX_R:
      return EVOASM_X64_PARAM_TYPE_UINT1;
    case EVOASM_X64_PARAM_REX_X:
      return EVOASM_X64_PARAM_TYPE_UINT1;
    case EVOASM_X64_PARAM_REX_B:
      return EVOASM_X64_PARAM_TYPE_UINT1;
    case EVOASM_X64_PARAM_LEGACY_PREFIX_ORDER:
      return EVOASM_X64_PARAM_TYPE_INT3;
    case EVOASM_X64_PARAM_LOCK:
      return EVOASM_X64_PARAM_TYPE_BOOL;
    case EVOASM_X64_PARAM_ADDR_SIZE:
      return EVOASM_X64_PARAM_TYPE_ADDR_SIZE;
    case EVOASM_X64_PARAM_REG_BASE:
      return EVOASM_X64_PARAM_TYPE_REG;
    case EVOASM_X64_PARAM_REG_INDEX:
      return EVOASM_X64_PARAM_TYPE_REG;
    case EVOASM_X64_PARAM_REX_W:
      return EVOASM_X64_PARAM_TYPE_UINT1;
    case EVOASM_X64_PARAM_DISP:
      return EVOASM_X64_PARAM_TYPE_INT32;
    case EVOASM_X64_PARAM_SCALE:
      return EVOASM_X64_PARAM_TYPE_SCALE;
    case EVOASM_X64_PARAM_FORCE_SIB:
      return EVOASM_X64_PARAM_TYPE_BOOL;
    case EVOASM_X64_PARAM_FORCE_DISP32:
      return EVOASM_X64_PARAM_TYPE_BOOL;
    case EVOASM_X64_PARAM_REG0_HIGH_BYTE:
      return EVOASM_X64_PARAM_TYPE_BOOL;
    case EVOASM_X64_PARAM_REG1_HIGH_BYTE:
      return EVOASM_X64_PARAM_TYPE_BOOL;
    case EVOASM_X64_PARAM_FORCE_LONG_VEX:
      return EVOASM_X64_PARAM_TYPE_BOOL;
    case EVOASM_X64_PARAM_REL:
      return EVOASM_X64_PARAM_TYPE_INT64;
    case EVOASM_X64_PARAM_IMM1:
      return EVOASM_X64_PARAM_TYPE_INT8;
    case EVOASM_X64_PARAM_MOFFS:
      return EVOASM_X64_PARAM_TYPE_INT64;
    case EVOASM_X64_PARAM_VEX_L:
      return EVOASM_X64_PARAM_TYPE_UINT1;
    case EVOASM_X64_PARAM_MODRM_REG:
      return EVOASM_X64_PARAM_TYPE_INT3;
    case EVOASM_X64_PARAM_VEX_V:
      return EVOASM_X64_PARAM_TYPE_INT4;
    default:
      evoasm_assert_not_reached();
  }
}

static inline evoasm_x64_param_type_t evoasm_x64_basic_param_get_type_(evoasm_x64_basic_param_id_t param) {
  switch(param) {
    case EVOASM_X64_BASIC_PARAM_REG0:
      return EVOASM_X64_PARAM_TYPE_REG;
    case EVOASM_X64_BASIC_PARAM_REG1:
      return EVOASM_X64_PARAM_TYPE_REG;
    case EVOASM_X64_BASIC_PARAM_REG2:
      return EVOASM_X64_PARAM_TYPE_REG;
    case EVOASM_X64_BASIC_PARAM_REG3:
      return EVOASM_X64_PARAM_TYPE_REG;
    case EVOASM_X64_BASIC_PARAM_IMM0:
      return EVOASM_X64_PARAM_TYPE_INT32;
    case EVOASM_X64_BASIC_PARAM_REG0_HIGH_BYTE:
      return EVOASM_X64_PARAM_TYPE_BOOL;
    case EVOASM_X64_BASIC_PARAM_REG1_HIGH_BYTE:
      return EVOASM_X64_PARAM_TYPE_BOOL;
    case EVOASM_X64_BASIC_PARAM_REL:
      return EVOASM_X64_PARAM_TYPE_INT32;
    default:
      evoasm_assert_not_reached();
  }
}
static inline const char * evoasm_x64_param_get_name_(evoasm_x64_param_id_t param) {
  switch(param) {
    case EVOASM_X64_PARAM_REG0:
      return "reg0";
    case EVOASM_X64_PARAM_REG1:
      return "reg1";
    case EVOASM_X64_PARAM_REG2:
      return "reg2";
    case EVOASM_X64_PARAM_REG3:
      return "reg3";
    case EVOASM_X64_PARAM_IMM0:
      return "imm0";
    case EVOASM_X64_PARAM_FORCE_REX:
      return "force_rex?";
    case EVOASM_X64_PARAM_REX_R:
      return "rex_r";
    case EVOASM_X64_PARAM_REX_X:
      return "rex_x";
    case EVOASM_X64_PARAM_REX_B:
      return "rex_b";
    case EVOASM_X64_PARAM_LEGACY_PREFIX_ORDER:
      return "legacy_prefix_order";
    case EVOASM_X64_PARAM_LOCK:
      return "lock?";
    case EVOASM_X64_PARAM_ADDR_SIZE:
      return "addr_size";
    case EVOASM_X64_PARAM_REG_BASE:
      return "reg_base";
    case EVOASM_X64_PARAM_REG_INDEX:
      return "reg_index";
    case EVOASM_X64_PARAM_REX_W:
      return "rex_w";
    case EVOASM_X64_PARAM_DISP:
      return "disp";
    case EVOASM_X64_PARAM_SCALE:
      return "scale";
    case EVOASM_X64_PARAM_FORCE_SIB:
      return "force_sib?";
    case EVOASM_X64_PARAM_FORCE_DISP32:
      return "force_disp32?";
    case EVOASM_X64_PARAM_REG0_HIGH_BYTE:
      return "reg0_high_byte?";
    case EVOASM_X64_PARAM_REG1_HIGH_BYTE:
      return "reg1_high_byte?";
    case EVOASM_X64_PARAM_FORCE_LONG_VEX:
      return "force_long_vex?";
    case EVOASM_X64_PARAM_REL:
      return "rel";
    case EVOASM_X64_PARAM_IMM1:
      return "imm1";
    case EVOASM_X64_PARAM_MOFFS:
      return "moffs";
    case EVOASM_X64_PARAM_VEX_L:
      return "vex_l";
    case EVOASM_X64_PARAM_MODRM_REG:
      return "modrm_reg";
    case EVOASM_X64_PARAM_VEX_V:
      return "vex_v";
    default:
      evoasm_assert_not_reached();
  }
}

static inline const char * evoasm_x64_basic_param_get_name_(evoasm_x64_basic_param_id_t param) {
  switch(param) {
    case EVOASM_X64_BASIC_PARAM_REG0:
      return "reg0";
    case EVOASM_X64_BASIC_PARAM_REG1:
      return "reg1";
    case EVOASM_X64_BASIC_PARAM_REG2:
      return "reg2";
    case EVOASM_X64_BASIC_PARAM_REG3:
      return "reg3";
    case EVOASM_X64_BASIC_PARAM_IMM0:
      return "imm0";
    case EVOASM_X64_BASIC_PARAM_REG0_HIGH_BYTE:
      return "reg0_high_byte?";
    case EVOASM_X64_BASIC_PARAM_REG1_HIGH_BYTE:
      return "reg1_high_byte?";
    case EVOASM_X64_BASIC_PARAM_REL:
      return "rel";
    default:
      evoasm_assert_not_reached();
  }
}

static inline evoasm_x64_basic_param_id_t evoasm_x64_param_to_basic_(evoasm_x64_param_id_t param) {
  switch(param) {
    case EVOASM_X64_PARAM_REG0:
      return EVOASM_X64_BASIC_PARAM_REG0;
    case EVOASM_X64_PARAM_REG1:
      return EVOASM_X64_BASIC_PARAM_REG1;
    case EVOASM_X64_PARAM_REG2:
      return EVOASM_X64_BASIC_PARAM_REG2;
    case EVOASM_X64_PARAM_REG3:
      return EVOASM_X64_BASIC_PARAM_REG3;
    case EVOASM_X64_PARAM_IMM0:
      return EVOASM_X64_BASIC_PARAM_IMM0;
    case EVOASM_X64_PARAM_FORCE_REX:
      return EVOASM_X64_BASIC_PARAM_NONE;
    case EVOASM_X64_PARAM_REX_R:
      return EVOASM_X64_BASIC_PARAM_NONE;
    case EVOASM_X64_PARAM_REX_X:
      return EVOASM_X64_BASIC_PARAM_NONE;
    case EVOASM_X64_PARAM_REX_B:
      return EVOASM_X64_BASIC_PARAM_NONE;
    case EVOASM_X64_PARAM_LEGACY_PREFIX_ORDER:
      return EVOASM_X64_BASIC_PARAM_NONE;
    case EVOASM_X64_PARAM_LOCK:
      return EVOASM_X64_BASIC_PARAM_NONE;
    case EVOASM_X64_PARAM_ADDR_SIZE:
      return EVOASM_X64_BASIC_PARAM_NONE;
    case EVOASM_X64_PARAM_REG_BASE:
      return EVOASM_X64_BASIC_PARAM_NONE;
    case EVOASM_X64_PARAM_REG_INDEX:
      return EVOASM_X64_BASIC_PARAM_NONE;
    case EVOASM_X64_PARAM_REX_W:
      return EVOASM_X64_BASIC_PARAM_NONE;
    case EVOASM_X64_PARAM_DISP:
      return EVOASM_X64_BASIC_PARAM_NONE;
    case EVOASM_X64_PARAM_SCALE:
      return EVOASM_X64_BASIC_PARAM_NONE;
    case EVOASM_X64_PARAM_FORCE_SIB:
      return EVOASM_X64_BASIC_PARAM_NONE;
    case EVOASM_X64_PARAM_FORCE_DISP32:
      return EVOASM_X64_BASIC_PARAM_NONE;
    case EVOASM_X64_PARAM_REG0_HIGH_BYTE:
      return EVOASM_X64_BASIC_PARAM_REG0_HIGH_BYTE;
    case EVOASM_X64_PARAM_REG1_HIGH_BYTE:
      return EVOASM_X64_BASIC_PARAM_REG1_HIGH_BYTE;
    case EVOASM_X64_PARAM_FORCE_LONG_VEX:
      return EVOASM_X64_BASIC_PARAM_NONE;
    case EVOASM_X64_PARAM_REL:
      return EVOASM_X64_BASIC_PARAM_REL;
    case EVOASM_X64_PARAM_IMM1:
      return EVOASM_X64_BASIC_PARAM_NONE;
    case EVOASM_X64_PARAM_MOFFS:
      return EVOASM_X64_BASIC_PARAM_NONE;
    case EVOASM_X64_PARAM_VEX_L:
      return EVOASM_X64_BASIC_PARAM_NONE;
    case EVOASM_X64_PARAM_MODRM_REG:
      return EVOASM_X64_BASIC_PARAM_NONE;
    case EVOASM_X64_PARAM_VEX_V:
      return EVOASM_X64_BASIC_PARAM_NONE;
    default:
      evoasm_assert_not_reached();
  }
}


_Static_assert(sizeof(evoasm_x64_basic_params_t) <= sizeof(uint64_t), "basic parameters should bit into 64 bits");