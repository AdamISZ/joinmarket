#define _CFFI_
#include <Python.h>
#ifdef __cplusplus
extern "C" {
#endif
#include <stddef.h>

/* See doc/misc/parse_c_type.rst in the source of CFFI for more information */

typedef void *_cffi_opcode_t;

#define _CFFI_OP(opcode, arg)   (_cffi_opcode_t)(opcode | (((uintptr_t)(arg)) << 8))
#define _CFFI_GETOP(cffi_opcode)    ((unsigned char)(uintptr_t)cffi_opcode)
#define _CFFI_GETARG(cffi_opcode)   (((uintptr_t)cffi_opcode) >> 8)

#define _CFFI_OP_PRIMITIVE       1
#define _CFFI_OP_POINTER         3
#define _CFFI_OP_ARRAY           5
#define _CFFI_OP_OPEN_ARRAY      7
#define _CFFI_OP_STRUCT_UNION    9
#define _CFFI_OP_ENUM           11
#define _CFFI_OP_FUNCTION       13
#define _CFFI_OP_FUNCTION_END   15
#define _CFFI_OP_NOOP           17
#define _CFFI_OP_BITFIELD       19
#define _CFFI_OP_TYPENAME       21
#define _CFFI_OP_CPYTHON_BLTN_V 23   // varargs
#define _CFFI_OP_CPYTHON_BLTN_N 25   // noargs
#define _CFFI_OP_CPYTHON_BLTN_O 27   // O  (i.e. a single arg)
#define _CFFI_OP_CONSTANT       29
#define _CFFI_OP_CONSTANT_INT   31
#define _CFFI_OP_GLOBAL_VAR     33
#define _CFFI_OP_DLOPEN_FUNC    35
#define _CFFI_OP_DLOPEN_CONST   37
#define _CFFI_OP_GLOBAL_VAR_F   39

#define _CFFI_PRIM_VOID          0
#define _CFFI_PRIM_BOOL          1
#define _CFFI_PRIM_CHAR          2
#define _CFFI_PRIM_SCHAR         3
#define _CFFI_PRIM_UCHAR         4
#define _CFFI_PRIM_SHORT         5
#define _CFFI_PRIM_USHORT        6
#define _CFFI_PRIM_INT           7
#define _CFFI_PRIM_UINT          8
#define _CFFI_PRIM_LONG          9
#define _CFFI_PRIM_ULONG        10
#define _CFFI_PRIM_LONGLONG     11
#define _CFFI_PRIM_ULONGLONG    12
#define _CFFI_PRIM_FLOAT        13
#define _CFFI_PRIM_DOUBLE       14
#define _CFFI_PRIM_LONGDOUBLE   15

#define _CFFI_PRIM_WCHAR        16
#define _CFFI_PRIM_INT8         17
#define _CFFI_PRIM_UINT8        18
#define _CFFI_PRIM_INT16        19
#define _CFFI_PRIM_UINT16       20
#define _CFFI_PRIM_INT32        21
#define _CFFI_PRIM_UINT32       22
#define _CFFI_PRIM_INT64        23
#define _CFFI_PRIM_UINT64       24
#define _CFFI_PRIM_INTPTR       25
#define _CFFI_PRIM_UINTPTR      26
#define _CFFI_PRIM_PTRDIFF      27
#define _CFFI_PRIM_SIZE         28
#define _CFFI_PRIM_SSIZE        29
#define _CFFI_PRIM_INT_LEAST8   30
#define _CFFI_PRIM_UINT_LEAST8  31
#define _CFFI_PRIM_INT_LEAST16  32
#define _CFFI_PRIM_UINT_LEAST16 33
#define _CFFI_PRIM_INT_LEAST32  34
#define _CFFI_PRIM_UINT_LEAST32 35
#define _CFFI_PRIM_INT_LEAST64  36
#define _CFFI_PRIM_UINT_LEAST64 37
#define _CFFI_PRIM_INT_FAST8    38
#define _CFFI_PRIM_UINT_FAST8   39
#define _CFFI_PRIM_INT_FAST16   40
#define _CFFI_PRIM_UINT_FAST16  41
#define _CFFI_PRIM_INT_FAST32   42
#define _CFFI_PRIM_UINT_FAST32  43
#define _CFFI_PRIM_INT_FAST64   44
#define _CFFI_PRIM_UINT_FAST64  45
#define _CFFI_PRIM_INTMAX       46
#define _CFFI_PRIM_UINTMAX      47

#define _CFFI__NUM_PRIM         48
#define _CFFI__UNKNOWN_PRIM    (-1)


struct _cffi_global_s {
    const char *name;
    void *address;
    _cffi_opcode_t type_op;
    void *size_or_direct_fn;  // OP_GLOBAL_VAR: size, or 0 if unknown
                              // OP_CPYTHON_BLTN_*: addr of direct function
};

struct _cffi_getconst_s {
    unsigned long long value;
    const struct _cffi_type_context_s *ctx;
    int gindex;
};

struct _cffi_struct_union_s {
    const char *name;
    int type_index;          // -> _cffi_types, on a OP_STRUCT_UNION
    int flags;               // _CFFI_F_* flags below
    size_t size;
    int alignment;
    int first_field_index;   // -> _cffi_fields array
    int num_fields;
};
#define _CFFI_F_UNION         0x01   // is a union, not a struct
#define _CFFI_F_CHECK_FIELDS  0x02   // complain if fields are not in the
                                     // "standard layout" or if some are missing
#define _CFFI_F_PACKED        0x04   // for CHECK_FIELDS, assume a packed struct
#define _CFFI_F_EXTERNAL      0x08   // in some other ffi.include()
#define _CFFI_F_OPAQUE        0x10   // opaque

struct _cffi_field_s {
    const char *name;
    size_t field_offset;
    size_t field_size;
    _cffi_opcode_t field_type_op;
};

struct _cffi_enum_s {
    const char *name;
    int type_index;          // -> _cffi_types, on a OP_ENUM
    int type_prim;           // _CFFI_PRIM_xxx
    const char *enumerators; // comma-delimited string
};

struct _cffi_typename_s {
    const char *name;
    int type_index;   /* if opaque, points to a possibly artificial
                         OP_STRUCT which is itself opaque */
};

struct _cffi_type_context_s {
    _cffi_opcode_t *types;
    const struct _cffi_global_s *globals;
    const struct _cffi_field_s *fields;
    const struct _cffi_struct_union_s *struct_unions;
    const struct _cffi_enum_s *enums;
    const struct _cffi_typename_s *typenames;
    int num_globals;
    int num_struct_unions;
    int num_enums;
    int num_typenames;
    const char *const *includes;
    int num_types;
    int flags;      /* future extension */
};

struct _cffi_parse_info_s {
    const struct _cffi_type_context_s *ctx;
    _cffi_opcode_t *output;
    unsigned int output_size;
    size_t error_location;
    const char *error_message;
};

#ifdef _CFFI_INTERNAL
static int parse_c_type(struct _cffi_parse_info_s *info, const char *input);
static int search_in_globals(const struct _cffi_type_context_s *ctx,
                             const char *search, size_t search_len);
static int search_in_struct_unions(const struct _cffi_type_context_s *ctx,
                                   const char *search, size_t search_len);
#endif

/* this block of #ifs should be kept exactly identical between
   c/_cffi_backend.c, cffi/vengine_cpy.py, cffi/vengine_gen.py
   and cffi/_cffi_include.h */
#if defined(_MSC_VER)
# include <malloc.h>   /* for alloca() */
# if _MSC_VER < 1600   /* MSVC < 2010 */
   typedef __int8 int8_t;
   typedef __int16 int16_t;
   typedef __int32 int32_t;
   typedef __int64 int64_t;
   typedef unsigned __int8 uint8_t;
   typedef unsigned __int16 uint16_t;
   typedef unsigned __int32 uint32_t;
   typedef unsigned __int64 uint64_t;
   typedef __int8 int_least8_t;
   typedef __int16 int_least16_t;
   typedef __int32 int_least32_t;
   typedef __int64 int_least64_t;
   typedef unsigned __int8 uint_least8_t;
   typedef unsigned __int16 uint_least16_t;
   typedef unsigned __int32 uint_least32_t;
   typedef unsigned __int64 uint_least64_t;
   typedef __int8 int_fast8_t;
   typedef __int16 int_fast16_t;
   typedef __int32 int_fast32_t;
   typedef __int64 int_fast64_t;
   typedef unsigned __int8 uint_fast8_t;
   typedef unsigned __int16 uint_fast16_t;
   typedef unsigned __int32 uint_fast32_t;
   typedef unsigned __int64 uint_fast64_t;
   typedef __int64 intmax_t;
   typedef unsigned __int64 uintmax_t;
# else
#  include <stdint.h>
# endif
# if _MSC_VER < 1800   /* MSVC < 2013 */
   typedef unsigned char _Bool;
# endif
#else
# include <stdint.h>
# if (defined (__SVR4) && defined (__sun)) || defined(_AIX) || defined(__hpux)
#  include <alloca.h>
# endif
#endif

#ifdef __GNUC__
# define _CFFI_UNUSED_FN  __attribute__((unused))
#else
# define _CFFI_UNUSED_FN  /* nothing */
#endif

/**********  CPython-specific section  **********/
#ifndef PYPY_VERSION


#if PY_MAJOR_VERSION >= 3
# define PyInt_FromLong PyLong_FromLong
#endif

#define _cffi_from_c_double PyFloat_FromDouble
#define _cffi_from_c_float PyFloat_FromDouble
#define _cffi_from_c_long PyInt_FromLong
#define _cffi_from_c_ulong PyLong_FromUnsignedLong
#define _cffi_from_c_longlong PyLong_FromLongLong
#define _cffi_from_c_ulonglong PyLong_FromUnsignedLongLong

#define _cffi_to_c_double PyFloat_AsDouble
#define _cffi_to_c_float PyFloat_AsDouble

#define _cffi_from_c_int(x, type)                                        \
    (((type)-1) > 0 ? /* unsigned */                                     \
        (sizeof(type) < sizeof(long) ?                                   \
            PyInt_FromLong((long)x) :                                    \
         sizeof(type) == sizeof(long) ?                                  \
            PyLong_FromUnsignedLong((unsigned long)x) :                  \
            PyLong_FromUnsignedLongLong((unsigned long long)x)) :        \
        (sizeof(type) <= sizeof(long) ?                                  \
            PyInt_FromLong((long)x) :                                    \
            PyLong_FromLongLong((long long)x)))

#define _cffi_to_c_int(o, type)                                          \
    ((type)(                                                             \
     sizeof(type) == 1 ? (((type)-1) > 0 ? (type)_cffi_to_c_u8(o)        \
                                         : (type)_cffi_to_c_i8(o)) :     \
     sizeof(type) == 2 ? (((type)-1) > 0 ? (type)_cffi_to_c_u16(o)       \
                                         : (type)_cffi_to_c_i16(o)) :    \
     sizeof(type) == 4 ? (((type)-1) > 0 ? (type)_cffi_to_c_u32(o)       \
                                         : (type)_cffi_to_c_i32(o)) :    \
     sizeof(type) == 8 ? (((type)-1) > 0 ? (type)_cffi_to_c_u64(o)       \
                                         : (type)_cffi_to_c_i64(o)) :    \
     (Py_FatalError("unsupported size for type " #type), (type)0)))

#define _cffi_to_c_i8                                                    \
                 ((int(*)(PyObject *))_cffi_exports[1])
#define _cffi_to_c_u8                                                    \
                 ((int(*)(PyObject *))_cffi_exports[2])
#define _cffi_to_c_i16                                                   \
                 ((int(*)(PyObject *))_cffi_exports[3])
#define _cffi_to_c_u16                                                   \
                 ((int(*)(PyObject *))_cffi_exports[4])
#define _cffi_to_c_i32                                                   \
                 ((int(*)(PyObject *))_cffi_exports[5])
#define _cffi_to_c_u32                                                   \
                 ((unsigned int(*)(PyObject *))_cffi_exports[6])
#define _cffi_to_c_i64                                                   \
                 ((long long(*)(PyObject *))_cffi_exports[7])
#define _cffi_to_c_u64                                                   \
                 ((unsigned long long(*)(PyObject *))_cffi_exports[8])
#define _cffi_to_c_char                                                  \
                 ((int(*)(PyObject *))_cffi_exports[9])
#define _cffi_from_c_pointer                                             \
    ((PyObject *(*)(char *, CTypeDescrObject *))_cffi_exports[10])
#define _cffi_to_c_pointer                                               \
    ((char *(*)(PyObject *, CTypeDescrObject *))_cffi_exports[11])
#define _cffi_get_struct_layout                                          \
    not used any more
#define _cffi_restore_errno                                              \
    ((void(*)(void))_cffi_exports[13])
#define _cffi_save_errno                                                 \
    ((void(*)(void))_cffi_exports[14])
#define _cffi_from_c_char                                                \
    ((PyObject *(*)(char))_cffi_exports[15])
#define _cffi_from_c_deref                                               \
    ((PyObject *(*)(char *, CTypeDescrObject *))_cffi_exports[16])
#define _cffi_to_c                                                       \
    ((int(*)(char *, CTypeDescrObject *, PyObject *))_cffi_exports[17])
#define _cffi_from_c_struct                                              \
    ((PyObject *(*)(char *, CTypeDescrObject *))_cffi_exports[18])
#define _cffi_to_c_wchar_t                                               \
    ((wchar_t(*)(PyObject *))_cffi_exports[19])
#define _cffi_from_c_wchar_t                                             \
    ((PyObject *(*)(wchar_t))_cffi_exports[20])
#define _cffi_to_c_long_double                                           \
    ((long double(*)(PyObject *))_cffi_exports[21])
#define _cffi_to_c__Bool                                                 \
    ((_Bool(*)(PyObject *))_cffi_exports[22])
#define _cffi_prepare_pointer_call_argument                              \
    ((Py_ssize_t(*)(CTypeDescrObject *, PyObject *, char **))_cffi_exports[23])
#define _cffi_convert_array_from_object                                  \
    ((int(*)(char *, CTypeDescrObject *, PyObject *))_cffi_exports[24])
#define _CFFI_NUM_EXPORTS 25

typedef struct _ctypedescr CTypeDescrObject;

static void *_cffi_exports[_CFFI_NUM_EXPORTS];

#define _cffi_type(index)   (                           \
    assert((((uintptr_t)_cffi_types[index]) & 1) == 0), \
    (CTypeDescrObject *)_cffi_types[index])

static PyObject *_cffi_init(const char *module_name, Py_ssize_t version,
                            const struct _cffi_type_context_s *ctx)
{
    PyObject *module, *o_arg, *new_module;
    void *raw[] = {
        (void *)module_name,
        (void *)version,
        (void *)_cffi_exports,
        (void *)ctx,
    };

    module = PyImport_ImportModule("_cffi_backend");
    if (module == NULL)
        goto failure;

    o_arg = PyLong_FromVoidPtr((void *)raw);
    if (o_arg == NULL)
        goto failure;

    new_module = PyObject_CallMethod(
        module, (char *)"_init_cffi_1_0_external_module", (char *)"O", o_arg);

    Py_DECREF(o_arg);
    Py_DECREF(module);
    return new_module;

  failure:
    Py_XDECREF(module);
    return NULL;
}

_CFFI_UNUSED_FN
static PyObject **_cffi_unpack_args(PyObject *args_tuple, Py_ssize_t expected,
                                    const char *fnname)
{
    if (PyTuple_GET_SIZE(args_tuple) != expected) {
        PyErr_Format(PyExc_TypeError,
                     "%.150s() takes exactly %zd arguments (%zd given)",
                     fnname, expected, PyTuple_GET_SIZE(args_tuple));
        return NULL;
    }
    return &PyTuple_GET_ITEM(args_tuple, 0);   /* pointer to the first item,
                                                  the others follow */
}

#endif
/**********  end CPython-specific section  **********/


#define _cffi_array_len(array)   (sizeof(array) / sizeof((array)[0]))

#define _cffi_prim_int(size, sign)                                      \
    ((size) == 1 ? ((sign) ? _CFFI_PRIM_INT8  : _CFFI_PRIM_UINT8)  :    \
     (size) == 2 ? ((sign) ? _CFFI_PRIM_INT16 : _CFFI_PRIM_UINT16) :    \
     (size) == 4 ? ((sign) ? _CFFI_PRIM_INT32 : _CFFI_PRIM_UINT32) :    \
     (size) == 8 ? ((sign) ? _CFFI_PRIM_INT64 : _CFFI_PRIM_UINT64) :    \
     _CFFI__UNKNOWN_PRIM)

#define _cffi_check_int(got, got_nonpos, expected)      \
    ((got_nonpos) == (expected <= 0) &&                 \
     (got) == (unsigned long long)expected)

#ifdef __cplusplus
}
#endif

/************************************************************/

#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <secp256k1_schnorr.h>
#include <secp256k1_ecdh.h>

/************************************************************/

static void *_cffi_types[] = {
/*  0 */ _CFFI_OP(_CFFI_OP_FUNCTION, 8), // int()(secp256k1_context *, unsigned char const *)
/*  1 */ _CFFI_OP(_CFFI_OP_POINTER, 175), // secp256k1_context *
/*  2 */ _CFFI_OP(_CFFI_OP_POINTER, 179), // unsigned char const *
/*  3 */ _CFFI_OP(_CFFI_OP_FUNCTION_END, 0),
/*  4 */ _CFFI_OP(_CFFI_OP_FUNCTION, 8), // int()(secp256k1_context const *, secp256k1_ecdsa_recoverable_signature *, unsigned char const *, int)
/*  5 */ _CFFI_OP(_CFFI_OP_POINTER, 175), // secp256k1_context const *
/*  6 */ _CFFI_OP(_CFFI_OP_POINTER, 176), // secp256k1_ecdsa_recoverable_signature *
/*  7 */ _CFFI_OP(_CFFI_OP_NOOP, 2),
/*  8 */ _CFFI_OP(_CFFI_OP_PRIMITIVE, 7), // int
/*  9 */ _CFFI_OP(_CFFI_OP_FUNCTION_END, 0),
/* 10 */ _CFFI_OP(_CFFI_OP_FUNCTION, 8), // int()(secp256k1_context const *, secp256k1_ecdsa_recoverable_signature *, unsigned char const *, unsigned char const *, int(*)(unsigned char *, unsigned char const *, unsigned char const *, unsigned char const *, void *, unsigned int), void const *)
/* 11 */ _CFFI_OP(_CFFI_OP_NOOP, 5),
/* 12 */ _CFFI_OP(_CFFI_OP_NOOP, 6),
/* 13 */ _CFFI_OP(_CFFI_OP_NOOP, 2),
/* 14 */ _CFFI_OP(_CFFI_OP_NOOP, 2),
/* 15 */ _CFFI_OP(_CFFI_OP_POINTER, 158), // int(*)(unsigned char *, unsigned char const *, unsigned char const *, unsigned char const *, void *, unsigned int)
/* 16 */ _CFFI_OP(_CFFI_OP_POINTER, 184), // void const *
/* 17 */ _CFFI_OP(_CFFI_OP_FUNCTION_END, 0),
/* 18 */ _CFFI_OP(_CFFI_OP_FUNCTION, 8), // int()(secp256k1_context const *, secp256k1_ecdsa_signature *, secp256k1_ecdsa_recoverable_signature const *)
/* 19 */ _CFFI_OP(_CFFI_OP_NOOP, 5),
/* 20 */ _CFFI_OP(_CFFI_OP_POINTER, 177), // secp256k1_ecdsa_signature *
/* 21 */ _CFFI_OP(_CFFI_OP_POINTER, 176), // secp256k1_ecdsa_recoverable_signature const *
/* 22 */ _CFFI_OP(_CFFI_OP_FUNCTION_END, 0),
/* 23 */ _CFFI_OP(_CFFI_OP_FUNCTION, 8), // int()(secp256k1_context const *, secp256k1_ecdsa_signature *, secp256k1_ecdsa_signature const *)
/* 24 */ _CFFI_OP(_CFFI_OP_NOOP, 5),
/* 25 */ _CFFI_OP(_CFFI_OP_NOOP, 20),
/* 26 */ _CFFI_OP(_CFFI_OP_POINTER, 177), // secp256k1_ecdsa_signature const *
/* 27 */ _CFFI_OP(_CFFI_OP_FUNCTION_END, 0),
/* 28 */ _CFFI_OP(_CFFI_OP_FUNCTION, 8), // int()(secp256k1_context const *, secp256k1_ecdsa_signature *, unsigned char const *)
/* 29 */ _CFFI_OP(_CFFI_OP_NOOP, 5),
/* 30 */ _CFFI_OP(_CFFI_OP_NOOP, 20),
/* 31 */ _CFFI_OP(_CFFI_OP_NOOP, 2),
/* 32 */ _CFFI_OP(_CFFI_OP_FUNCTION_END, 0),
/* 33 */ _CFFI_OP(_CFFI_OP_FUNCTION, 8), // int()(secp256k1_context const *, secp256k1_ecdsa_signature *, unsigned char const *, size_t)
/* 34 */ _CFFI_OP(_CFFI_OP_NOOP, 5),
/* 35 */ _CFFI_OP(_CFFI_OP_NOOP, 20),
/* 36 */ _CFFI_OP(_CFFI_OP_NOOP, 2),
/* 37 */ _CFFI_OP(_CFFI_OP_PRIMITIVE, 28), // size_t
/* 38 */ _CFFI_OP(_CFFI_OP_FUNCTION_END, 0),
/* 39 */ _CFFI_OP(_CFFI_OP_FUNCTION, 8), // int()(secp256k1_context const *, secp256k1_ecdsa_signature *, unsigned char const *, unsigned char const *, int(*)(unsigned char *, unsigned char const *, unsigned char const *, unsigned char const *, void *, unsigned int), void const *)
/* 40 */ _CFFI_OP(_CFFI_OP_NOOP, 5),
/* 41 */ _CFFI_OP(_CFFI_OP_NOOP, 20),
/* 42 */ _CFFI_OP(_CFFI_OP_NOOP, 2),
/* 43 */ _CFFI_OP(_CFFI_OP_NOOP, 2),
/* 44 */ _CFFI_OP(_CFFI_OP_NOOP, 15),
/* 45 */ _CFFI_OP(_CFFI_OP_NOOP, 16),
/* 46 */ _CFFI_OP(_CFFI_OP_FUNCTION_END, 0),
/* 47 */ _CFFI_OP(_CFFI_OP_FUNCTION, 8), // int()(secp256k1_context const *, secp256k1_ecdsa_signature const *, unsigned char const *, secp256k1_pubkey const *)
/* 48 */ _CFFI_OP(_CFFI_OP_NOOP, 5),
/* 49 */ _CFFI_OP(_CFFI_OP_NOOP, 26),
/* 50 */ _CFFI_OP(_CFFI_OP_NOOP, 2),
/* 51 */ _CFFI_OP(_CFFI_OP_POINTER, 178), // secp256k1_pubkey const *
/* 52 */ _CFFI_OP(_CFFI_OP_FUNCTION_END, 0),
/* 53 */ _CFFI_OP(_CFFI_OP_FUNCTION, 8), // int()(secp256k1_context const *, secp256k1_pubkey *, secp256k1_ecdsa_recoverable_signature const *, unsigned char const *)
/* 54 */ _CFFI_OP(_CFFI_OP_NOOP, 5),
/* 55 */ _CFFI_OP(_CFFI_OP_POINTER, 178), // secp256k1_pubkey *
/* 56 */ _CFFI_OP(_CFFI_OP_NOOP, 21),
/* 57 */ _CFFI_OP(_CFFI_OP_NOOP, 2),
/* 58 */ _CFFI_OP(_CFFI_OP_FUNCTION_END, 0),
/* 59 */ _CFFI_OP(_CFFI_OP_FUNCTION, 8), // int()(secp256k1_context const *, secp256k1_pubkey *, secp256k1_pubkey const * *, int)
/* 60 */ _CFFI_OP(_CFFI_OP_NOOP, 5),
/* 61 */ _CFFI_OP(_CFFI_OP_NOOP, 55),
/* 62 */ _CFFI_OP(_CFFI_OP_POINTER, 51), // secp256k1_pubkey const * *
/* 63 */ _CFFI_OP(_CFFI_OP_PRIMITIVE, 7),
/* 64 */ _CFFI_OP(_CFFI_OP_FUNCTION_END, 0),
/* 65 */ _CFFI_OP(_CFFI_OP_FUNCTION, 8), // int()(secp256k1_context const *, secp256k1_pubkey *, unsigned char *, unsigned char const *, unsigned char const *, int(*)(unsigned char *, unsigned char const *, unsigned char const *, unsigned char const *, void *, unsigned int), void const *)
/* 66 */ _CFFI_OP(_CFFI_OP_NOOP, 5),
/* 67 */ _CFFI_OP(_CFFI_OP_NOOP, 55),
/* 68 */ _CFFI_OP(_CFFI_OP_POINTER, 179), // unsigned char *
/* 69 */ _CFFI_OP(_CFFI_OP_NOOP, 2),
/* 70 */ _CFFI_OP(_CFFI_OP_NOOP, 2),
/* 71 */ _CFFI_OP(_CFFI_OP_NOOP, 15),
/* 72 */ _CFFI_OP(_CFFI_OP_NOOP, 16),
/* 73 */ _CFFI_OP(_CFFI_OP_FUNCTION_END, 0),
/* 74 */ _CFFI_OP(_CFFI_OP_FUNCTION, 8), // int()(secp256k1_context const *, secp256k1_pubkey *, unsigned char const *)
/* 75 */ _CFFI_OP(_CFFI_OP_NOOP, 5),
/* 76 */ _CFFI_OP(_CFFI_OP_NOOP, 55),
/* 77 */ _CFFI_OP(_CFFI_OP_NOOP, 2),
/* 78 */ _CFFI_OP(_CFFI_OP_FUNCTION_END, 0),
/* 79 */ _CFFI_OP(_CFFI_OP_FUNCTION, 8), // int()(secp256k1_context const *, secp256k1_pubkey *, unsigned char const *, size_t)
/* 80 */ _CFFI_OP(_CFFI_OP_NOOP, 5),
/* 81 */ _CFFI_OP(_CFFI_OP_NOOP, 55),
/* 82 */ _CFFI_OP(_CFFI_OP_NOOP, 2),
/* 83 */ _CFFI_OP(_CFFI_OP_PRIMITIVE, 28),
/* 84 */ _CFFI_OP(_CFFI_OP_FUNCTION_END, 0),
/* 85 */ _CFFI_OP(_CFFI_OP_FUNCTION, 8), // int()(secp256k1_context const *, secp256k1_pubkey *, unsigned char const *, unsigned char const *)
/* 86 */ _CFFI_OP(_CFFI_OP_NOOP, 5),
/* 87 */ _CFFI_OP(_CFFI_OP_NOOP, 55),
/* 88 */ _CFFI_OP(_CFFI_OP_NOOP, 2),
/* 89 */ _CFFI_OP(_CFFI_OP_NOOP, 2),
/* 90 */ _CFFI_OP(_CFFI_OP_FUNCTION_END, 0),
/* 91 */ _CFFI_OP(_CFFI_OP_FUNCTION, 8), // int()(secp256k1_context const *, unsigned char *, int *, secp256k1_ecdsa_recoverable_signature const *)
/* 92 */ _CFFI_OP(_CFFI_OP_NOOP, 5),
/* 93 */ _CFFI_OP(_CFFI_OP_NOOP, 68),
/* 94 */ _CFFI_OP(_CFFI_OP_POINTER, 8), // int *
/* 95 */ _CFFI_OP(_CFFI_OP_NOOP, 21),
/* 96 */ _CFFI_OP(_CFFI_OP_FUNCTION_END, 0),
/* 97 */ _CFFI_OP(_CFFI_OP_FUNCTION, 8), // int()(secp256k1_context const *, unsigned char *, secp256k1_ecdsa_signature const *)
/* 98 */ _CFFI_OP(_CFFI_OP_NOOP, 5),
/* 99 */ _CFFI_OP(_CFFI_OP_NOOP, 68),
/* 100 */ _CFFI_OP(_CFFI_OP_NOOP, 26),
/* 101 */ _CFFI_OP(_CFFI_OP_FUNCTION_END, 0),
/* 102 */ _CFFI_OP(_CFFI_OP_FUNCTION, 8), // int()(secp256k1_context const *, unsigned char *, secp256k1_pubkey const *, unsigned char const *)
/* 103 */ _CFFI_OP(_CFFI_OP_NOOP, 5),
/* 104 */ _CFFI_OP(_CFFI_OP_NOOP, 68),
/* 105 */ _CFFI_OP(_CFFI_OP_NOOP, 51),
/* 106 */ _CFFI_OP(_CFFI_OP_NOOP, 2),
/* 107 */ _CFFI_OP(_CFFI_OP_FUNCTION_END, 0),
/* 108 */ _CFFI_OP(_CFFI_OP_FUNCTION, 8), // int()(secp256k1_context const *, unsigned char *, size_t *, secp256k1_ecdsa_signature const *)
/* 109 */ _CFFI_OP(_CFFI_OP_NOOP, 5),
/* 110 */ _CFFI_OP(_CFFI_OP_NOOP, 68),
/* 111 */ _CFFI_OP(_CFFI_OP_POINTER, 37), // size_t *
/* 112 */ _CFFI_OP(_CFFI_OP_NOOP, 26),
/* 113 */ _CFFI_OP(_CFFI_OP_FUNCTION_END, 0),
/* 114 */ _CFFI_OP(_CFFI_OP_FUNCTION, 8), // int()(secp256k1_context const *, unsigned char *, size_t *, secp256k1_pubkey const *, unsigned int)
/* 115 */ _CFFI_OP(_CFFI_OP_NOOP, 5),
/* 116 */ _CFFI_OP(_CFFI_OP_NOOP, 68),
/* 117 */ _CFFI_OP(_CFFI_OP_NOOP, 111),
/* 118 */ _CFFI_OP(_CFFI_OP_NOOP, 51),
/* 119 */ _CFFI_OP(_CFFI_OP_PRIMITIVE, 8), // unsigned int
/* 120 */ _CFFI_OP(_CFFI_OP_FUNCTION_END, 0),
/* 121 */ _CFFI_OP(_CFFI_OP_FUNCTION, 8), // int()(secp256k1_context const *, unsigned char *, unsigned char const * *, int)
/* 122 */ _CFFI_OP(_CFFI_OP_NOOP, 5),
/* 123 */ _CFFI_OP(_CFFI_OP_NOOP, 68),
/* 124 */ _CFFI_OP(_CFFI_OP_POINTER, 2), // unsigned char const * *
/* 125 */ _CFFI_OP(_CFFI_OP_PRIMITIVE, 7),
/* 126 */ _CFFI_OP(_CFFI_OP_FUNCTION_END, 0),
/* 127 */ _CFFI_OP(_CFFI_OP_FUNCTION, 8), // int()(secp256k1_context const *, unsigned char *, unsigned char const *)
/* 128 */ _CFFI_OP(_CFFI_OP_NOOP, 5),
/* 129 */ _CFFI_OP(_CFFI_OP_NOOP, 68),
/* 130 */ _CFFI_OP(_CFFI_OP_NOOP, 2),
/* 131 */ _CFFI_OP(_CFFI_OP_FUNCTION_END, 0),
/* 132 */ _CFFI_OP(_CFFI_OP_FUNCTION, 8), // int()(secp256k1_context const *, unsigned char *, unsigned char const *, unsigned char const *, int(*)(unsigned char *, unsigned char const *, unsigned char const *, unsigned char const *, void *, unsigned int), void const *)
/* 133 */ _CFFI_OP(_CFFI_OP_NOOP, 5),
/* 134 */ _CFFI_OP(_CFFI_OP_NOOP, 68),
/* 135 */ _CFFI_OP(_CFFI_OP_NOOP, 2),
/* 136 */ _CFFI_OP(_CFFI_OP_NOOP, 2),
/* 137 */ _CFFI_OP(_CFFI_OP_NOOP, 15),
/* 138 */ _CFFI_OP(_CFFI_OP_NOOP, 16),
/* 139 */ _CFFI_OP(_CFFI_OP_FUNCTION_END, 0),
/* 140 */ _CFFI_OP(_CFFI_OP_FUNCTION, 8), // int()(secp256k1_context const *, unsigned char *, unsigned char const *, unsigned char const *, secp256k1_pubkey const *, unsigned char const *)
/* 141 */ _CFFI_OP(_CFFI_OP_NOOP, 5),
/* 142 */ _CFFI_OP(_CFFI_OP_NOOP, 68),
/* 143 */ _CFFI_OP(_CFFI_OP_NOOP, 2),
/* 144 */ _CFFI_OP(_CFFI_OP_NOOP, 2),
/* 145 */ _CFFI_OP(_CFFI_OP_NOOP, 51),
/* 146 */ _CFFI_OP(_CFFI_OP_NOOP, 2),
/* 147 */ _CFFI_OP(_CFFI_OP_FUNCTION_END, 0),
/* 148 */ _CFFI_OP(_CFFI_OP_FUNCTION, 8), // int()(secp256k1_context const *, unsigned char const *)
/* 149 */ _CFFI_OP(_CFFI_OP_NOOP, 5),
/* 150 */ _CFFI_OP(_CFFI_OP_NOOP, 2),
/* 151 */ _CFFI_OP(_CFFI_OP_FUNCTION_END, 0),
/* 152 */ _CFFI_OP(_CFFI_OP_FUNCTION, 8), // int()(secp256k1_context const *, unsigned char const *, unsigned char const *, secp256k1_pubkey const *)
/* 153 */ _CFFI_OP(_CFFI_OP_NOOP, 5),
/* 154 */ _CFFI_OP(_CFFI_OP_NOOP, 2),
/* 155 */ _CFFI_OP(_CFFI_OP_NOOP, 2),
/* 156 */ _CFFI_OP(_CFFI_OP_NOOP, 51),
/* 157 */ _CFFI_OP(_CFFI_OP_FUNCTION_END, 0),
/* 158 */ _CFFI_OP(_CFFI_OP_FUNCTION, 8), // int()(unsigned char *, unsigned char const *, unsigned char const *, unsigned char const *, void *, unsigned int)
/* 159 */ _CFFI_OP(_CFFI_OP_NOOP, 68),
/* 160 */ _CFFI_OP(_CFFI_OP_NOOP, 2),
/* 161 */ _CFFI_OP(_CFFI_OP_NOOP, 2),
/* 162 */ _CFFI_OP(_CFFI_OP_NOOP, 2),
/* 163 */ _CFFI_OP(_CFFI_OP_POINTER, 184), // void *
/* 164 */ _CFFI_OP(_CFFI_OP_PRIMITIVE, 8),
/* 165 */ _CFFI_OP(_CFFI_OP_FUNCTION_END, 0),
/* 166 */ _CFFI_OP(_CFFI_OP_FUNCTION, 1), // secp256k1_context *()(int)
/* 167 */ _CFFI_OP(_CFFI_OP_PRIMITIVE, 7),
/* 168 */ _CFFI_OP(_CFFI_OP_FUNCTION_END, 0),
/* 169 */ _CFFI_OP(_CFFI_OP_FUNCTION, 1), // secp256k1_context *()(secp256k1_context const *)
/* 170 */ _CFFI_OP(_CFFI_OP_NOOP, 5),
/* 171 */ _CFFI_OP(_CFFI_OP_FUNCTION_END, 0),
/* 172 */ _CFFI_OP(_CFFI_OP_FUNCTION, 184), // void()(secp256k1_context *)
/* 173 */ _CFFI_OP(_CFFI_OP_NOOP, 1),
/* 174 */ _CFFI_OP(_CFFI_OP_FUNCTION_END, 0),
/* 175 */ _CFFI_OP(_CFFI_OP_STRUCT_UNION, 3), // secp256k1_context
/* 176 */ _CFFI_OP(_CFFI_OP_STRUCT_UNION, 0), // secp256k1_ecdsa_recoverable_signature
/* 177 */ _CFFI_OP(_CFFI_OP_STRUCT_UNION, 1), // secp256k1_ecdsa_signature
/* 178 */ _CFFI_OP(_CFFI_OP_STRUCT_UNION, 2), // secp256k1_pubkey
/* 179 */ _CFFI_OP(_CFFI_OP_PRIMITIVE, 4), // unsigned char
/* 180 */ _CFFI_OP(_CFFI_OP_ARRAY, 179), // unsigned char[64]
/* 181 */ (_cffi_opcode_t)(64),
/* 182 */ _CFFI_OP(_CFFI_OP_ARRAY, 179), // unsigned char[65]
/* 183 */ (_cffi_opcode_t)(65),
/* 184 */ _CFFI_OP(_CFFI_OP_PRIMITIVE, 0), // void
};

_CFFI_UNUSED_FN
static void _cffi_checkfld_typedef_secp256k1_ecdsa_recoverable_signature(secp256k1_ecdsa_recoverable_signature *p)
{
  /* only to generate compile-time warnings or errors */
  (void)p;
  { unsigned char(*tmp)[65] = &p->data; (void)tmp; }
}
struct _cffi_align_typedef_secp256k1_ecdsa_recoverable_signature { char x; secp256k1_ecdsa_recoverable_signature y; };

_CFFI_UNUSED_FN
static void _cffi_checkfld_typedef_secp256k1_ecdsa_signature(secp256k1_ecdsa_signature *p)
{
  /* only to generate compile-time warnings or errors */
  (void)p;
  { unsigned char(*tmp)[64] = &p->data; (void)tmp; }
}
struct _cffi_align_typedef_secp256k1_ecdsa_signature { char x; secp256k1_ecdsa_signature y; };

_CFFI_UNUSED_FN
static void _cffi_checkfld_typedef_secp256k1_pubkey(secp256k1_pubkey *p)
{
  /* only to generate compile-time warnings or errors */
  (void)p;
  { unsigned char(*tmp)[64] = &p->data; (void)tmp; }
}
struct _cffi_align_typedef_secp256k1_pubkey { char x; secp256k1_pubkey y; };

static void _cffi_const_secp256k1_nonce_function_default(char *o)
{
  *(int(* *)(unsigned char *, unsigned char const *, unsigned char const *, unsigned char const *, void *, unsigned int))o = secp256k1_nonce_function_default;
}

static void _cffi_const_secp256k1_nonce_function_rfc6979(char *o)
{
  *(int(* *)(unsigned char *, unsigned char const *, unsigned char const *, unsigned char const *, void *, unsigned int))o = secp256k1_nonce_function_rfc6979;
}

static secp256k1_context * _cffi_d_secp256k1_context_clone(secp256k1_context const * x0)
{
  return secp256k1_context_clone(x0);
}
#ifndef PYPY_VERSION
static PyObject *
_cffi_f_secp256k1_context_clone(PyObject *self, PyObject *arg0)
{
  secp256k1_context const * x0;
  Py_ssize_t datasize;
  secp256k1_context * result;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(5), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = (secp256k1_context const *)alloca((size_t)datasize);
    memset((void *)x0, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(5), arg0) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = secp256k1_context_clone(x0); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  (void)self; /* unused */
  return _cffi_from_c_pointer((char *)result, _cffi_type(1));
}
#else
#  define _cffi_f_secp256k1_context_clone _cffi_d_secp256k1_context_clone
#endif

static secp256k1_context * _cffi_d_secp256k1_context_create(int x0)
{
  return secp256k1_context_create(x0);
}
#ifndef PYPY_VERSION
static PyObject *
_cffi_f_secp256k1_context_create(PyObject *self, PyObject *arg0)
{
  int x0;
  secp256k1_context * result;

  x0 = _cffi_to_c_int(arg0, int);
  if (x0 == (int)-1 && PyErr_Occurred())
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = secp256k1_context_create(x0); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  (void)self; /* unused */
  return _cffi_from_c_pointer((char *)result, _cffi_type(1));
}
#else
#  define _cffi_f_secp256k1_context_create _cffi_d_secp256k1_context_create
#endif

static void _cffi_d_secp256k1_context_destroy(secp256k1_context * x0)
{
  secp256k1_context_destroy(x0);
}
#ifndef PYPY_VERSION
static PyObject *
_cffi_f_secp256k1_context_destroy(PyObject *self, PyObject *arg0)
{
  secp256k1_context * x0;
  Py_ssize_t datasize;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(1), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = (secp256k1_context *)alloca((size_t)datasize);
    memset((void *)x0, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(1), arg0) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { secp256k1_context_destroy(x0); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  (void)self; /* unused */
  Py_INCREF(Py_None);
  return Py_None;
}
#else
#  define _cffi_f_secp256k1_context_destroy _cffi_d_secp256k1_context_destroy
#endif

static int _cffi_d_secp256k1_context_randomize(secp256k1_context * x0, unsigned char const * x1)
{
  return secp256k1_context_randomize(x0, x1);
}
#ifndef PYPY_VERSION
static PyObject *
_cffi_f_secp256k1_context_randomize(PyObject *self, PyObject *args)
{
  secp256k1_context * x0;
  unsigned char const * x1;
  Py_ssize_t datasize;
  int result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject **aa;

  aa = _cffi_unpack_args(args, 2, "secp256k1_context_randomize");
  if (aa == NULL)
    return NULL;
  arg0 = aa[0];
  arg1 = aa[1];

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(1), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = (secp256k1_context *)alloca((size_t)datasize);
    memset((void *)x0, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(1), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(2), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = (unsigned char const *)alloca((size_t)datasize);
    memset((void *)x1, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(2), arg1) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = secp256k1_context_randomize(x0, x1); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  (void)self; /* unused */
  return _cffi_from_c_int(result, int);
}
#else
#  define _cffi_f_secp256k1_context_randomize _cffi_d_secp256k1_context_randomize
#endif

static int _cffi_d_secp256k1_ec_privkey_tweak_add(secp256k1_context const * x0, unsigned char * x1, unsigned char const * x2)
{
  return secp256k1_ec_privkey_tweak_add(x0, x1, x2);
}
#ifndef PYPY_VERSION
static PyObject *
_cffi_f_secp256k1_ec_privkey_tweak_add(PyObject *self, PyObject *args)
{
  secp256k1_context const * x0;
  unsigned char * x1;
  unsigned char const * x2;
  Py_ssize_t datasize;
  int result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;
  PyObject **aa;

  aa = _cffi_unpack_args(args, 3, "secp256k1_ec_privkey_tweak_add");
  if (aa == NULL)
    return NULL;
  arg0 = aa[0];
  arg1 = aa[1];
  arg2 = aa[2];

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(5), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = (secp256k1_context const *)alloca((size_t)datasize);
    memset((void *)x0, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(5), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(68), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = (unsigned char *)alloca((size_t)datasize);
    memset((void *)x1, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(68), arg1) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(2), arg2, (char **)&x2);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x2 = (unsigned char const *)alloca((size_t)datasize);
    memset((void *)x2, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x2, _cffi_type(2), arg2) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = secp256k1_ec_privkey_tweak_add(x0, x1, x2); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  (void)self; /* unused */
  return _cffi_from_c_int(result, int);
}
#else
#  define _cffi_f_secp256k1_ec_privkey_tweak_add _cffi_d_secp256k1_ec_privkey_tweak_add
#endif

static int _cffi_d_secp256k1_ec_privkey_tweak_mul(secp256k1_context const * x0, unsigned char * x1, unsigned char const * x2)
{
  return secp256k1_ec_privkey_tweak_mul(x0, x1, x2);
}
#ifndef PYPY_VERSION
static PyObject *
_cffi_f_secp256k1_ec_privkey_tweak_mul(PyObject *self, PyObject *args)
{
  secp256k1_context const * x0;
  unsigned char * x1;
  unsigned char const * x2;
  Py_ssize_t datasize;
  int result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;
  PyObject **aa;

  aa = _cffi_unpack_args(args, 3, "secp256k1_ec_privkey_tweak_mul");
  if (aa == NULL)
    return NULL;
  arg0 = aa[0];
  arg1 = aa[1];
  arg2 = aa[2];

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(5), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = (secp256k1_context const *)alloca((size_t)datasize);
    memset((void *)x0, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(5), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(68), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = (unsigned char *)alloca((size_t)datasize);
    memset((void *)x1, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(68), arg1) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(2), arg2, (char **)&x2);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x2 = (unsigned char const *)alloca((size_t)datasize);
    memset((void *)x2, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x2, _cffi_type(2), arg2) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = secp256k1_ec_privkey_tweak_mul(x0, x1, x2); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  (void)self; /* unused */
  return _cffi_from_c_int(result, int);
}
#else
#  define _cffi_f_secp256k1_ec_privkey_tweak_mul _cffi_d_secp256k1_ec_privkey_tweak_mul
#endif

static int _cffi_d_secp256k1_ec_pubkey_combine(secp256k1_context const * x0, secp256k1_pubkey * x1, secp256k1_pubkey const * * x2, int x3)
{
  return secp256k1_ec_pubkey_combine(x0, x1, x2, x3);
}
#ifndef PYPY_VERSION
static PyObject *
_cffi_f_secp256k1_ec_pubkey_combine(PyObject *self, PyObject *args)
{
  secp256k1_context const * x0;
  secp256k1_pubkey * x1;
  secp256k1_pubkey const * * x2;
  int x3;
  Py_ssize_t datasize;
  int result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;
  PyObject *arg3;
  PyObject **aa;

  aa = _cffi_unpack_args(args, 4, "secp256k1_ec_pubkey_combine");
  if (aa == NULL)
    return NULL;
  arg0 = aa[0];
  arg1 = aa[1];
  arg2 = aa[2];
  arg3 = aa[3];

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(5), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = (secp256k1_context const *)alloca((size_t)datasize);
    memset((void *)x0, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(5), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(55), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = (secp256k1_pubkey *)alloca((size_t)datasize);
    memset((void *)x1, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(55), arg1) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(62), arg2, (char **)&x2);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x2 = (secp256k1_pubkey const * *)alloca((size_t)datasize);
    memset((void *)x2, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x2, _cffi_type(62), arg2) < 0)
      return NULL;
  }

  x3 = _cffi_to_c_int(arg3, int);
  if (x3 == (int)-1 && PyErr_Occurred())
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = secp256k1_ec_pubkey_combine(x0, x1, x2, x3); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  (void)self; /* unused */
  return _cffi_from_c_int(result, int);
}
#else
#  define _cffi_f_secp256k1_ec_pubkey_combine _cffi_d_secp256k1_ec_pubkey_combine
#endif

static int _cffi_d_secp256k1_ec_pubkey_create(secp256k1_context const * x0, secp256k1_pubkey * x1, unsigned char const * x2)
{
  return secp256k1_ec_pubkey_create(x0, x1, x2);
}
#ifndef PYPY_VERSION
static PyObject *
_cffi_f_secp256k1_ec_pubkey_create(PyObject *self, PyObject *args)
{
  secp256k1_context const * x0;
  secp256k1_pubkey * x1;
  unsigned char const * x2;
  Py_ssize_t datasize;
  int result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;
  PyObject **aa;

  aa = _cffi_unpack_args(args, 3, "secp256k1_ec_pubkey_create");
  if (aa == NULL)
    return NULL;
  arg0 = aa[0];
  arg1 = aa[1];
  arg2 = aa[2];

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(5), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = (secp256k1_context const *)alloca((size_t)datasize);
    memset((void *)x0, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(5), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(55), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = (secp256k1_pubkey *)alloca((size_t)datasize);
    memset((void *)x1, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(55), arg1) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(2), arg2, (char **)&x2);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x2 = (unsigned char const *)alloca((size_t)datasize);
    memset((void *)x2, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x2, _cffi_type(2), arg2) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = secp256k1_ec_pubkey_create(x0, x1, x2); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  (void)self; /* unused */
  return _cffi_from_c_int(result, int);
}
#else
#  define _cffi_f_secp256k1_ec_pubkey_create _cffi_d_secp256k1_ec_pubkey_create
#endif

static int _cffi_d_secp256k1_ec_pubkey_parse(secp256k1_context const * x0, secp256k1_pubkey * x1, unsigned char const * x2, size_t x3)
{
  return secp256k1_ec_pubkey_parse(x0, x1, x2, x3);
}
#ifndef PYPY_VERSION
static PyObject *
_cffi_f_secp256k1_ec_pubkey_parse(PyObject *self, PyObject *args)
{
  secp256k1_context const * x0;
  secp256k1_pubkey * x1;
  unsigned char const * x2;
  size_t x3;
  Py_ssize_t datasize;
  int result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;
  PyObject *arg3;
  PyObject **aa;

  aa = _cffi_unpack_args(args, 4, "secp256k1_ec_pubkey_parse");
  if (aa == NULL)
    return NULL;
  arg0 = aa[0];
  arg1 = aa[1];
  arg2 = aa[2];
  arg3 = aa[3];

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(5), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = (secp256k1_context const *)alloca((size_t)datasize);
    memset((void *)x0, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(5), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(55), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = (secp256k1_pubkey *)alloca((size_t)datasize);
    memset((void *)x1, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(55), arg1) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(2), arg2, (char **)&x2);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x2 = (unsigned char const *)alloca((size_t)datasize);
    memset((void *)x2, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x2, _cffi_type(2), arg2) < 0)
      return NULL;
  }

  x3 = _cffi_to_c_int(arg3, size_t);
  if (x3 == (size_t)-1 && PyErr_Occurred())
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = secp256k1_ec_pubkey_parse(x0, x1, x2, x3); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  (void)self; /* unused */
  return _cffi_from_c_int(result, int);
}
#else
#  define _cffi_f_secp256k1_ec_pubkey_parse _cffi_d_secp256k1_ec_pubkey_parse
#endif

static int _cffi_d_secp256k1_ec_pubkey_serialize(secp256k1_context const * x0, unsigned char * x1, size_t * x2, secp256k1_pubkey const * x3, unsigned int x4)
{
  return secp256k1_ec_pubkey_serialize(x0, x1, x2, x3, x4);
}
#ifndef PYPY_VERSION
static PyObject *
_cffi_f_secp256k1_ec_pubkey_serialize(PyObject *self, PyObject *args)
{
  secp256k1_context const * x0;
  unsigned char * x1;
  size_t * x2;
  secp256k1_pubkey const * x3;
  unsigned int x4;
  Py_ssize_t datasize;
  int result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;
  PyObject *arg3;
  PyObject *arg4;
  PyObject **aa;

  aa = _cffi_unpack_args(args, 5, "secp256k1_ec_pubkey_serialize");
  if (aa == NULL)
    return NULL;
  arg0 = aa[0];
  arg1 = aa[1];
  arg2 = aa[2];
  arg3 = aa[3];
  arg4 = aa[4];

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(5), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = (secp256k1_context const *)alloca((size_t)datasize);
    memset((void *)x0, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(5), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(68), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = (unsigned char *)alloca((size_t)datasize);
    memset((void *)x1, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(68), arg1) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(111), arg2, (char **)&x2);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x2 = (size_t *)alloca((size_t)datasize);
    memset((void *)x2, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x2, _cffi_type(111), arg2) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(51), arg3, (char **)&x3);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x3 = (secp256k1_pubkey const *)alloca((size_t)datasize);
    memset((void *)x3, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x3, _cffi_type(51), arg3) < 0)
      return NULL;
  }

  x4 = _cffi_to_c_int(arg4, unsigned int);
  if (x4 == (unsigned int)-1 && PyErr_Occurred())
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = secp256k1_ec_pubkey_serialize(x0, x1, x2, x3, x4); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  (void)self; /* unused */
  return _cffi_from_c_int(result, int);
}
#else
#  define _cffi_f_secp256k1_ec_pubkey_serialize _cffi_d_secp256k1_ec_pubkey_serialize
#endif

static int _cffi_d_secp256k1_ec_pubkey_tweak_add(secp256k1_context const * x0, secp256k1_pubkey * x1, unsigned char const * x2)
{
  return secp256k1_ec_pubkey_tweak_add(x0, x1, x2);
}
#ifndef PYPY_VERSION
static PyObject *
_cffi_f_secp256k1_ec_pubkey_tweak_add(PyObject *self, PyObject *args)
{
  secp256k1_context const * x0;
  secp256k1_pubkey * x1;
  unsigned char const * x2;
  Py_ssize_t datasize;
  int result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;
  PyObject **aa;

  aa = _cffi_unpack_args(args, 3, "secp256k1_ec_pubkey_tweak_add");
  if (aa == NULL)
    return NULL;
  arg0 = aa[0];
  arg1 = aa[1];
  arg2 = aa[2];

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(5), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = (secp256k1_context const *)alloca((size_t)datasize);
    memset((void *)x0, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(5), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(55), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = (secp256k1_pubkey *)alloca((size_t)datasize);
    memset((void *)x1, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(55), arg1) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(2), arg2, (char **)&x2);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x2 = (unsigned char const *)alloca((size_t)datasize);
    memset((void *)x2, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x2, _cffi_type(2), arg2) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = secp256k1_ec_pubkey_tweak_add(x0, x1, x2); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  (void)self; /* unused */
  return _cffi_from_c_int(result, int);
}
#else
#  define _cffi_f_secp256k1_ec_pubkey_tweak_add _cffi_d_secp256k1_ec_pubkey_tweak_add
#endif

static int _cffi_d_secp256k1_ec_pubkey_tweak_mul(secp256k1_context const * x0, secp256k1_pubkey * x1, unsigned char const * x2)
{
  return secp256k1_ec_pubkey_tweak_mul(x0, x1, x2);
}
#ifndef PYPY_VERSION
static PyObject *
_cffi_f_secp256k1_ec_pubkey_tweak_mul(PyObject *self, PyObject *args)
{
  secp256k1_context const * x0;
  secp256k1_pubkey * x1;
  unsigned char const * x2;
  Py_ssize_t datasize;
  int result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;
  PyObject **aa;

  aa = _cffi_unpack_args(args, 3, "secp256k1_ec_pubkey_tweak_mul");
  if (aa == NULL)
    return NULL;
  arg0 = aa[0];
  arg1 = aa[1];
  arg2 = aa[2];

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(5), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = (secp256k1_context const *)alloca((size_t)datasize);
    memset((void *)x0, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(5), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(55), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = (secp256k1_pubkey *)alloca((size_t)datasize);
    memset((void *)x1, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(55), arg1) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(2), arg2, (char **)&x2);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x2 = (unsigned char const *)alloca((size_t)datasize);
    memset((void *)x2, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x2, _cffi_type(2), arg2) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = secp256k1_ec_pubkey_tweak_mul(x0, x1, x2); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  (void)self; /* unused */
  return _cffi_from_c_int(result, int);
}
#else
#  define _cffi_f_secp256k1_ec_pubkey_tweak_mul _cffi_d_secp256k1_ec_pubkey_tweak_mul
#endif

static int _cffi_d_secp256k1_ec_seckey_verify(secp256k1_context const * x0, unsigned char const * x1)
{
  return secp256k1_ec_seckey_verify(x0, x1);
}
#ifndef PYPY_VERSION
static PyObject *
_cffi_f_secp256k1_ec_seckey_verify(PyObject *self, PyObject *args)
{
  secp256k1_context const * x0;
  unsigned char const * x1;
  Py_ssize_t datasize;
  int result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject **aa;

  aa = _cffi_unpack_args(args, 2, "secp256k1_ec_seckey_verify");
  if (aa == NULL)
    return NULL;
  arg0 = aa[0];
  arg1 = aa[1];

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(5), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = (secp256k1_context const *)alloca((size_t)datasize);
    memset((void *)x0, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(5), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(2), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = (unsigned char const *)alloca((size_t)datasize);
    memset((void *)x1, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(2), arg1) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = secp256k1_ec_seckey_verify(x0, x1); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  (void)self; /* unused */
  return _cffi_from_c_int(result, int);
}
#else
#  define _cffi_f_secp256k1_ec_seckey_verify _cffi_d_secp256k1_ec_seckey_verify
#endif

static int _cffi_d_secp256k1_ecdh(secp256k1_context const * x0, unsigned char * x1, secp256k1_pubkey const * x2, unsigned char const * x3)
{
  return secp256k1_ecdh(x0, x1, x2, x3);
}
#ifndef PYPY_VERSION
static PyObject *
_cffi_f_secp256k1_ecdh(PyObject *self, PyObject *args)
{
  secp256k1_context const * x0;
  unsigned char * x1;
  secp256k1_pubkey const * x2;
  unsigned char const * x3;
  Py_ssize_t datasize;
  int result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;
  PyObject *arg3;
  PyObject **aa;

  aa = _cffi_unpack_args(args, 4, "secp256k1_ecdh");
  if (aa == NULL)
    return NULL;
  arg0 = aa[0];
  arg1 = aa[1];
  arg2 = aa[2];
  arg3 = aa[3];

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(5), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = (secp256k1_context const *)alloca((size_t)datasize);
    memset((void *)x0, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(5), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(68), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = (unsigned char *)alloca((size_t)datasize);
    memset((void *)x1, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(68), arg1) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(51), arg2, (char **)&x2);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x2 = (secp256k1_pubkey const *)alloca((size_t)datasize);
    memset((void *)x2, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x2, _cffi_type(51), arg2) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(2), arg3, (char **)&x3);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x3 = (unsigned char const *)alloca((size_t)datasize);
    memset((void *)x3, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x3, _cffi_type(2), arg3) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = secp256k1_ecdh(x0, x1, x2, x3); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  (void)self; /* unused */
  return _cffi_from_c_int(result, int);
}
#else
#  define _cffi_f_secp256k1_ecdh _cffi_d_secp256k1_ecdh
#endif

static int _cffi_d_secp256k1_ecdsa_recover(secp256k1_context const * x0, secp256k1_pubkey * x1, secp256k1_ecdsa_recoverable_signature const * x2, unsigned char const * x3)
{
  return secp256k1_ecdsa_recover(x0, x1, x2, x3);
}
#ifndef PYPY_VERSION
static PyObject *
_cffi_f_secp256k1_ecdsa_recover(PyObject *self, PyObject *args)
{
  secp256k1_context const * x0;
  secp256k1_pubkey * x1;
  secp256k1_ecdsa_recoverable_signature const * x2;
  unsigned char const * x3;
  Py_ssize_t datasize;
  int result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;
  PyObject *arg3;
  PyObject **aa;

  aa = _cffi_unpack_args(args, 4, "secp256k1_ecdsa_recover");
  if (aa == NULL)
    return NULL;
  arg0 = aa[0];
  arg1 = aa[1];
  arg2 = aa[2];
  arg3 = aa[3];

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(5), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = (secp256k1_context const *)alloca((size_t)datasize);
    memset((void *)x0, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(5), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(55), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = (secp256k1_pubkey *)alloca((size_t)datasize);
    memset((void *)x1, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(55), arg1) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(21), arg2, (char **)&x2);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x2 = (secp256k1_ecdsa_recoverable_signature const *)alloca((size_t)datasize);
    memset((void *)x2, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x2, _cffi_type(21), arg2) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(2), arg3, (char **)&x3);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x3 = (unsigned char const *)alloca((size_t)datasize);
    memset((void *)x3, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x3, _cffi_type(2), arg3) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = secp256k1_ecdsa_recover(x0, x1, x2, x3); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  (void)self; /* unused */
  return _cffi_from_c_int(result, int);
}
#else
#  define _cffi_f_secp256k1_ecdsa_recover _cffi_d_secp256k1_ecdsa_recover
#endif

static int _cffi_d_secp256k1_ecdsa_recoverable_signature_convert(secp256k1_context const * x0, secp256k1_ecdsa_signature * x1, secp256k1_ecdsa_recoverable_signature const * x2)
{
  return secp256k1_ecdsa_recoverable_signature_convert(x0, x1, x2);
}
#ifndef PYPY_VERSION
static PyObject *
_cffi_f_secp256k1_ecdsa_recoverable_signature_convert(PyObject *self, PyObject *args)
{
  secp256k1_context const * x0;
  secp256k1_ecdsa_signature * x1;
  secp256k1_ecdsa_recoverable_signature const * x2;
  Py_ssize_t datasize;
  int result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;
  PyObject **aa;

  aa = _cffi_unpack_args(args, 3, "secp256k1_ecdsa_recoverable_signature_convert");
  if (aa == NULL)
    return NULL;
  arg0 = aa[0];
  arg1 = aa[1];
  arg2 = aa[2];

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(5), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = (secp256k1_context const *)alloca((size_t)datasize);
    memset((void *)x0, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(5), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(20), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = (secp256k1_ecdsa_signature *)alloca((size_t)datasize);
    memset((void *)x1, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(20), arg1) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(21), arg2, (char **)&x2);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x2 = (secp256k1_ecdsa_recoverable_signature const *)alloca((size_t)datasize);
    memset((void *)x2, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x2, _cffi_type(21), arg2) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = secp256k1_ecdsa_recoverable_signature_convert(x0, x1, x2); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  (void)self; /* unused */
  return _cffi_from_c_int(result, int);
}
#else
#  define _cffi_f_secp256k1_ecdsa_recoverable_signature_convert _cffi_d_secp256k1_ecdsa_recoverable_signature_convert
#endif

static int _cffi_d_secp256k1_ecdsa_recoverable_signature_parse_compact(secp256k1_context const * x0, secp256k1_ecdsa_recoverable_signature * x1, unsigned char const * x2, int x3)
{
  return secp256k1_ecdsa_recoverable_signature_parse_compact(x0, x1, x2, x3);
}
#ifndef PYPY_VERSION
static PyObject *
_cffi_f_secp256k1_ecdsa_recoverable_signature_parse_compact(PyObject *self, PyObject *args)
{
  secp256k1_context const * x0;
  secp256k1_ecdsa_recoverable_signature * x1;
  unsigned char const * x2;
  int x3;
  Py_ssize_t datasize;
  int result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;
  PyObject *arg3;
  PyObject **aa;

  aa = _cffi_unpack_args(args, 4, "secp256k1_ecdsa_recoverable_signature_parse_compact");
  if (aa == NULL)
    return NULL;
  arg0 = aa[0];
  arg1 = aa[1];
  arg2 = aa[2];
  arg3 = aa[3];

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(5), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = (secp256k1_context const *)alloca((size_t)datasize);
    memset((void *)x0, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(5), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(6), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = (secp256k1_ecdsa_recoverable_signature *)alloca((size_t)datasize);
    memset((void *)x1, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(6), arg1) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(2), arg2, (char **)&x2);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x2 = (unsigned char const *)alloca((size_t)datasize);
    memset((void *)x2, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x2, _cffi_type(2), arg2) < 0)
      return NULL;
  }

  x3 = _cffi_to_c_int(arg3, int);
  if (x3 == (int)-1 && PyErr_Occurred())
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = secp256k1_ecdsa_recoverable_signature_parse_compact(x0, x1, x2, x3); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  (void)self; /* unused */
  return _cffi_from_c_int(result, int);
}
#else
#  define _cffi_f_secp256k1_ecdsa_recoverable_signature_parse_compact _cffi_d_secp256k1_ecdsa_recoverable_signature_parse_compact
#endif

static int _cffi_d_secp256k1_ecdsa_recoverable_signature_serialize_compact(secp256k1_context const * x0, unsigned char * x1, int * x2, secp256k1_ecdsa_recoverable_signature const * x3)
{
  return secp256k1_ecdsa_recoverable_signature_serialize_compact(x0, x1, x2, x3);
}
#ifndef PYPY_VERSION
static PyObject *
_cffi_f_secp256k1_ecdsa_recoverable_signature_serialize_compact(PyObject *self, PyObject *args)
{
  secp256k1_context const * x0;
  unsigned char * x1;
  int * x2;
  secp256k1_ecdsa_recoverable_signature const * x3;
  Py_ssize_t datasize;
  int result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;
  PyObject *arg3;
  PyObject **aa;

  aa = _cffi_unpack_args(args, 4, "secp256k1_ecdsa_recoverable_signature_serialize_compact");
  if (aa == NULL)
    return NULL;
  arg0 = aa[0];
  arg1 = aa[1];
  arg2 = aa[2];
  arg3 = aa[3];

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(5), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = (secp256k1_context const *)alloca((size_t)datasize);
    memset((void *)x0, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(5), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(68), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = (unsigned char *)alloca((size_t)datasize);
    memset((void *)x1, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(68), arg1) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(94), arg2, (char **)&x2);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x2 = (int *)alloca((size_t)datasize);
    memset((void *)x2, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x2, _cffi_type(94), arg2) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(21), arg3, (char **)&x3);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x3 = (secp256k1_ecdsa_recoverable_signature const *)alloca((size_t)datasize);
    memset((void *)x3, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x3, _cffi_type(21), arg3) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = secp256k1_ecdsa_recoverable_signature_serialize_compact(x0, x1, x2, x3); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  (void)self; /* unused */
  return _cffi_from_c_int(result, int);
}
#else
#  define _cffi_f_secp256k1_ecdsa_recoverable_signature_serialize_compact _cffi_d_secp256k1_ecdsa_recoverable_signature_serialize_compact
#endif

static int _cffi_d_secp256k1_ecdsa_sign(secp256k1_context const * x0, secp256k1_ecdsa_signature * x1, unsigned char const * x2, unsigned char const * x3, int(* x4)(unsigned char *, unsigned char const *, unsigned char const *, unsigned char const *, void *, unsigned int), void const * x5)
{
  return secp256k1_ecdsa_sign(x0, x1, x2, x3, x4, x5);
}
#ifndef PYPY_VERSION
static PyObject *
_cffi_f_secp256k1_ecdsa_sign(PyObject *self, PyObject *args)
{
  secp256k1_context const * x0;
  secp256k1_ecdsa_signature * x1;
  unsigned char const * x2;
  unsigned char const * x3;
  int(* x4)(unsigned char *, unsigned char const *, unsigned char const *, unsigned char const *, void *, unsigned int);
  void const * x5;
  Py_ssize_t datasize;
  int result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;
  PyObject *arg3;
  PyObject *arg4;
  PyObject *arg5;
  PyObject **aa;

  aa = _cffi_unpack_args(args, 6, "secp256k1_ecdsa_sign");
  if (aa == NULL)
    return NULL;
  arg0 = aa[0];
  arg1 = aa[1];
  arg2 = aa[2];
  arg3 = aa[3];
  arg4 = aa[4];
  arg5 = aa[5];

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(5), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = (secp256k1_context const *)alloca((size_t)datasize);
    memset((void *)x0, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(5), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(20), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = (secp256k1_ecdsa_signature *)alloca((size_t)datasize);
    memset((void *)x1, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(20), arg1) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(2), arg2, (char **)&x2);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x2 = (unsigned char const *)alloca((size_t)datasize);
    memset((void *)x2, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x2, _cffi_type(2), arg2) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(2), arg3, (char **)&x3);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x3 = (unsigned char const *)alloca((size_t)datasize);
    memset((void *)x3, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x3, _cffi_type(2), arg3) < 0)
      return NULL;
  }

  x4 = (int(*)(unsigned char *, unsigned char const *, unsigned char const *, unsigned char const *, void *, unsigned int))_cffi_to_c_pointer(arg4, _cffi_type(15));
  if (x4 == (int(*)(unsigned char *, unsigned char const *, unsigned char const *, unsigned char const *, void *, unsigned int))NULL && PyErr_Occurred())
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(16), arg5, (char **)&x5);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x5 = (void const *)alloca((size_t)datasize);
    memset((void *)x5, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x5, _cffi_type(16), arg5) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = secp256k1_ecdsa_sign(x0, x1, x2, x3, x4, x5); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  (void)self; /* unused */
  return _cffi_from_c_int(result, int);
}
#else
#  define _cffi_f_secp256k1_ecdsa_sign _cffi_d_secp256k1_ecdsa_sign
#endif

static int _cffi_d_secp256k1_ecdsa_sign_recoverable(secp256k1_context const * x0, secp256k1_ecdsa_recoverable_signature * x1, unsigned char const * x2, unsigned char const * x3, int(* x4)(unsigned char *, unsigned char const *, unsigned char const *, unsigned char const *, void *, unsigned int), void const * x5)
{
  return secp256k1_ecdsa_sign_recoverable(x0, x1, x2, x3, x4, x5);
}
#ifndef PYPY_VERSION
static PyObject *
_cffi_f_secp256k1_ecdsa_sign_recoverable(PyObject *self, PyObject *args)
{
  secp256k1_context const * x0;
  secp256k1_ecdsa_recoverable_signature * x1;
  unsigned char const * x2;
  unsigned char const * x3;
  int(* x4)(unsigned char *, unsigned char const *, unsigned char const *, unsigned char const *, void *, unsigned int);
  void const * x5;
  Py_ssize_t datasize;
  int result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;
  PyObject *arg3;
  PyObject *arg4;
  PyObject *arg5;
  PyObject **aa;

  aa = _cffi_unpack_args(args, 6, "secp256k1_ecdsa_sign_recoverable");
  if (aa == NULL)
    return NULL;
  arg0 = aa[0];
  arg1 = aa[1];
  arg2 = aa[2];
  arg3 = aa[3];
  arg4 = aa[4];
  arg5 = aa[5];

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(5), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = (secp256k1_context const *)alloca((size_t)datasize);
    memset((void *)x0, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(5), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(6), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = (secp256k1_ecdsa_recoverable_signature *)alloca((size_t)datasize);
    memset((void *)x1, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(6), arg1) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(2), arg2, (char **)&x2);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x2 = (unsigned char const *)alloca((size_t)datasize);
    memset((void *)x2, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x2, _cffi_type(2), arg2) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(2), arg3, (char **)&x3);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x3 = (unsigned char const *)alloca((size_t)datasize);
    memset((void *)x3, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x3, _cffi_type(2), arg3) < 0)
      return NULL;
  }

  x4 = (int(*)(unsigned char *, unsigned char const *, unsigned char const *, unsigned char const *, void *, unsigned int))_cffi_to_c_pointer(arg4, _cffi_type(15));
  if (x4 == (int(*)(unsigned char *, unsigned char const *, unsigned char const *, unsigned char const *, void *, unsigned int))NULL && PyErr_Occurred())
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(16), arg5, (char **)&x5);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x5 = (void const *)alloca((size_t)datasize);
    memset((void *)x5, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x5, _cffi_type(16), arg5) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = secp256k1_ecdsa_sign_recoverable(x0, x1, x2, x3, x4, x5); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  (void)self; /* unused */
  return _cffi_from_c_int(result, int);
}
#else
#  define _cffi_f_secp256k1_ecdsa_sign_recoverable _cffi_d_secp256k1_ecdsa_sign_recoverable
#endif

static int _cffi_d_secp256k1_ecdsa_signature_normalize(secp256k1_context const * x0, secp256k1_ecdsa_signature * x1, secp256k1_ecdsa_signature const * x2)
{
  return secp256k1_ecdsa_signature_normalize(x0, x1, x2);
}
#ifndef PYPY_VERSION
static PyObject *
_cffi_f_secp256k1_ecdsa_signature_normalize(PyObject *self, PyObject *args)
{
  secp256k1_context const * x0;
  secp256k1_ecdsa_signature * x1;
  secp256k1_ecdsa_signature const * x2;
  Py_ssize_t datasize;
  int result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;
  PyObject **aa;

  aa = _cffi_unpack_args(args, 3, "secp256k1_ecdsa_signature_normalize");
  if (aa == NULL)
    return NULL;
  arg0 = aa[0];
  arg1 = aa[1];
  arg2 = aa[2];

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(5), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = (secp256k1_context const *)alloca((size_t)datasize);
    memset((void *)x0, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(5), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(20), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = (secp256k1_ecdsa_signature *)alloca((size_t)datasize);
    memset((void *)x1, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(20), arg1) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(26), arg2, (char **)&x2);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x2 = (secp256k1_ecdsa_signature const *)alloca((size_t)datasize);
    memset((void *)x2, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x2, _cffi_type(26), arg2) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = secp256k1_ecdsa_signature_normalize(x0, x1, x2); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  (void)self; /* unused */
  return _cffi_from_c_int(result, int);
}
#else
#  define _cffi_f_secp256k1_ecdsa_signature_normalize _cffi_d_secp256k1_ecdsa_signature_normalize
#endif

static int _cffi_d_secp256k1_ecdsa_signature_parse_compact(secp256k1_context const * x0, secp256k1_ecdsa_signature * x1, unsigned char const * x2)
{
  return secp256k1_ecdsa_signature_parse_compact(x0, x1, x2);
}
#ifndef PYPY_VERSION
static PyObject *
_cffi_f_secp256k1_ecdsa_signature_parse_compact(PyObject *self, PyObject *args)
{
  secp256k1_context const * x0;
  secp256k1_ecdsa_signature * x1;
  unsigned char const * x2;
  Py_ssize_t datasize;
  int result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;
  PyObject **aa;

  aa = _cffi_unpack_args(args, 3, "secp256k1_ecdsa_signature_parse_compact");
  if (aa == NULL)
    return NULL;
  arg0 = aa[0];
  arg1 = aa[1];
  arg2 = aa[2];

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(5), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = (secp256k1_context const *)alloca((size_t)datasize);
    memset((void *)x0, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(5), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(20), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = (secp256k1_ecdsa_signature *)alloca((size_t)datasize);
    memset((void *)x1, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(20), arg1) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(2), arg2, (char **)&x2);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x2 = (unsigned char const *)alloca((size_t)datasize);
    memset((void *)x2, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x2, _cffi_type(2), arg2) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = secp256k1_ecdsa_signature_parse_compact(x0, x1, x2); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  (void)self; /* unused */
  return _cffi_from_c_int(result, int);
}
#else
#  define _cffi_f_secp256k1_ecdsa_signature_parse_compact _cffi_d_secp256k1_ecdsa_signature_parse_compact
#endif

static int _cffi_d_secp256k1_ecdsa_signature_parse_der(secp256k1_context const * x0, secp256k1_ecdsa_signature * x1, unsigned char const * x2, size_t x3)
{
  return secp256k1_ecdsa_signature_parse_der(x0, x1, x2, x3);
}
#ifndef PYPY_VERSION
static PyObject *
_cffi_f_secp256k1_ecdsa_signature_parse_der(PyObject *self, PyObject *args)
{
  secp256k1_context const * x0;
  secp256k1_ecdsa_signature * x1;
  unsigned char const * x2;
  size_t x3;
  Py_ssize_t datasize;
  int result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;
  PyObject *arg3;
  PyObject **aa;

  aa = _cffi_unpack_args(args, 4, "secp256k1_ecdsa_signature_parse_der");
  if (aa == NULL)
    return NULL;
  arg0 = aa[0];
  arg1 = aa[1];
  arg2 = aa[2];
  arg3 = aa[3];

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(5), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = (secp256k1_context const *)alloca((size_t)datasize);
    memset((void *)x0, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(5), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(20), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = (secp256k1_ecdsa_signature *)alloca((size_t)datasize);
    memset((void *)x1, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(20), arg1) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(2), arg2, (char **)&x2);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x2 = (unsigned char const *)alloca((size_t)datasize);
    memset((void *)x2, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x2, _cffi_type(2), arg2) < 0)
      return NULL;
  }

  x3 = _cffi_to_c_int(arg3, size_t);
  if (x3 == (size_t)-1 && PyErr_Occurred())
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = secp256k1_ecdsa_signature_parse_der(x0, x1, x2, x3); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  (void)self; /* unused */
  return _cffi_from_c_int(result, int);
}
#else
#  define _cffi_f_secp256k1_ecdsa_signature_parse_der _cffi_d_secp256k1_ecdsa_signature_parse_der
#endif

static int _cffi_d_secp256k1_ecdsa_signature_serialize_compact(secp256k1_context const * x0, unsigned char * x1, secp256k1_ecdsa_signature const * x2)
{
  return secp256k1_ecdsa_signature_serialize_compact(x0, x1, x2);
}
#ifndef PYPY_VERSION
static PyObject *
_cffi_f_secp256k1_ecdsa_signature_serialize_compact(PyObject *self, PyObject *args)
{
  secp256k1_context const * x0;
  unsigned char * x1;
  secp256k1_ecdsa_signature const * x2;
  Py_ssize_t datasize;
  int result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;
  PyObject **aa;

  aa = _cffi_unpack_args(args, 3, "secp256k1_ecdsa_signature_serialize_compact");
  if (aa == NULL)
    return NULL;
  arg0 = aa[0];
  arg1 = aa[1];
  arg2 = aa[2];

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(5), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = (secp256k1_context const *)alloca((size_t)datasize);
    memset((void *)x0, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(5), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(68), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = (unsigned char *)alloca((size_t)datasize);
    memset((void *)x1, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(68), arg1) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(26), arg2, (char **)&x2);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x2 = (secp256k1_ecdsa_signature const *)alloca((size_t)datasize);
    memset((void *)x2, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x2, _cffi_type(26), arg2) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = secp256k1_ecdsa_signature_serialize_compact(x0, x1, x2); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  (void)self; /* unused */
  return _cffi_from_c_int(result, int);
}
#else
#  define _cffi_f_secp256k1_ecdsa_signature_serialize_compact _cffi_d_secp256k1_ecdsa_signature_serialize_compact
#endif

static int _cffi_d_secp256k1_ecdsa_signature_serialize_der(secp256k1_context const * x0, unsigned char * x1, size_t * x2, secp256k1_ecdsa_signature const * x3)
{
  return secp256k1_ecdsa_signature_serialize_der(x0, x1, x2, x3);
}
#ifndef PYPY_VERSION
static PyObject *
_cffi_f_secp256k1_ecdsa_signature_serialize_der(PyObject *self, PyObject *args)
{
  secp256k1_context const * x0;
  unsigned char * x1;
  size_t * x2;
  secp256k1_ecdsa_signature const * x3;
  Py_ssize_t datasize;
  int result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;
  PyObject *arg3;
  PyObject **aa;

  aa = _cffi_unpack_args(args, 4, "secp256k1_ecdsa_signature_serialize_der");
  if (aa == NULL)
    return NULL;
  arg0 = aa[0];
  arg1 = aa[1];
  arg2 = aa[2];
  arg3 = aa[3];

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(5), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = (secp256k1_context const *)alloca((size_t)datasize);
    memset((void *)x0, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(5), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(68), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = (unsigned char *)alloca((size_t)datasize);
    memset((void *)x1, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(68), arg1) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(111), arg2, (char **)&x2);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x2 = (size_t *)alloca((size_t)datasize);
    memset((void *)x2, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x2, _cffi_type(111), arg2) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(26), arg3, (char **)&x3);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x3 = (secp256k1_ecdsa_signature const *)alloca((size_t)datasize);
    memset((void *)x3, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x3, _cffi_type(26), arg3) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = secp256k1_ecdsa_signature_serialize_der(x0, x1, x2, x3); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  (void)self; /* unused */
  return _cffi_from_c_int(result, int);
}
#else
#  define _cffi_f_secp256k1_ecdsa_signature_serialize_der _cffi_d_secp256k1_ecdsa_signature_serialize_der
#endif

static int _cffi_d_secp256k1_ecdsa_verify(secp256k1_context const * x0, secp256k1_ecdsa_signature const * x1, unsigned char const * x2, secp256k1_pubkey const * x3)
{
  return secp256k1_ecdsa_verify(x0, x1, x2, x3);
}
#ifndef PYPY_VERSION
static PyObject *
_cffi_f_secp256k1_ecdsa_verify(PyObject *self, PyObject *args)
{
  secp256k1_context const * x0;
  secp256k1_ecdsa_signature const * x1;
  unsigned char const * x2;
  secp256k1_pubkey const * x3;
  Py_ssize_t datasize;
  int result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;
  PyObject *arg3;
  PyObject **aa;

  aa = _cffi_unpack_args(args, 4, "secp256k1_ecdsa_verify");
  if (aa == NULL)
    return NULL;
  arg0 = aa[0];
  arg1 = aa[1];
  arg2 = aa[2];
  arg3 = aa[3];

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(5), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = (secp256k1_context const *)alloca((size_t)datasize);
    memset((void *)x0, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(5), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(26), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = (secp256k1_ecdsa_signature const *)alloca((size_t)datasize);
    memset((void *)x1, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(26), arg1) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(2), arg2, (char **)&x2);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x2 = (unsigned char const *)alloca((size_t)datasize);
    memset((void *)x2, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x2, _cffi_type(2), arg2) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(51), arg3, (char **)&x3);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x3 = (secp256k1_pubkey const *)alloca((size_t)datasize);
    memset((void *)x3, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x3, _cffi_type(51), arg3) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = secp256k1_ecdsa_verify(x0, x1, x2, x3); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  (void)self; /* unused */
  return _cffi_from_c_int(result, int);
}
#else
#  define _cffi_f_secp256k1_ecdsa_verify _cffi_d_secp256k1_ecdsa_verify
#endif

static int _cffi_d_secp256k1_schnorr_generate_nonce_pair(secp256k1_context const * x0, secp256k1_pubkey * x1, unsigned char * x2, unsigned char const * x3, unsigned char const * x4, int(* x5)(unsigned char *, unsigned char const *, unsigned char const *, unsigned char const *, void *, unsigned int), void const * x6)
{
  return secp256k1_schnorr_generate_nonce_pair(x0, x1, x2, x3, x4, x5, x6);
}
#ifndef PYPY_VERSION
static PyObject *
_cffi_f_secp256k1_schnorr_generate_nonce_pair(PyObject *self, PyObject *args)
{
  secp256k1_context const * x0;
  secp256k1_pubkey * x1;
  unsigned char * x2;
  unsigned char const * x3;
  unsigned char const * x4;
  int(* x5)(unsigned char *, unsigned char const *, unsigned char const *, unsigned char const *, void *, unsigned int);
  void const * x6;
  Py_ssize_t datasize;
  int result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;
  PyObject *arg3;
  PyObject *arg4;
  PyObject *arg5;
  PyObject *arg6;
  PyObject **aa;

  aa = _cffi_unpack_args(args, 7, "secp256k1_schnorr_generate_nonce_pair");
  if (aa == NULL)
    return NULL;
  arg0 = aa[0];
  arg1 = aa[1];
  arg2 = aa[2];
  arg3 = aa[3];
  arg4 = aa[4];
  arg5 = aa[5];
  arg6 = aa[6];

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(5), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = (secp256k1_context const *)alloca((size_t)datasize);
    memset((void *)x0, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(5), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(55), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = (secp256k1_pubkey *)alloca((size_t)datasize);
    memset((void *)x1, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(55), arg1) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(68), arg2, (char **)&x2);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x2 = (unsigned char *)alloca((size_t)datasize);
    memset((void *)x2, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x2, _cffi_type(68), arg2) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(2), arg3, (char **)&x3);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x3 = (unsigned char const *)alloca((size_t)datasize);
    memset((void *)x3, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x3, _cffi_type(2), arg3) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(2), arg4, (char **)&x4);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x4 = (unsigned char const *)alloca((size_t)datasize);
    memset((void *)x4, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x4, _cffi_type(2), arg4) < 0)
      return NULL;
  }

  x5 = (int(*)(unsigned char *, unsigned char const *, unsigned char const *, unsigned char const *, void *, unsigned int))_cffi_to_c_pointer(arg5, _cffi_type(15));
  if (x5 == (int(*)(unsigned char *, unsigned char const *, unsigned char const *, unsigned char const *, void *, unsigned int))NULL && PyErr_Occurred())
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(16), arg6, (char **)&x6);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x6 = (void const *)alloca((size_t)datasize);
    memset((void *)x6, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x6, _cffi_type(16), arg6) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = secp256k1_schnorr_generate_nonce_pair(x0, x1, x2, x3, x4, x5, x6); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  (void)self; /* unused */
  return _cffi_from_c_int(result, int);
}
#else
#  define _cffi_f_secp256k1_schnorr_generate_nonce_pair _cffi_d_secp256k1_schnorr_generate_nonce_pair
#endif

static int _cffi_d_secp256k1_schnorr_partial_combine(secp256k1_context const * x0, unsigned char * x1, unsigned char const * * x2, int x3)
{
  return secp256k1_schnorr_partial_combine(x0, x1, x2, x3);
}
#ifndef PYPY_VERSION
static PyObject *
_cffi_f_secp256k1_schnorr_partial_combine(PyObject *self, PyObject *args)
{
  secp256k1_context const * x0;
  unsigned char * x1;
  unsigned char const * * x2;
  int x3;
  Py_ssize_t datasize;
  int result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;
  PyObject *arg3;
  PyObject **aa;

  aa = _cffi_unpack_args(args, 4, "secp256k1_schnorr_partial_combine");
  if (aa == NULL)
    return NULL;
  arg0 = aa[0];
  arg1 = aa[1];
  arg2 = aa[2];
  arg3 = aa[3];

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(5), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = (secp256k1_context const *)alloca((size_t)datasize);
    memset((void *)x0, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(5), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(68), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = (unsigned char *)alloca((size_t)datasize);
    memset((void *)x1, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(68), arg1) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(124), arg2, (char **)&x2);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x2 = (unsigned char const * *)alloca((size_t)datasize);
    memset((void *)x2, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x2, _cffi_type(124), arg2) < 0)
      return NULL;
  }

  x3 = _cffi_to_c_int(arg3, int);
  if (x3 == (int)-1 && PyErr_Occurred())
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = secp256k1_schnorr_partial_combine(x0, x1, x2, x3); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  (void)self; /* unused */
  return _cffi_from_c_int(result, int);
}
#else
#  define _cffi_f_secp256k1_schnorr_partial_combine _cffi_d_secp256k1_schnorr_partial_combine
#endif

static int _cffi_d_secp256k1_schnorr_partial_sign(secp256k1_context const * x0, unsigned char * x1, unsigned char const * x2, unsigned char const * x3, secp256k1_pubkey const * x4, unsigned char const * x5)
{
  return secp256k1_schnorr_partial_sign(x0, x1, x2, x3, x4, x5);
}
#ifndef PYPY_VERSION
static PyObject *
_cffi_f_secp256k1_schnorr_partial_sign(PyObject *self, PyObject *args)
{
  secp256k1_context const * x0;
  unsigned char * x1;
  unsigned char const * x2;
  unsigned char const * x3;
  secp256k1_pubkey const * x4;
  unsigned char const * x5;
  Py_ssize_t datasize;
  int result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;
  PyObject *arg3;
  PyObject *arg4;
  PyObject *arg5;
  PyObject **aa;

  aa = _cffi_unpack_args(args, 6, "secp256k1_schnorr_partial_sign");
  if (aa == NULL)
    return NULL;
  arg0 = aa[0];
  arg1 = aa[1];
  arg2 = aa[2];
  arg3 = aa[3];
  arg4 = aa[4];
  arg5 = aa[5];

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(5), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = (secp256k1_context const *)alloca((size_t)datasize);
    memset((void *)x0, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(5), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(68), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = (unsigned char *)alloca((size_t)datasize);
    memset((void *)x1, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(68), arg1) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(2), arg2, (char **)&x2);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x2 = (unsigned char const *)alloca((size_t)datasize);
    memset((void *)x2, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x2, _cffi_type(2), arg2) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(2), arg3, (char **)&x3);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x3 = (unsigned char const *)alloca((size_t)datasize);
    memset((void *)x3, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x3, _cffi_type(2), arg3) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(51), arg4, (char **)&x4);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x4 = (secp256k1_pubkey const *)alloca((size_t)datasize);
    memset((void *)x4, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x4, _cffi_type(51), arg4) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(2), arg5, (char **)&x5);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x5 = (unsigned char const *)alloca((size_t)datasize);
    memset((void *)x5, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x5, _cffi_type(2), arg5) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = secp256k1_schnorr_partial_sign(x0, x1, x2, x3, x4, x5); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  (void)self; /* unused */
  return _cffi_from_c_int(result, int);
}
#else
#  define _cffi_f_secp256k1_schnorr_partial_sign _cffi_d_secp256k1_schnorr_partial_sign
#endif

static int _cffi_d_secp256k1_schnorr_recover(secp256k1_context const * x0, secp256k1_pubkey * x1, unsigned char const * x2, unsigned char const * x3)
{
  return secp256k1_schnorr_recover(x0, x1, x2, x3);
}
#ifndef PYPY_VERSION
static PyObject *
_cffi_f_secp256k1_schnorr_recover(PyObject *self, PyObject *args)
{
  secp256k1_context const * x0;
  secp256k1_pubkey * x1;
  unsigned char const * x2;
  unsigned char const * x3;
  Py_ssize_t datasize;
  int result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;
  PyObject *arg3;
  PyObject **aa;

  aa = _cffi_unpack_args(args, 4, "secp256k1_schnorr_recover");
  if (aa == NULL)
    return NULL;
  arg0 = aa[0];
  arg1 = aa[1];
  arg2 = aa[2];
  arg3 = aa[3];

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(5), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = (secp256k1_context const *)alloca((size_t)datasize);
    memset((void *)x0, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(5), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(55), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = (secp256k1_pubkey *)alloca((size_t)datasize);
    memset((void *)x1, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(55), arg1) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(2), arg2, (char **)&x2);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x2 = (unsigned char const *)alloca((size_t)datasize);
    memset((void *)x2, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x2, _cffi_type(2), arg2) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(2), arg3, (char **)&x3);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x3 = (unsigned char const *)alloca((size_t)datasize);
    memset((void *)x3, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x3, _cffi_type(2), arg3) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = secp256k1_schnorr_recover(x0, x1, x2, x3); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  (void)self; /* unused */
  return _cffi_from_c_int(result, int);
}
#else
#  define _cffi_f_secp256k1_schnorr_recover _cffi_d_secp256k1_schnorr_recover
#endif

static int _cffi_d_secp256k1_schnorr_sign(secp256k1_context const * x0, unsigned char * x1, unsigned char const * x2, unsigned char const * x3, int(* x4)(unsigned char *, unsigned char const *, unsigned char const *, unsigned char const *, void *, unsigned int), void const * x5)
{
  return secp256k1_schnorr_sign(x0, x1, x2, x3, x4, x5);
}
#ifndef PYPY_VERSION
static PyObject *
_cffi_f_secp256k1_schnorr_sign(PyObject *self, PyObject *args)
{
  secp256k1_context const * x0;
  unsigned char * x1;
  unsigned char const * x2;
  unsigned char const * x3;
  int(* x4)(unsigned char *, unsigned char const *, unsigned char const *, unsigned char const *, void *, unsigned int);
  void const * x5;
  Py_ssize_t datasize;
  int result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;
  PyObject *arg3;
  PyObject *arg4;
  PyObject *arg5;
  PyObject **aa;

  aa = _cffi_unpack_args(args, 6, "secp256k1_schnorr_sign");
  if (aa == NULL)
    return NULL;
  arg0 = aa[0];
  arg1 = aa[1];
  arg2 = aa[2];
  arg3 = aa[3];
  arg4 = aa[4];
  arg5 = aa[5];

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(5), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = (secp256k1_context const *)alloca((size_t)datasize);
    memset((void *)x0, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(5), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(68), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = (unsigned char *)alloca((size_t)datasize);
    memset((void *)x1, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(68), arg1) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(2), arg2, (char **)&x2);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x2 = (unsigned char const *)alloca((size_t)datasize);
    memset((void *)x2, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x2, _cffi_type(2), arg2) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(2), arg3, (char **)&x3);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x3 = (unsigned char const *)alloca((size_t)datasize);
    memset((void *)x3, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x3, _cffi_type(2), arg3) < 0)
      return NULL;
  }

  x4 = (int(*)(unsigned char *, unsigned char const *, unsigned char const *, unsigned char const *, void *, unsigned int))_cffi_to_c_pointer(arg4, _cffi_type(15));
  if (x4 == (int(*)(unsigned char *, unsigned char const *, unsigned char const *, unsigned char const *, void *, unsigned int))NULL && PyErr_Occurred())
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(16), arg5, (char **)&x5);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x5 = (void const *)alloca((size_t)datasize);
    memset((void *)x5, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x5, _cffi_type(16), arg5) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = secp256k1_schnorr_sign(x0, x1, x2, x3, x4, x5); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  (void)self; /* unused */
  return _cffi_from_c_int(result, int);
}
#else
#  define _cffi_f_secp256k1_schnorr_sign _cffi_d_secp256k1_schnorr_sign
#endif

static int _cffi_d_secp256k1_schnorr_verify(secp256k1_context const * x0, unsigned char const * x1, unsigned char const * x2, secp256k1_pubkey const * x3)
{
  return secp256k1_schnorr_verify(x0, x1, x2, x3);
}
#ifndef PYPY_VERSION
static PyObject *
_cffi_f_secp256k1_schnorr_verify(PyObject *self, PyObject *args)
{
  secp256k1_context const * x0;
  unsigned char const * x1;
  unsigned char const * x2;
  secp256k1_pubkey const * x3;
  Py_ssize_t datasize;
  int result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;
  PyObject *arg3;
  PyObject **aa;

  aa = _cffi_unpack_args(args, 4, "secp256k1_schnorr_verify");
  if (aa == NULL)
    return NULL;
  arg0 = aa[0];
  arg1 = aa[1];
  arg2 = aa[2];
  arg3 = aa[3];

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(5), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = (secp256k1_context const *)alloca((size_t)datasize);
    memset((void *)x0, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(5), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(2), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = (unsigned char const *)alloca((size_t)datasize);
    memset((void *)x1, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(2), arg1) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(2), arg2, (char **)&x2);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x2 = (unsigned char const *)alloca((size_t)datasize);
    memset((void *)x2, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x2, _cffi_type(2), arg2) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(51), arg3, (char **)&x3);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x3 = (secp256k1_pubkey const *)alloca((size_t)datasize);
    memset((void *)x3, 0, (size_t)datasize);
    if (_cffi_convert_array_from_object((char *)x3, _cffi_type(51), arg3) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = secp256k1_schnorr_verify(x0, x1, x2, x3); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  (void)self; /* unused */
  return _cffi_from_c_int(result, int);
}
#else
#  define _cffi_f_secp256k1_schnorr_verify _cffi_d_secp256k1_schnorr_verify
#endif

static int _cffi_const_SECP256K1_CONTEXT_NONE(unsigned long long *o)
{
  int n = (SECP256K1_CONTEXT_NONE) <= 0;
  *o = (unsigned long long)((SECP256K1_CONTEXT_NONE) << 0);  /* check that SECP256K1_CONTEXT_NONE is an integer */
  if (!_cffi_check_int(*o, n, 1U))
    n |= 2;
  return n;
}

static int _cffi_const_SECP256K1_CONTEXT_SIGN(unsigned long long *o)
{
  int n = (SECP256K1_CONTEXT_SIGN) <= 0;
  *o = (unsigned long long)((SECP256K1_CONTEXT_SIGN) << 0);  /* check that SECP256K1_CONTEXT_SIGN is an integer */
  if (!_cffi_check_int(*o, n, 513U))
    n |= 2;
  return n;
}

static int _cffi_const_SECP256K1_CONTEXT_VERIFY(unsigned long long *o)
{
  int n = (SECP256K1_CONTEXT_VERIFY) <= 0;
  *o = (unsigned long long)((SECP256K1_CONTEXT_VERIFY) << 0);  /* check that SECP256K1_CONTEXT_VERIFY is an integer */
  if (!_cffi_check_int(*o, n, 257U))
    n |= 2;
  return n;
}

static int _cffi_const_SECP256K1_EC_COMPRESSED(unsigned long long *o)
{
  int n = (SECP256K1_EC_COMPRESSED) <= 0;
  *o = (unsigned long long)((SECP256K1_EC_COMPRESSED) << 0);  /* check that SECP256K1_EC_COMPRESSED is an integer */
  if (!_cffi_check_int(*o, n, 258U))
    n |= 2;
  return n;
}

static int _cffi_const_SECP256K1_EC_UNCOMPRESSED(unsigned long long *o)
{
  int n = (SECP256K1_EC_UNCOMPRESSED) <= 0;
  *o = (unsigned long long)((SECP256K1_EC_UNCOMPRESSED) << 0);  /* check that SECP256K1_EC_UNCOMPRESSED is an integer */
  if (!_cffi_check_int(*o, n, 2U))
    n |= 2;
  return n;
}

static int _cffi_const_SECP256K1_FLAGS_BIT_COMPRESSION(unsigned long long *o)
{
  int n = (SECP256K1_FLAGS_BIT_COMPRESSION) <= 0;
  *o = (unsigned long long)((SECP256K1_FLAGS_BIT_COMPRESSION) << 0);  /* check that SECP256K1_FLAGS_BIT_COMPRESSION is an integer */
  if (!_cffi_check_int(*o, n, 256U))
    n |= 2;
  return n;
}

static int _cffi_const_SECP256K1_FLAGS_BIT_CONTEXT_SIGN(unsigned long long *o)
{
  int n = (SECP256K1_FLAGS_BIT_CONTEXT_SIGN) <= 0;
  *o = (unsigned long long)((SECP256K1_FLAGS_BIT_CONTEXT_SIGN) << 0);  /* check that SECP256K1_FLAGS_BIT_CONTEXT_SIGN is an integer */
  if (!_cffi_check_int(*o, n, 512U))
    n |= 2;
  return n;
}

static int _cffi_const_SECP256K1_FLAGS_BIT_CONTEXT_VERIFY(unsigned long long *o)
{
  int n = (SECP256K1_FLAGS_BIT_CONTEXT_VERIFY) <= 0;
  *o = (unsigned long long)((SECP256K1_FLAGS_BIT_CONTEXT_VERIFY) << 0);  /* check that SECP256K1_FLAGS_BIT_CONTEXT_VERIFY is an integer */
  if (!_cffi_check_int(*o, n, 256U))
    n |= 2;
  return n;
}

static int _cffi_const_SECP256K1_FLAGS_TYPE_COMPRESSION(unsigned long long *o)
{
  int n = (SECP256K1_FLAGS_TYPE_COMPRESSION) <= 0;
  *o = (unsigned long long)((SECP256K1_FLAGS_TYPE_COMPRESSION) << 0);  /* check that SECP256K1_FLAGS_TYPE_COMPRESSION is an integer */
  if (!_cffi_check_int(*o, n, 2U))
    n |= 2;
  return n;
}

static int _cffi_const_SECP256K1_FLAGS_TYPE_CONTEXT(unsigned long long *o)
{
  int n = (SECP256K1_FLAGS_TYPE_CONTEXT) <= 0;
  *o = (unsigned long long)((SECP256K1_FLAGS_TYPE_CONTEXT) << 0);  /* check that SECP256K1_FLAGS_TYPE_CONTEXT is an integer */
  if (!_cffi_check_int(*o, n, 1U))
    n |= 2;
  return n;
}

static int _cffi_const_SECP256K1_FLAGS_TYPE_MASK(unsigned long long *o)
{
  int n = (SECP256K1_FLAGS_TYPE_MASK) <= 0;
  *o = (unsigned long long)((SECP256K1_FLAGS_TYPE_MASK) << 0);  /* check that SECP256K1_FLAGS_TYPE_MASK is an integer */
  if (!_cffi_check_int(*o, n, 255U))
    n |= 2;
  return n;
}

static const struct _cffi_global_s _cffi_globals[] = {
  { "SECP256K1_CONTEXT_NONE", (void *)_cffi_const_SECP256K1_CONTEXT_NONE, _CFFI_OP(_CFFI_OP_CONSTANT_INT, -1), (void *)0 },
  { "SECP256K1_CONTEXT_SIGN", (void *)_cffi_const_SECP256K1_CONTEXT_SIGN, _CFFI_OP(_CFFI_OP_CONSTANT_INT, -1), (void *)0 },
  { "SECP256K1_CONTEXT_VERIFY", (void *)_cffi_const_SECP256K1_CONTEXT_VERIFY, _CFFI_OP(_CFFI_OP_CONSTANT_INT, -1), (void *)0 },
  { "SECP256K1_EC_COMPRESSED", (void *)_cffi_const_SECP256K1_EC_COMPRESSED, _CFFI_OP(_CFFI_OP_CONSTANT_INT, -1), (void *)0 },
  { "SECP256K1_EC_UNCOMPRESSED", (void *)_cffi_const_SECP256K1_EC_UNCOMPRESSED, _CFFI_OP(_CFFI_OP_CONSTANT_INT, -1), (void *)0 },
  { "SECP256K1_FLAGS_BIT_COMPRESSION", (void *)_cffi_const_SECP256K1_FLAGS_BIT_COMPRESSION, _CFFI_OP(_CFFI_OP_CONSTANT_INT, -1), (void *)0 },
  { "SECP256K1_FLAGS_BIT_CONTEXT_SIGN", (void *)_cffi_const_SECP256K1_FLAGS_BIT_CONTEXT_SIGN, _CFFI_OP(_CFFI_OP_CONSTANT_INT, -1), (void *)0 },
  { "SECP256K1_FLAGS_BIT_CONTEXT_VERIFY", (void *)_cffi_const_SECP256K1_FLAGS_BIT_CONTEXT_VERIFY, _CFFI_OP(_CFFI_OP_CONSTANT_INT, -1), (void *)0 },
  { "SECP256K1_FLAGS_TYPE_COMPRESSION", (void *)_cffi_const_SECP256K1_FLAGS_TYPE_COMPRESSION, _CFFI_OP(_CFFI_OP_CONSTANT_INT, -1), (void *)0 },
  { "SECP256K1_FLAGS_TYPE_CONTEXT", (void *)_cffi_const_SECP256K1_FLAGS_TYPE_CONTEXT, _CFFI_OP(_CFFI_OP_CONSTANT_INT, -1), (void *)0 },
  { "SECP256K1_FLAGS_TYPE_MASK", (void *)_cffi_const_SECP256K1_FLAGS_TYPE_MASK, _CFFI_OP(_CFFI_OP_CONSTANT_INT, -1), (void *)0 },
  { "secp256k1_context_clone", (void *)_cffi_f_secp256k1_context_clone, _CFFI_OP(_CFFI_OP_CPYTHON_BLTN_O, 169), (void *)_cffi_d_secp256k1_context_clone },
  { "secp256k1_context_create", (void *)_cffi_f_secp256k1_context_create, _CFFI_OP(_CFFI_OP_CPYTHON_BLTN_O, 166), (void *)_cffi_d_secp256k1_context_create },
  { "secp256k1_context_destroy", (void *)_cffi_f_secp256k1_context_destroy, _CFFI_OP(_CFFI_OP_CPYTHON_BLTN_O, 172), (void *)_cffi_d_secp256k1_context_destroy },
  { "secp256k1_context_randomize", (void *)_cffi_f_secp256k1_context_randomize, _CFFI_OP(_CFFI_OP_CPYTHON_BLTN_V, 0), (void *)_cffi_d_secp256k1_context_randomize },
  { "secp256k1_ec_privkey_tweak_add", (void *)_cffi_f_secp256k1_ec_privkey_tweak_add, _CFFI_OP(_CFFI_OP_CPYTHON_BLTN_V, 127), (void *)_cffi_d_secp256k1_ec_privkey_tweak_add },
  { "secp256k1_ec_privkey_tweak_mul", (void *)_cffi_f_secp256k1_ec_privkey_tweak_mul, _CFFI_OP(_CFFI_OP_CPYTHON_BLTN_V, 127), (void *)_cffi_d_secp256k1_ec_privkey_tweak_mul },
  { "secp256k1_ec_pubkey_combine", (void *)_cffi_f_secp256k1_ec_pubkey_combine, _CFFI_OP(_CFFI_OP_CPYTHON_BLTN_V, 59), (void *)_cffi_d_secp256k1_ec_pubkey_combine },
  { "secp256k1_ec_pubkey_create", (void *)_cffi_f_secp256k1_ec_pubkey_create, _CFFI_OP(_CFFI_OP_CPYTHON_BLTN_V, 74), (void *)_cffi_d_secp256k1_ec_pubkey_create },
  { "secp256k1_ec_pubkey_parse", (void *)_cffi_f_secp256k1_ec_pubkey_parse, _CFFI_OP(_CFFI_OP_CPYTHON_BLTN_V, 79), (void *)_cffi_d_secp256k1_ec_pubkey_parse },
  { "secp256k1_ec_pubkey_serialize", (void *)_cffi_f_secp256k1_ec_pubkey_serialize, _CFFI_OP(_CFFI_OP_CPYTHON_BLTN_V, 114), (void *)_cffi_d_secp256k1_ec_pubkey_serialize },
  { "secp256k1_ec_pubkey_tweak_add", (void *)_cffi_f_secp256k1_ec_pubkey_tweak_add, _CFFI_OP(_CFFI_OP_CPYTHON_BLTN_V, 74), (void *)_cffi_d_secp256k1_ec_pubkey_tweak_add },
  { "secp256k1_ec_pubkey_tweak_mul", (void *)_cffi_f_secp256k1_ec_pubkey_tweak_mul, _CFFI_OP(_CFFI_OP_CPYTHON_BLTN_V, 74), (void *)_cffi_d_secp256k1_ec_pubkey_tweak_mul },
  { "secp256k1_ec_seckey_verify", (void *)_cffi_f_secp256k1_ec_seckey_verify, _CFFI_OP(_CFFI_OP_CPYTHON_BLTN_V, 148), (void *)_cffi_d_secp256k1_ec_seckey_verify },
  { "secp256k1_ecdh", (void *)_cffi_f_secp256k1_ecdh, _CFFI_OP(_CFFI_OP_CPYTHON_BLTN_V, 102), (void *)_cffi_d_secp256k1_ecdh },
  { "secp256k1_ecdsa_recover", (void *)_cffi_f_secp256k1_ecdsa_recover, _CFFI_OP(_CFFI_OP_CPYTHON_BLTN_V, 53), (void *)_cffi_d_secp256k1_ecdsa_recover },
  { "secp256k1_ecdsa_recoverable_signature_convert", (void *)_cffi_f_secp256k1_ecdsa_recoverable_signature_convert, _CFFI_OP(_CFFI_OP_CPYTHON_BLTN_V, 18), (void *)_cffi_d_secp256k1_ecdsa_recoverable_signature_convert },
  { "secp256k1_ecdsa_recoverable_signature_parse_compact", (void *)_cffi_f_secp256k1_ecdsa_recoverable_signature_parse_compact, _CFFI_OP(_CFFI_OP_CPYTHON_BLTN_V, 4), (void *)_cffi_d_secp256k1_ecdsa_recoverable_signature_parse_compact },
  { "secp256k1_ecdsa_recoverable_signature_serialize_compact", (void *)_cffi_f_secp256k1_ecdsa_recoverable_signature_serialize_compact, _CFFI_OP(_CFFI_OP_CPYTHON_BLTN_V, 91), (void *)_cffi_d_secp256k1_ecdsa_recoverable_signature_serialize_compact },
  { "secp256k1_ecdsa_sign", (void *)_cffi_f_secp256k1_ecdsa_sign, _CFFI_OP(_CFFI_OP_CPYTHON_BLTN_V, 39), (void *)_cffi_d_secp256k1_ecdsa_sign },
  { "secp256k1_ecdsa_sign_recoverable", (void *)_cffi_f_secp256k1_ecdsa_sign_recoverable, _CFFI_OP(_CFFI_OP_CPYTHON_BLTN_V, 10), (void *)_cffi_d_secp256k1_ecdsa_sign_recoverable },
  { "secp256k1_ecdsa_signature_normalize", (void *)_cffi_f_secp256k1_ecdsa_signature_normalize, _CFFI_OP(_CFFI_OP_CPYTHON_BLTN_V, 23), (void *)_cffi_d_secp256k1_ecdsa_signature_normalize },
  { "secp256k1_ecdsa_signature_parse_compact", (void *)_cffi_f_secp256k1_ecdsa_signature_parse_compact, _CFFI_OP(_CFFI_OP_CPYTHON_BLTN_V, 28), (void *)_cffi_d_secp256k1_ecdsa_signature_parse_compact },
  { "secp256k1_ecdsa_signature_parse_der", (void *)_cffi_f_secp256k1_ecdsa_signature_parse_der, _CFFI_OP(_CFFI_OP_CPYTHON_BLTN_V, 33), (void *)_cffi_d_secp256k1_ecdsa_signature_parse_der },
  { "secp256k1_ecdsa_signature_serialize_compact", (void *)_cffi_f_secp256k1_ecdsa_signature_serialize_compact, _CFFI_OP(_CFFI_OP_CPYTHON_BLTN_V, 97), (void *)_cffi_d_secp256k1_ecdsa_signature_serialize_compact },
  { "secp256k1_ecdsa_signature_serialize_der", (void *)_cffi_f_secp256k1_ecdsa_signature_serialize_der, _CFFI_OP(_CFFI_OP_CPYTHON_BLTN_V, 108), (void *)_cffi_d_secp256k1_ecdsa_signature_serialize_der },
  { "secp256k1_ecdsa_verify", (void *)_cffi_f_secp256k1_ecdsa_verify, _CFFI_OP(_CFFI_OP_CPYTHON_BLTN_V, 47), (void *)_cffi_d_secp256k1_ecdsa_verify },
  { "secp256k1_nonce_function_default", (void *)_cffi_const_secp256k1_nonce_function_default, _CFFI_OP(_CFFI_OP_CONSTANT, 15), (void *)0 },
  { "secp256k1_nonce_function_rfc6979", (void *)_cffi_const_secp256k1_nonce_function_rfc6979, _CFFI_OP(_CFFI_OP_CONSTANT, 15), (void *)0 },
  { "secp256k1_schnorr_generate_nonce_pair", (void *)_cffi_f_secp256k1_schnorr_generate_nonce_pair, _CFFI_OP(_CFFI_OP_CPYTHON_BLTN_V, 65), (void *)_cffi_d_secp256k1_schnorr_generate_nonce_pair },
  { "secp256k1_schnorr_partial_combine", (void *)_cffi_f_secp256k1_schnorr_partial_combine, _CFFI_OP(_CFFI_OP_CPYTHON_BLTN_V, 121), (void *)_cffi_d_secp256k1_schnorr_partial_combine },
  { "secp256k1_schnorr_partial_sign", (void *)_cffi_f_secp256k1_schnorr_partial_sign, _CFFI_OP(_CFFI_OP_CPYTHON_BLTN_V, 140), (void *)_cffi_d_secp256k1_schnorr_partial_sign },
  { "secp256k1_schnorr_recover", (void *)_cffi_f_secp256k1_schnorr_recover, _CFFI_OP(_CFFI_OP_CPYTHON_BLTN_V, 85), (void *)_cffi_d_secp256k1_schnorr_recover },
  { "secp256k1_schnorr_sign", (void *)_cffi_f_secp256k1_schnorr_sign, _CFFI_OP(_CFFI_OP_CPYTHON_BLTN_V, 132), (void *)_cffi_d_secp256k1_schnorr_sign },
  { "secp256k1_schnorr_verify", (void *)_cffi_f_secp256k1_schnorr_verify, _CFFI_OP(_CFFI_OP_CPYTHON_BLTN_V, 152), (void *)_cffi_d_secp256k1_schnorr_verify },
};

static const struct _cffi_field_s _cffi_fields[] = {
  { "data", offsetof(secp256k1_ecdsa_recoverable_signature, data),
            sizeof(((secp256k1_ecdsa_recoverable_signature *)0)->data),
            _CFFI_OP(_CFFI_OP_NOOP, 182) },
  { "data", offsetof(secp256k1_ecdsa_signature, data),
            sizeof(((secp256k1_ecdsa_signature *)0)->data),
            _CFFI_OP(_CFFI_OP_NOOP, 180) },
  { "data", offsetof(secp256k1_pubkey, data),
            sizeof(((secp256k1_pubkey *)0)->data),
            _CFFI_OP(_CFFI_OP_NOOP, 180) },
};

static const struct _cffi_struct_union_s _cffi_struct_unions[] = {
  { "$secp256k1_ecdsa_recoverable_signature", 176, _CFFI_F_CHECK_FIELDS,
    sizeof(secp256k1_ecdsa_recoverable_signature), offsetof(struct _cffi_align_typedef_secp256k1_ecdsa_recoverable_signature, y), 0, 1 },
  { "$secp256k1_ecdsa_signature", 177, _CFFI_F_CHECK_FIELDS,
    sizeof(secp256k1_ecdsa_signature), offsetof(struct _cffi_align_typedef_secp256k1_ecdsa_signature, y), 1, 1 },
  { "$secp256k1_pubkey", 178, _CFFI_F_CHECK_FIELDS,
    sizeof(secp256k1_pubkey), offsetof(struct _cffi_align_typedef_secp256k1_pubkey, y), 2, 1 },
  { "secp256k1_context_struct", 175, _CFFI_F_OPAQUE,
    (size_t)-1, -1, -1, 0 /* opaque */ },
};

static const struct _cffi_typename_s _cffi_typenames[] = {
  { "secp256k1_context", 175 },
  { "secp256k1_ecdsa_recoverable_signature", 176 },
  { "secp256k1_ecdsa_signature", 177 },
  { "secp256k1_nonce_function", 15 },
  { "secp256k1_pubkey", 178 },
};

static const struct _cffi_type_context_s _cffi_type_context = {
  _cffi_types,
  _cffi_globals,
  _cffi_fields,
  _cffi_struct_unions,
  NULL,  /* no enums */
  _cffi_typenames,
  45,  /* num_globals */
  4,  /* num_struct_unions */
  0,  /* num_enums */
  5,  /* num_typenames */
  NULL,  /* no includes */
  185,  /* num_types */
  0,  /* flags */
};

#ifdef PYPY_VERSION
PyMODINIT_FUNC
_cffi_pypyinit__libsecp256k1(const void *p[])
{
    p[0] = (const void *)0x2601;
    p[1] = &_cffi_type_context;
}
#  ifdef _MSC_VER
     PyMODINIT_FUNC
#  if PY_MAJOR_VERSION >= 3
     PyInit__libsecp256k1(void) { return NULL; }
#  else
     init_libsecp256k1(void) { }
#  endif
#  endif
#elif PY_MAJOR_VERSION >= 3
PyMODINIT_FUNC
PyInit__libsecp256k1(void)
{
  return _cffi_init("_libsecp256k1", 0x2601, &_cffi_type_context);
}
#else
PyMODINIT_FUNC
init_libsecp256k1(void)
{
  _cffi_init("_libsecp256k1", 0x2601, &_cffi_type_context);
}
#endif
