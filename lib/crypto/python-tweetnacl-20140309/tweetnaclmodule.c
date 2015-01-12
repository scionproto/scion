#include <Python.h>
#include <stdint.h>
#include "tweetnacl.h"
#include "randombytes.h"

#if PY_VERSION_HEX < 0x02060000
#define PyBytes_FromStringAndSize PyString_FromStringAndSize
#define PyBytes_AS_STRING PyString_AS_STRING
#define _PyBytes_Resize _PyString_Resize
#endif

#if PY_VERSION_HEX < 0x02030000
#define PyMODINIT_FUNC DL_EXPORT(void)
#endif

#if PY_VERSION_HEX < 0x02050000
typedef int Py_ssize_t;
#endif

#if PY_MAJOR_VERSION < 2
void PyModule_AddIntConstant(PyObject *m, const char *name, long value) {

    PyObject *v, *d;

    d = PyModule_GetDict(m);
    if (!d) return;

    v = PyInt_FromLong(value);
    if(!v){ PyErr_Clear(); return; }
    PyDict_SetItemString(d, name, v);
    Py_DECREF(v);
    return;
}
void PyModule_AddStringConstant(PyObject *m, const char *name, const char *value) {

    PyObject *v, *d;

    d = PyModule_GetDict(m);
    if (!d) return;

    v = PyString_FromString(value);
    if(!v){ PyErr_Clear(); return; }
    PyDict_SetItemString(d, name, v);
    Py_DECREF(v);
    return;
}
#endif


PyObject *naclexception(const char *text) {
    PyErr_SetString(PyExc_ValueError, text);
    return (PyObject *)0;
}

/* API: n = _randreplace(m); */
PyObject *nacl_randreplace(PyObject *self, PyObject *args, PyObject *kw) {

    unsigned char *m;
    Py_ssize_t msize=0;
    static const char *kwlist[] = {"m", 0};
    uint32_t a,b;
    unsigned long long i;
    PyObject *ret;
    unsigned char *n;


    if (!PyArg_ParseTupleAndKeywords(args, kw,
                                     "|s#:_randreplace",
                                     (char **)kwlist,
                                     (char **)&m, &msize)) {
        return (PyObject *)0;
    }

    ret = PyBytes_FromStringAndSize((char *)0, msize);
    if (!ret) return ret;
    n = (unsigned char *)PyBytes_AS_STRING(ret);

    for (i = 0; i < msize; ++i) n[i] = m[i];

    randombytes((unsigned char *)&a, 4);
    randombytes((unsigned char *)&b, 4);

    n[a % msize] += 1 + (b % 255);

    return ret;
}

/* API: r = randombytes(len); */
PyObject *naclrandombytes(PyObject *self, PyObject *args, PyObject *kw) {

    Py_ssize_t len=0;
    PyObject *ret;
    static const char *kwlist[] = {"len", 0};

    if (!PyArg_ParseTupleAndKeywords(args, kw,
#if PY_VERSION_HEX < 0x02050000
                                     "|i:randombytes",
#else
                                     "|n:randombytes",
#endif
                                     (char **)kwlist,
                                     &len)) {
        return (PyObject *)0;
    }

    ret = PyBytes_FromStringAndSize((char *)0, len);
    if (!ret) return ret;

    randombytes(
        (unsigned char *)PyBytes_AS_STRING(ret),
        len
    );

    return ret;
}

const char randombytes__doc__[]=
"randombytes(len) -> str\n\n\
Return a string of 'len' random bytes suitable for cryptographic use.\n\
";


static unsigned char fromhex(unsigned char t)
{
  unsigned char u;

  u = t - 'a';
  if (u < 6) return u + 10;
  u = t - 'A';
  if (u < 6) return u + 10;
  u = t - '0';
  if (u < 10) return u;
  return 0;
}

/* API: s = _fromhex(h); */
PyObject *nacl_fromhex(PyObject *self, PyObject *args, PyObject *kw) {

    unsigned char *h, *r;
    Py_ssize_t hlen=0, rlen=0;
    static const char *kwlist[] = {"h", 0};
    unsigned int i;
    PyObject *ret;

    if (!PyArg_ParseTupleAndKeywords(args, kw,
                                     "|s#:_fromhex",
                                     (char **)kwlist,
                                     (char **)&h, &hlen)) {
        return (PyObject *)0;
    }

    if (hlen % 2) return naclexception("bad length");
    rlen = hlen/2;


    ret = PyBytes_FromStringAndSize((char *)0, rlen);
    if (!ret) return ret;
    r = (unsigned char *)PyBytes_AS_STRING(ret);

    for(i = 0; i < rlen; ++i) {
        r[i] = 16*fromhex(h[2*i]);
        r[i] += fromhex(h[2*i+1]);
    }
    return ret;
}


/* API: a = crypto_onetimeauth(m,k); */
PyObject *pycrypto_onetimeauth(PyObject *self, PyObject *args, PyObject *kw) {

    const unsigned char *m, *k;
    Py_ssize_t msize = 0, ksize = 0;
    static const char *kwlist[] = {"m", "k", 0};
    PyObject *ret;

    if (!PyArg_ParseTupleAndKeywords(args, kw,
                                     "|s#s#:crypto_onetimeauth",
                                     (char **)kwlist,
                                     (char **)&m, &msize,
                                     (char **)&k, &ksize)) {
        return (PyObject *)0;
    }

    if (ksize != crypto_onetimeauth_KEYBYTES)
        return naclexception("incorrect key length");

    ret = PyBytes_FromStringAndSize((char *)0, crypto_onetimeauth_BYTES);
    if (!ret) return ret;
    crypto_onetimeauth(
        (unsigned char *)PyBytes_AS_STRING(ret),
        m,
        msize,
        k
    );
    return ret;
}

const char pycrypto_onetimeauth__doc__[]=
"crypto_onetimeauth(m,k) -> a\n\n\
The crypto_onetimeauth function authenticates a message m\n\
using a secret key k. The function returns an authenticator a.\n\
The authenticator length is always crypto_onetimeauth_BYTES.\n\
The function raises an exception if len(k) is not crypto_onetimeauth_KEYBYTES.\n\
";

/* API: crypto_onetimeauth_verify(a,m,k); */
PyObject *pycrypto_onetimeauth_verify(PyObject *self, PyObject *args, PyObject *kw) {

    unsigned char *m, *k, *a;
    Py_ssize_t msize = 0, ksize = 0, alen = 0;
    static const char *kwlist[] = {"a", "m", "k", 0};

    if (!PyArg_ParseTupleAndKeywords(args, kw,
                                     "|s#s#s#:crypto_onetimeauth_verify",
                                     (char **)kwlist,
                                     (char **)&a, &alen,
                                     (char **)&m, &msize,
                                     (char **)&k, &ksize)) {
        return (PyObject *)0;
    }

    if (alen != crypto_onetimeauth_BYTES)
        return naclexception("incorrect authenticator length");

    if (ksize != crypto_onetimeauth_KEYBYTES)
        return naclexception("incorrect key length");

    if (crypto_onetimeauth_verify(a, m, msize, k) != 0) {
        return naclexception("invalid authenticator");
    }

    Py_INCREF(Py_None);
    return Py_None;
}

const char pycrypto_onetimeauth_verify__doc__[]=
"crypto_onetimeauth_verify(a,m,k)\n\n\
The crypto_onetimeauth_verify function checks that:\n\
  len(k) is crypto_onetimeauth_KEYBYTES;\n\
  len(a) is crypto_onetimeauth_BYTES;\n\
  and a is a correct authenticator of a message m under the secret key k.\n\
If any of these checks fail, the function raises an exception.\n\
";

/* API: a = crypto_onetimeauth_poly1305(m,k); */
PyObject *pycrypto_onetimeauth_poly1305(PyObject *self, PyObject *args, PyObject *kw) {

    const unsigned char *m, *k;
    Py_ssize_t msize = 0, ksize = 0;
    static const char *kwlist[] = {"m", "k", 0};
    PyObject *ret;

    if (!PyArg_ParseTupleAndKeywords(args, kw,
                                     "|s#s#:crypto_onetimeauth_poly1305",
                                     (char **)kwlist,
                                     (char **)&m, &msize,
                                     (char **)&k, &ksize)) {
        return (PyObject *)0;
    }

    if (ksize != crypto_onetimeauth_poly1305_KEYBYTES)
        return naclexception("incorrect key length");

    ret = PyBytes_FromStringAndSize((char *)0, crypto_onetimeauth_poly1305_BYTES);
    if (!ret) return ret;
    crypto_onetimeauth_poly1305(
        (unsigned char *)PyBytes_AS_STRING(ret),
        m,
        msize,
        k
    );
    return ret;
}

const char pycrypto_onetimeauth_poly1305__doc__[]=
"crypto_onetimeauth_poly1305(m,k) -> a\n\n\
The crypto_onetimeauth_poly1305 function authenticates a message m\n\
using a secret key k. The function returns an authenticator a.\n\
The authenticator length is always crypto_onetimeauth_poly1305_BYTES.\n\
The function raises an exception if len(k) is not crypto_onetimeauth_poly1305_KEYBYTES.\n\
";

/* API: crypto_onetimeauth_poly1305_verify(a,m,k); */
PyObject *pycrypto_onetimeauth_poly1305_verify(PyObject *self, PyObject *args, PyObject *kw) {

    unsigned char *m, *k, *a;
    Py_ssize_t msize = 0, ksize = 0, alen = 0;
    static const char *kwlist[] = {"a", "m", "k", 0};

    if (!PyArg_ParseTupleAndKeywords(args, kw,
                                     "|s#s#s#:crypto_onetimeauth_poly1305_verify",
                                     (char **)kwlist,
                                     (char **)&a, &alen,
                                     (char **)&m, &msize,
                                     (char **)&k, &ksize)) {
        return (PyObject *)0;
    }

    if (alen != crypto_onetimeauth_poly1305_BYTES)
        return naclexception("incorrect authenticator length");

    if (ksize != crypto_onetimeauth_poly1305_KEYBYTES)
        return naclexception("incorrect key length");

    if (crypto_onetimeauth_poly1305_verify(a, m, msize, k) != 0) {
        return naclexception("invalid authenticator");
    }

    Py_INCREF(Py_None);
    return Py_None;
}

const char pycrypto_onetimeauth_poly1305_verify__doc__[]=
"crypto_onetimeauth_poly1305_verify(a,m,k)\n\n\
The crypto_onetimeauth_poly1305_verify function checks that:\n\
  len(k) is crypto_onetimeauth_poly1305_KEYBYTES;\n\
  len(a) is crypto_onetimeauth_poly1305_BYTES;\n\
  and a is a correct authenticator of a message m under the secret key k.\n\
If any of these checks fail, the function raises an exception.\n\
";


/* API: h = crypto_hash(m); */
PyObject *pycrypto_hash(PyObject *self, PyObject *args, PyObject *kw) {

    const unsigned char *m;
    Py_ssize_t msize = 0;
    static const char *kwlist[] = {"m", 0};
    PyObject *ret;

    if (!PyArg_ParseTupleAndKeywords(args, kw,
                                     "|s#:crypto_hash",
                                     (char **)kwlist,
                                     (char **)&m, &msize)) {
        return (PyObject *)0;
    }

    ret = PyBytes_FromStringAndSize((char *)0, crypto_hash_BYTES);
    if (!ret) return ret;

    crypto_hash(
        (unsigned char *)PyBytes_AS_STRING(ret),
        m,
        msize
    );

    return ret;
}

const char pycrypto_hash__doc__[]=
"crypto_hash(m) -> h\n\n\
The crypto_hash function hashes a message m.\n\
It returns a hash h. The output length len(h) is always crypto_hash_BYTES.\n\
";


/* API: h = crypto_hash_sha512(m); */
PyObject *pycrypto_hash_sha512(PyObject *self, PyObject *args, PyObject *kw) {

    const unsigned char *m;
    Py_ssize_t msize = 0;
    static const char *kwlist[] = {"m", 0};
    PyObject *ret;

    if (!PyArg_ParseTupleAndKeywords(args, kw,
                                     "|s#:crypto_hash_sha512",
                                     (char **)kwlist,
                                     (char **)&m, &msize)) {
        return (PyObject *)0;
    }

    ret = PyBytes_FromStringAndSize((char *)0, crypto_hash_sha512_BYTES);
    if (!ret) return ret;

    crypto_hash_sha512(
        (unsigned char *)PyBytes_AS_STRING(ret),
        m,
        msize
    );

    return ret;
}

const char pycrypto_hash_sha512__doc__[]=
"crypto_hash_sha512(m) -> h\n\n\
The crypto_hash_sha512 function hashes a message m.\n\
It returns a hash h. The output length len(h) is always crypto_hash_sha512_BYTES.\n\
";


/* API: crypto_verify_16(x,y); */
PyObject *pycrypto_verify_16(PyObject *self, PyObject *args, PyObject *kw) {

    const unsigned char *x, *y;
    Py_ssize_t xlen = 0, ylen = 0;
    static const char *kwlist[] = {"x", "y", 0};

    if (!PyArg_ParseTupleAndKeywords(args, kw,
                                     "|s#s#:crypto_verify_16",
                                     (char **) kwlist,
                                     (char **)&x, &xlen,
                                     (char **)&y, &ylen)) {
        return (PyObject *)0;
    }

    if (xlen != crypto_verify_16_BYTES)
        return naclexception("incorrect x-string length");
    if (ylen != crypto_verify_16_BYTES)
        return naclexception("incorrect y-string length");
    if (crypto_verify_16(x, y) != 0)
        return naclexception("strings doesn't match");

    Py_INCREF(Py_None);
    return Py_None;
}

const char pycrypto_verify_16__doc__[]=
"crypto_verify_16(x,y)\n\n\
The crypto_verify_16 function checks that:\n\
  len(x) is crypto_verify_16_BYTES;\n\
  len(y) is crypto_verify_16_BYTES;\n\
  and check if strings x and y has same content.\n\
If any of these checks fail, the function raises an exception.\n\
The time taken by crypto_verify_16 is independent of the contents of x and y.\n\
";


/* API: crypto_verify_32(x,y); */
PyObject *pycrypto_verify_32(PyObject *self, PyObject *args, PyObject *kw) {

    const unsigned char *x, *y;
    Py_ssize_t xlen = 0, ylen = 0;
    static const char *kwlist[] = {"x", "y", 0};

    if (!PyArg_ParseTupleAndKeywords(args, kw,
                                     "|s#s#:crypto_verify_32",
                                     (char **) kwlist,
                                     (char **)&x, &xlen,
                                     (char **)&y, &ylen)) {
        return (PyObject *)0;
    }

    if (xlen != crypto_verify_32_BYTES)
        return naclexception("incorrect x-string length");
    if (ylen != crypto_verify_32_BYTES)
        return naclexception("incorrect y-string length");
    if (crypto_verify_32(x, y) != 0)
        return naclexception("strings doesn't match");

    Py_INCREF(Py_None);
    return Py_None;
}

const char pycrypto_verify_32__doc__[]=
"crypto_verify_32(x,y)\n\n\
The crypto_verify_32 function checks that:\n\
  len(x) is crypto_verify_32_BYTES;\n\
  len(y) is crypto_verify_32_BYTES;\n\
  and check if strings x and y has same content.\n\
If any of these checks fail, the function raises an exception.\n\
The time taken by crypto_verify_32 is independent of the contents of x and y.\n\
";


/* API: crypto_scalarmult(n,p); */
PyObject *pycrypto_scalarmult(PyObject *self, PyObject *args, PyObject *kw) {

    const unsigned char *n, *p;
    Py_ssize_t nlen = 0, plen = 0;
    static const char *kwlist[] = {"n", "p", 0};
    PyObject *ret;

    if (!PyArg_ParseTupleAndKeywords(args, kw,
                                     "|s#s#:crypto_scalarmult",
                                     (char **)kwlist,
                                     (char **)&n, &nlen,
                                     (char **)&p, &plen)) {
        return (PyObject *)0;
    }

    if (nlen != crypto_scalarmult_SCALARBYTES)
        return naclexception("incorrect scalar length");
    if (plen != crypto_scalarmult_BYTES)
        return naclexception("incorrect element length");

    ret = PyBytes_FromStringAndSize((char *)0, crypto_scalarmult_BYTES);
    if (!ret) return ret;

    crypto_scalarmult(
        (unsigned char *)PyBytes_AS_STRING(ret),
        n,
        p
    );

    return ret;
}

const char pycrypto_scalarmult__doc__[]=
"crypto_scalarmult(n) -> q\n\n\
This function multiplies a group element p by an integer n.\n\
It returns the resulting group element q of length crypto_scalarmult_BYTES.\n\
The function raises an exception if len(p) is not crypto_scalarmult_BYTES.\n\
It also raises an exception if len(n) is not crypto_scalarmult_SCALARBYTES.\n\
";


/* API: crypto_scalarmult_base(n); */
PyObject *pycrypto_scalarmult_base(PyObject *self, PyObject *args, PyObject *kw) {

    const unsigned char *n;
    Py_ssize_t nlen = 0;
    static const char *kwlist[] = {"n", 0};
    PyObject *ret;

    if (!PyArg_ParseTupleAndKeywords(args, kw,
                                     "|s#:crypto_scalarmult_base",
                                     (char **)kwlist,
                                     (char **)&n, &nlen)) {
        return (PyObject *)0;
    }

    if (nlen != crypto_scalarmult_SCALARBYTES)
        return naclexception("incorrect scalar length");

    ret = PyBytes_FromStringAndSize((char *)0, crypto_scalarmult_BYTES);
    if (!ret) return ret;

    crypto_scalarmult_base(
        (unsigned char *)PyBytes_AS_STRING(ret),
        n
    );
    return ret;
}

const char pycrypto_scalarmult_base__doc__[]=
"crypto_scalarmult_base(n,p) -> q\n\n\
The crypto_scalarmult_base function computes\n\
the scalar product of a standard group element and an integer n.\n\
It returns the resulting group element q of length crypto_scalarmult_BYTES.\n\
It raises an exception if len(n) is not crypto_scalarmult_SCALARBYTES.\n\
";


/* API: crypto_scalarmult_curve25519(n,p); */
PyObject *pycrypto_scalarmult_curve25519(PyObject *self, PyObject *args, PyObject *kw) {

    const unsigned char *n, *p;
    Py_ssize_t nlen = 0, plen = 0;
    static const char *kwlist[] = {"n", "p", 0};
    PyObject *ret;

    if (!PyArg_ParseTupleAndKeywords(args, kw,
                                     "|s#s#:crypto_scalarmult_curve25519",
                                     (char **)kwlist,
                                     (char **)&n, &nlen,
                                     (char **)&p, &plen)) {
        return (PyObject *)0;
    }

    if (nlen != crypto_scalarmult_curve25519_SCALARBYTES)
        return naclexception("incorrect scalar length");
    if (plen != crypto_scalarmult_curve25519_BYTES)
        return naclexception("incorrect element length");

    ret = PyBytes_FromStringAndSize((char *)0, crypto_scalarmult_curve25519_BYTES);
    if (!ret) return ret;

    crypto_scalarmult_curve25519(
        (unsigned char *)PyBytes_AS_STRING(ret),
        n,
        p
    );

    return ret;
}

const char pycrypto_scalarmult_curve25519__doc__[]=
"crypto_scalarmult_curve25519(n) -> q\n\n\
This function multiplies a group element p by an integer n.\n\
It returns the resulting group element q of length crypto_scalarmult_curve25519_BYTES.\n\
The function raises an exception if len(p) is not crypto_scalarmult_curve25519_BYTES.\n\
It also raises an exception if len(n) is not crypto_scalarmult_curve25519_SCALARBYTES.\n\
";


/* API: crypto_scalarmult_curve25519_base(n); */
PyObject *pycrypto_scalarmult_curve25519_base(PyObject *self, PyObject *args, PyObject *kw) {

    const unsigned char *n;
    Py_ssize_t nlen = 0;
    static const char *kwlist[] = {"n", 0};
    PyObject *ret;

    if (!PyArg_ParseTupleAndKeywords(args, kw,
                                     "|s#:crypto_scalarmult_curve25519_base",
                                     (char **)kwlist,
                                     (char **)&n, &nlen)) {
        return (PyObject *)0;
    }

    if (nlen != crypto_scalarmult_curve25519_SCALARBYTES)
        return naclexception("incorrect scalar length");

    ret = PyBytes_FromStringAndSize((char *)0, crypto_scalarmult_curve25519_BYTES);
    if (!ret) return ret;

    crypto_scalarmult_curve25519_base(
        (unsigned char *)PyBytes_AS_STRING(ret),
        n
    );
    return ret;
}

const char pycrypto_scalarmult_curve25519_base__doc__[]=
"crypto_scalarmult_curve25519_base(n,p) -> q\n\n\
The crypto_scalarmult_curve25519_base function computes\n\
the scalar product of a standard group element and an integer n.\n\
It returns the resulting group element q of length crypto_scalarmult_curve25519_BYTES.\n\
It raises an exception if len(n) is not crypto_scalarmult_curve25519_SCALARBYTES.\n\
";


/* API: c = crypto_stream(clen,n,k); */
PyObject *pycrypto_stream(PyObject *self, PyObject *args, PyObject *kw) {

    const unsigned char *n, *k;
    Py_ssize_t nsize = 0, ksize = 0, clen = 0;
    static const char *kwlist[] = {"clen", "n", "k", 0};
    PyObject *ret;

    if (!PyArg_ParseTupleAndKeywords(args, kw,
#if PY_VERSION_HEX < 0x02050000
                                     "|is#s#:crypto_stream",
#else
                                     "|ns#s#:crypto_stream",
#endif

                                     (char **) kwlist,
                                     &clen,
                                     (char **)&n, &nsize,
                                     (char **)&k, &ksize)) {
        return (PyObject *)0;
    }

    if (nsize != crypto_stream_NONCEBYTES) return naclexception("incorrect nonce length");
    if (ksize != crypto_stream_KEYBYTES) return naclexception("incorrect key length");
    if (clen < 0) return naclexception("incorrect clen");

    ret = PyBytes_FromStringAndSize((char *)0, clen);
    if (!ret) return ret;

    crypto_stream(
        (unsigned char *)PyBytes_AS_STRING(ret),
        clen,
        n,
        k
    );

    return ret;
}

const char pycrypto_stream__doc__[]=
"crypto_stream(clen,n,k) -> c\n\n\
The crypto_stream function produces a clen-byte stream c\n\
as a function of a secret key k and a nonce n.\n\
The function raises an exception:\n\
  if len(k) is not crypto_stream_KEYBYTES;\n\
  if len(n) is not crypto_stream_NONCEBYTES;\n\
  if clen is smaller than 0.\n\
";


/* API: c = crypto_stream_xor(m,n,k); */
PyObject *pycrypto_stream_xor(PyObject *self, PyObject *args, PyObject *kw) {

    const unsigned char *m, *n, *k;
    Py_ssize_t msize = 0, nsize = 0, ksize = 0;
    static const char *kwlist[] = {"m", "n", "k", 0};
    PyObject *ret;

    if (!PyArg_ParseTupleAndKeywords(args, kw,
                                     "|s#s#s#:crypto_stream",
                                     (char **) kwlist,
                                     (char **)&m, &msize,
                                     (char **)&n, &nsize,
                                     (char **)&k, &ksize)) {
        return (PyObject *)0;
    }

    if (nsize != crypto_stream_NONCEBYTES) return naclexception("incorrect nonce length");
    if (ksize != crypto_stream_KEYBYTES) return naclexception("incorrect key length");

    ret = PyBytes_FromStringAndSize((char *)0, msize);
    if (!ret) return ret;

    crypto_stream_xor(
        (unsigned char *) PyBytes_AS_STRING(ret),
        m, msize,
        n,
        k
    );
    return ret;
}

const char pycrypto_stream_xor__doc__[]=
"crypto_stream_xor(m,n,k) -> c\n\n\
The crypto_stream_xor function encrypts a message m using a secret key k\n\
and a nonce n. The crypto_stream_xor function returns the ciphertext c.\n\
The function raises an exception:\n\
  if len(k) is not crypto_stream_KEYBYTES;\n\
  if len(n) is not crypto_stream_NONCEBYTES.\n\
";


/* API: c = crypto_stream_xsalsa20(clen,n,k); */
PyObject *pycrypto_stream_xsalsa20(PyObject *self, PyObject *args, PyObject *kw) {

    const unsigned char *n, *k;
    Py_ssize_t nsize = 0, ksize = 0, clen = 0;
    static const char *kwlist[] = {"clen", "n", "k", 0};
    PyObject *ret;

    if (!PyArg_ParseTupleAndKeywords(args, kw,
#if PY_VERSION_HEX < 0x02050000
                                     "|is#s#:crypto_stream_xsalsa20",
#else
                                     "|ns#s#:crypto_stream_xsalsa20",
#endif

                                     (char **) kwlist,
                                     &clen,
                                     (char **)&n, &nsize,
                                     (char **)&k, &ksize)) {
        return (PyObject *)0;
    }

    if (nsize != crypto_stream_xsalsa20_NONCEBYTES) return naclexception("incorrect nonce length");
    if (ksize != crypto_stream_xsalsa20_KEYBYTES) return naclexception("incorrect key length");
    if (clen < 0) return naclexception("incorrect clen");

    ret = PyBytes_FromStringAndSize((char *)0, clen);
    if (!ret) return ret;

    crypto_stream_xsalsa20(
        (unsigned char *)PyBytes_AS_STRING(ret),
        clen,
        n,
        k
    );

    return ret;
}

const char pycrypto_stream_xsalsa20__doc__[]=
"crypto_stream_xsalsa20(clen,n,k) -> c\n\n\
The crypto_stream_xsalsa20 function produces a clen-byte stream c\n\
as a function of a secret key k and a nonce n.\n\
The function raises an exception:\n\
  if len(k) is not crypto_stream_xsalsa20_KEYBYTES;\n\
  if len(n) is not crypto_stream_xsalsa20_NONCEBYTES;\n\
  if clen is smaller than 0.\n\
";


/* API: c = crypto_stream_xsalsa20_xor(m,n,k); */
PyObject *pycrypto_stream_xsalsa20_xor(PyObject *self, PyObject *args, PyObject *kw) {

    const unsigned char *m, *n, *k;
    Py_ssize_t msize = 0, nsize = 0, ksize = 0;
    static const char *kwlist[] = {"m", "n", "k", 0};
    PyObject *ret;

    if (!PyArg_ParseTupleAndKeywords(args, kw,
                                     "|s#s#s#:crypto_stream_xsalsa20",
                                     (char **) kwlist,
                                     (char **)&m, &msize,
                                     (char **)&n, &nsize,
                                     (char **)&k, &ksize)) {
        return (PyObject *)0;
    }

    if (nsize != crypto_stream_xsalsa20_NONCEBYTES) return naclexception("incorrect nonce length");
    if (ksize != crypto_stream_xsalsa20_KEYBYTES) return naclexception("incorrect key length");

    ret = PyBytes_FromStringAndSize((char *)0, msize);
    if (!ret) return ret;

    crypto_stream_xsalsa20_xor(
        (unsigned char *) PyBytes_AS_STRING(ret),
        m, msize,
        n,
        k
    );
    return ret;
}

const char pycrypto_stream_xsalsa20_xor__doc__[]=
"crypto_stream_xsalsa20_xor(m,n,k) -> c\n\n\
The crypto_stream_xsalsa20_xor function encrypts a message m using a secret key k\n\
and a nonce n. The crypto_stream_xsalsa20_xor function returns the ciphertext c.\n\
The function raises an exception:\n\
  if len(k) is not crypto_stream_xsalsa20_KEYBYTES;\n\
  if len(n) is not crypto_stream_xsalsa20_NONCEBYTES.\n\
";


/* API: c = crypto_stream_salsa20(clen,n,k); */
PyObject *pycrypto_stream_salsa20(PyObject *self, PyObject *args, PyObject *kw) {

    const unsigned char *n, *k;
    Py_ssize_t nsize = 0, ksize = 0, clen = 0;
    static const char *kwlist[] = {"clen", "n", "k", 0};
    PyObject *ret;

    if (!PyArg_ParseTupleAndKeywords(args, kw,
#if PY_VERSION_HEX < 0x02050000
                                     "|is#s#:crypto_stream_salsa20",
#else
                                     "|ns#s#:crypto_stream_salsa20",
#endif

                                     (char **) kwlist,
                                     &clen,
                                     (char **)&n, &nsize,
                                     (char **)&k, &ksize)) {
        return (PyObject *)0;
    }

    if (nsize != crypto_stream_salsa20_NONCEBYTES) return naclexception("incorrect nonce length");
    if (ksize != crypto_stream_salsa20_KEYBYTES) return naclexception("incorrect key length");
    if (clen < 0) return naclexception("incorrect clen");

    ret = PyBytes_FromStringAndSize((char *)0, clen);
    if (!ret) return ret;

    crypto_stream_salsa20(
        (unsigned char *)PyBytes_AS_STRING(ret),
        clen,
        n,
        k
    );

    return ret;
}

const char pycrypto_stream_salsa20__doc__[]=
"crypto_stream_salsa20(clen,n,k) -> c\n\n\
The crypto_stream_salsa20 function produces a clen-byte stream c\n\
as a function of a secret key k and a nonce n.\n\
The function raises an exception:\n\
  if len(k) is not crypto_stream_salsa20_KEYBYTES;\n\
  if len(n) is not crypto_stream_salsa20_NONCEBYTES;\n\
  if clen is smaller than 0.\n\
";


/* API: c = crypto_stream_salsa20_xor(m,n,k); */
PyObject *pycrypto_stream_salsa20_xor(PyObject *self, PyObject *args, PyObject *kw) {

    const unsigned char *m, *n, *k;
    Py_ssize_t msize = 0, nsize = 0, ksize = 0;
    static const char *kwlist[] = {"m", "n", "k", 0};
    PyObject *ret;

    if (!PyArg_ParseTupleAndKeywords(args, kw,
                                     "|s#s#s#:crypto_stream_salsa20",
                                     (char **) kwlist,
                                     (char **)&m, &msize,
                                     (char **)&n, &nsize,
                                     (char **)&k, &ksize)) {
        return (PyObject *)0;
    }

    if (nsize != crypto_stream_salsa20_NONCEBYTES) return naclexception("incorrect nonce length");
    if (ksize != crypto_stream_salsa20_KEYBYTES) return naclexception("incorrect key length");

    ret = PyBytes_FromStringAndSize((char *)0, msize);
    if (!ret) return ret;

    crypto_stream_salsa20_xor(
        (unsigned char *) PyBytes_AS_STRING(ret),
        m, msize,
        n,
        k
    );
    return ret;
}

const char pycrypto_stream_salsa20_xor__doc__[]=
"crypto_stream_salsa20_xor(m,n,k) -> c\n\n\
The crypto_stream_salsa20_xor function encrypts a message m using a secret key k\n\
and a nonce n. The crypto_stream_salsa20_xor function returns the ciphertext c.\n\
The function raises an exception:\n\
  if len(k) is not crypto_stream_salsa20_KEYBYTES;\n\
  if len(n) is not crypto_stream_salsa20_NONCEBYTES.\n\
";


/* API: sm = crypto_sign(m,sk); */
PyObject *pycrypto_sign(PyObject *self, PyObject *args, PyObject *kw) {

    Py_ssize_t mlen = 0, sksize = 0;
    const unsigned char *sk, *m;
    static const char *kwlist[] = {"m", "sk", 0};
    PyObject *ret;
    unsigned long long smlen;

    if (!PyArg_ParseTupleAndKeywords(args, kw,
                                     "|s#s#:crypto_sign",
                                     (char **) kwlist,
                                     (char **)&m, &mlen,
                                     (char **)&sk, &sksize)) {
        return (PyObject *)0;
    }

    if (sksize != crypto_sign_SECRETKEYBYTES)
        return naclexception("incorrect secret-key length");

    ret = PyBytes_FromStringAndSize((char *)0, mlen + crypto_sign_BYTES);
    if (!ret) return ret;

    if (crypto_sign(
        (unsigned char *)PyBytes_AS_STRING(ret),
        &smlen,
        m,
        mlen,
        sk
    ) != 0) {
        Py_DECREF(ret);
        return naclexception("crypto_sign returns nonzero");
    }
    _PyBytes_Resize(&ret, smlen);
    return ret;
}

const char pycrypto_sign__doc__[]=
"crypto_sign(m,sk) -> sm\n\n\
The crypto_sign function signs a message m using the sender's secret key sk.\n\
The crypto_sign function returns the resulting signed message sm.\n\
The function raises an exception if len(sk) is not crypto_sign_SECRETKEYBYTES.\n\
";


/* API: m = crypto_sign_open(sm,pk); */
PyObject *pycrypto_sign_open(PyObject *self, PyObject *args, PyObject *kw) {

    const unsigned char *sm, *pk;
    Py_ssize_t smlen=0, pksize=0;
    static const char *kwlist[] = {"sm", "pk", 0};
    PyObject *ret;
    unsigned long long mlen;

    if (!PyArg_ParseTupleAndKeywords(args, kw,
                                     "|s#s#:crypto_sign_open",
                                     (char **)kwlist,
                                     (char **)&sm, &smlen,
                                     (char **)&pk, &pksize)) {
        return (PyObject *)0;
    }

    if (pksize != crypto_sign_PUBLICKEYBYTES)
        return naclexception("incorrect public-key length");

    ret = PyBytes_FromStringAndSize((char *)0, smlen);
    if (!ret) return ret;

    if (crypto_sign_open(
        (unsigned char *)PyBytes_AS_STRING(ret),
        &mlen,
        sm,
        smlen,
        pk
    ) != 0) {
        Py_DECREF(ret);
        return naclexception("ciphertext fails verification");
    }
    _PyBytes_Resize(&ret, mlen);
    return ret;
}

const char pycrypto_sign_open__doc__[]=
"crypto_sign_open(sm,pk) -> m\n\n\
The crypto_sign_open function verifies the signature in\n\
sm using the receiver's secret key sk.\n\
The crypto_sign_open function returns the message m.\n\n\
If the signature fails verification, crypto_sign_open raises an exception.\n\
The function also raises an exception if len(pk) is not crypto_sign_PUBLICKEYBYTES.\n\
";


/* API: (pk,sk) = crypto_sign_keypair(); */
PyObject *pycrypto_sign_keypair(PyObject *self) {

    PyObject *pypk, *pysk, *ret;

    pypk = PyBytes_FromStringAndSize((char *)0, crypto_sign_PUBLICKEYBYTES);
    if (!pypk) return (PyObject *)0;

    pysk = PyBytes_FromStringAndSize((char *)0, crypto_sign_SECRETKEYBYTES);
    if (!pysk) {
        Py_DECREF(pypk);
        return (PyObject *)0;
    }
    ret = PyTuple_New(2);
    if (!ret) {
        Py_DECREF(pypk);
        Py_DECREF(pysk);
        return (PyObject *)0;
    }
    PyTuple_SET_ITEM(ret, 0, pypk);
    PyTuple_SET_ITEM(ret, 1, pysk);

    crypto_sign_keypair(
        (unsigned char *)PyBytes_AS_STRING(pypk),
        (unsigned char *)PyBytes_AS_STRING(pysk)
    );

    return ret;
}

const char pycrypto_sign_keypair__doc__[]=
"crypto_sign_keypair() -> (pk,sk)\n\n\
The crypto_sign_keypair function randomly generates a secret key and\n\
a corresponding public key. It returns tuple containing the secret key in sk and\n\
public key in pk.\n\
It guarantees that sk has crypto_sign_SECRETKEYBYTES bytes\n\
and that pk has crypto_sign_PUBLICKEYBYTES bytes.\n\
";


/* API: sm = crypto_sign_ed25519(m,sk); */
PyObject *pycrypto_sign_ed25519(PyObject *self, PyObject *args, PyObject *kw) {

    Py_ssize_t mlen = 0, sksize = 0;
    const unsigned char *sk, *m;
    static const char *kwlist[] = {"m", "sk", 0};
    PyObject *ret;
    unsigned long long smlen;

    if (!PyArg_ParseTupleAndKeywords(args, kw,
                                     "|s#s#:crypto_sign_ed25519",
                                     (char **) kwlist,
                                     (char **)&m, &mlen,
                                     (char **)&sk, &sksize)) {
        return (PyObject *)0;
    }

    if (sksize != crypto_sign_ed25519_SECRETKEYBYTES)
        return naclexception("incorrect secret-key length");

    ret = PyBytes_FromStringAndSize((char *)0, mlen + crypto_sign_ed25519_BYTES);
    if (!ret) return ret;

    if (crypto_sign_ed25519(
        (unsigned char *)PyBytes_AS_STRING(ret),
        &smlen,
        m,
        mlen,
        sk
    ) != 0) {
        Py_DECREF(ret);
        return naclexception("crypto_sign_ed25519 returns nonzero");
    }
    _PyBytes_Resize(&ret, smlen);
    return ret;
}

const char pycrypto_sign_ed25519__doc__[]=
"crypto_sign_ed25519(m,sk) -> sm\n\n\
The crypto_sign_ed25519 function signs a message m using the sender's secret key sk.\n\
The crypto_sign_ed25519 function returns the resulting signed message sm.\n\
The function raises an exception if len(sk) is not crypto_sign_ed25519_SECRETKEYBYTES.\n\
";


/* API: m = crypto_sign_ed25519_open(sm,pk); */
PyObject *pycrypto_sign_ed25519_open(PyObject *self, PyObject *args, PyObject *kw) {

    const unsigned char *sm, *pk;
    Py_ssize_t smlen=0, pksize=0;
    static const char *kwlist[] = {"sm", "pk", 0};
    PyObject *ret;
    unsigned long long mlen;

    if (!PyArg_ParseTupleAndKeywords(args, kw,
                                     "|s#s#:crypto_sign_ed25519_open",
                                     (char **)kwlist,
                                     (char **)&sm, &smlen,
                                     (char **)&pk, &pksize)) {
        return (PyObject *)0;
    }

    if (pksize != crypto_sign_ed25519_PUBLICKEYBYTES)
        return naclexception("incorrect public-key length");

    ret = PyBytes_FromStringAndSize((char *)0, smlen);
    if (!ret) return ret;

    if (crypto_sign_ed25519_open(
        (unsigned char *)PyBytes_AS_STRING(ret),
        &mlen,
        sm,
        smlen,
        pk
    ) != 0) {
        Py_DECREF(ret);
        return naclexception("ciphertext fails verification");
    }
    _PyBytes_Resize(&ret, mlen);
    return ret;
}

const char pycrypto_sign_ed25519_open__doc__[]=
"crypto_sign_ed25519_open(sm,pk) -> m\n\n\
The crypto_sign_ed25519_open function verifies the signature in\n\
sm using the receiver's secret key sk.\n\
The crypto_sign_ed25519_open function returns the message m.\n\n\
If the signature fails verification, crypto_sign_ed25519_open raises an exception.\n\
The function also raises an exception if len(pk) is not crypto_sign_ed25519_PUBLICKEYBYTES.\n\
";


/* API: (pk,sk) = crypto_sign_ed25519_keypair(); */
PyObject *pycrypto_sign_ed25519_keypair(PyObject *self) {

    PyObject *pypk, *pysk, *ret;

    pypk = PyBytes_FromStringAndSize((char *)0, crypto_sign_ed25519_PUBLICKEYBYTES);
    if (!pypk) return (PyObject *)0;

    pysk = PyBytes_FromStringAndSize((char *)0, crypto_sign_ed25519_SECRETKEYBYTES);
    if (!pysk) {
        Py_DECREF(pypk);
        return (PyObject *)0;
    }
    ret = PyTuple_New(2);
    if (!ret) {
        Py_DECREF(pypk);
        Py_DECREF(pysk);
        return (PyObject *)0;
    }
    PyTuple_SET_ITEM(ret, 0, pypk);
    PyTuple_SET_ITEM(ret, 1, pysk);

    crypto_sign_ed25519_keypair(
        (unsigned char *)PyBytes_AS_STRING(pypk),
        (unsigned char *)PyBytes_AS_STRING(pysk)
    );

    return ret;
}

const char pycrypto_sign_ed25519_keypair__doc__[]=
"crypto_sign_ed25519_keypair() -> (pk,sk)\n\n\
The crypto_sign_ed25519_keypair function randomly generates a secret key and\n\
a corresponding public key. It returns tuple containing the secret key in sk and\n\
public key in pk.\n\
It guarantees that sk has crypto_sign_ed25519_SECRETKEYBYTES bytes\n\
and that pk has crypto_sign_ed25519_PUBLICKEYBYTES bytes.\n\
";


/* API: c = crypto_secretbox(m,n,k); */
PyObject *pycrypto_secretbox(PyObject *self, PyObject *args, PyObject *kw) {

    const unsigned char *m, *n, *k;
    Py_ssize_t msize = 0, nsize = 0, ksize = 0;
    static const char *kwlist[] = {"m", "n", "k", 0};
    PyObject *ret;
    long long i;
    unsigned long long mlen;
    unsigned char *mpad;
    unsigned char *cpad;

    if (!PyArg_ParseTupleAndKeywords(args, kw,
                                     "|s#s#s#:crypto_secretbox",
                                     (char **)kwlist,
                                     (char **)&m, &msize,
                                     (char **)&n, &nsize,
                                     (char **)&k, &ksize)) {
        return (PyObject *)0;
    }

    if (nsize != crypto_secretbox_NONCEBYTES) return naclexception("incorrect nonce length");
    if (ksize != crypto_secretbox_KEYBYTES) return naclexception("incorrect key length");

    mlen = msize + crypto_secretbox_ZEROBYTES;
    mpad = PyMem_Malloc(mlen);
    if (!mpad) return PyErr_NoMemory();
    cpad = PyMem_Malloc(mlen + crypto_secretbox_BOXZEROBYTES);
    if (!cpad) {
        PyMem_Free(mpad);
        return PyErr_NoMemory();
    }

    for (i = 0; i < crypto_secretbox_ZEROBYTES; ++i) mpad[i] = 0;
    for (i = crypto_secretbox_ZEROBYTES; i < mlen; ++i) mpad[i] = m[i - crypto_secretbox_ZEROBYTES];

    crypto_secretbox(cpad, mpad, mlen, n, k);

    ret = PyBytes_FromStringAndSize(
        (char *)cpad + crypto_secretbox_BOXZEROBYTES,
        mlen - crypto_secretbox_BOXZEROBYTES
    );

    PyMem_Free(mpad);
    PyMem_Free(cpad);
    return ret;
}

const char pycrypto_secretbox__doc__[]=
"crypto_secretbox(m,n,k) -> c\n\n\
The crypto_secretbox function encrypts and authenticates\n\
a message m using a secret key k and a nonce n. \n\
The crypto_secretbox function returns the resulting ciphertext c. \n\
The function raises an exception if len(k) is not crypto_secretbox_KEYBYTES.\n\
The function also raises an exception if len(n) is not crypto_secretbox_NONCEBYTES.\n\
";


/* API: m = crypto_secretbox_open(c,n,k); */
PyObject *pycrypto_secretbox_open(PyObject *self, PyObject *args, PyObject *kw) {

    const unsigned char *c, *n, *k;
    Py_ssize_t csize = 0, nsize = 0, ksize = 0;
    static const char *kwlist[] = {"c", "n", "k", 0};
    PyObject *ret;
    long long i;
    unsigned long long clen;
    unsigned char *mpad;
    unsigned char *cpad;

    if (!PyArg_ParseTupleAndKeywords(args, kw,
                                     "|s#s#s#:crypto_secretbox_open",
                                     (char **)kwlist,
                                     (char **)&c, &csize,
                                     (char **)&n, &nsize,
                                     (char **)&k, &ksize)) {
        return (PyObject *)0;
    }

    if (nsize != crypto_secretbox_NONCEBYTES) return naclexception("incorrect nonce length");
    if (ksize != crypto_secretbox_KEYBYTES) return naclexception("incorrect key length");

    clen = csize + crypto_secretbox_BOXZEROBYTES;
    mpad = PyMem_Malloc(clen);
    if (!mpad) return PyErr_NoMemory();
    cpad = PyMem_Malloc(clen + crypto_secretbox_ZEROBYTES);
    if (!cpad) {
        PyMem_Free(mpad);
        return PyErr_NoMemory();
    }

    for (i = 0; i < crypto_secretbox_BOXZEROBYTES; ++i) cpad[i] = 0;
    for (i = crypto_secretbox_BOXZEROBYTES; i < clen; ++i) cpad[i] = c[i - crypto_secretbox_BOXZEROBYTES];

    if (crypto_secretbox_open(mpad, cpad, clen, n, k) != 0) {
        PyMem_Free(mpad);
        PyMem_Free(cpad);
        return naclexception("ciphertext fails verification");
    }
    if (clen < crypto_secretbox_ZEROBYTES) {
        PyMem_Free(mpad);
        PyMem_Free(cpad);
        return naclexception("ciphertext too short");
    }

    ret = PyBytes_FromStringAndSize(
        (char *)mpad + crypto_secretbox_ZEROBYTES,
        clen - crypto_secretbox_ZEROBYTES
    );

    PyMem_Free(mpad);
    PyMem_Free(cpad);
    return ret;
}

const char pycrypto_secretbox_open__doc__[]=
"crypto_secretbox_open(c,n,k) -> m\n\n\
The crypto_secretbox_open function verifies and decrypts \n\
a ciphertext c using a secret key k and a nonce n.\n\
The crypto_secretbox_open function returns the resulting plaintext m.\n\
If the ciphertext fails verification, crypto_secretbox_open raises an exception.\n\
The function also raises an exception if len(k) is not crypto_secretbox_KEYBYTES,\n\
or if len(n) is not crypto_secretbox_NONCEBYTES.\n\
";


/* API: c = crypto_secretbox_xsalsa20poly1305(m,n,k); */
PyObject *pycrypto_secretbox_xsalsa20poly1305(PyObject *self, PyObject *args, PyObject *kw) {

    const unsigned char *m, *n, *k;
    Py_ssize_t msize = 0, nsize = 0, ksize = 0;
    static const char *kwlist[] = {"m", "n", "k", 0};
    PyObject *ret;
    long long i;
    unsigned long long mlen;
    unsigned char *mpad;
    unsigned char *cpad;

    if (!PyArg_ParseTupleAndKeywords(args, kw,
                                     "|s#s#s#:crypto_secretbox_xsalsa20poly1305",
                                     (char **)kwlist,
                                     (char **)&m, &msize,
                                     (char **)&n, &nsize,
                                     (char **)&k, &ksize)) {
        return (PyObject *)0;
    }

    if (nsize != crypto_secretbox_xsalsa20poly1305_NONCEBYTES) return naclexception("incorrect nonce length");
    if (ksize != crypto_secretbox_xsalsa20poly1305_KEYBYTES) return naclexception("incorrect key length");

    mlen = msize + crypto_secretbox_xsalsa20poly1305_ZEROBYTES;
    mpad = PyMem_Malloc(mlen);
    if (!mpad) return PyErr_NoMemory();
    cpad = PyMem_Malloc(mlen + crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES);
    if (!cpad) {
        PyMem_Free(mpad);
        return PyErr_NoMemory();
    }

    for (i = 0; i < crypto_secretbox_xsalsa20poly1305_ZEROBYTES; ++i) mpad[i] = 0;
    for (i = crypto_secretbox_xsalsa20poly1305_ZEROBYTES; i < mlen; ++i) mpad[i] = m[i - crypto_secretbox_xsalsa20poly1305_ZEROBYTES];

    crypto_secretbox_xsalsa20poly1305(cpad, mpad, mlen, n, k);

    ret = PyBytes_FromStringAndSize(
        (char *)cpad + crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES,
        mlen - crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES
    );

    PyMem_Free(mpad);
    PyMem_Free(cpad);
    return ret;
}

const char pycrypto_secretbox_xsalsa20poly1305__doc__[]=
"crypto_secretbox_xsalsa20poly1305(m,n,k) -> c\n\n\
The crypto_secretbox_xsalsa20poly1305 function encrypts and authenticates\n\
a message m using a secret key k and a nonce n. \n\
The crypto_secretbox_xsalsa20poly1305 function returns the resulting ciphertext c. \n\
The function raises an exception if len(k) is not crypto_secretbox_xsalsa20poly1305_KEYBYTES.\n\
The function also raises an exception if len(n) is not crypto_secretbox_xsalsa20poly1305_NONCEBYTES.\n\
";


/* API: m = crypto_secretbox_xsalsa20poly1305_open(c,n,k); */
PyObject *pycrypto_secretbox_xsalsa20poly1305_open(PyObject *self, PyObject *args, PyObject *kw) {

    const unsigned char *c, *n, *k;
    Py_ssize_t csize = 0, nsize = 0, ksize = 0;
    static const char *kwlist[] = {"c", "n", "k", 0};
    PyObject *ret;
    long long i;
    unsigned long long clen;
    unsigned char *mpad;
    unsigned char *cpad;

    if (!PyArg_ParseTupleAndKeywords(args, kw,
                                     "|s#s#s#:crypto_secretbox_xsalsa20poly1305_open",
                                     (char **)kwlist,
                                     (char **)&c, &csize,
                                     (char **)&n, &nsize,
                                     (char **)&k, &ksize)) {
        return (PyObject *)0;
    }

    if (nsize != crypto_secretbox_xsalsa20poly1305_NONCEBYTES) return naclexception("incorrect nonce length");
    if (ksize != crypto_secretbox_xsalsa20poly1305_KEYBYTES) return naclexception("incorrect key length");

    clen = csize + crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES;
    mpad = PyMem_Malloc(clen);
    if (!mpad) return PyErr_NoMemory();
    cpad = PyMem_Malloc(clen + crypto_secretbox_xsalsa20poly1305_ZEROBYTES);
    if (!cpad) {
        PyMem_Free(mpad);
        return PyErr_NoMemory();
    }

    for (i = 0; i < crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES; ++i) cpad[i] = 0;
    for (i = crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES; i < clen; ++i) cpad[i] = c[i - crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES];

    if (crypto_secretbox_xsalsa20poly1305_open(mpad, cpad, clen, n, k) != 0) {
        PyMem_Free(mpad);
        PyMem_Free(cpad);
        return naclexception("ciphertext fails verification");
    }
    if (clen < crypto_secretbox_xsalsa20poly1305_ZEROBYTES) {
        PyMem_Free(mpad);
        PyMem_Free(cpad);
        return naclexception("ciphertext too short");
    }

    ret = PyBytes_FromStringAndSize(
        (char *)mpad + crypto_secretbox_xsalsa20poly1305_ZEROBYTES,
        clen - crypto_secretbox_xsalsa20poly1305_ZEROBYTES
    );

    PyMem_Free(mpad);
    PyMem_Free(cpad);
    return ret;
}

const char pycrypto_secretbox_xsalsa20poly1305_open__doc__[]=
"crypto_secretbox_xsalsa20poly1305_open(c,n,k) -> m\n\n\
The crypto_secretbox_xsalsa20poly1305_open function verifies and decrypts \n\
a ciphertext c using a secret key k and a nonce n.\n\
The crypto_secretbox_xsalsa20poly1305_open function returns the resulting plaintext m.\n\
If the ciphertext fails verification, crypto_secretbox_xsalsa20poly1305_open raises an exception.\n\
The function also raises an exception if len(k) is not crypto_secretbox_xsalsa20poly1305_KEYBYTES,\n\
or if len(n) is not crypto_secretbox_xsalsa20poly1305_NONCEBYTES.\n\
";


/* C API: c = crypto_box(m,n,pk,sk); */
PyObject *pycrypto_box(PyObject *self, PyObject *args, PyObject *kw) {

    const unsigned char *m, *n, *pk, *sk;
    Py_ssize_t msize = 0, nsize = 0, pksize = 0, sksize = 0;
    static const char *kwlist[] = {"m", "n", "pk", "sk", 0};
    PyObject *ret;
    long long i;
    unsigned long long mlen;
    unsigned char *mpad;
    unsigned char *cpad;

    if (!PyArg_ParseTupleAndKeywords(args, kw,
                                     "|s#s#s#s#:crypto_box",
                                     (char **)kwlist,
                                     (char **)&m, &msize,
                                     (char **)&n, &nsize,
                                     (char **)&pk, &pksize,
                                     (char **)&sk, &sksize)) {
        return (PyObject *)0;
    }

    if (nsize != crypto_box_NONCEBYTES) return naclexception("incorrect nonce length");
    if (pksize != crypto_box_PUBLICKEYBYTES) return naclexception("incorrect public-key length");
    if (sksize != crypto_box_SECRETKEYBYTES) return naclexception("incorrect secret-key length");

    mlen = msize + crypto_box_ZEROBYTES;
    mpad = PyMem_Malloc(mlen);
    if (!mpad) return PyErr_NoMemory();
    cpad = PyMem_Malloc(mlen + crypto_box_BOXZEROBYTES);
    if (!cpad) {
        PyMem_Free(mpad);
        return PyErr_NoMemory();
    }

    for (i = 0; i < crypto_box_ZEROBYTES; ++i) mpad[i] = 0;
    for (i = crypto_box_ZEROBYTES; i < mlen; ++i) mpad[i] = m[i - crypto_box_ZEROBYTES];

    crypto_box(cpad, mpad, mlen, n, pk, sk);

    ret = PyBytes_FromStringAndSize(
        (char *)cpad + crypto_box_BOXZEROBYTES,
        mlen - crypto_box_BOXZEROBYTES
    );

    PyMem_Free(mpad);
    PyMem_Free(cpad);
    return ret;
}

const char pycrypto_box__doc__[]=
"crypto_box(m,n,pk,sk) -> c\n\n\
The crypto_box function encrypts and authenticates a message m\n\
using the sender's secret key sk, the receiver's public key pk,\n\
and a nonce n. The crypto_box function returns the resulting ciphertext c.\n\
The function raises an exception if len(sk) is not crypto_box_SECRETKEYBYTES\n\
or if len(pk) is not crypto_box_PUBLICKEYBYTES\n\
or if len(n) is not crypto_box_NONCEBYTES.\n\
";


/* API: m = crypto_box_open(c,n,pk,sk); */
PyObject *pycrypto_box_open(PyObject *self, PyObject *args, PyObject *kw) {

    const unsigned char *c, *n, *pk, *sk;
    Py_ssize_t csize = 0, nsize = 0, pksize = 0, sksize = 0;
    static const char *kwlist[] = {"c", "n", "pk", "sk", 0};
    PyObject *ret;
    long long i;
    unsigned long long clen;
    unsigned char *mpad;
    unsigned char *cpad;

    if (!PyArg_ParseTupleAndKeywords(args, kw,
                                     "|s#s#s#s#:crypto_box_open",
                                     (char **)kwlist,
                                     (char **)&c, &csize,
                                     (char **)&n, &nsize,
                                     (char **)&pk, &pksize,
                                     (char **)&sk, &sksize)) {
        return (PyObject *)0;
    }

    if (nsize != crypto_box_NONCEBYTES) return naclexception("incorrect nonce length");
    if (pksize != crypto_box_PUBLICKEYBYTES) return naclexception("incorrect public-key length");
    if (sksize != crypto_box_SECRETKEYBYTES) return naclexception("incorrect secret-key length");

    clen = csize + crypto_box_BOXZEROBYTES;
    mpad = PyMem_Malloc(clen);
    if (!mpad) return PyErr_NoMemory();
    cpad = PyMem_Malloc(clen + crypto_box_ZEROBYTES);
    if (!cpad) {
        PyMem_Free(mpad);
        return PyErr_NoMemory();
    }

    for (i = 0; i < crypto_box_BOXZEROBYTES; ++i) cpad[i] = 0;
    for (i = crypto_box_BOXZEROBYTES; i < clen; ++i) cpad[i] = c[i - crypto_box_BOXZEROBYTES];

    if (crypto_box_open(mpad, cpad, clen, n, pk, sk) != 0) {
        PyMem_Free(mpad);
        PyMem_Free(cpad);
        return naclexception("ciphertext fails verification");
    }
    if (clen < crypto_box_ZEROBYTES) {
        PyMem_Free(mpad);
        PyMem_Free(cpad);
        return naclexception("ciphertext too short");
    }
    ret = PyBytes_FromStringAndSize(
        (char *)mpad + crypto_box_ZEROBYTES,
        clen - crypto_box_ZEROBYTES
    );
    PyMem_Free(mpad);
    PyMem_Free(cpad);
    return ret;

}

const char pycrypto_box_open__doc__[]=
"crypto_box_open(c,n,pk,sk) -> m\n\n\
The crypto_box_open function verifies and decrypts\n\
a ciphertext c using the receiver's secret key sk,\n\
the sender's public key pk, and a nonce n.\n\
The crypto_box_open function returns the resulting plaintext m.\n\
The function raises an exception if len(sk) is not crypto_box_SECRETKEYBYTES\n\
or if len(pk) is not crypto_box_PUBLICKEYBYTES\n\
or if len(n) is not crypto_box_NONCEBYTES.\n\
";


/* API: (pk,sk) = crypto_box_keypair(); */
PyObject *pycrypto_box_keypair(PyObject *self) {

    PyObject *pypk, *pysk, *ret;

    pypk = PyBytes_FromStringAndSize((char *)0, crypto_box_PUBLICKEYBYTES);
    if (!pypk) return (PyObject *)0;

    pysk = PyBytes_FromStringAndSize((char *)0, crypto_box_SECRETKEYBYTES);
    if (!pysk) {
        Py_DECREF(pypk);
        return (PyObject *)0;
    }
    ret = PyTuple_New(2);
    if (!ret) {
        Py_DECREF(pypk);
        Py_DECREF(pysk);
        return (PyObject *)0;
    }
    PyTuple_SET_ITEM(ret, 0, pypk);
    PyTuple_SET_ITEM(ret, 1, pysk);

    crypto_box_keypair(
        (unsigned char *)PyBytes_AS_STRING(pypk),
        (unsigned char *)PyBytes_AS_STRING(pysk)
    );

    return ret;
}

const char pycrypto_box_keypair__doc__[]=
"crypto_box_keypair() -> (pk,sk)\n\n\
The crypto_box_keypair function randomly generates a secret key and\n\
a corresponding public key. It returns tuple containing the secret key in sk and\n\
public key in pk.\n\
It guarantees that sk has crypto_box_SECRETKEYBYTES bytes\n\
and that pk has crypto_box_PUBLICKEYBYTES bytes.\n\
";


/* API: s = crypto_box_beforenm(pk,sk); */
PyObject *pycrypto_box_beforenm(PyObject *self, PyObject *args, PyObject *kw) {

    const unsigned char *pk, *sk;
    Py_ssize_t pklen=0, sklen=0;
    static const char *kwlist[] = {"pk", "sk", 0};
    PyObject *ret;

    if (!PyArg_ParseTupleAndKeywords(args, kw,
                                     "|s#s#:crypto_box_beforenm",
                                     (char **) kwlist,
                                     (char **)&pk, &pklen,
                                     (char **)&sk, &sklen)) {
        return (PyObject *)0;
    }


    if (pklen != crypto_box_PUBLICKEYBYTES)
        return naclexception("incorrect public-key length");
    if (sklen != crypto_box_SECRETKEYBYTES)
        return naclexception("incorrect secret-key length");

    ret = PyBytes_FromStringAndSize((char *)0, crypto_box_BEFORENMBYTES);
    if (!ret) return ret;
    crypto_box_beforenm((unsigned char *)PyBytes_AS_STRING(ret), pk, sk);
    return ret;
}

const char pycrypto_box_beforenm__doc__[]=
"crypto_box_beforenm(pk,sk) -> s\n\n\
Function crypto_box_beforenm computes a shared secret s from \n\
public key pk and secret key sk\n\
The function raises an exception if len(sk) is not crypto_box_SECRETKEYBYTES.\n\
It also raises an exception if len(pk) is not crypto_box_PUBLICKEYBYTES.\n\
";


/* API: c = crypto_box_afternm(m,n,k); */
PyObject *pycrypto_box_afternm(PyObject *self, PyObject *args, PyObject *kw) {

    const unsigned char *m, *n, *k;
    Py_ssize_t msize = 0, nsize = 0, ksize = 0;
    static const char *kwlist[] = {"m", "n", "k", 0};
    PyObject *ret;
    long long i;
    unsigned long long mlen;
    unsigned char *mpad;
    unsigned char *cpad;

    if (!PyArg_ParseTupleAndKeywords(args, kw,
                                     "|s#s#s#:crypto_box_afternm",
                                     (char **)kwlist,
                                     (char **)&m, &msize,
                                     (char **)&n, &nsize,
                                     (char **)&k, &ksize)) {
        return (PyObject *)0;
    }

    if (nsize != crypto_box_NONCEBYTES) return naclexception("incorrect nonce length");
    if (ksize != crypto_box_BEFORENMBYTES) return naclexception("incorrect key length");

    mlen = msize + crypto_box_ZEROBYTES;
    mpad = PyMem_Malloc(mlen);
    if (!mpad) return PyErr_NoMemory();
    cpad = PyMem_Malloc(mlen + crypto_box_BOXZEROBYTES);
    if (!cpad) {
        PyMem_Free(mpad);
        return PyErr_NoMemory();
    }

    for (i = 0; i < crypto_box_ZEROBYTES; ++i) mpad[i] = 0;
    for (i = crypto_box_ZEROBYTES; i < mlen; ++i) mpad[i] = m[i - crypto_box_ZEROBYTES];

    crypto_box_afternm(cpad, mpad, mlen, n, k);

    ret = PyBytes_FromStringAndSize(
        (char *)cpad + crypto_box_BOXZEROBYTES,
        mlen - crypto_box_BOXZEROBYTES
    );

    PyMem_Free(mpad);
    PyMem_Free(cpad);
    return ret;
}

const char pycrypto_box_afternm__doc__[]=
"crypto_box_afternm(m,n,k) -> c\n\n\
The crypto_box_afternm function encrypts and authenticates\n\
a message m using a secret key k and a nonce n. \n\
The crypto_box_afternm function returns the resulting ciphertext c. \n\
The function raises an exception if len(k) is not crypto_box_BEFORENMBYTES.\n\
The function also raises an exception if len(n) is not crypto_box_NONCEBYTES.\n\
";


/* API: m = crypto_box_open_afternm(c,n,k); */
PyObject *pycrypto_box_open_afternm(PyObject *self, PyObject *args, PyObject *kw) {

    const unsigned char *c, *n, *k;
    Py_ssize_t csize = 0, nsize = 0, ksize = 0;
    static const char *kwlist[] = {"c", "n", "k", 0};
    PyObject *ret;
    long long i;
    unsigned long long clen;
    unsigned char *mpad;
    unsigned char *cpad;

    if (!PyArg_ParseTupleAndKeywords(args, kw,
                                     "|s#s#s#:crypto_box_open_afternm",
                                     (char **)kwlist,
                                     (char **)&c, &csize,
                                     (char **)&n, &nsize,
                                     (char **)&k, &ksize)) {
        return (PyObject *)0;
    }

    if (nsize != crypto_box_NONCEBYTES) return naclexception("incorrect nonce length");
    if (ksize != crypto_box_BEFORENMBYTES) return naclexception("incorrect key length");

    clen = csize + crypto_box_BOXZEROBYTES;
    mpad = PyMem_Malloc(clen);
    if (!mpad) return PyErr_NoMemory();
    cpad = PyMem_Malloc(clen + crypto_box_ZEROBYTES);
    if (!cpad) {
        PyMem_Free(mpad);
        return PyErr_NoMemory();
    }

    for (i = 0; i < crypto_box_BOXZEROBYTES; ++i) cpad[i] = 0;
    for (i = crypto_box_BOXZEROBYTES; i < clen; ++i) cpad[i] = c[i - crypto_box_BOXZEROBYTES];

    if (crypto_box_open_afternm(mpad, cpad, clen, n, k) != 0) {
        PyMem_Free(mpad);
        PyMem_Free(cpad);
        return naclexception("ciphertext fails verification");
    }
    if (clen < crypto_box_ZEROBYTES) {
        PyMem_Free(mpad);
        PyMem_Free(cpad);
        return naclexception("ciphertext too short");
    }

    ret = PyBytes_FromStringAndSize(
        (char *)mpad + crypto_box_ZEROBYTES,
        clen - crypto_box_ZEROBYTES
    );

    PyMem_Free(mpad);
    PyMem_Free(cpad);
    return ret;
}

const char pycrypto_box_open_afternm__doc__[]=
"crypto_box_open_afternm(c,n,k) -> m\n\n\
The crypto_box_open_afternm function verifies and decrypts \n\
a ciphertext c using a secret key k and a nonce n.\n\
The crypto_box_open_afternm function returns the resulting plaintext m.\n\
If the ciphertext fails verification, crypto_box_open_afternm raises an exception.\n\
The function also raises an exception if len(k) is not crypto_box_BEFORENMBYTES,\n\
or if len(n) is not crypto_box_NONCEBYTES.\n\
";


/* C API: c = crypto_box_curve25519xsalsa20poly1305(m,n,pk,sk); */
PyObject *pycrypto_box_curve25519xsalsa20poly1305(PyObject *self, PyObject *args, PyObject *kw) {

    const unsigned char *m, *n, *pk, *sk;
    Py_ssize_t msize = 0, nsize = 0, pksize = 0, sksize = 0;
    static const char *kwlist[] = {"m", "n", "pk", "sk", 0};
    PyObject *ret;
    long long i;
    unsigned long long mlen;
    unsigned char *mpad;
    unsigned char *cpad;

    if (!PyArg_ParseTupleAndKeywords(args, kw,
                                     "|s#s#s#s#:crypto_box_curve25519xsalsa20poly1305",
                                     (char **)kwlist,
                                     (char **)&m, &msize,
                                     (char **)&n, &nsize,
                                     (char **)&pk, &pksize,
                                     (char **)&sk, &sksize)) {
        return (PyObject *)0;
    }

    if (nsize != crypto_box_curve25519xsalsa20poly1305_NONCEBYTES) return naclexception("incorrect nonce length");
    if (pksize != crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES) return naclexception("incorrect public-key length");
    if (sksize != crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES) return naclexception("incorrect secret-key length");

    mlen = msize + crypto_box_curve25519xsalsa20poly1305_ZEROBYTES;
    mpad = PyMem_Malloc(mlen);
    if (!mpad) return PyErr_NoMemory();
    cpad = PyMem_Malloc(mlen + crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES);
    if (!cpad) {
        PyMem_Free(mpad);
        return PyErr_NoMemory();
    }

    for (i = 0; i < crypto_box_curve25519xsalsa20poly1305_ZEROBYTES; ++i) mpad[i] = 0;
    for (i = crypto_box_curve25519xsalsa20poly1305_ZEROBYTES; i < mlen; ++i) mpad[i] = m[i - crypto_box_curve25519xsalsa20poly1305_ZEROBYTES];

    crypto_box_curve25519xsalsa20poly1305(cpad, mpad, mlen, n, pk, sk);

    ret = PyBytes_FromStringAndSize(
        (char *)cpad + crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES,
        mlen - crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES
    );

    PyMem_Free(mpad);
    PyMem_Free(cpad);
    return ret;
}

const char pycrypto_box_curve25519xsalsa20poly1305__doc__[]=
"crypto_box_curve25519xsalsa20poly1305(m,n,pk,sk) -> c\n\n\
The crypto_box_curve25519xsalsa20poly1305 function encrypts and authenticates a message m\n\
using the sender's secret key sk, the receiver's public key pk,\n\
and a nonce n. The crypto_box_curve25519xsalsa20poly1305 function returns the resulting ciphertext c.\n\
The function raises an exception if len(sk) is not crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES\n\
or if len(pk) is not crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES\n\
or if len(n) is not crypto_box_curve25519xsalsa20poly1305_NONCEBYTES.\n\
";


/* API: m = crypto_box_curve25519xsalsa20poly1305_open(c,n,pk,sk); */
PyObject *pycrypto_box_curve25519xsalsa20poly1305_open(PyObject *self, PyObject *args, PyObject *kw) {

    const unsigned char *c, *n, *pk, *sk;
    Py_ssize_t csize = 0, nsize = 0, pksize = 0, sksize = 0;
    static const char *kwlist[] = {"c", "n", "pk", "sk", 0};
    PyObject *ret;
    long long i;
    unsigned long long clen;
    unsigned char *mpad;
    unsigned char *cpad;

    if (!PyArg_ParseTupleAndKeywords(args, kw,
                                     "|s#s#s#s#:crypto_box_curve25519xsalsa20poly1305_open",
                                     (char **)kwlist,
                                     (char **)&c, &csize,
                                     (char **)&n, &nsize,
                                     (char **)&pk, &pksize,
                                     (char **)&sk, &sksize)) {
        return (PyObject *)0;
    }

    if (nsize != crypto_box_curve25519xsalsa20poly1305_NONCEBYTES) return naclexception("incorrect nonce length");
    if (pksize != crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES) return naclexception("incorrect public-key length");
    if (sksize != crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES) return naclexception("incorrect secret-key length");

    clen = csize + crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES;
    mpad = PyMem_Malloc(clen);
    if (!mpad) return PyErr_NoMemory();
    cpad = PyMem_Malloc(clen + crypto_box_curve25519xsalsa20poly1305_ZEROBYTES);
    if (!cpad) {
        PyMem_Free(mpad);
        return PyErr_NoMemory();
    }

    for (i = 0; i < crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES; ++i) cpad[i] = 0;
    for (i = crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES; i < clen; ++i) cpad[i] = c[i - crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES];

    if (crypto_box_curve25519xsalsa20poly1305_open(mpad, cpad, clen, n, pk, sk) != 0) {
        PyMem_Free(mpad);
        PyMem_Free(cpad);
        return naclexception("ciphertext fails verification");
    }
    if (clen < crypto_box_curve25519xsalsa20poly1305_ZEROBYTES) {
        PyMem_Free(mpad);
        PyMem_Free(cpad);
        return naclexception("ciphertext too short");
    }
    ret = PyBytes_FromStringAndSize(
        (char *)mpad + crypto_box_curve25519xsalsa20poly1305_ZEROBYTES,
        clen - crypto_box_curve25519xsalsa20poly1305_ZEROBYTES
    );
    PyMem_Free(mpad);
    PyMem_Free(cpad);
    return ret;

}

const char pycrypto_box_curve25519xsalsa20poly1305_open__doc__[]=
"crypto_box_curve25519xsalsa20poly1305_open(c,n,pk,sk) -> m\n\n\
The crypto_box_curve25519xsalsa20poly1305_open function verifies and decrypts\n\
a ciphertext c using the receiver's secret key sk,\n\
the sender's public key pk, and a nonce n.\n\
The crypto_box_curve25519xsalsa20poly1305_open function returns the resulting plaintext m.\n\
The function raises an exception if len(sk) is not crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES\n\
or if len(pk) is not crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES\n\
or if len(n) is not crypto_box_curve25519xsalsa20poly1305_NONCEBYTES.\n\
";


/* API: (pk,sk) = crypto_box_curve25519xsalsa20poly1305_keypair(); */
PyObject *pycrypto_box_curve25519xsalsa20poly1305_keypair(PyObject *self) {

    PyObject *pypk, *pysk, *ret;

    pypk = PyBytes_FromStringAndSize((char *)0, crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES);
    if (!pypk) return (PyObject *)0;

    pysk = PyBytes_FromStringAndSize((char *)0, crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES);
    if (!pysk) {
        Py_DECREF(pypk);
        return (PyObject *)0;
    }
    ret = PyTuple_New(2);
    if (!ret) {
        Py_DECREF(pypk);
        Py_DECREF(pysk);
        return (PyObject *)0;
    }
    PyTuple_SET_ITEM(ret, 0, pypk);
    PyTuple_SET_ITEM(ret, 1, pysk);

    crypto_box_curve25519xsalsa20poly1305_keypair(
        (unsigned char *)PyBytes_AS_STRING(pypk),
        (unsigned char *)PyBytes_AS_STRING(pysk)
    );

    return ret;
}

const char pycrypto_box_curve25519xsalsa20poly1305_keypair__doc__[]=
"crypto_box_curve25519xsalsa20poly1305_keypair() -> (pk,sk)\n\n\
The crypto_box_curve25519xsalsa20poly1305_keypair function randomly generates a secret key and\n\
a corresponding public key. It returns tuple containing the secret key in sk and\n\
public key in pk.\n\
It guarantees that sk has crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES bytes\n\
and that pk has crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES bytes.\n\
";


/* API: s = crypto_box_curve25519xsalsa20poly1305_beforenm(pk,sk); */
PyObject *pycrypto_box_curve25519xsalsa20poly1305_beforenm(PyObject *self, PyObject *args, PyObject *kw) {

    const unsigned char *pk, *sk;
    Py_ssize_t pklen=0, sklen=0;
    static const char *kwlist[] = {"pk", "sk", 0};
    PyObject *ret;

    if (!PyArg_ParseTupleAndKeywords(args, kw,
                                     "|s#s#:crypto_box_curve25519xsalsa20poly1305_beforenm",
                                     (char **) kwlist,
                                     (char **)&pk, &pklen,
                                     (char **)&sk, &sklen)) {
        return (PyObject *)0;
    }


    if (pklen != crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES)
        return naclexception("incorrect public-key length");
    if (sklen != crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES)
        return naclexception("incorrect secret-key length");

    ret = PyBytes_FromStringAndSize((char *)0, crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES);
    if (!ret) return ret;
    crypto_box_curve25519xsalsa20poly1305_beforenm((unsigned char *)PyBytes_AS_STRING(ret), pk, sk);
    return ret;
}

const char pycrypto_box_curve25519xsalsa20poly1305_beforenm__doc__[]=
"crypto_box_curve25519xsalsa20poly1305_beforenm(pk,sk) -> s\n\n\
Function crypto_box_curve25519xsalsa20poly1305_beforenm computes a shared secret s from \n\
public key pk and secret key sk\n\
The function raises an exception if len(sk) is not crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES.\n\
It also raises an exception if len(pk) is not crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES.\n\
";


/* API: c = crypto_box_curve25519xsalsa20poly1305_afternm(m,n,k); */
PyObject *pycrypto_box_curve25519xsalsa20poly1305_afternm(PyObject *self, PyObject *args, PyObject *kw) {

    const unsigned char *m, *n, *k;
    Py_ssize_t msize = 0, nsize = 0, ksize = 0;
    static const char *kwlist[] = {"m", "n", "k", 0};
    PyObject *ret;
    long long i;
    unsigned long long mlen;
    unsigned char *mpad;
    unsigned char *cpad;

    if (!PyArg_ParseTupleAndKeywords(args, kw,
                                     "|s#s#s#:crypto_box_curve25519xsalsa20poly1305_afternm",
                                     (char **)kwlist,
                                     (char **)&m, &msize,
                                     (char **)&n, &nsize,
                                     (char **)&k, &ksize)) {
        return (PyObject *)0;
    }

    if (nsize != crypto_box_curve25519xsalsa20poly1305_NONCEBYTES) return naclexception("incorrect nonce length");
    if (ksize != crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES) return naclexception("incorrect key length");

    mlen = msize + crypto_box_curve25519xsalsa20poly1305_ZEROBYTES;
    mpad = PyMem_Malloc(mlen);
    if (!mpad) return PyErr_NoMemory();
    cpad = PyMem_Malloc(mlen + crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES);
    if (!cpad) {
        PyMem_Free(mpad);
        return PyErr_NoMemory();
    }

    for (i = 0; i < crypto_box_curve25519xsalsa20poly1305_ZEROBYTES; ++i) mpad[i] = 0;
    for (i = crypto_box_curve25519xsalsa20poly1305_ZEROBYTES; i < mlen; ++i) mpad[i] = m[i - crypto_box_curve25519xsalsa20poly1305_ZEROBYTES];

    crypto_box_curve25519xsalsa20poly1305_afternm(cpad, mpad, mlen, n, k);

    ret = PyBytes_FromStringAndSize(
        (char *)cpad + crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES,
        mlen - crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES
    );

    PyMem_Free(mpad);
    PyMem_Free(cpad);
    return ret;
}

const char pycrypto_box_curve25519xsalsa20poly1305_afternm__doc__[]=
"crypto_box_curve25519xsalsa20poly1305_afternm(m,n,k) -> c\n\n\
The crypto_box_curve25519xsalsa20poly1305_afternm function encrypts and authenticates\n\
a message m using a secret key k and a nonce n. \n\
The crypto_box_curve25519xsalsa20poly1305_afternm function returns the resulting ciphertext c. \n\
The function raises an exception if len(k) is not crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES.\n\
The function also raises an exception if len(n) is not crypto_box_curve25519xsalsa20poly1305_NONCEBYTES.\n\
";


/* API: m = crypto_box_curve25519xsalsa20poly1305_open_afternm(c,n,k); */
PyObject *pycrypto_box_curve25519xsalsa20poly1305_open_afternm(PyObject *self, PyObject *args, PyObject *kw) {

    const unsigned char *c, *n, *k;
    Py_ssize_t csize = 0, nsize = 0, ksize = 0;
    static const char *kwlist[] = {"c", "n", "k", 0};
    PyObject *ret;
    long long i;
    unsigned long long clen;
    unsigned char *mpad;
    unsigned char *cpad;

    if (!PyArg_ParseTupleAndKeywords(args, kw,
                                     "|s#s#s#:crypto_box_curve25519xsalsa20poly1305_open_afternm",
                                     (char **)kwlist,
                                     (char **)&c, &csize,
                                     (char **)&n, &nsize,
                                     (char **)&k, &ksize)) {
        return (PyObject *)0;
    }

    if (nsize != crypto_box_curve25519xsalsa20poly1305_NONCEBYTES) return naclexception("incorrect nonce length");
    if (ksize != crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES) return naclexception("incorrect key length");

    clen = csize + crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES;
    mpad = PyMem_Malloc(clen);
    if (!mpad) return PyErr_NoMemory();
    cpad = PyMem_Malloc(clen + crypto_box_curve25519xsalsa20poly1305_ZEROBYTES);
    if (!cpad) {
        PyMem_Free(mpad);
        return PyErr_NoMemory();
    }

    for (i = 0; i < crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES; ++i) cpad[i] = 0;
    for (i = crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES; i < clen; ++i) cpad[i] = c[i - crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES];

    if (crypto_box_curve25519xsalsa20poly1305_open_afternm(mpad, cpad, clen, n, k) != 0) {
        PyMem_Free(mpad);
        PyMem_Free(cpad);
        return naclexception("ciphertext fails verification");
    }
    if (clen < crypto_box_curve25519xsalsa20poly1305_ZEROBYTES) {
        PyMem_Free(mpad);
        PyMem_Free(cpad);
        return naclexception("ciphertext too short");
    }

    ret = PyBytes_FromStringAndSize(
        (char *)mpad + crypto_box_curve25519xsalsa20poly1305_ZEROBYTES,
        clen - crypto_box_curve25519xsalsa20poly1305_ZEROBYTES
    );

    PyMem_Free(mpad);
    PyMem_Free(cpad);
    return ret;
}

const char pycrypto_box_curve25519xsalsa20poly1305_open_afternm__doc__[]=
"crypto_box_curve25519xsalsa20poly1305_open_afternm(c,n,k) -> m\n\n\
The crypto_box_curve25519xsalsa20poly1305_open_afternm function verifies and decrypts \n\
a ciphertext c using a secret key k and a nonce n.\n\
The crypto_box_curve25519xsalsa20poly1305_open_afternm function returns the resulting plaintext m.\n\
If the ciphertext fails verification, crypto_box_curve25519xsalsa20poly1305_open_afternm raises an exception.\n\
The function also raises an exception if len(k) is not crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES,\n\
or if len(n) is not crypto_box_curve25519xsalsa20poly1305_NONCEBYTES.\n\
";

static PyMethodDef nacl_methods[] = {
    {"crypto_onetimeauth", (PyCFunction)pycrypto_onetimeauth, METH_VARARGS | METH_KEYWORDS, pycrypto_onetimeauth__doc__},
    {"crypto_onetimeauth_verify", (PyCFunction)pycrypto_onetimeauth_verify, METH_VARARGS | METH_KEYWORDS, pycrypto_onetimeauth_verify__doc__},
    {"crypto_onetimeauth_poly1305", (PyCFunction)pycrypto_onetimeauth_poly1305, METH_VARARGS | METH_KEYWORDS, pycrypto_onetimeauth_poly1305__doc__},
    {"crypto_onetimeauth_poly1305_verify", (PyCFunction)pycrypto_onetimeauth_poly1305_verify, METH_VARARGS | METH_KEYWORDS, pycrypto_onetimeauth_poly1305_verify__doc__},
    {"crypto_hash", (PyCFunction)pycrypto_hash, METH_VARARGS | METH_KEYWORDS, pycrypto_hash__doc__},
    {"crypto_hash_sha512", (PyCFunction)pycrypto_hash_sha512, METH_VARARGS | METH_KEYWORDS, pycrypto_hash_sha512__doc__},
    {"crypto_verify_16", (PyCFunction)pycrypto_verify_16, METH_VARARGS | METH_KEYWORDS, pycrypto_verify_16__doc__},
    {"crypto_verify_32", (PyCFunction)pycrypto_verify_32, METH_VARARGS | METH_KEYWORDS, pycrypto_verify_32__doc__},
    {"crypto_scalarmult", (PyCFunction)pycrypto_scalarmult, METH_VARARGS | METH_KEYWORDS, pycrypto_scalarmult__doc__},
    {"crypto_scalarmult_base", (PyCFunction)pycrypto_scalarmult_base, METH_VARARGS | METH_KEYWORDS, pycrypto_scalarmult_base__doc__},
    {"crypto_scalarmult_curve25519", (PyCFunction)pycrypto_scalarmult_curve25519, METH_VARARGS | METH_KEYWORDS, pycrypto_scalarmult_curve25519__doc__},
    {"crypto_scalarmult_curve25519_base", (PyCFunction)pycrypto_scalarmult_curve25519_base, METH_VARARGS | METH_KEYWORDS, pycrypto_scalarmult_curve25519_base__doc__},
    {"crypto_stream", (PyCFunction)pycrypto_stream, METH_VARARGS | METH_KEYWORDS, pycrypto_stream__doc__},
    {"crypto_stream_xor", (PyCFunction)pycrypto_stream_xor, METH_VARARGS | METH_KEYWORDS, pycrypto_stream_xor__doc__},
    {"crypto_stream_xsalsa20", (PyCFunction)pycrypto_stream_xsalsa20, METH_VARARGS | METH_KEYWORDS, pycrypto_stream_xsalsa20__doc__},
    {"crypto_stream_xsalsa20_xor", (PyCFunction)pycrypto_stream_xsalsa20_xor, METH_VARARGS | METH_KEYWORDS, pycrypto_stream_xsalsa20_xor__doc__},
    {"crypto_stream_salsa20", (PyCFunction)pycrypto_stream_salsa20, METH_VARARGS | METH_KEYWORDS, pycrypto_stream_salsa20__doc__},
    {"crypto_stream_salsa20_xor", (PyCFunction)pycrypto_stream_salsa20_xor, METH_VARARGS | METH_KEYWORDS, pycrypto_stream_salsa20_xor__doc__},
    {"crypto_sign", (PyCFunction)pycrypto_sign, METH_VARARGS | METH_KEYWORDS, pycrypto_sign__doc__},
    {"crypto_sign_open", (PyCFunction)pycrypto_sign_open, METH_VARARGS | METH_KEYWORDS, pycrypto_sign_open__doc__},
    {"crypto_sign_keypair", (PyCFunction)pycrypto_sign_keypair, METH_VARARGS | METH_KEYWORDS, pycrypto_sign_keypair__doc__},
    {"crypto_sign_ed25519", (PyCFunction)pycrypto_sign_ed25519, METH_VARARGS | METH_KEYWORDS, pycrypto_sign_ed25519__doc__},
    {"crypto_sign_ed25519_open", (PyCFunction)pycrypto_sign_ed25519_open, METH_VARARGS | METH_KEYWORDS, pycrypto_sign_ed25519_open__doc__},
    {"crypto_sign_ed25519_keypair", (PyCFunction)pycrypto_sign_ed25519_keypair, METH_VARARGS | METH_KEYWORDS, pycrypto_sign_ed25519_keypair__doc__},
    {"crypto_secretbox", (PyCFunction)pycrypto_secretbox, METH_VARARGS | METH_KEYWORDS, pycrypto_secretbox__doc__},
    {"crypto_secretbox_open", (PyCFunction)pycrypto_secretbox_open, METH_VARARGS | METH_KEYWORDS, pycrypto_secretbox_open__doc__},
    {"crypto_secretbox_xsalsa20poly1305", (PyCFunction)pycrypto_secretbox_xsalsa20poly1305, METH_VARARGS | METH_KEYWORDS, pycrypto_secretbox_xsalsa20poly1305__doc__},
    {"crypto_secretbox_xsalsa20poly1305_open", (PyCFunction)pycrypto_secretbox_xsalsa20poly1305_open, METH_VARARGS | METH_KEYWORDS, pycrypto_secretbox_xsalsa20poly1305_open__doc__},
    {"crypto_box", (PyCFunction)pycrypto_box, METH_VARARGS | METH_KEYWORDS, pycrypto_box__doc__},
    {"crypto_box_open", (PyCFunction)pycrypto_box_open, METH_VARARGS | METH_KEYWORDS, pycrypto_box_open__doc__},
    {"crypto_box_keypair", (PyCFunction)pycrypto_box_keypair, METH_VARARGS | METH_KEYWORDS, pycrypto_box_keypair__doc__},
    {"crypto_box_beforenm", (PyCFunction)pycrypto_box_beforenm, METH_VARARGS | METH_KEYWORDS, pycrypto_box_beforenm__doc__},
    {"crypto_box_afternm", (PyCFunction)pycrypto_box_afternm, METH_VARARGS | METH_KEYWORDS, pycrypto_box_afternm__doc__},
    {"crypto_box_open_afternm", (PyCFunction)pycrypto_box_open_afternm, METH_VARARGS | METH_KEYWORDS, pycrypto_box_open_afternm__doc__},
    {"crypto_box_curve25519xsalsa20poly1305", (PyCFunction)pycrypto_box_curve25519xsalsa20poly1305, METH_VARARGS | METH_KEYWORDS, pycrypto_box_curve25519xsalsa20poly1305__doc__},
    {"crypto_box_curve25519xsalsa20poly1305_open", (PyCFunction)pycrypto_box_curve25519xsalsa20poly1305_open, METH_VARARGS | METH_KEYWORDS, pycrypto_box_curve25519xsalsa20poly1305_open__doc__},
    {"crypto_box_curve25519xsalsa20poly1305_keypair", (PyCFunction)pycrypto_box_curve25519xsalsa20poly1305_keypair, METH_VARARGS | METH_KEYWORDS, pycrypto_box_curve25519xsalsa20poly1305_keypair__doc__},
    {"crypto_box_curve25519xsalsa20poly1305_beforenm", (PyCFunction)pycrypto_box_curve25519xsalsa20poly1305_beforenm, METH_VARARGS | METH_KEYWORDS, pycrypto_box_curve25519xsalsa20poly1305_beforenm__doc__},
    {"crypto_box_curve25519xsalsa20poly1305_afternm", (PyCFunction)pycrypto_box_curve25519xsalsa20poly1305_afternm, METH_VARARGS | METH_KEYWORDS, pycrypto_box_curve25519xsalsa20poly1305_afternm__doc__},
    {"crypto_box_curve25519xsalsa20poly1305_open_afternm", (PyCFunction)pycrypto_box_curve25519xsalsa20poly1305_open_afternm, METH_VARARGS | METH_KEYWORDS, pycrypto_box_curve25519xsalsa20poly1305_open_afternm__doc__},

    {"randombytes",(PyCFunction)naclrandombytes, METH_VARARGS | METH_KEYWORDS, randombytes__doc__},
    {"_randreplace", (PyCFunction)nacl_randreplace, METH_VARARGS | METH_KEYWORDS},
    {"_fromhex", (PyCFunction)nacl_fromhex, METH_VARARGS | METH_KEYWORDS},
    {(void *)0, (void *)0}
};

void add_constants(PyObject *m) {
    PyModule_AddStringConstant(m, "crypto_onetimeauth_PRIMITIVE", crypto_onetimeauth_PRIMITIVE);
    PyModule_AddStringConstant(m, "crypto_onetimeauth_IMPLEMENTATION", crypto_onetimeauth_IMPLEMENTATION);
    PyModule_AddStringConstant(m, "crypto_onetimeauth_VERSION", crypto_onetimeauth_VERSION);
    PyModule_AddIntConstant(m, "crypto_onetimeauth_BYTES", crypto_onetimeauth_BYTES);
    PyModule_AddIntConstant(m, "crypto_onetimeauth_KEYBYTES", crypto_onetimeauth_KEYBYTES);
    PyModule_AddIntConstant(m, "crypto_onetimeauth_poly1305_BYTES", crypto_onetimeauth_poly1305_BYTES);
    PyModule_AddIntConstant(m, "crypto_onetimeauth_poly1305_KEYBYTES", crypto_onetimeauth_poly1305_KEYBYTES);
    PyModule_AddStringConstant(m, "crypto_onetimeauth_poly1305_IMPLEMENTATION", crypto_onetimeauth_poly1305_IMPLEMENTATION);
    PyModule_AddStringConstant(m, "crypto_onetimeauth_poly1305_VERSION", crypto_onetimeauth_poly1305_VERSION);
    PyModule_AddStringConstant(m, "crypto_hash_PRIMITIVE", crypto_hash_PRIMITIVE);
    PyModule_AddStringConstant(m, "crypto_hash_IMPLEMENTATION", crypto_hash_IMPLEMENTATION);
    PyModule_AddStringConstant(m, "crypto_hash_VERSION", crypto_hash_VERSION);
    PyModule_AddIntConstant(m, "crypto_hash_BYTES", crypto_hash_BYTES);
    PyModule_AddIntConstant(m, "crypto_hash_sha512_BYTES", crypto_hash_sha512_BYTES);
    PyModule_AddStringConstant(m, "crypto_hash_sha512_IMPLEMENTATION", crypto_hash_sha512_IMPLEMENTATION);
    PyModule_AddStringConstant(m, "crypto_hash_sha512_VERSION", crypto_hash_sha512_VERSION);
    PyModule_AddIntConstant(m, "crypto_verify_16_BYTES", crypto_verify_16_BYTES);
    PyModule_AddStringConstant(m, "crypto_verify_16_IMPLEMENTATION", crypto_verify_16_IMPLEMENTATION);
    PyModule_AddStringConstant(m, "crypto_verify_16_VERSION", crypto_verify_16_VERSION);
    PyModule_AddIntConstant(m, "crypto_verify_32_BYTES", crypto_verify_32_BYTES);
    PyModule_AddStringConstant(m, "crypto_verify_32_IMPLEMENTATION", crypto_verify_32_IMPLEMENTATION);
    PyModule_AddStringConstant(m, "crypto_verify_32_VERSION", crypto_verify_32_VERSION);
    PyModule_AddStringConstant(m, "crypto_scalarmult_PRIMITIVE", crypto_scalarmult_PRIMITIVE);
    PyModule_AddStringConstant(m, "crypto_scalarmult_IMPLEMENTATION", crypto_scalarmult_IMPLEMENTATION);
    PyModule_AddStringConstant(m, "crypto_scalarmult_VERSION", crypto_scalarmult_VERSION);
    PyModule_AddIntConstant(m, "crypto_scalarmult_BYTES", crypto_scalarmult_BYTES);
    PyModule_AddIntConstant(m, "crypto_scalarmult_SCALARBYTES", crypto_scalarmult_SCALARBYTES);
    PyModule_AddIntConstant(m, "crypto_scalarmult_curve25519_BYTES", crypto_scalarmult_curve25519_BYTES);
    PyModule_AddIntConstant(m, "crypto_scalarmult_curve25519_SCALARBYTES", crypto_scalarmult_curve25519_SCALARBYTES);
    PyModule_AddStringConstant(m, "crypto_scalarmult_curve25519_IMPLEMENTATION", crypto_scalarmult_curve25519_IMPLEMENTATION);
    PyModule_AddStringConstant(m, "crypto_scalarmult_curve25519_VERSION", crypto_scalarmult_curve25519_VERSION);
    PyModule_AddStringConstant(m, "crypto_stream_PRIMITIVE", crypto_stream_PRIMITIVE);
    PyModule_AddStringConstant(m, "crypto_stream_IMPLEMENTATION", crypto_stream_IMPLEMENTATION);
    PyModule_AddStringConstant(m, "crypto_stream_VERSION", crypto_stream_VERSION);
    PyModule_AddIntConstant(m, "crypto_stream_KEYBYTES", crypto_stream_KEYBYTES);
    PyModule_AddIntConstant(m, "crypto_stream_NONCEBYTES", crypto_stream_NONCEBYTES);
    PyModule_AddIntConstant(m, "crypto_stream_xsalsa20_KEYBYTES", crypto_stream_xsalsa20_KEYBYTES);
    PyModule_AddIntConstant(m, "crypto_stream_xsalsa20_NONCEBYTES", crypto_stream_xsalsa20_NONCEBYTES);
    PyModule_AddStringConstant(m, "crypto_stream_xsalsa20_IMPLEMENTATION", crypto_stream_xsalsa20_IMPLEMENTATION);
    PyModule_AddStringConstant(m, "crypto_stream_xsalsa20_VERSION", crypto_stream_xsalsa20_VERSION);
    PyModule_AddIntConstant(m, "crypto_stream_salsa20_KEYBYTES", crypto_stream_salsa20_KEYBYTES);
    PyModule_AddIntConstant(m, "crypto_stream_salsa20_NONCEBYTES", crypto_stream_salsa20_NONCEBYTES);
    PyModule_AddStringConstant(m, "crypto_stream_salsa20_IMPLEMENTATION", crypto_stream_salsa20_IMPLEMENTATION);
    PyModule_AddStringConstant(m, "crypto_stream_salsa20_VERSION", crypto_stream_salsa20_VERSION);
    PyModule_AddStringConstant(m, "crypto_sign_PRIMITIVE", crypto_sign_PRIMITIVE);
    PyModule_AddStringConstant(m, "crypto_sign_IMPLEMENTATION", crypto_sign_IMPLEMENTATION);
    PyModule_AddStringConstant(m, "crypto_sign_VERSION", crypto_sign_VERSION);
    PyModule_AddIntConstant(m, "crypto_sign_BYTES", crypto_sign_BYTES);
    PyModule_AddIntConstant(m, "crypto_sign_PUBLICKEYBYTES", crypto_sign_PUBLICKEYBYTES);
    PyModule_AddIntConstant(m, "crypto_sign_SECRETKEYBYTES", crypto_sign_SECRETKEYBYTES);
    PyModule_AddIntConstant(m, "crypto_sign_ed25519_BYTES", crypto_sign_ed25519_BYTES);
    PyModule_AddIntConstant(m, "crypto_sign_ed25519_PUBLICKEYBYTES", crypto_sign_ed25519_PUBLICKEYBYTES);
    PyModule_AddIntConstant(m, "crypto_sign_ed25519_SECRETKEYBYTES", crypto_sign_ed25519_SECRETKEYBYTES);
    PyModule_AddStringConstant(m, "crypto_sign_ed25519_IMPLEMENTATION", crypto_sign_ed25519_IMPLEMENTATION);
    PyModule_AddStringConstant(m, "crypto_sign_ed25519_VERSION", crypto_sign_ed25519_VERSION);
    PyModule_AddStringConstant(m, "crypto_secretbox_PRIMITIVE", crypto_secretbox_PRIMITIVE);
    PyModule_AddStringConstant(m, "crypto_secretbox_IMPLEMENTATION", crypto_secretbox_IMPLEMENTATION);
    PyModule_AddStringConstant(m, "crypto_secretbox_VERSION", crypto_secretbox_VERSION);
    PyModule_AddIntConstant(m, "crypto_secretbox_KEYBYTES", crypto_secretbox_KEYBYTES);
    PyModule_AddIntConstant(m, "crypto_secretbox_NONCEBYTES", crypto_secretbox_NONCEBYTES);
    PyModule_AddIntConstant(m, "crypto_secretbox_ZEROBYTES", crypto_secretbox_ZEROBYTES);
    PyModule_AddIntConstant(m, "crypto_secretbox_BOXZEROBYTES", crypto_secretbox_BOXZEROBYTES);
    PyModule_AddIntConstant(m, "crypto_secretbox_xsalsa20poly1305_KEYBYTES", crypto_secretbox_xsalsa20poly1305_KEYBYTES);
    PyModule_AddIntConstant(m, "crypto_secretbox_xsalsa20poly1305_NONCEBYTES", crypto_secretbox_xsalsa20poly1305_NONCEBYTES);
    PyModule_AddIntConstant(m, "crypto_secretbox_xsalsa20poly1305_ZEROBYTES", crypto_secretbox_xsalsa20poly1305_ZEROBYTES);
    PyModule_AddIntConstant(m, "crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES", crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES);
    PyModule_AddStringConstant(m, "crypto_secretbox_xsalsa20poly1305_IMPLEMENTATION", crypto_secretbox_xsalsa20poly1305_IMPLEMENTATION);
    PyModule_AddStringConstant(m, "crypto_secretbox_xsalsa20poly1305_VERSION", crypto_secretbox_xsalsa20poly1305_VERSION);
    PyModule_AddStringConstant(m, "crypto_box_PRIMITIVE", crypto_box_PRIMITIVE);
    PyModule_AddStringConstant(m, "crypto_box_IMPLEMENTATION", crypto_box_IMPLEMENTATION);
    PyModule_AddStringConstant(m, "crypto_box_VERSION", crypto_box_VERSION);
    PyModule_AddIntConstant(m, "crypto_box_PUBLICKEYBYTES", crypto_box_PUBLICKEYBYTES);
    PyModule_AddIntConstant(m, "crypto_box_SECRETKEYBYTES", crypto_box_SECRETKEYBYTES);
    PyModule_AddIntConstant(m, "crypto_box_BEFORENMBYTES", crypto_box_BEFORENMBYTES);
    PyModule_AddIntConstant(m, "crypto_box_NONCEBYTES", crypto_box_NONCEBYTES);
    PyModule_AddIntConstant(m, "crypto_box_ZEROBYTES", crypto_box_ZEROBYTES);
    PyModule_AddIntConstant(m, "crypto_box_BOXZEROBYTES", crypto_box_BOXZEROBYTES);
    PyModule_AddIntConstant(m, "crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES", crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES);
    PyModule_AddIntConstant(m, "crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES", crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES);
    PyModule_AddIntConstant(m, "crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES", crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES);
    PyModule_AddIntConstant(m, "crypto_box_curve25519xsalsa20poly1305_NONCEBYTES", crypto_box_curve25519xsalsa20poly1305_NONCEBYTES);
    PyModule_AddIntConstant(m, "crypto_box_curve25519xsalsa20poly1305_ZEROBYTES", crypto_box_curve25519xsalsa20poly1305_ZEROBYTES);
    PyModule_AddIntConstant(m, "crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES", crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES);
    PyModule_AddStringConstant(m, "crypto_box_curve25519xsalsa20poly1305_IMPLEMENTATION", crypto_box_curve25519xsalsa20poly1305_IMPLEMENTATION);
    PyModule_AddStringConstant(m, "crypto_box_curve25519xsalsa20poly1305_VERSION", crypto_box_curve25519xsalsa20poly1305_VERSION);
    return;
}

#if PY_MAJOR_VERSION >= 3
struct PyModuleDef nacl_def = {
    PyModuleDef_HEAD_INIT,
    "tweetnacl",
    NULL,
    -1,
    nacl_methods,
    NULL, NULL, NULL, NULL
};
#endif

#if PY_MAJOR_VERSION >= 3
PyMODINIT_FUNC PyInit_tweetnacl(void) {
#else
PyMODINIT_FUNC inittweetnacl(void) {
#endif
    PyObject *m;
    unsigned char dummy[1];
#if PY_MAJOR_VERSION >= 3
    m = PyModule_Create( &nacl_def );
    if (!m) return m;
#else
    m = Py_InitModule("tweetnacl", nacl_methods);
    if (!m) return;
#endif
    add_constants(m);
    randombytes(dummy,0);
#if PY_MAJOR_VERSION >= 3
    return m;
#endif
}

